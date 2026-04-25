import boto3
from botocore.exceptions import ClientError
import time
import csv
import io


class AWSSessionManager:
    def __init__(self, role_arn, session_name="CISScannerSession"):
        self.role_arn = role_arn
        self.session_name = session_name
        self.session = None
        self.credential_report = None

    def assume_role(self):
        try:
            sts_client = boto3.client("sts")

            response = sts_client.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName=self.session_name
            )

            creds = response["Credentials"]

            self.session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )

            print("[+] Role assumed successfully")

        except ClientError as e:
            print("[-] Failed to assume role:", e)
            self.session = None

    def get_client(self, service, region_name=None):
        if not self.session:
            raise Exception("Session not initialized. Call assume_role() first.")
        return self.session.client(service, region_name=region_name)

    def get_credential_report(self):
        if self.credential_report:
            return self.credential_report

        iam = self.get_client("iam")

        try:
            try:
                iam.get_credential_report()
            except iam.exceptions.CredentialReportNotPresentException:
                iam.generate_credential_report()
                time.sleep(2)

            report = iam.get_credential_report()
            content = report["Content"].decode("utf-8")

            reader = list(csv.DictReader(io.StringIO(content)))
            self.credential_report = reader

            return reader

        except Exception as e:
            print("[-] Error fetching credential report:", e)
            return []


# ---------------- CIS CHECKS ---------------- #

def check_root_account(aws_manager):
    print("\n[+] CIS 1.1 - Root Account Usage & MFA")

    iam = aws_manager.get_client("iam")
    report = aws_manager.get_credential_report()

    result = {
        "control": "CIS 1.1",
        "description": "Ensure root access has MFA enabled & not used recently",
        "root_mfa_enabled": False,
        "root_last_used": None,
        "severity": "HIGH",
        "status": "UNKNOWN"
    }

    try:
        summary = iam.get_account_summary()
        result["root_mfa_enabled"] = bool(summary["SummaryMap"].get("AccountMFAEnabled", 0))

        for row in report:
            if row["user"] == "<root_account>":
                result["root_last_used"] = row["password_last_used"]

        if result["root_mfa_enabled"] and result["root_last_used"] in ["N/A", "no_information"]:
            result["status"] = "PASS"
        else:
            result["status"] = "FAIL"

    except Exception as e:
        print("[-] Error:", e)

    print(result)
    return result


def check_root_access_keys(aws_manager):
    print("\n[+] CIS 1.2 - Root Access Keys")

    report = aws_manager.get_credential_report()

    result = {
        "control": "CIS 1.2",
        "descirption": "Ensure no root account access keys exist",
        "root_access_keys_present": False,
        "severity": "CRITICAL",
        "status": "UNKNOWN"
    }

    for row in report:
        if row["user"] == "<root_account>":
            if row["access_key_1_active"] == "true" or row["access_key_2_active"] == "true":
                result["root_access_keys_present"] = True

    result["status"] = "FAIL" if result["root_access_keys_present"] else "PASS"

    print(result)
    return result


def check_iam_user_mfa(aws_manager):
    print("\n[+] CIS 1.3 - IAM User MFA")

    report = aws_manager.get_credential_report()

    result = {
        "control": "CIS 1.3",
        "descirption" : "Ensure MFA is enabled for all IAM users with console access",
        "non_compliant_users": [],
        "severity": "HIGH",
        "status": "UNKNOWN"
    }

    for row in report:
        username = row["user"]

        if username == "<root_account>":
            continue

        if row["password_enabled"] == "true" and row["mfa_active"] == "false":
            result["non_compliant_users"].append(username)

    result["status"] = "FAIL" if result["non_compliant_users"] else "PASS"

    print(result)
    return result

def check_password_policy(aws_manager):
    print("\n[+] CIS 1.4 - IAM Password Policy")

    iam = aws_manager.get_client("iam")

    result = {
        "control": "CIS 1.4",
        "descirption" : "Ensure IAM password policy enforces strong password complexity and rotation",
        "status": "UNKNOWN",
        "severity": "HIGH",
        "details": {}
    }

    try:
        response = iam.get_account_password_policy()
        policy = response["PasswordPolicy"]

        checks = {
            "min_length": policy.get("MinimumPasswordLength", 0),
            "require_uppercase": policy.get("RequireUppercaseCharacters", False),
            "require_lowercase": policy.get("RequireLowercaseCharacters", False),
            "require_numbers": policy.get("RequireNumbers", False),
            "require_symbols": policy.get("RequireSymbols", False),
            "password_reuse_prevention": policy.get("PasswordReusePrevention", 0),
            "max_age_enabled": "MaxPasswordAge" in policy
        }

        result["details"] = checks

        # ---- CIS evaluation rules (simplified but practical) ----
        failures = []

        if checks["min_length"] < 14:
            failures.append("Min length < 14")

        if not checks["require_uppercase"]:
            failures.append("Uppercase not required")

        if not checks["require_lowercase"]:
            failures.append("Lowercase not required")

        if not checks["require_numbers"]:
            failures.append("Numbers not required")

        if not checks["require_symbols"]:
            failures.append("Symbols not required")

        if checks["password_reuse_prevention"] < 24:
            failures.append("Password reuse prevention < 24")

        if not checks["max_age_enabled"]:
            failures.append("Password expiration not enabled")

        # ---- Final status ----
        if len(failures) == 0:
            result["status"] = "PASS"
        else:
            result["status"] = "FAIL"
            result["details"]["failures"] = failures

    except iam.exceptions.NoSuchEntityException:
        result["status"] = "FAIL"
        result["details"]["error"] = "No password policy configured"

    except Exception as e:
        result["status"] = "ERROR"
        result["details"]["error"] = str(e)

    print(result)
    return result

# ---------------- MAIN ---------------- #

if __name__ == "__main__":
    ROLE_ARN = "arn:aws:iam::984606368270:role/CisScannerRole"

    aws_manager = AWSSessionManager(ROLE_ARN)
    aws_manager.assume_role()

    if aws_manager.session:
        results = []

        results.append(check_root_account(aws_manager))
        results.append(check_root_access_keys(aws_manager))
        results.append(check_iam_user_mfa(aws_manager))
        results.append(check_password_policy(aws_manager))