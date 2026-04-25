def cis_1_1(aws):
    report = aws.credential_report()

    result = {
        "control": "CIS 1.1",
        "description": "Ensure root account is not used and MFA is enabled",
        "severity": "HIGH",
        "resource_count": 0,
        "status": "PASS",
        "details": {
            "root_mfa_enabled": False,
            "root_last_used": None
        }
    }

    try:
        iam = aws.client("iam")

        report = aws.credential_report()

        # MFA check
        summary = iam.get_account_summary()
        result["details"]["root_mfa_enabled"] = bool(
            summary["SummaryMap"].get("AccountMFAEnabled", 0)
        )

        # root usage check
        for r in report:
            if r["user"] == "<root_account>":
                result["details"]["root_last_used"] = r["password_last_used"]

        # evaluation
        if not result["details"]["root_mfa_enabled"]:
            result["status"] = "FAIL"

        if result["details"]["root_last_used"] not in ["N/A", "no_information"]:
            result["status"] = "FAIL"

    except Exception as e:
        result["status"] = "ERROR"
        result["details"]["error"] = str(e)

    return result

def cis_1_2(aws):
    report = aws.credential_report()

    result = {
        "control": "CIS 1.2",
        "description": "Ensure root account access keys do not exist",
        "severity": "CRITICAL",
        "status": "PASS",
    }

    for r in report:
        if r["user"] == "<root_account>":
            if r["access_key_1_active"] == "true" or r["access_key_2_active"] == "true":
                result["status"] = "FAIL"

    return result


def cis_1_3(aws):
    report = aws.credential_report()

    result = {
        "control": "CIS 1.3",
        "description": "Ensure IAM users with console access have MFA enabled",
        "severity": "HIGH",
        "status": "PASS",
        "non_compliant_users": [],
        "resource_count": 0
    }

    try:
        for row in report:
            username = row.get("user")

            # Skip root account
            if username == "<root_account>":
                continue

            password_enabled = row.get("password_enabled", "false").lower()
            mfa_active = row.get("mfa_active", "false").lower()

            # Count only console-enabled users
            if password_enabled == "true":
                result["resource_count"] += 1

                # MFA violation
                if mfa_active != "true":
                    result["non_compliant_users"].append(username)

        if result["non_compliant_users"]:
            result["status"] = "FAIL"

    except Exception as e:
        print("DEBUG ERROR CIS 1.3:", str(e))

    return result