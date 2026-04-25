import boto3
import time
import csv
import io

class AWSSessionManager:
    def __init__(self, role_arn, session_name="CISScanner"):
        self.role_arn = role_arn
        self.session_name = session_name
        self.session = None
        self._credential_report = None

    def assume_role(self):
        sts = boto3.client("sts")

        response = sts.assume_role(
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

    def client(self, service, region=None):
        return self.session.client(service, region_name=region)

    def credential_report(self):
        if self._credential_report:
            return self._credential_report

        iam = self.client("iam")

        try:
            try:
                iam.get_credential_report()
            except iam.exceptions.CredentialReportNotPresentException:
                iam.generate_credential_report()
                time.sleep(2)

            report = iam.get_credential_report()
            content = report["Content"].decode("utf-8")

            self._credential_report = list(csv.DictReader(io.StringIO(content)))
            return self._credential_report

        except Exception as e:
            print("[-] Credential report error:", e)
            return []