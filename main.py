import os

from core.aws_session import AWSSessionManager
from engine import ScanEngine
from core.report import export_json_report
from pyfiglet import Figlet
from colorama import Fore, Style


def show_banner():
    banner = Figlet(font="slant")
    print(Fore.CYAN + banner.renderText("AWS CSPM SCANNER"))
    print(Fore.YELLOW + "| Version = 1.1.0 | Author = evilprince00 |\n" + Style.RESET_ALL)


def main():
    role_arn = os.environ.get("AWS_SCANNER_ROLE_ARN")
    if not role_arn:
        raise SystemExit(
            "Set AWS_SCANNER_ROLE_ARN to the IAM role ARN the scanner is authorized to assume."
        )

    aws = AWSSessionManager(role_arn)
    aws.assume_role()

    show_banner()
    engine = ScanEngine(aws)
    results = engine.run_all()
    export_json_report(results, aws)


if __name__ == "__main__":
    main()
