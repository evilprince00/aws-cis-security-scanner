from core.aws_session import AWSSessionManager
from engine import ScanEngine
from core.report import export_json_report
from pyfiglet import Figlet
from colorama import Fore, Style


ROLE_ARN = "arn:aws:iam::984606368270:role/CisScannerRole"

aws = AWSSessionManager(ROLE_ARN)
aws.assume_role()

def show_banner():
    banner = Figlet(font='slant')
    print(Fore.CYAN + banner.renderText('AWS CSPM SCANNER'))
    print(Fore.YELLOW + "| Version = 1.1.0 | Author = evilprince00 |\n" + Style.RESET_ALL)

show_banner()

engine = ScanEngine(aws)
results = engine.run_all()

export_json_report(results, aws)
