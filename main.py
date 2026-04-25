from core.aws_session import AWSSessionManager
from engine import ScanEngine
from core.report import export_json_report


ROLE_ARN = "arn:aws:iam::984606368270:role/CisScannerRole"

aws = AWSSessionManager(ROLE_ARN)
aws.assume_role()

engine = ScanEngine(aws)
results = engine.run_all()

export_json_report(results, aws)