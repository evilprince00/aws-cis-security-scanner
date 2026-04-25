from modules import iam, s3, cloudtrail, ec2
from core.report import print_result
from core.ec2_cache import EC2DataCache
from core.correlation import detect_attack_paths 


class ScanEngine:
    def __init__(self, aws):
        self.aws = aws
        self.results = []

    def run_iam_checks(self):
        checks = [
            iam.cis_1_1,
            iam.cis_1_2,
            iam.cis_1_3
        ]

        for check in checks:
            result = check(self.aws)
            self.results.append(result)
            print_result(result)
            
    def run_s3_checks(self):
        checks = [
            s3.cis_2_1,
            s3.cis_2_2,
            s3.cis_2_3,
            s3.cis_2_4
        ]

        for check in checks:
            result = check(self.aws)
            self.results.append(result)
            print_result(result)
    
    def run_cloudtrail_checks(self):
        checks = [
            cloudtrail.cis_3_1,
            cloudtrail.cis_3_2,
            cloudtrail.cis_3_3,
            cloudtrail.cis_3_4,
            cloudtrail.cis_3_5,
            cloudtrail.cis_3_6, 
            cloudtrail.cis_3_7
        ]

        for check in checks:
            result = check(self.aws)
            self.results.append(result)
            print_result(result)

    def run_ec2_checks(self):
        
        ec2_cache = EC2DataCache(self.aws)
        ec2_cache.load_all()

        checks = [
            ec2.cis_4_1,
            ec2.cis_4_2,
            ec2.cis_4_3, 
            ec2.cis_imdsv2,
            ec2.cis_ebs_encryption,
            ec2.cis_public_ip
        ]

        for check in checks:
            result = check(self.aws, ec2_cache)
            self.results.append(result)
            print_result(result)

        attack_paths = detect_attack_paths(ec2_cache)

        if attack_paths:
            print("\n🚨 ATTACK PATH FINDINGS 🚨")
            for ap in attack_paths:
                print(ap)

    def run_all(self):
        self.run_iam_checks()
        self.run_s3_checks()
        self.run_cloudtrail_checks()
        self.run_ec2_checks()
        return self.results