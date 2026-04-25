class EC2DataCache:
    def __init__(self, aws):
        self.aws = aws
        self.regions = []
        self.instances = {}
        self.security_groups = {}

    def load_regions(self):
        ec2 = self.aws.client("ec2", region="ap-south-1")
        response = ec2.describe_regions()
        self.regions = [r["RegionName"] for r in response["Regions"]]

    def load_instances(self):
        for region in self.regions:
            ec2 = self.aws.client("ec2", region=region)

            response = ec2.describe_instances()

            instances = []
            for r in response["Reservations"]:
                for i in r["Instances"]:
                    instances.append(i)

            self.instances[region] = instances

    def load_security_groups(self):
        for region in self.regions:
            ec2 = self.aws.client("ec2", region=region)
            response = ec2.describe_security_groups()
            self.security_groups[region] = response["SecurityGroups"]

    def load_all(self):
        self.load_regions()
        self.load_instances()
        self.load_security_groups()