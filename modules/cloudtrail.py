import json

def cis_3_1(aws):

    cloudtrail = aws.client("cloudtrail")
    ec2 = aws.client("ec2")

    result = {
        "control": "CIS 3.1",
        "description": "Ensure CloudTrail is enabled in all regions",
        "severity": "CRITICAL",
        "status": "FAIL",
        "trails_found": [],
        "resource_count": 0
    }

    try:
        # Get all regions
        regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]

        trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
        result["resource_count"] = len(trails)

        multi_region_trail_found = False
        logging_enabled = False

        for trail in trails:
            result["trails_found"].append(trail.get("Name"))

            if trail.get("IsMultiRegionTrail"):
                multi_region_trail_found = True

                # Check logging status
                status = cloudtrail.get_trail_status(Name=trail.get("Name"))
                if status.get("IsLogging"):
                    logging_enabled = True

        if multi_region_trail_found and logging_enabled:
            result["status"] = "PASS"

        if result["resource_count"] == 0:
            result["status"] = "FAIL"
            result["note"] = "No CloudTrail trails found"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def cis_3_2(aws):

    cloudtrail = aws.client("cloudtrail")

    result = {
        "control": "CIS 3.2",
        "description": "Ensure CloudTrail log file validation is enabled",
        "severity": "HIGH",
        "status": "PASS",
        "non_compliant_trails": [],
        "resource_count": 0
    }

    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
        result["resource_count"] = len(trails)

        for trail in trails:
            trail_name = trail.get("Name")

            if not trail.get("LogFileValidationEnabled", False):
                result["non_compliant_trails"].append(trail_name)

        if result["non_compliant_trails"]:
            result["status"] = "FAIL"

        if result["resource_count"] == 0:
            result["status"] = "FAIL"
            result["note"] = "No CloudTrail trails found"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def cis_3_3(aws):

    cloudtrail = aws.client("cloudtrail")

    result = {
        "control": "CIS 3.3",
        "description": "Ensure CloudTrail logs are encrypted with KMS",
        "severity": "HIGH",
        "status": "PASS",
        "non_compliant_trails": [],
        "resource_count": 0
    }

    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
        result["resource_count"] = len(trails)

        for trail in trails:
            trail_name = trail.get("Name")
            kms_key = trail.get("KmsKeyId")

            if not kms_key:
                result["non_compliant_trails"].append(trail_name)

        if result["non_compliant_trails"]:
            result["status"] = "FAIL"

        if result["resource_count"] == 0:
            result["status"] = "FAIL"
            result["note"] = "No CloudTrail trails found"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def cis_3_4(aws):

    cloudtrail = aws.client("cloudtrail")
    s3 = aws.client("s3")

    result = {
        "control": "CIS 3.4",
        "description": "Ensure CloudTrail logs are stored in a secure S3 bucket",
        "severity": "CRITICAL",
        "status": "PASS",
        "non_compliant_trails": [],
        "resource_count": 0
    }

    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
        result["resource_count"] = len(trails)

        for trail in trails:
            trail_name = trail.get("Name")
            bucket_name = trail.get("S3BucketName")

            if not bucket_name:
                result["non_compliant_trails"].append(trail_name)
                continue

            is_public = False

            # ---- Check Public Access Block ----
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab["PublicAccessBlockConfiguration"]

                if not all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False)
                ]):
                    is_public = True

            except Exception:
                is_public = True

            # ---- Check ACL ----
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)

                for grant in acl["Grants"]:
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        is_public = True

            except Exception:
                pass

            # ---- Check Policy ----
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy["Policy"])

                for stmt in policy_json.get("Statement", []):
                    if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                        if not stmt.get("Condition"):
                            is_public = True

            except Exception:
                pass

            if is_public:
                result["non_compliant_trails"].append(trail_name)

        if result["non_compliant_trails"]:
            result["status"] = "FAIL"

        if result["resource_count"] == 0:
            result["status"] = "FAIL"
            result["note"] = "No CloudTrail trails found"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result

def cis_3_5(aws):

    cloudtrail = aws.client("cloudtrail")

    result = {
        "control": "CIS 3.5",
        "description": "Ensure CloudTrail is integrated with CloudWatch Logs",
        "severity": "MEDIUM",
        "status": "PASS",
        "non_compliant_trails": [],
        "resource_count": 0
    }

    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
        result["resource_count"] = len(trails)

        for trail in trails:
            trail_name = trail.get("Name")

            log_group = trail.get("CloudWatchLogsLogGroupArn")
            role_arn = trail.get("CloudWatchLogsRoleArn")

            if not log_group or not role_arn:
                result["non_compliant_trails"].append(trail_name)

        if result["non_compliant_trails"]:
            result["status"] = "FAIL"

        if result["resource_count"] == 0:
            result["status"] = "FAIL"
            result["note"] = "No CloudTrail trails found"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def cis_3_6(aws):

    cloudtrail = aws.client("cloudtrail")
    logs = aws.client("logs")

    result = {
        "control": "CIS 3.6",
        "description": "Ensure metric filter exists for unauthorized API calls",
        "severity": "HIGH",
        "status": "FAIL",
        "non_compliant_trails": [],
        "resource_count": 0
    }

    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
        result["resource_count"] = len(trails)

        for trail in trails:
            trail_name = trail.get("Name")
            log_group_arn = trail.get("CloudWatchLogsLogGroupArn")

            if not log_group_arn:
                result["non_compliant_trails"].append(trail_name)
                continue

            # Extract log group name from ARN
            log_group_name = log_group_arn.split(":log-group:")[-1]

            try:
                filters = logs.describe_metric_filters(
                    logGroupName=log_group_name
                )["metricFilters"]

                found = False

                for f in filters:
                    pattern = f.get("filterPattern", "")

                    if "UnauthorizedOperation" in pattern or "AccessDenied" in pattern:
                        found = True
                        break

                if not found:
                    result["non_compliant_trails"].append(trail_name)

            except Exception:
                result["non_compliant_trails"].append(trail_name)

        if result["non_compliant_trails"]:
            result["status"] = "FAIL"

        if result["resource_count"] == 0:
            result["note"] = "No CloudTrail trails found"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result

def cis_3_7(aws):

    cloudtrail = aws.client("cloudtrail")
    logs = aws.client("logs")

    result = {
        "control": "CIS 3.7",
        "description": "Ensure metric filter exists for console login without MFA",
        "severity": "HIGH",
        "status": "FAIL",
        "non_compliant_trails": [],
        "resource_count": 0
    }

    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
        result["resource_count"] = len(trails)

        for trail in trails:
            trail_name = trail.get("Name")
            log_group_arn = trail.get("CloudWatchLogsLogGroupArn")

            if not log_group_arn:
                result["non_compliant_trails"].append(trail_name)
                continue

            # Extract log group name
            log_group_name = log_group_arn.split(":log-group:")[-1]

            try:
                filters = logs.describe_metric_filters(
                    logGroupName=log_group_name
                )["metricFilters"]

                found = False

                for f in filters:
                    pattern = f.get("filterPattern", "")

                    if "ConsoleLogin" in pattern and "MFAUsed" in pattern:
                        found = True
                        break

                if not found:
                    result["non_compliant_trails"].append(trail_name)

            except Exception:
                result["non_compliant_trails"].append(trail_name)

        if result["non_compliant_trails"]:
            result["status"] = "FAIL"

        if result["resource_count"] == 0:
            result["note"] = "No CloudTrail trails found"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result