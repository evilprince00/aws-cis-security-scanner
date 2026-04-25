import json

def cis_2_1(aws):
    s3 = aws.client("s3")



    result = {
        "control": "CIS 2.1",
        "description": "Ensure S3 buckets are not publicly accessible",
        "severity": "CRITICAL",
        "status": "PASS",
        "resource_count" : 0,
        "public_buckets": []
    }

    try:
        buckets = s3.list_buckets()["Buckets"]
        result["resource_count"] = len(buckets)

        for bucket in buckets:
            bucket_name = bucket["Name"]
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
                # If no block config → risky
                is_public = True

            # ---- Check ACL ----
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)

                for grant in acl["Grants"]:
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")

                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        is_public = True

            except Exception:
                pass

            # ---- Check Bucket Policy ----
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy["Policy"])

                for stmt in policy_json.get("Statement", []):
                    if stmt.get("Principal") == "*":
                        is_public = True

            except Exception:
                pass

            # ---- Final decision ----
            if is_public:
                result["public_buckets"].append(bucket_name)

        if result["public_buckets"]:
            result["status"] = "FAIL"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def cis_2_2(aws):

    s3 = aws.client("s3")

    result = {
        "control": "CIS 2.2",
        "description": "Ensure S3 buckets do not allow public write access",
        "severity": "CRITICAL",
        "status": "PASS",
        "public_write_buckets": []
    }

    try:
        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            bucket_name = bucket["Name"]
            is_public_write = False

            # ----------------------------
            # 1. Check Bucket ACL
            # ----------------------------
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)

                for grant in acl["Grants"]:
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    permission = grant.get("Permission", "")

                    if ("AllUsers" in uri or "AuthenticatedUsers" in uri):
                        if permission in ["WRITE", "FULL_CONTROL"]:
                            is_public_write = True

            except Exception:
                pass

            # ----------------------------
            # 2. Check Bucket Policy
            # ----------------------------
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy["Policy"])

                for stmt in policy_json.get("Statement", []):

                    principal = stmt.get("Principal")
                    effect = stmt.get("Effect", "Deny")
                    actions = stmt.get("Action", [])

                    # Normalize action to list
                    if isinstance(actions, str):
                        actions = [actions]

                    # Only care about ALLOW
                    if effect != "Allow":
                        continue

                    # Public principal check
                    if principal == "*" or principal == {"AWS": "*"}:

                        for action in actions:
                            if action.lower() in [
                                "s3:putobject",
                                "s3:deleteobject",
                                "s3:*"
                            ]:
                                is_public_write = True

            except Exception:
                pass

            # ----------------------------
            # Final decision
            # ----------------------------
            if is_public_write:
                result["public_write_buckets"].append(bucket_name)

        if result["public_write_buckets"]:
            result["status"] = "FAIL"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def cis_2_3(aws):

    s3 = aws.client("s3")

    result = {
        "control": "CIS 2.3",
        "description": "Ensure S3 bucket policies restrict public access",
        "severity": "HIGH",
        "status": "PASS",
        "unrestricted_public_buckets": [],
        "restricted_public_buckets": []
    }

    try:
        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy["Policy"])

                for stmt in policy_json.get("Statement", []):

                    effect = stmt.get("Effect", "Deny")
                    principal = stmt.get("Principal")
                    condition = stmt.get("Condition", {})

                    # Only care about ALLOW
                    if effect != "Allow":
                        continue

                    # Check public principal
                    if principal == "*" or principal == {"AWS": "*"}:

                        # Check if condition exists (restriction)
                        if condition:
                            result["restricted_public_buckets"].append(bucket_name)
                        else:
                            result["unrestricted_public_buckets"].append(bucket_name)

            except Exception:
                # No policy → skip
                continue

        # ----------------------------
        # Evaluation
        # ----------------------------
        if result["unrestricted_public_buckets"]:
            result["status"] = "FAIL"
        elif result["restricted_public_buckets"]:
            result["status"] = "WARNING"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def cis_2_4(aws):

    s3 = aws.client("s3")

    result = {
        "control": "CIS 2.4",
        "description": "Ensure S3 bucket logging is enabled",
        "severity": "MEDIUM",
        "status": "PASS",
        "buckets_without_logging": [],
        "buckets_with_logging": []
    }

    try:
        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                logging = s3.get_bucket_logging(Bucket=bucket_name)

                if "LoggingEnabled" in logging:
                    result["buckets_with_logging"].append(bucket_name)
                else:
                    result["buckets_without_logging"].append(bucket_name)

            except Exception:
                # If error fetching logging → treat as no logging
                result["buckets_without_logging"].append(bucket_name)

        # ----------------------------
        # Evaluation
        # ----------------------------
        if result["buckets_without_logging"]:
            result["status"] = "FAIL"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result