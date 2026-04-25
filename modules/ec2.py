def is_port_exposed(perm, target_port):

    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")

    # Handle cases like "all ports"
    if from_port is None or to_port is None:
        port_match = True
    else:
        port_match = from_port <= target_port <= to_port

    if not port_match:
        return False

    # Check IPv4
    for ip_range in perm.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            return True

    # Check IPv6
    for ip_range in perm.get("Ipv6Ranges", []):
        if ip_range.get("CidrIpv6") == "::/0":
            return True

    return False


def cis_4_1(aws, ec2_cache):

    result = {
        "control": "CIS 4.1",
        "description": "Ensure no security groups allow SSH (22) from the internet",
        "severity": "CRITICAL",
        "status": "PASS",
        "non_compliant_sgs": []
    }

    seen = set()

    try:
        for region, sgs in ec2_cache.security_groups.items():

            for sg in sgs:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")

                for rule in sg.get("IpPermissions", []):

                    if rule.get("FromPort") == 22 and rule.get("ToPort") == 22:

                        # IPv4
                        for ip in rule.get("IpRanges", []):
                            if ip.get("CidrIp") == "0.0.0.0/0":

                                key = (sg_id, region)
                                if key not in seen:
                                    seen.add(key)

                                    result["non_compliant_sgs"].append({
                                        "GroupId": sg_id,
                                        "GroupName": sg_name,
                                        "Region": region
                                    })

                        # IPv6
                        for ip in rule.get("Ipv6Ranges", []):
                            if ip.get("CidrIpv6") == "::/0":

                                key = (sg_id, region)
                                if key not in seen:
                                    seen.add(key)

                                    result["non_compliant_sgs"].append({
                                        "GroupId": sg_id,
                                        "GroupName": sg_name,
                                        "Region": region
                                    })

        if result["non_compliant_sgs"]:
            result["status"] = "FAIL"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def cis_4_2(aws, ec2_cache):

    ec2 = aws.client("ec2")

    result = {
        "control": "CIS 4.2",
        "description": "Ensure no security groups allow RDP from the internet",
        "severity": "CRITICAL",
        "status": "PASS",
        "non_compliant_sgs": [],
        "resource_count": 0
    }

    try:
        for region, sgs in ec2_cache.security_groups.items():
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):

                    if rule.get("FromPort") == 3389:
                        for ip in rule.get("IpRanges", []):
                            if ip.get("CidrIp") == "0.0.0.0/0":
                                result["non_compliant_sgs"].append(sg["GroupId"])

        if result["non_compliant_sgs"]:
            result["status"] = "FAIL"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def cis_4_3(aws, ec2_cache):

    result = {
        "control": "CIS 4.3",
        "description": "Ensure no security groups allow unrestricted ports to the internet",
        "severity": "HIGH",
        "status": "PASS",
        "risky_sgs": []
    }

    seen = set()

    try:
        for region, sgs in ec2_cache.security_groups.items():

            for sg in sgs:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")

                for rule in sg.get("IpPermissions", []):

                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")

                    for ip in rule.get("IpRanges", []):
                        if ip.get("CidrIp") != "0.0.0.0/0":
                            continue

                        is_wide_open = (
                            from_port is None or
                            to_port is None or
                            (from_port == 0 and to_port == 65535) or
                            (to_port - from_port > 1000)
                        )

                        if is_wide_open:
                            key = (sg_id, region)
                            if key not in seen:
                                seen.add(key)

                                result["risky_sgs"].append({
                                    "GroupId": sg_id,
                                    "GroupName": sg_name,
                                    "Region": region,
                                    "PortRange": f"{from_port}-{to_port}"
                                })

        if result["risky_sgs"]:
            result["status"] = "FAIL"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result

def cis_imdsv2(aws, ec2_cache):

    ec2 = aws.client("ec2")

    result = {
        "control": "EC2 IMDSv2",
        "description": "Ensure EC2 instances enforce IMDSv2",
        "severity": "HIGH",
        "status": "PASS",
        "non_compliant_instances": [],
        "resource_count": 0
    }

    try:
        paginator = ec2.get_paginator("describe_instances")

        instance_count = 0

        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_id = instance["InstanceId"]
                    instance_count += 1

                    metadata = instance.get("MetadataOptions", {})
                    http_tokens = metadata.get("HttpTokens")

                    if http_tokens != "required":
                        result["non_compliant_instances"].append(instance_id)

        result["resource_count"] = instance_count

        if result["non_compliant_instances"]:
            result["status"] = "FAIL"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result

def cis_ebs_encryption(aws, ec2_cache):

    ec2 = aws.client("ec2")

    result = {
        "control": "EC2 EBS Encryption",
        "description": "Ensure all EBS volumes are encrypted",
        "severity": "HIGH",
        "status": "PASS",
        "non_compliant_volumes": [],
        "resource_count": 0
    }

    try:
        paginator = ec2.get_paginator("describe_volumes")

        volume_count = 0

        for page in paginator.paginate():
            for vol in page["Volumes"]:
                volume_id = vol["VolumeId"]
                volume_count += 1

                if not vol.get("Encrypted", False):
                    result["non_compliant_volumes"].append(volume_id)

        result["resource_count"] = volume_count

        if result["non_compliant_volumes"]:
            result["status"] = "FAIL"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result

def cis_public_ip(aws, ec2_cache):

    ec2 = aws.client("ec2")

    result = {
        "control": "EC2 Public IP Exposure",
        "description": "Ensure EC2 instances are not publicly exposed",
        "severity": "MEDIUM",
        "status": "PASS",
        "non_compliant_instances": [],
        "resource_count": 0
    }

    try:
        for region, instances in ec2_cache.instances.items():
            sgs = ec2_cache.security_groups.get(region, [])

            # Map SG ID → SG rules
            sg_map = {sg["GroupId"]: sg for sg in sgs}

            for instance in instances:

                public_ip = instance.get("PublicIpAddress")
                if not public_ip:
                    continue

                instance_id = instance["InstanceId"]
                attached_sgs = instance.get("SecurityGroups", [])

                is_open = False

                for sg_ref in attached_sgs:
                    sg_id = sg_ref["GroupId"]
                    sg = sg_map.get(sg_id, {})

                    for rule in sg.get("IpPermissions", []):
                        for ip in rule.get("IpRanges", []):
                            if ip.get("CidrIp") == "0.0.0.0/0":
                                is_open = True

                if is_open:
                    result["status"] = "FAIL"
                    severity = "CRITICAL"
                else:
                    severity = "WARNING"

                result["exposed_instances"].append({
                    "InstanceId": instance_id,
                    "PublicIp": public_ip,
                    "Region": region,
                    "Exposure": "OPEN" if is_open else "LIMITED",
                    "Severity": severity
                })

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result