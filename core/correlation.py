def detect_attack_paths(ec2_cache):
    findings = []

    try:
        for region, instances in ec2_cache.instances.items():
            sgs = ec2_cache.security_groups.get(region, [])

            # Map SGs
            sg_map = {sg["GroupId"]: sg for sg in sgs}

            for instance in instances:

                instance_id = instance["InstanceId"]
                public_ip = instance.get("PublicIpAddress")
                metadata = instance.get("MetadataOptions", {})

                has_public_ip = bool(public_ip)
                imdsv2_required = metadata.get("HttpTokens") == "required"

                attached_sgs = instance.get("SecurityGroups", [])

                ssh_open = False

                for sg_ref in attached_sgs:
                    sg = sg_map.get(sg_ref["GroupId"], {})

                    for rule in sg.get("IpPermissions", []):
                        if rule.get("FromPort") == 22 and rule.get("ToPort") == 22:
                            for ip in rule.get("IpRanges", []):
                                if ip.get("CidrIp") == "0.0.0.0/0":
                                    ssh_open = True

                # 🔥 Attack path detection
                if has_public_ip and ssh_open and not imdsv2_required:

                    findings.append({
                        "InstanceId": instance_id,
                        "Region": region,
                        "PublicIp": public_ip,
                        "Risk": "CRITICAL",
                        "AttackPath": "Public IP + SSH Open + IMDSv1 enabled",
                        "Impact": "Potential credential theft via metadata service"
                    })

    except Exception as e:
        return [{"error": str(e)}]

    return findings