def print_result(result):
    print("\n----------------------------")
    
    print("Control     :", result["control"])
    print("Title       :", result.get("description", "N/A"))
    print("Status      :", result["status"])
    print("Severity    :", result.get("severity", "N/A"))

    if "details" in result and result["details"]:
        print("Details     :", result["details"])

    if "resource_count" in result:
        print("Resources   :", result["resource_count"])

    if "non_compliant_users" in result and result["non_compliant_users"]:
        print("Non-Compliant Users:", result["non_compliant_users"])

    if "non_compliant_buckets" in result and result["non_compliant_buckets"]:
        print("Non-Compliant Buckets:", result["non_compliant_buckets"])

    if "public_buckets" in result and result["public_buckets"]:
        print("Public Buckets:", result["public_buckets"])

    if "public_write_buckets" in result and result["public_write_buckets"]:
        print("Public Write Buckets:", result["public_write_buckets"])

    if "public_policy_buckets" in result and result["public_policy_buckets"]:
        print("Public Policy Buckets:", result["public_policy_buckets"])

    if "non_compliant_trails" in result and result["non_compliant_trails"]:
        print("Non-Compliant Trails:", result["non_compliant_trails"])

    if "non_compliant_sgs" in result and result["non_compliant_sgs"]:
        print("Non-Compliant Security Groups:", result["non_compliant_sgs"])

    if "non_compliant_instances" in result and result["non_compliant_instances"]:
        print("Non-Compliant Instances:", result["non_compliant_instances"])

    if "error" in result:
        print("Error       :", result["error"])

    print("----------------------------")


import json
from datetime import datetime


def generate_summary(results):
    summary = {
        "total_controls": len(results),
        "pass": 0,
        "fail": 0,
        "error": 0
    }

    for r in results:
        status = r.get("status")

        if status == "PASS":
            summary["pass"] += 1
        elif status == "FAIL":
            summary["fail"] += 1
        else:
            summary["error"] += 1

    return summary


def export_json_report(results, aws, file_path="results/scan.json"):
    try:
        sts = aws.client("sts")
        identity = sts.get_caller_identity()

        report = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "account_id": identity.get("Account"),
                "arn": identity.get("Arn"),
                "region": "global"
            },
            "summary": generate_summary(results),
            "results": results
        }

        with open(file_path, "w") as f:
            json.dump(report, f, indent=4)

        print(f"\n[+] JSON report exported: {file_path}")

    except Exception as e:
        print("[-] Failed to export report:", e)

    summary = generate_summary(results)

    print("\n===== Scan Summary =====")
    print(f"Total Controls : {summary['total_controls']}")
    print(f"PASS           : {summary['pass']} ({summary['pass_percentage']}%)")
    print(f"FAIL           : {summary['fail']} ({summary['fail_percentage']}%)")
    print(f"ERROR          : {summary['error']}")
    print("========================\n")

    return

def generate_summary(results):
    summary = {
        "total_controls": len(results),
        "pass": 0,
        "fail": 0,
        "error": 0,
        "pass_percentage": 0,
        "fail_percentage": 0
    }

    for r in results:
        status = r.get("status")

        if status == "PASS":
            summary["pass"] += 1
        elif status == "FAIL":
            summary["fail"] += 1
        else:
            summary["error"] += 1

    total = summary["total_controls"]

    if total > 0:
        summary["pass_percentage"] = round((summary["pass"] / total) * 100, 2)
        summary["fail_percentage"] = round((summary["fail"] / total) * 100, 2)

    return summary