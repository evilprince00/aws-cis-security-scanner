import json
import os
from datetime import datetime, timezone


def print_result(result):
    print("\n----------------------------")
    print("Control     :", result.get("control", "N/A"))
    print("Title       :", result.get("description", "N/A"))
    print("Status      :", result.get("status", "N/A"))
    print("Severity    :", result.get("severity", "N/A"))

    if result.get("details"):
        print("Details     :", result["details"])
    if "resource_count" in result:
        print("Resources   :", result["resource_count"])

    for key in (
        "non_compliant_users", "non_compliant_buckets", "public_buckets",
        "public_write_buckets", "unrestricted_public_buckets",
        "restricted_public_buckets", "non_compliant_trails",
        "non_compliant_sgs", "risky_sgs", "non_compliant_instances",
        "non_compliant_volumes", "exposed_instances"
    ):
        if result.get(key):
            print(f"{key.replace('_', ' ').title():<24}: {result[key]}")

    if result.get("error"):
        print("Error       :", result["error"])
    print("----------------------------")


def generate_summary(results):
    summary = {
        "total_controls": len(results),
        "pass": 0,
        "fail": 0,
        "warning": 0,
        "error": 0,
        "pass_percentage": 0.0,
        "fail_percentage": 0.0
    }

    for result in results:
        status = str(result.get("status", "ERROR")).upper()
        if status == "PASS":
            summary["pass"] += 1
        elif status == "FAIL":
            summary["fail"] += 1
        elif status == "WARNING":
            summary["warning"] += 1
        else:
            summary["error"] += 1

    total = summary["total_controls"]
    if total:
        summary["pass_percentage"] = round(summary["pass"] * 100 / total, 2)
        summary["fail_percentage"] = round(summary["fail"] * 100 / total, 2)
    return summary


def export_json_report(results, aws, file_path="results/scan.json"):
    report = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "account_id": None,
            "arn": None,
            "region": "multi-region"
        },
        "summary": generate_summary(results),
        "results": results
    }

    try:
        identity = aws.client("sts").get_caller_identity()
        report["scan_metadata"]["account_id"] = identity.get("Account")
        report["scan_metadata"]["arn"] = identity.get("Arn")
    except Exception as exc:
        report["scan_metadata"]["identity_error"] = str(exc)

    try:
        output_dir = os.path.dirname(file_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, default=str)
        print(f"\n[+] JSON report exported: {file_path}")
    except OSError as exc:
        print(f"[-] Failed to export report: {exc}")

    summary = report["summary"]
    print("\n===== Scan Summary =====")
    print(f"Total Controls : {summary['total_controls']}")
    print(f"PASS           : {summary['pass']} ({summary['pass_percentage']}%)")
    print(f"FAIL           : {summary['fail']} ({summary['fail_percentage']}%)")
    print(f"WARNING        : {summary['warning']}")
    print(f"ERROR          : {summary['error']}")
    print("========================\n")
