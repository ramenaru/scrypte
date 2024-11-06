import json

def generate_json_report(scan_results, output_filename):
    detailed_report = {
        "url": scan_results["url"],
        "vulnerabilities": []
    }
    for vuln in scan_results["vulnerabilities"]:
        detailed_report["vulnerabilities"].append({
            "issue": vuln["issue"],
            "severity": vuln["severity"],
            "description": vuln["description"],
            "recommendation": vuln["recommendation"]
        })

    with open(output_filename, "w") as report:
        json.dump(detailed_report, report, indent=4)
