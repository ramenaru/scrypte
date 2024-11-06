import json

def generate_text_report(scan_results, output_filename):
    with open(f"reports/{output_filename}", "w") as report:
        report.write(f"Report for {scan_results['url']}\n")
        report.write("Vulnerabilities:\n")
        for vuln in scan_results["vulnerabilities"]:
            report.write(f"- {vuln}\n")

def generate_json_report(scan_results, output_filename):
    with open(f"reports/{output_filename}", "w") as report:
        json.dump(scan_results, report, indent=4)

def generate_html_report(scan_results, output_filename):
    with open(f"reports/{output_filename}", "w") as report:
        report.write("<html><head><title>Scan Report</title></head><body>")
        report.write(f"<h1>Report for {scan_results['url']}</h1>")
        report.write("<ul>")
        for vuln in scan_results["vulnerabilities"]:
            report.write(f"<li>{vuln}</li>")
        report.write("</ul></body></html>")
