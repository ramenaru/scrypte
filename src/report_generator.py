def generate_report(scan_results, output_filename):
    with open(f"reports/{output_filename}", "w") as report:
        report.write(f"Report for {scan_results['url']}\n")
        report.write(f"Status Code: {scan_results['status_code']}\n\n")
        
        if 'error' in scan_results:
            report.write(f"Error: {scan_results['error']}\n")
        else:
            report.write("Vulnerabilities found:\n")
            for vuln in scan_results["vulnerabilities"]:
                report.write(f"- {vuln}\n")

    print(f"Report saved as {output_filename}")
