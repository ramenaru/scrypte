import argparse
from scanner import scan_website  
from report import report_generator  

import os

def display_banner():
    banner = """
                           _       
                          | |      
 ___  ___ _ __ _   _ _ __ | |_ ___ 
/ __|/ __| '__| | | | '_ \| __/ _ \
\__ \ (__| |  | |_| | |_) | ||  __/
|___/\___|_|   \__, | .__/ \__\___|
                __/ | |            
               |___/|_|            
 """
    print(banner)

def parse_arguments():
    parser = argparse.ArgumentParser(description="SCRYPT3 - A powerful web vulnerability scanner")
    parser.add_argument("url", type=str, help="URL of the website to scan")
    parser.add_argument("--output", type=str, default="report.txt", help="Report file name")
    parser.add_argument("--json", action="store_true", help="Output report as JSON")
    parser.add_argument("--html", action="store_true", help="Output report as HTML")
    parser.add_argument("--all", action="store_true", help="Run all scans")
    parser.add_argument("--headers", action="store_true", help="Scan headers for vulnerabilities")
    parser.add_argument("--xss", action="store_true", help="Check for potential XSS vulnerabilities")
    parser.add_argument("--sql", action="store_true", help="Check for SQL injection vulnerabilities")
    return parser.parse_args()

def run():
    display_banner()
    args = parse_arguments()

    scan_results = scan_website(args.url, args)

    if args.json:
        report_generator.generate_json_report(scan_results, args.output)
    elif args.html:
        report_generator.generate_html_report(scan_results, args.output)
    else:
        report_generator.generate_text_report(scan_results, args.output)

if __name__ == "__main__":
    run()
