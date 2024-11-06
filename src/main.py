import argparse
from scanner import scan_website
from report_generator import generate_report

def main():
    parser = argparse.ArgumentParser(description="Web Scraper for Vulnerabilities")
    parser.add_argument("url", type=str, help="URL of the website to scan")
    parser.add_argument("--output", type=str, default="report.txt", help="File name for the generated report")
    args = parser.parse_args()

    scan_results = scan_website(args.url)
    generate_report(scan_results, args.output)

if __name__ == "__main__":
    main()
