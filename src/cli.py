import os
import time
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import urlparse
from scanner import scan_website
from report import report_generator

init(autoreset=True)

def display_animated_banner():
    banner_text = """
    ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗███████╗
    ██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝
    ███████╗██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╗  
    ╚════██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔══╝  
    ███████║╚██████╗██║  ██║   ██║   ██║        ██║   ███████╗
    ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝                                              

    Version 1.0 by ramenaru
    """
    for line in banner_text.splitlines():
        print(Fore.CYAN + line)
        time.sleep(0.04)
    print("\n" + Fore.YELLOW + "Welcome to scrypte - Your comprehensive web vulnerability scanner!")
    time.sleep(1)

def display_credits():
    credits = """
Follow ramenaru on GitHub for more projects!
GitHub: https://github.com/ramenaru      
    """
    print(Fore.GREEN + credits)

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def prompt_url():
    url = input(Fore.MAGENTA + "\nEnter the URL you want to scan: ")
    
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    if "ramenaru.me" in url:
        print(Fore.GREEN + f"\nSpecial URL detected: {url}")
    elif validate_url(url):
        print(Fore.CYAN + f"\nURL entered: {url}")
    else:
        print(Fore.RED + "Invalid URL format. Please enter a valid URL starting with http:// or https://.")
        return prompt_url()
    
    return url

def prompt_scan_type():
    print(Fore.MAGENTA + "\nChoose the type of scan to perform:")
    print("1. General Header Scan")
    print("2. XSS Vulnerability Scan")
    print("3. SQL Injection Scan")
    print("4. TLS/SSL Security Scan")
    print("5. Run All Scans")
    choice = input(Fore.MAGENTA + "\nSelect an option (1-5): ")

    if choice not in ["1", "2", "3", "4", "5"]:
        print(Fore.RED + "Invalid selection. Please choose a valid option (1-5).")
        return prompt_scan_type()
    return choice

def generate_report_filename(scan_type):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"{timestamp}_{scan_type}.json"

def create_reports_folder():
    if not os.path.exists("reports"):
        os.makedirs("reports")
        print(Fore.GREEN + "Reports folder created.")
    else:
        print(Fore.YELLOW + "Reports folder exists. Overwriting existing reports...")

def display_progress(message):
    print(Fore.CYAN + message, end="", flush=True)
    for _ in range(3):
        time.sleep(0.5)
        print(Fore.CYAN + ".", end="", flush=True)
    print("\n")

def display_report(scan_results):
    print("\n" + Fore.CYAN + "SCAN REPORT")
    print(Fore.CYAN + f"URL: {scan_results['url']}")
    print(Fore.CYAN + "----------------------------------------")

    if not scan_results["vulnerabilities"]:
        print(Fore.GREEN + "No vulnerabilities detected.")
        return

    for vuln in scan_results["vulnerabilities"]:
        severity = vuln["severity"].upper()
        color = Fore.RED if severity == "HIGH" or severity == "CRITICAL" else Fore.YELLOW if severity == "MEDIUM" else Fore.GREEN
        print(color + f"\nIssue: {vuln['issue']}")
        print(Style.BRIGHT + color + f"Severity: {vuln['severity']}")
        print(Fore.WHITE + f"Description: {vuln['description']}")
        print(Fore.WHITE + f"Recommendation: {vuln['recommendation']}")
        print(Fore.CYAN + "----------------------------------------")

def display_summary(scan_results):
    high_count = sum(1 for vuln in scan_results["vulnerabilities"] if vuln["severity"] == "high")
    medium_count = sum(1 for vuln in scan_results["vulnerabilities"] if vuln["severity"] == "medium")
    low_count = sum(1 for vuln in scan_results["vulnerabilities"] if vuln["severity"] == "low")

    print(Fore.CYAN + "\nSUMMARY OF SCAN")
    print(Fore.RED + f"High Severity Issues: {high_count}")
    print(Fore.YELLOW + f"Medium Severity Issues: {medium_count}")
    print(Fore.GREEN + f"Low Severity Issues: {low_count}")
    print(Fore.CYAN + "----------------------------------------")

def run():
    try:
        display_animated_banner()
        url = prompt_url()
        scan_type = prompt_scan_type()

        scan_map = {
            "1": "headers",
            "2": "xss",
            "3": "sql",
            "4": "tls",
            "5": "all"
        }

        scan_choice = scan_map[scan_type]
        filename = generate_report_filename(scan_choice)
        create_reports_folder()

        args = type("Args", (object,), {
            "url": url,
            "all": scan_choice == "all",
            "headers": scan_choice == "headers" or scan_choice == "all",
            "xss": scan_choice == "xss" or scan_choice == "all",
            "sql": scan_choice == "sql" or scan_choice == "all",
            "tls": scan_choice == "tls" or scan_choice == "all"
        })

        display_progress("Scanning in progress")
        scan_results = scan_website(url, args)

        display_report(scan_results)
        report_generator.generate_json_report(scan_results, os.path.join("reports", filename))
        print(Fore.GREEN + f"\nScan complete! Report saved as reports/{filename}")

        display_summary(scan_results)
        display_credits()

    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {e}")
        print(Fore.YELLOW + "Please check your inputs or try again later.")

if __name__ == "__main__":
    run()
