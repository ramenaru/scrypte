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

    Version 1.0.0 by ramenaru
    """
    for line in banner_text.splitlines():
        print(Fore.CYAN + line)
        time.sleep(0.04)
    print(Fore.YELLOW + "\n✨ Welcome to scrypte! Your Web Vulnerability Scanner ✨\n")
    time.sleep(0.5)

def display_credits():
    credits = """
🌟 Follow ramenaru on GitHub for more projects!
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
    while True:
        url = input(Fore.MAGENTA + "\n🔍 Enter the URL to scan (or type 'exit' to quit): ")
        
        if url.lower() == 'exit':
            print(Fore.RED + "Exiting the application. Goodbye!")
            exit()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        if "ramenaru.me" in url:
            print(Fore.GREEN + f"🌟 Special URL detected: {url}")
            return url
        elif validate_url(url):
            print(Fore.CYAN + f"✅ Valid URL entered: {url}")
            return url
        else:
            print(Fore.RED + "❌ Invalid URL format. Please enter a valid URL starting with http:// or https://.")

def prompt_scan_type():
    menu_text = f"""{Fore.MAGENTA}
🌐 Choose the type of scan to perform:
    {Fore.YELLOW}1. General Header Scan
    2. XSS Vulnerability Scan
    3. SQL Injection Scan
    4. TLS/SSL Security Scan
    5. Directory and File Enumeration Scan
    6. Run All Scans
"""
    print(menu_text)
    choice = input(Fore.MAGENTA + "Select an option (1-6): ")

    if choice not in ["1", "2", "3", "4", "5", "6"]:
        print(Fore.RED + "❌ Invalid selection. Please choose a valid option (1-6).")
        return prompt_scan_type()
    return choice


def generate_report_filename(scan_type):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"{timestamp}_{scan_type}.json"

def create_reports_folder():
    if not os.path.exists("reports"):
        os.makedirs("reports")
        print(Fore.GREEN + "📂 Reports folder created.")
    else:
        print(Fore.YELLOW + "📁 Reports folder exists. Saving new report...")

def display_progress(message):
    print(Fore.CYAN + f"{message} ", end="")
    for _ in range(3):
        time.sleep(0.4)
        print(Fore.CYAN + ".", end="", flush=True)
    print("\n")

def display_report(scan_results):
    print("\n" + Fore.CYAN + "🔍 SCAN REPORT")
    print(Fore.CYAN + "----------------------------------------")

    if not isinstance(scan_results, dict):
        print(Fore.RED + "Error: scan_results is not in the expected dictionary format.")
        return

    vulnerabilities = scan_results.get("vulnerabilities", [])
    if not vulnerabilities:
        print(Fore.GREEN + "🎉 No vulnerabilities detected! Your site seems secure.")
        return

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").upper()
        color = (
            Fore.RED if severity in ["HIGH", "CRITICAL"]
            else Fore.YELLOW if severity == "MEDIUM"
            else Fore.GREEN
        )
        print(color + f"\n⚠️  Issue: {vuln.get('issue', 'Unknown Issue')}")
        print(Style.BRIGHT + color + f"🔴 Severity: {severity}")
        print(Fore.WHITE + f"🔎 Description: {vuln.get('description', 'No description provided.')}")
        print(Fore.WHITE + f"💡 Recommendation: {vuln.get('recommendation', 'No recommendation provided.')}")
        print(Fore.CYAN + "----------------------------------------")

def display_summary(scan_results):
    if not scan_results or "vulnerabilities" not in scan_results:
        print(Fore.RED + "No summary available. Check for issues in the scan process.")
        return

    high_count = sum(1 for vuln in scan_results["vulnerabilities"] if vuln["severity"] == "high")
    medium_count = sum(1 for vuln in scan_results["vulnerabilities"] if vuln["severity"] == "medium")
    low_count = sum(1 for vuln in scan_results["vulnerabilities"] if vuln["severity"] == "low")

    print(Fore.CYAN + "\n📊 SUMMARY OF SCAN")
    print(Fore.RED + f"🔴 High Severity Issues: {high_count}")
    print(Fore.YELLOW + f"🟡 Medium Severity Issues: {medium_count}")
    print(Fore.GREEN + f"🟢 Low Severity Issues: {low_count}")
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
            "5": "directory",
            "6": "all"
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
            "tls": scan_choice == "tls" or scan_choice == "all",
            "directory": scan_choice == "directory" or scan_choice == "all"
        })

        display_progress("🔄 Scanning in progress")
        scan_results = scan_website(url, args)

        display_report(scan_results)
        report_generator.generate_json_report(scan_results, os.path.join("reports", filename))
        print(Fore.GREEN + f"\n✅ Scan complete! Report saved as reports/{filename}")

        display_summary(scan_results)
        display_credits()

    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {e}")
        print(Fore.YELLOW + "Please check your inputs or try again later.")

if __name__ == "__main__":
    run()
