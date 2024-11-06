import os
from datetime import datetime
from scanner import scan_website
from report import report_generator

def display_banner():
    banner = """
 ░▒▓███████▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░▒▓████████▓▒░▒▓████████▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░        
 ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░  ░▒▓█▓▒░   ░▒▓██████▓▒░   
       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░        ░▒▓█▓▒░   ░▒▓█▓▒░        
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░        ░▒▓█▓▒░   ░▒▓█▓▒░        
░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░        ░▒▓█▓▒░   ░▒▓████████▓▒░ 
                                                                                                                                                    
    """
    print(banner)

def prompt_url():
    url = input("Enter the URL you want to scan: ")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url 
    return url

def prompt_scan_type():
    print("\nChoose the type of scan to perform:")
    print("1. General Header Scan")
    print("2. XSS Vulnerability Scan")
    print("3. SQL Injection Scan")
    print("4. TLS/SSL Security Scan")
    print("5. Run All Scans")
    choice = input("\nSelect an option (1-5): ")
    return choice

def generate_report_filename(scan_type):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"{timestamp}_{scan_type}.json"

def create_reports_folder():
    if not os.path.exists("reports"):
        os.makedirs("reports")
    else:
        print("Reports folder exists. Overwriting existing reports...")

def run():
    display_banner()
    url = prompt_url()
    scan_type = prompt_scan_type()

    scan_map = {
        "1": "headers",
        "2": "xss",
        "3": "sql",
        "4": "tls",
        "5": "all"
    }

    if scan_type not in scan_map:
        print("Invalid selection. Please choose a valid option.")
        return

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

    scan_results = scan_website(url, args)

    report_generator.generate_json_report(scan_results, os.path.join("reports", filename))
    print(f"\nScan complete! Report saved as reports/{filename}")

if __name__ == "__main__":
    run()
