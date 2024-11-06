from .header_scan import HeaderScan
from .xss_scan import XSSScan

def scan_website(url, args):
    vulnerabilities = []

    if args.all or args.headers:
        header_scan = HeaderScan(url)
        header_scan.run()
        vulnerabilities.extend(header_scan.get_vulnerabilities())

    if args.all or args.xss:
        xss_scan = XSSScan(url)
        xss_scan.run()
        vulnerabilities.extend(xss_scan.get_vulnerabilities())

    return {
        "url": url,
        "vulnerabilities": vulnerabilities,
    }
