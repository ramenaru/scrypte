from .header_scan import HeaderScan
from .xss_scan import XSSScan
from .directory_scan import DirectoryScan
from .sql_injection_scan import SQLInjectionScan
from .tls_scan import TLSScan


def scan_website(url, args):
    vulnerabilities = []

    # Header Scan
    if args.all or args.headers:
        header_scan = HeaderScan(url)
        header_scan.run()
        vulnerabilities.extend(header_scan.get_vulnerabilities())

    # XSS Scan
    if args.all or args.xss:
        xss_scan = XSSScan(url)
        xss_scan.run()
        vulnerabilities.extend(xss_scan.get_vulnerabilities())

    # Directory Scan
    if args.all or args.directory:
        directory_scan = DirectoryScan(url)
        directory_scan.run()
        vulnerabilities.extend(directory_scan.get_vulnerabilities())

    # SQL Injection Scan
    if args.all or args.sql:
        sql_scan = SQLInjectionScan(url)
        sql_scan.run()
        vulnerabilities.extend(sql_scan.get_vulnerabilities())

    # TLS Scan
    if args.all or args.tls:
        tls_scan = TLSScan(url)
        tls_scan.run()
        vulnerabilities.extend(tls_scan.get_vulnerabilities())

    return {
        "url": url,
        "vulnerabilities": vulnerabilities,
    }
