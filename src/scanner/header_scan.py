from .base_scan import BaseScan
import requests

class HeaderScan(BaseScan):
    def run(self):
        try:
            response = requests.get(self.url, timeout=10)
            headers = response.headers

            self.check_server_version(headers)
            self.check_security_headers(headers)

        except requests.exceptions.RequestException as e:
            self.vulnerabilities.append({
                "issue": "Network error",
                "severity": "critical",
                "description": f"Error accessing {self.url}: {e}",
                "recommendation": "Check URL validity and network connectivity."
            })

    def check_server_version(self, headers):
        server_header = headers.get("Server", "")
        if "Apache/2.4.1" in server_header:
            self.vulnerabilities.append({
                "issue": "Outdated Apache server",
                "severity": "high",
                "description": f"Server version detected: {server_header}",
                "recommendation": "Update Apache server to a secure version."
            })
        elif server_header:
            self.vulnerabilities.append({
                "issue": "Server version exposed",
                "severity": "medium",
                "description": f"Server version detected: {server_header}",
                "recommendation": "Hide server version information to reduce attack surface."
            })

    def check_security_headers(self, headers):
        if "Content-Security-Policy" not in headers:
            self.vulnerabilities.append({
                "issue": "Missing Content-Security-Policy",
                "severity": "high",
                "description": "Content-Security-Policy header is missing.",
                "recommendation": "Add a CSP header to mitigate XSS attacks."
            })

        if headers.get("X-Content-Type-Options") != "nosniff":
            self.vulnerabilities.append({
                "issue": "Missing or incorrect X-Content-Type-Options",
                "severity": "medium",
                "description": "X-Content-Type-Options header is missing or not set to 'nosniff'.",
                "recommendation": "Set X-Content-Type-Options to 'nosniff' to prevent MIME-type sniffing."
            })

        if "Strict-Transport-Security" not in headers:
            self.vulnerabilities.append({
                "issue": "Missing Strict-Transport-Security",
                "severity": "high",
                "description": "Strict-Transport-Security header is missing.",
                "recommendation": "Add HSTS header to enforce HTTPS and protect against protocol downgrade attacks."
            })

        if headers.get("X-Frame-Options") not in ["DENY", "SAMEORIGIN"]:
            self.vulnerabilities.append({
                "issue": "Missing or incorrect X-Frame-Options",
                "severity": "medium",
                "description": "X-Frame-Options header is missing or set to an insecure value.",
                "recommendation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent clickjacking."
            })
