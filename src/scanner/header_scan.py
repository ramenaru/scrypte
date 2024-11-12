from .base_scan import BaseScan
import requests


class HeaderScan(BaseScan):
    def run(self):
        try:
            response = requests.get(self.url, timeout=10)
            headers = response.headers

            self.check_server_version(headers)
            self.check_security_headers(headers)
            self.check_http_methods()
            self.check_ssl_tls()
            self.check_cookies_security(headers)

        except requests.exceptions.RequestException as e:
            self.vulnerabilities.append(
                {
                    "issue": "Network error",
                    "severity": "critical",
                    "description": f"Error accessing {self.url}: {e}",
                    "recommendation": "Check URL validity and network connectivity.",
                }
            )

    def check_server_version(self, headers):
        server_header = headers.get("Server", "")
        if "Apache/2.4.1" in server_header:
            self.vulnerabilities.append(
                {
                    "issue": "Outdated Apache server",
                    "severity": "high",
                    "description": f"Server version detected: {server_header}",
                    "recommendation": "Update Apache server to a secure version.",
                }
            )
        elif server_header:
            self.vulnerabilities.append(
                {
                    "issue": "Server version exposed",
                    "severity": "medium",
                    "description": f"Server version detected: {server_header}",
                    "recommendation": "Hide server version information to reduce attack surface.",
                }
            )

    def check_security_headers(self, headers):
        if "Content-Security-Policy" not in headers:
            self.vulnerabilities.append(
                {
                    "issue": "Missing Content-Security-Policy",
                    "severity": "high",
                    "description": "Content-Security-Policy header is missing.",
                    "recommendation": "Add a CSP header to mitigate XSS attacks.",
                }
            )
        elif "script-src 'unsafe-inline'" in headers.get("Content-Security-Policy", ""):
            self.vulnerabilities.append(
                {
                    "issue": "Unsafe inline scripts allowed in CSP",
                    "severity": "high",
                    "description": "Content-Security-Policy allows inline scripts, which can lead to XSS attacks.",
                    "recommendation": "Avoid 'unsafe-inline' in script-src; use hash or nonce-based CSP.",
                }
            )

        if headers.get("X-Content-Type-Options") != "nosniff":
            self.vulnerabilities.append(
                {
                    "issue": "Missing or incorrect X-Content-Type-Options",
                    "severity": "medium",
                    "description": "X-Content-Type-Options header is missing or not set to 'nosniff'.",
                    "recommendation": "Set X-Content-Type-Options to 'nosniff' to prevent MIME-type sniffing.",
                }
            )

        if "Strict-Transport-Security" not in headers:
            self.vulnerabilities.append(
                {
                    "issue": "Missing Strict-Transport-Security",
                    "severity": "high",
                    "description": "Strict-Transport-Security header is missing.",
                    "recommendation": "Add HSTS header to enforce HTTPS and protect against protocol downgrade attacks.",
                }
            )

        if headers.get("X-Frame-Options") not in ["DENY", "SAMEORIGIN"]:
            self.vulnerabilities.append(
                {
                    "issue": "Missing or incorrect X-Frame-Options",
                    "severity": "medium",
                    "description": "X-Frame-Options header is missing or set to an insecure value.",
                    "recommendation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent clickjacking.",
                }
            )

        if "Referrer-Policy" not in headers:
            self.vulnerabilities.append(
                {
                    "issue": "Missing Referrer-Policy",
                    "severity": "medium",
                    "description": "Referrer-Policy header is missing.",
                    "recommendation": "Add a Referrer-Policy header to control information sent in the Referrer header.",
                }
            )

        if "Permissions-Policy" not in headers:
            self.vulnerabilities.append(
                {
                    "issue": "Missing Permissions-Policy",
                    "severity": "low",
                    "description": "Permissions-Policy header is missing.",
                    "recommendation": "Add a Permissions-Policy header to restrict feature access and improve security.",
                }
            )

        if (
            "Access-Control-Allow-Origin" in headers
            and headers["Access-Control-Allow-Origin"] == "*"
        ):
            self.vulnerabilities.append(
                {
                    "issue": "Insecure CORS policy",
                    "severity": "high",
                    "description": "Access-Control-Allow-Origin is set to '*', allowing any domain to access resources.",
                    "recommendation": "Restrict Access-Control-Allow-Origin to trusted domains only.",
                }
            )

    def check_http_methods(self):
        try:
            response = requests.options(self.url, timeout=10)
            allowed_methods = response.headers.get("Allow", "").split(", ")

            insecure_methods = [
                method
                for method in ["TRACE", "OPTIONS", "DELETE", "PUT"]
                if method in allowed_methods
            ]
            if insecure_methods:
                self.vulnerabilities.append(
                    {
                        "issue": "Insecure HTTP methods enabled",
                        "severity": "high",
                        "description": f"The following insecure HTTP methods are enabled: {', '.join(insecure_methods)}",
                        "recommendation": "Disable unused or insecure HTTP methods to reduce attack vectors.",
                    }
                )
        except requests.exceptions.RequestException:
            self.vulnerabilities.append(
                {
                    "issue": "HTTP methods check failed",
                    "severity": "low",
                    "description": "Unable to retrieve allowed HTTP methods.",
                    "recommendation": "Ensure OPTIONS requests are permitted to check allowed methods.",
                }
            )

    def check_ssl_tls(self):
        try:
            response = requests.get(self.url, timeout=10, allow_redirects=False)
            if response.status_code == 301 and "https" in response.headers.get(
                "Location", ""
            ):
                self.vulnerabilities.append(
                    {
                        "issue": "HTTP to HTTPS redirection missing",
                        "severity": "high",
                        "description": "Server does not redirect HTTP requests to HTTPS.",
                        "recommendation": "Configure the server to redirect all HTTP traffic to HTTPS.",
                    }
                )
        except requests.exceptions.RequestException:
            self.vulnerabilities.append(
                {
                    "issue": "SSL/TLS check failed",
                    "severity": "low",
                    "description": "Unable to verify SSL/TLS configuration.",
                    "recommendation": "Check if the server enforces HTTPS with SSL/TLS certificates.",
                }
            )

    def check_cookies_security(self, headers):
        cookies = headers.get("Set-Cookie", "").split(", ")
        for cookie in cookies:
            if "Secure" not in cookie:
                self.vulnerabilities.append(
                    {
                        "issue": "Cookie missing Secure attribute",
                        "severity": "medium",
                        "description": f"Cookie '{cookie}' is missing the 'Secure' attribute.",
                        "recommendation": "Add 'Secure' attribute to cookies to ensure they are only sent over HTTPS.",
                    }
                )
            if "HttpOnly" not in cookie:
                self.vulnerabilities.append(
                    {
                        "issue": "Cookie missing HttpOnly attribute",
                        "severity": "medium",
                        "description": f"Cookie '{cookie}' is missing the 'HttpOnly' attribute.",
                        "recommendation": "Add 'HttpOnly' attribute to cookies to prevent JavaScript access.",
                    }
                )
