from .base_scan import BaseScan
from src.utils import get_certificate_info, is_certificate_valid, check_tls_protocol_support, check_tls_headers
from urllib.parse import urlparse

class TLSScan(BaseScan):
    def __init__(self, url):
        super().__init__(url)

    def run(self):
        hostname = urlparse(self.url).hostname

        try:
            cert = get_certificate_info(hostname)
            if not is_certificate_valid(cert):
                not_after = cert['notAfter']
                self.vulnerabilities.append({
                    "issue": "Expired or Invalid Certificate",
                    "severity": "high",
                    "description": f"The SSL certificate expired on {not_after}.",
                    "recommendation": "Renew the SSL/TLS certificate to ensure it is valid."
                })
        except Exception as e:
            self.vulnerabilities.append({
                "issue": "Certificate Retrieval Error",
                "severity": "critical",
                "description": f"Could not retrieve certificate information: {e}",
                "recommendation": "Verify the server's SSL/TLS configuration and ensure it's accessible over port 443."
            })
            return self.vulnerabilities

        supported_protocols = check_tls_protocol_support(hostname)
        if "TLS 1.2" not in supported_protocols and "TLS 1.3" not in supported_protocols:
            self.vulnerabilities.append({
                "issue": "Outdated TLS Protocol Support",
                "severity": "high",
                "description": "Server does not support modern TLS protocols (TLS 1.2 or 1.3).",
                "recommendation": "Configure the server to support at least TLS 1.2 or newer."
            })

        missing_headers = check_tls_headers(self.url)
        for header in missing_headers:
            self.vulnerabilities.append({
                "issue": f"Missing or Incorrect Header: {header['header']}",
                "severity": "medium",
                "description": f"Expected '{header['header']}: {header['expected']}', but found '{header['found']}'.",
                "recommendation": f"Add the '{header['header']}' header with value '{header['expected']}' to enforce best practices."
            })

        return self.vulnerabilities
