from .base_scan import BaseScan
import requests
from src.utils import check_xss

class XSSScan(BaseScan):
    def run(self):
        try:
            response = requests.get(self.url)
            html_content = response.text

            vulnerabilities = check_xss(html_content)
            self.vulnerabilities.extend(vulnerabilities)

            payloads = [
                "<script>alert('XSS')</script>",
                "\"><img src=x onerror=alert('XSS')>",
                "javascript:alert(1)",
                "<svg/onload=alert(1)>",
                "'';!--\"<XSS>=&{()}"
            ]

            for payload in payloads:
                test_url = f"{self.url}?q={payload}"
                test_response = requests.get(test_url)
                if payload in test_response.text:
                    self.vulnerabilities.append({
                        "issue": "Reflected XSS vulnerability",
                        "severity": "high",
                        "description": f"Reflected XSS payload '{payload}' found in response.",
                        "recommendation": "Sanitize and encode all user inputs."
                    })

        except requests.exceptions.RequestException as e:
            self.vulnerabilities.append({
                "issue": "Network error",
                "severity": "critical",
                "description": f"Error accessing {self.url}: {e}",
                "recommendation": "Check URL validity and network connectivity."
            })
