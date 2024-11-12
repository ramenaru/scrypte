from .base_scan import BaseScan
import requests
from src.utils import check_xss, test_reflected_xss


class XSSScan(BaseScan):
    def run(self):
        try:
            response = requests.get(self.url)
            html_content = response.text
            vulnerabilities = check_xss(html_content)
            self.vulnerabilities.extend(vulnerabilities)

            reflected_vulnerabilities = test_reflected_xss(self.url)
            self.vulnerabilities.extend(reflected_vulnerabilities)

        except requests.exceptions.RequestException as e:
            self.vulnerabilities.append(
                {
                    "issue": "Network error",
                    "severity": "critical",
                    "description": f"Error accessing {self.url}: {e}",
                    "recommendation": "Check URL validity and network connectivity.",
                }
            )
