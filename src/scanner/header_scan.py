from .base_scan import BaseScan  
import requests

class HeaderScan(BaseScan):
    def run(self):
        response = requests.get(self.url)
        headers = response.headers

        # Example check for outdated headers
        if "Server" in headers and "Apache/2.4.1" in headers.get("Server", ""):
            self.vulnerabilities.append("Outdated Apache server detected.")
