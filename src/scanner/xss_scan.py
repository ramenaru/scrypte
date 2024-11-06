from .base_scan import BaseScan 
import re
import requests

class XSSScan(BaseScan):
    def run(self):
        response = requests.get(self.url)
        xss_patterns = [r"<script>alert\(", r"<img src="]
        
        for pattern in xss_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                self.vulnerabilities.append("Potential XSS vulnerability detected.")
