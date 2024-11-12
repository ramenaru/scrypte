from .base_scan import BaseScan
from src.utils import directory_enumeration

class DirectoryScan(BaseScan):
    def __init__(self, url):
        super().__init__(url)

    def run(self):
        results = directory_enumeration(self.url)
        self.vulnerabilities.extend(results)
        return self.vulnerabilities