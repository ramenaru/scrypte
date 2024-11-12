from .base_scan import BaseScan
from src.utils import directory_enumeration

class DirectoryScan(BaseScan):
    def __init__(self, url, custom_paths=None, custom_extensions=None, max_workers=10):
        super().__init__(url)
        self.custom_paths = custom_paths
        self.custom_extensions = custom_extensions
        self.max_workers = max_workers

    def run(self):
        results = directory_enumeration(
            self.url, 
            custom_paths=self.custom_paths, 
            custom_extensions=self.custom_extensions, 
            max_workers=self.max_workers
        )
        self.vulnerabilities.extend(results)
        return self.vulnerabilities
