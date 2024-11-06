class BaseScan:
    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []

    def run(self):
        raise NotImplementedError("Subclasses should implement this method")

    def get_vulnerabilities(self):
        return self.vulnerabilities
