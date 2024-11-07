from .base_scan import BaseScan
from src.utils import (
    SQL_PAYLOADS, check_error_based_injection, 
    check_boolean_based_injection, check_time_based_injection, 
    construct_url, generate_unique_marker
)
from urllib.parse import urlparse, parse_qs

class SQLInjectionScan(BaseScan):
    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []

    def scan(self):
        parsed_url = urlparse(self.url)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in SQL_PAYLOADS:
                marker = generate_unique_marker()
                test_payload = payload.replace("1=1", f"1=1 -- {marker}")
                test_params = query_params.copy()
                test_params[param] = test_payload
                test_url = construct_url(self.url, test_params)

                error_based_result = check_error_based_injection(test_url)
                if error_based_result:
                    self.vulnerabilities.append(error_based_result)
                    continue

                boolean_based_result = check_boolean_based_injection(self.url, param, query_params, marker)
                if boolean_based_result:
                    self.vulnerabilities.append(boolean_based_result)
                    continue

                time_based_result = check_time_based_injection(self.url, param, query_params)
                if time_based_result:
                    self.vulnerabilities.append(time_based_result)
                    continue

        return self.vulnerabilities
