import requests
from utils import check_headers, check_xss

def scan_website(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        headers = response.headers

        # Vulnerability checks
        vulnerabilities = []
        vulnerabilities.extend(check_headers(headers))
        vulnerabilities.extend(check_xss(response.text))

        return {
            "url": url,
            "vulnerabilities": vulnerabilities,
            "status_code": response.status_code,
        }

    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return {"url": url, "error": str(e), "vulnerabilities": []}
