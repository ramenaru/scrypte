import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode

def check_headers(headers):
    vulnerabilities = []

    if "Server" in headers:
        server_header = headers.get("Server", "")
        if "Apache/2.4.1" in server_header:
            vulnerabilities.append({
                "issue": "Outdated Apache server detected",
                "severity": "high",
                "description": "The server is running Apache version 2.4.1, which may have known vulnerabilities.",
                "recommendation": "Update the Apache server to the latest secure version."
            })
        elif "nginx/1.14.0" in server_header:
            vulnerabilities.append({
                "issue": "Outdated Nginx server detected",
                "severity": "high",
                "description": "The server is running an outdated version of Nginx.",
                "recommendation": "Update the Nginx server to the latest secure version."
            })
        elif server_header:
            vulnerabilities.append({
                "issue": "Server version exposed",
                "severity": "medium",
                "description": f"The server version is exposed in the headers: {server_header}",
                "recommendation": "Remove or obscure the server version header to reduce the attack surface."
            })

    if "X-Powered-By" in headers:
        vulnerabilities.append({
            "issue": "Technology exposure via X-Powered-By header",
            "severity": "medium",
            "description": "The server discloses its technology via the X-Powered-By header.",
            "recommendation": "Remove the X-Powered-By header to limit information disclosure."
        })

    security_headers = {
        "Content-Security-Policy": "high",
        "X-Content-Type-Options": "medium",
        "Strict-Transport-Security": "high",
        "X-Frame-Options": "medium",
        "Referrer-Policy": "medium",
        "Permissions-Policy": "low"
    }

    for header, severity in security_headers.items():
        if header not in headers:
            vulnerabilities.append({
                "issue": f"Missing {header} header",
                "severity": severity,
                "description": f"The {header} header is not present, which can reduce security.",
                "recommendation": f"Add the {header} header to enhance security."
            })

    if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
        vulnerabilities.append({
            "issue": "Insecure CORS policy",
            "severity": "high",
            "description": "The Access-Control-Allow-Origin header allows access from any domain ('*').",
            "recommendation": "Restrict Access-Control-Allow-Origin to trusted domains only."
        })

    return vulnerabilities

def check_xss(html_content):
    vulnerabilities = []
    
    xss_patterns = [
        r"<script.*?>.*?</script>",                 
        r"<img\s+.*?src=['\"]?javascript:",           # JavaScript in image src
        r"on\w+\s*=",                                 # Inline event handlers
        r"<iframe.*?>",                               # Inline iframes
        r"<object.*?>",                               # Inline objects
        r"style\s*=\s*['\"].*expression\(.*?\)",      # CSS expressions
        r"document\.cookie",                          # Accessing cookies
        r"window\.",                                  # Accessing window properties
        r"eval\(",                                    # JavaScript eval function
        r"javascript\s*:",                            # JavaScript URIs
        r"<.*?srcdoc=['\"].*?</.*?>",                 # Potential XSS in srcdoc attribute
        r"<svg.*?onload=",                            # SVG tag with onload
        r"document\.write\(",                         # document.write usage
        r"innerHTML\s*=",                             # Potential for DOM-based XSS
        r"<body.*?onload=",                           # body tag with onload event
        r"<input.*?onfocus=",                         # input tag with event
        r"<link.*?href=['\"]?javascript:",            # JavaScript in href of <link>
        r"\bonerror\b",                               # Inline onerror event
    ]

    for pattern in xss_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            vulnerabilities.append({
                "issue": "Potential XSS vulnerability detected",
                "severity": "high",
                "description": f"Pattern '{pattern}' suggests a possible XSS vulnerability.",
                "recommendation": "Sanitize inputs, validate all data, and apply CSP."
            })

    dom_patterns = [
        r"document\.write\(",
        r"innerHTML\s*=",
        r"eval\(", 
        r"setTimeout\(",
        r"setInterval\(",
    ]
    for pattern in dom_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            vulnerabilities.append({
                "issue": "Potential DOM-based XSS vulnerability",
                "severity": "medium",
                "description": f"Detected use of '{pattern}', which can enable DOM-based XSS.",
                "recommendation": "Avoid unsafe JavaScript methods; use safer alternatives like textContent."
            })

    return vulnerabilities

def test_reflected_xss(url):
    vulnerabilities = []
    
    payloads = [
        "<script>alert('XSS')</script>",
        "\"><img src=x onerror=alert('XSS')>",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
        "'';!--\"<XSS>=&{()}",
        "<img src=x onerror='alert(String.fromCharCode(88,83,83))'>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<object data='javascript:alert(\"XSS\")'></object>",
        "<a href='javascript:alert(1)'>Click me</a>",
        "%3Cscript%3Ealert(%27XSS%27)%3C/script%3E" 
    ]

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = payload
            test_query = urlencode(test_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"
            vulnerabilities.extend(check_payload_in_response(test_url, payload))

            encoded_payload = urlencode({param: payload})
            encoded_test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{encoded_payload}"
            vulnerabilities.extend(check_payload_in_response(encoded_test_url, payload))

    return vulnerabilities

def check_payload_in_response(test_url, payload):
    vulnerabilities = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0",
        "Accept-Language": "en-US,en;q=0.5"
    }
    try:
        test_response = requests.get(test_url, headers=headers, timeout=5)
        
        if payload in test_response.text:
            vulnerabilities.append({
                "issue": "Reflected XSS vulnerability",
                "severity": "high",
                "description": f"Reflected XSS payload '{payload}' detected in response.",
                "recommendation": "Sanitize and encode all user inputs to prevent XSS."
            })
        
        encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        if encoded_payload in test_response.text:
            vulnerabilities.append({
                "issue": "Possible XSS via encoded reflection",
                "severity": "medium",
                "description": f"Encoded payload '{encoded_payload}' was reflected, indicating weak sanitization.",
                "recommendation": "Ensure all user inputs are fully sanitized and properly encoded."
            })

    except requests.exceptions.RequestException as e:
        vulnerabilities.append({
            "issue": "Network error during XSS testing",
            "severity": "critical",
            "description": f"Error accessing {test_url}: {e}",
            "recommendation": "Ensure network stability and URL accessibility during testing."
        })

    return vulnerabilities
