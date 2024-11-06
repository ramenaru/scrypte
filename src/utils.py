import re

def check_headers(headers):
    vulnerabilities = []

    if "Server" in headers:
        server_header = headers.get("Server", "")
        if "Apache/2.4.1" in server_header:
            vulnerabilities.append("Outdated Apache server detected.")
        elif "nginx/1.14.0" in server_header:
            vulnerabilities.append("Outdated Nginx server detected.")
        elif server_header:
            vulnerabilities.append(f"Server version exposed: {server_header}")

    if "X-Powered-By" in headers:
        vulnerabilities.append("Server reveals technology in headers (X-Powered-By).")
    
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
            vulnerabilities.append(f"Missing {header} header ({severity} severity).")

    if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
        vulnerabilities.append("Insecure CORS policy: Access-Control-Allow-Origin set to '*'.")

    return vulnerabilities

import re

def check_xss(html_content):
    vulnerabilities = []
    
    xss_patterns = [
        r"<script.*?>.*?</script>",                  # Inline script tags
        r"<img\s+.*?src=['\"]?javascript:",          # JavaScript in image src
        r"on\w+\s*=",                                # Inline event handlers
        r"<iframe.*?>",                              # Inline iframes
        r"<object.*?>",                              # Inline objects
        r"style\s*=\s*['\"].*expression\(.*?\)",     # CSS expressions
        r"document\.cookie",                         # Accessing cookies
        r"window\.",                                 # Accessing window properties
        r"eval\(",                                   # JavaScript eval function
        r"javascript\s*:",                           # JavaScript URIs
        r"<.*?srcdoc=['\"].*?</.*?>",                # Potential XSS in srcdoc attribute
        r"&#[xX]?[0-9A-Fa-f]+;"                      # Suspicious HTML entities
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            vulnerabilities.append(f"Potential XSS vulnerability detected: pattern '{pattern}' found.")

    inline_event_handlers = [
        "onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur"
    ]
    for event in inline_event_handlers:
        event_pattern = rf"{event}\s*="
        if re.search(event_pattern, html_content, re.IGNORECASE):
            vulnerabilities.append(f"Potential XSS vulnerability: inline event handler '{event}' detected.")

    return vulnerabilities
