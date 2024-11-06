import re

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
        r"<img\s+.*?src=['\"]?javascript:",
        r"on\w+\s*=",
        r"<iframe.*?>",
        r"<object.*?>",
        r"style\s*=\s*['\"].*expression\(.*?\)",
        r"document\.cookie",
        r"window\.",
        r"eval\(",
        r"javascript\s*:",
        r"<.*?srcdoc=['\"].*?</.*?>",
        r"&#[xX]?[0-9A-Fa-f]+;"
    ]

    for pattern in xss_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            vulnerabilities.append({
                "issue": "Potential XSS vulnerability detected",
                "severity": "high",
                "description": f"Detected pattern '{pattern}' which could be a potential XSS vulnerability.",
                "recommendation": "Sanitize and validate all inputs and consider using CSP to prevent XSS attacks."
            })

    inline_event_handlers = [
        "onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur"
    ]
    for event in inline_event_handlers:
        event_pattern = rf"{event}\s*="
        if re.search(event_pattern, html_content, re.IGNORECASE):
            vulnerabilities.append({
                "issue": f"Potential XSS vulnerability via inline event handler '{event}'",
                "severity": "medium",
                "description": f"The '{event}' inline event handler could allow XSS attacks.",
                "recommendation": "Avoid using inline event handlers or ensure proper input validation."
            })

    return vulnerabilities
