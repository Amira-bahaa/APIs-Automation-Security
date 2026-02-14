# SQL Injection
SQL_INJECTIONS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT null,null,null --",
    "1' AND '1'='1",
    "admin'--",
    "' OR 1=1 --",
]

# NoSQL Injection
NOSQL_INJECTIONS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    '{"$exists": true}',
]

# XSS
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
]

# SSRF
SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0",
    "file:///etc/passwd",
]

# OTP bypass attempts
OTP_BYPASS_VALUES = [
    "",
    "000000",
    "123456",
    "111111",
    "999999",
    "' OR '1'='1",
    "null",
    "-1",
]

# patterns we don't want to see in responses
SENSITIVE_PATTERNS = [
    "password", "secret", "token", "ssn", "credit_card",
    "stack_trace", "Traceback", "at com.", "at java.",
    "Exception", "SELECT", "FROM users", "/var/", "/home/",
    "C:\\\\", "X-Powered-By",
]

# headers that should be present
EXPECTED_SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
]

# roles to try for privilege escalation
ESCALATION_ROLES = [
    "ADMIN",
    "SUPER_ADMIN",
    "ROOT",
    "SYSTEM_ADMIN",
    "OWNER",
]
