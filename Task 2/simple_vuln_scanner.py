"""
simple_vuln_scanner.py

A small, non-destructive scanner for:
 - Reflected XSS (basic, reflected)
 - Basic SQL injection (error-based checks)

Usage (example with local vulnerable app):
    python3 simple_vuln_scanner.py

NOTE: Only scan targets you own or have explicit permission to test.
"""
import json
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, urlunparse

import requests
from bs4 import BeautifulSoup

# ---------------------------
# Config / Payloads
# ---------------------------
SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 -- ", "\" OR 1=1 -- ",
    "'; --", "' OR '1'='1' -- ", "admin' --", "' OR '1'='1' /*",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><svg/onload=alert('XSS')>",
]

SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(", re.I),
    re.compile(r"sql syntax.*mysql", re.I),
    re.compile(r"sqlstate", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"ORA-\d{5}", re.I),  # Oracle
]

DEFAULT_HEADERS = {
    "User-Agent": "SimpleVulnScanner/1.0 (+https://example.com/ - authorized testing only)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

DEFAULT_URL = "http://127.0.0.1:5000/?q=test"
OUTPUT_FILE = "scan_report.json"
REQUEST_DELAY = 0.5
REQUEST_TIMEOUT = 10

# ---------------------------
# Helpers
# ---------------------------
def get_forms(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        details = {}
        details["method"] = (form.get("method") or "get").lower()
        action = form.get("action")
        details["action"] = urljoin(base_url, action) if action else base_url
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inp_type = inp.get("type", "text")
            value = inp.get("value", "")
            inputs.append({"name": name, "type": inp_type, "value": value})
        details["inputs"] = inputs
        forms.append(details)
    return forms

def detect_sql_error(text):
    for pat in SQL_ERROR_PATTERNS:
        if pat.search(text):
            return True, pat.pattern
    return False, None

def is_payload_reflected(resp_text, payload):
    if payload in resp_text:
        return True
    if payload.replace("<", "&lt;").replace(">", "&gt;") in resp_text:
        return True
    return False

# ---------------------------
# Scanning functions
# ---------------------------
def test_url_params(session, url, delay=0.5, timeout=10):
    results = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return results
    for param in qs:
        orig_values = qs[param]
        for payload in SQLI_PAYLOADS + XSS_PAYLOADS:
            test_qs = qs.copy()
            test_qs[param] = [orig_values[0] + payload]
            new_query = urlencode({k: v[0] for k, v in test_qs.items()}, doseq=False)
            new_parsed = parsed._replace(query=new_query)
            test_url = urlunparse(new_parsed)
            try:
                r = session.get(test_url, timeout=timeout)
                text = r.text
                sql_found, pattern = detect_sql_error(text)
                if sql_found:
                    results.append({
                        "type": "sql_error_in_url_param",
                        "param": param,
                        "payload": payload,
                        "evidence": pattern,
                        "request_url": test_url,
                        "status_code": r.status_code,
                    })
                if payload in XSS_PAYLOADS and is_payload_reflected(text, payload):
                    results.append({
                        "type": "reflected_xss_in_url_param",
                        "param": param,
                        "payload": payload,
                        "request_url": test_url,
                        "status_code": r.status_code,
                    })
            except requests.RequestException as e:
                results.append({
                    "type": "request_error",
                    "param": param,
                    "payload": payload,
                    "error": str(e),
                    "request_url": test_url,
                })
            time.sleep(delay)
    return results

def test_form(session, form, delay=0.5, timeout=10):
    findings = []
    action = form["action"]
    method = form["method"]
    inputs = form["inputs"]
    base_data = {}
    for inp in inputs:
        if inp["type"] in ["text", "search", "textarea", "email", "url", "tel"]:
            base_data[inp["name"]] = inp.get("value", "test")
        elif inp["type"] in ["hidden"]:
            base_data[inp["name"]] = inp.get("value", "")
        else:
            base_data[inp["name"]] = inp.get("value", "")
    for inp in inputs:
        name = inp["name"]
        for payload in SQLI_PAYLOADS + XSS_PAYLOADS:
            data = base_data.copy()
            data[name] = (data.get(name, "") or "") + payload
            try:
                if method == "post":
                    r = session.post(action, data=data, timeout=timeout)
                else:
                    r = session.get(action, params=data, timeout=timeout)
                text = r.text
                sql_found, pattern = detect_sql_error(text)
                if sql_found:
                    findings.append({
                        "type": "sql_error_in_form",
                        "form_action": action,
                        "input": name,
                        "payload": payload,
                        "evidence": pattern,
                        "status_code": r.status_code,
                    })
                if payload in XSS_PAYLOADS and is_payload_reflected(text, payload):
                    findings.append({
                        "type": "reflected_xss_in_form",
                        "form_action": action,
                        "input": name,
                        "payload": payload,
                        "status_code": r.status_code,
                    })
            except requests.RequestException as e:
                findings.append({
                    "type": "request_error",
                    "form_action": action,
                    "input": name,
                    "payload": payload,
                    "error": str(e),
                })
            time.sleep(delay)
    return findings

# ---------------------------
# Runner
# ---------------------------
def run_scan(target_url, delay=0.5, timeout=10, headers=None, output_file="scan_report.json"):
    session = requests.Session()
    session.headers.update(headers or DEFAULT_HEADERS)
    report = {
        "target": target_url,
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "issues": [],
        "notes": "Only basic reflected XSS and simple error-based SQL injection checks performed.",
    }
    try:
        resp = session.get(target_url, timeout=timeout)
    except requests.RequestException as e:
        print(f"[!] Could not fetch target: {e}")
        return None

    base_html = resp.text
    base_url = resp.url
    print("[*] Testing URL parameters...")
    url_param_results = test_url_params(session, base_url, delay=delay, timeout=timeout)
    report["issues"].extend(url_param_results)

    print("[*] Extracting forms and testing...")
    forms = get_forms(base_html, base_url)
    report["forms_found"] = len(forms)
    for idx, form in enumerate(forms, 1):
        print(f"    - Testing form {idx}/{len(forms)}: {form['action']} ({form['method']})")
        findings = test_form(session, form, delay=delay, timeout=timeout)
        report["issues"].extend(findings)

    report["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[*] Scan complete. Issues found: {len(report['issues'])}. Report saved to {output_file}")
    return report

if __name__ == "__main__":
    print("WARNING: Only scan targets you own or have explicit permission to test.")
    run_scan(DEFAULT_URL, delay=REQUEST_DELAY, timeout=REQUEST_TIMEOUT, output_file=OUTPUT_FILE)
