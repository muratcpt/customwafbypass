#!/usr/bin/env python3
import requests
import urllib.parse
import urllib3
import json
import os
from urllib.parse import urlsplit, parse_qsl, urljoin
from bs4 import BeautifulSoup
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGETS_FILE  = "logs/targets.txt"
PAYLOADS_FILE = "payloads/xss_payloads.txt"
OUTPUT_JSON   = "report/results.json"
MAX_WORKERS   = 10

# Load lines from a file, ignoring comments and blanks
def load_list(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return []

# Extract base URL and list of GET params from a URL
def extract_base_and_params(url):
    parts = urlsplit(url)
    qs = parse_qsl(parts.query, keep_blank_values=True)
    base = f"{parts.scheme}://{parts.netloc}{parts.path}"
    params = [k for k,_ in qs]
    return base, params

# Test reflected GET XSS
def run_get_xss(base, param, payload):
    url = f"{base}?{param}={urllib.parse.quote_plus(payload)}"
    try:
        r = requests.get(url, verify=False, timeout=10)
        return payload in r.text, r.status_code
    except:
        return False, None

# Test DOM-based XSS
def run_dom_xss(base, payload):
    url = f"{base}#{urllib.parse.quote_plus(payload)}"
    try:
        r = requests.get(url, verify=False, timeout=10)
        return payload in r.text, r.status_code
    except:
        return False, None

# Test stored XSS via comment form
def run_comment_xss(url, payload):
    try:
        resp = requests.get(url, verify=False, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        form = soup.find('form')
        action = form.get('action') if form and form.get('action') else url
        if not action.startswith('http'):
            action = urljoin(url, action)
        
        # Data to be sent in the comment form
        data = {
            "comment": payload,
            "name": "null",  # User's name
            "email": "null@gmail.com",  # User's email
            "website": "https://null.com"  # User's website
        }
        
        r2 = requests.post(action, data=data, verify=False, timeout=10)
        page = requests.get(url, verify=False, timeout=10)
        return payload in page.text, r2.status_code
    except:
        return False, None

# Test XSS in various input fields
def test_xss_in_fields(url, payload):
    try:
        resp = requests.get(url, verify=False, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Test in search fields
        search_fields = soup.find_all('input', {'type': 'search'})
        for field in search_fields:
            action = field.form.get('action') if field.form else url
            if not action.startswith('http'):
                action = urljoin(url, action)
            data = {field.get('name'): payload}
            r = requests.get(action, params=data, verify=False, timeout=10)
            if payload in r.text:
                return True, r.status_code

        # Test in comment forms
        comment_forms = soup.find_all('form')
        for form in comment_forms:
            action = form.get('action') if form.get('action') else url
            if not action.startswith('http'):
                action = urljoin(url, action)
            data = {input.get('name'): payload for input in form.find_all('input')}
            data['comment'] = payload  # Ensure the payload is in the comment field
            r = requests.post(action, data=data, verify=False, timeout=10)
            page = requests.get(url, verify=False, timeout=10)
            if payload in page.text:
                return True, r.status_code

        # Test in other form fields
        form_fields = soup.find_all('input')
        for field in form_fields:
            action = field.form.get('action') if field.form else url
            if not action.startswith('http'):
                action = urljoin(url, action)
            data = {field.get('name'): payload}
            r = requests.post(action, data=data, verify=False, timeout=10)
            if payload in r.text:
                return True, r.status_code

        return False, None
    except Exception as e:
        print(f"Error: {e}")
        return False, None

# Interactive menu selection
def select_multiple(options, prompt):
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    choices = input(prompt).split(',')
    idx = [int(c.strip())-1 for c in choices if c.strip().isdigit() and 0 < int(c.strip()) <= len(options)]
    return [options[i] for i in idx]

if __name__ == '__main__':
    targets = load_list(TARGETS_FILE)
    payloads = load_list(PAYLOADS_FILE)
    if not targets or not payloads:
        print("[!] targets.txt veya xss_payloads.txt eksik.")
        exit(1)

    print("Select targets to test:")
    chosen = select_multiple(targets, "Enter numbers (comma separated): ")

    tasks = []
    for tgt in chosen:
        for pl in payloads:
            tasks.append(("GET", tgt, pl))
            tasks.append(("POST", tgt, pl))
            tasks.append(("DOM", tgt, pl))

    if not tasks:
        print("[!] No tasks scheduled.")
        exit(1)

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {}
        for method, target, payload in tasks:
            if method == "GET":
                fut = executor.submit(run_get_xss, target, payload)
            elif method == "POST":
                fut = executor.submit(run_comment_xss, target, payload)
            else:
                fut = executor.submit(test_xss_in_fields, target, payload)
            future_map[fut] = (method, target, payload)

        for fut in tqdm(as_completed(future_map), total=len(future_map), desc="Running tests"):
            method, target, payload = future_map[fut]
            success, status = fut.result()
            results.append({"method": method, "target": target, "payload": payload, "status": status, "success": success})

    summary = {}
    for r in results:
        summary.setdefault(r['target'], []).append(r)
    for tgt, entries in summary.items():
        print(f"\n=== Results for {tgt} ===")
        print(f"Method    Success  Status")
        for e in entries:
            stat = e['status'] if e['status'] is not None else 'ERR'
            ok = 'YES' if e['success'] else ' NO'
            print(f"{e['method']:10} {ok:7} {stat}")

    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n✅ Report saved to {OUTPUT_JSON}")
