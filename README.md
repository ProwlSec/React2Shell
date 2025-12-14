# React2Shell – Advanced Discovery & Exploitation Framework

An advanced **React Server Components (RSC)** vulnerability **scanner and exploiter** for  
**CVE-2025-55182** and **CVE-2025-66478** affecting **Next.js applications**.

This tool expands upon the original React2Shell research and proof-of-concept by introducing **automated exploitation, WAF bypass techniques, Windows support, multi-threaded scanning, and operational-grade reliability**.

---

## 🚀 Overview

`react2shell.py` is an **advanced evolution** of the React2Shell detection methodology, capable of:

- High-confidence vulnerability discovery
- Safe and unsafe exploitation modes
- Automated post-detection command execution
- WAF and edge protection bypass
- Linux & Windows target support
- Scalable multi-target scanning

---

## 🧠 How It Works

The scanner abuses a flaw in how **Next.js React Server Components** process server actions.

A crafted `multipart/form-data` request injects a controlled payload that executes on the server.  
By default, a harmless command is executed to confirm RCE capability.

Successful exploitation confirms **server-side command execution**.

---

## 🛡 Detection & Exploitation Modes

### Standard Mode
- Sends a deterministic RCE payload
- Confirms execution via reflected response behavior

### Auto-Exploit Mode
- Automatically exploits confirmed vulnerable targets
- Executes attacker-supplied commands

Enable with:
```bash
--auto-exploit
```

🧱 WAF Bypass Support

The framework includes WAF evasion techniques designed to:

Evade request body inspection

Bypass common edge protections

Improve reliability against hardened deployments

Enable with:
```bash
--waf-bypass
```

🪟 Windows Target Support

Use PowerShell payloads for Windows-based Next.js deployments:
```bash
-w / --windows
```

📦 Requirements

Python 3.9+

requests

tqdm

Install dependencies:
```bash
pip install -r requirements.txt
```

🔧 Usage
```bash
usage: react2shell.py [-h] [-u URL] [-l LIST] [-c COMMAND] [-w] [-t THREADS]
               [--timeout TIMEOUT] [--no-ssl-verify] [--waf-bypass]
               [--auto-exploit] [-o OUTPUT] [-v]

Advanced React2Shell Scanner and Exploiter - ProwlSec
```

⚙️ Options
Option	Description

-h, --help	Show help message
-u, --url URL	Single target URL
-l, --list LIST	File containing list of targets
-c, --command COMMAND	Command to execute (default: id)
-w, --windows	Target Windows systems (PowerShell payload)
-t, --threads THREADS	Number of concurrent threads
--timeout TIMEOUT	Request timeout in seconds
--no-ssl-verify	Disable SSL certificate verification
--waf-bypass	Enable WAF bypass techniques
--auto-exploit	Automatically exploit vulnerable targets
-o, --output OUTPUT	Output file for results
-v, --verbose	Verbose output


🧪 Examples
Scan a Single Target
```bash
python3 react2shell.py -u https://example.com
```

Scan Multiple Targets
```bash
python3 react2shell.py -l targets.txt
```

Execute a Custom Command
```bash
python3 react2shell.py -u https://example.com -c "whoami"
```

Auto Exploit Vulnerable Targets
```bash
python3 react2shell.py -l targets.txt --auto-exploit
```

Windows Targets
```bash
python3 react2shell.py -u https://example.com -w -c "whoami"
```

Enable WAF Bypass
```bash
python3 react2shell.py -u https://example.com --waf-bypass
```

Save Results
```bash
python3 react2shell.py -l targets.txt -o results.json
```

📤 Output

Vulnerable targets are printed to the terminal

When -o is used, results are saved to a file

Output includes exploitation status and execution results

🧾 Credits & Attribution
Original RCE Proof-of-Concept

@maple3142
Original React Server Components RCE PoC that laid the foundation for this research.

Research Contributions

Assetnote Security Research Team
(Adam Kues, Tomais Williamson, Dylan Pindur, Patrik Grobshäuser, Shubham Shah)

xEHLE_ — Response header reflection insights

Nagli

Advanced Framework & Exploitation Engine

ProwlSec
Complete redesign, automated exploitation logic, WAF bypass techniques, Windows support, and scalable scanning architecture.

⚠️ Disclaimer

This tool is intended only for authorized security testing, research, and educational purposes.
Unauthorized use against systems without explicit permission is illegal and unethical.

🔗 Research Reference

High-Fidelity Detection Mechanism for RSC Next.js RCE:
https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478
