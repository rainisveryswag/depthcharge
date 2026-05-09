# DepthCharge — Static Analysis Module

**Module owner:** Yousra Zarri  
**Project:** DepthCharge — Supply Chain Attack Detector  
**Institution:** ENSA Marrakech — GCDSTE  
**Academic year:** 2025–2026

---

## Table of Contents

1. [What This Module Does](#1-what-this-module-does)
2. [Why Static Analysis](#2-why-static-analysis)
3. [Module Architecture](#3-module-architecture)
4. [Detection Techniques](#4-detection-techniques)
   - [AST Analysis](#41-ast-analysis)
   - [Shannon Entropy Analysis](#42-shannon-entropy-analysis)
   - [YARA Rules](#43-yara-rules)
5. [YARA Rules Reference](#5-yara-rules-reference)
6. [Scoring System](#6-scoring-system)
7. [Dataset & Testing](#7-dataset--testing)
8. [Test Results](#8-test-results)
9. [Installation & Usage](#9-installation--usage)
10. [Output Format](#10-output-format)
11. [Known Limitations](#11-known-limitations)

---

## 1. What This Module Does

The static analysis module is one of four detection layers in DepthCharge. It analyzes the **source code of a Python package without executing it**, looking for patterns characteristic of malicious packages on PyPI.

Given a package name and path, it produces a **JSON risk report** with a score from 0 to 100 and a list of findings that explain exactly what was detected and where.

```
Input: path to extracted package
         ↓
   AST Analysis        → dangerous function calls
   Entropy Analysis    → obfuscated/encoded strings
   YARA Scanning       → known malicious patterns
         ↓
Output: JSON report with score + findings
```

---

## 2. Why Static Analysis

Current tools like Dependabot and Snyk rely exclusively on CVE databases — they only detect **known vulnerabilities**. They are completely blind to zero-day supply chain attacks: newly published malicious packages with no CVE assigned.

Static analysis addresses this gap by **reading and analyzing the package code directly**, without needing a prior database entry. A package published 10 minutes ago with a hidden reverse shell can be detected the same way as a known malware sample.

**Key advantage over database lookup:** static analysis works on **any package**, known or unknown, because it examines behavior patterns in the code rather than matching against a list.

**Key advantage over dynamic analysis:** no execution required, no sandbox needed, no risk of the malware running on your machine.

---

## 3. Module Architecture

```
modules/static/
├── static_module.py          # Main entry point — orchestrates all 3 analyzers
├── ast_analyzer.py           # AST-based dangerous call detection
├── entropy.py                # Shannon entropy analysis for obfuscated strings
├── yara_scanner.py           # YARA rule matching
└── rules/
    ├── exec_base64.yar       # Obfuscation and code execution patterns
    ├── network_in_setup.yar  # Network calls and data exfiltration
    ├── env_steal.yar         # Environment variable theft patterns
    └── suspicious_subprocess.yar  # Shell and subprocess abuse
```

**Data flow:**

```
static_module.py
      │
      ├── ast_analyzer.py      → findings list
      ├── entropy.py           → findings list
      └── yara_scanner.py      → findings list
                    │
            combine + score
                    │
              JSON output
```

`static_module.py` is the **only file** the rest of the DepthCharge pipeline talks to. It calls the three analyzers, collects their findings, calculates the risk score, and returns a standardized JSON object.

---

## 4. Detection Techniques

### 4.1 AST Analysis

**File:** `ast_analyzer.py`

AST (Abstract Syntax Tree) analysis parses Python source code into its syntactic structure and traverses it looking for dangerous function calls.

**Why AST instead of simple text search?**
AST understands the code structure. It knows the exact line number, the context of the call, and distinguishes between a function definition and a function call. Simple text search would miss obfuscated variants and produce more false positives.

**Priority files:** `setup.py`, `__init__.py`, `setup.cfg` are scanned first and flagged with higher severity. These files execute automatically during package installation — malware placed here runs without the developer ever importing the package.

**Detected patterns:**

| Pattern | Severity in setup.py | Severity elsewhere | Why it's dangerous |
|---------|---------------------|-------------------|-------------------|
| `eval()` | critical | skipped | Executes arbitrary string as code |
| `exec()` | critical | high | Executes arbitrary code object |
| `compile()` | critical | skipped | Compiles code for later execution |
| `os.system()` | critical | skipped | Runs shell commands |
| `os.popen()` | critical | skipped | Opens a pipe to a shell command |
| `subprocess.Popen()` | critical | skipped | Spawns child processes |
| `subprocess.call()` | critical | skipped | Runs a command |
| `subprocess.run()` | critical | skipped | Runs a command |
| `socket.connect()` | critical | high | Opens a network connection |
| `socket.create_connection()` | critical | high | Opens a network connection |
| `urllib.request.urlopen()` | critical | high | Makes an HTTP request |
| `requests.get()` | critical | high | Makes an HTTP GET request |
| `requests.post()` | critical | high | Makes an HTTP POST request |

**Suspicious calls in install hooks** (lower severity, but still flagged):

| Pattern | Why it's suspicious |
|---------|-------------------|
| `os.environ` | Reading environment variables (potential credential theft) |
| `base64.b64decode()` | Decoding base64 (potential payload) |
| `marshal.loads()` | Deserializing bytecode (evasion technique) |
| `ctypes.cdll` | Loading native libraries |

**False positive mitigation:**
- `eval`, `exec`, `compile` are only flagged with critical severity in priority files; in regular files they are flagged as `high` or skipped to reduce noise
- Test files (`test_*.py`, files in `tests/` directories) are excluded from scanning entirely
- Known legitimate files like `shell.py` that intentionally use `exec` are whitelisted

---

### 4.2 Shannon Entropy Analysis

**File:** `entropy.py`

Shannon entropy measures how "random" a string is. It is calculated as:

```
H = -Σ p(c) × log₂(p(c))
```

Where `p(c)` is the probability of each character appearing in the string.

**Why entropy matters for malware detection:**
Malicious packages frequently hide their payloads inside base64-encoded or otherwise obfuscated strings to evade simple text pattern matching. These encoded strings appear highly random — they have high entropy.

**Example:**
- Normal English text: entropy ≈ 3.5–4.0
- Base64-encoded payload: entropy ≈ 5.5–6.0
- Random binary data: entropy ≈ 6.0+

**Configuration:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `ENTROPY_THRESHOLD` | 5.5 | Validated empirically on 5 legitimate packages |
| `MIN_STRING_LENGTH` | 50 characters | Short strings produce unreliable entropy scores |

**Whitelist:** Known safe high-entropy strings are excluded to prevent false positives:
- Alphabet character sets (`ABCDEFGHIJKLMNOPQRSTUVWXYZ...`)
- Base62 alphabets used by legitimate libraries
- Strings with more than 40 unique characters and length < 100 (character set definitions)

**False positive mitigation:**
- Threshold raised from 4.5 to 5.5 after testing on legitimate packages
- Minimum length filter eliminates short strings with misleading entropy
- Explicit whitelist for known safe patterns

---

### 4.3 YARA Rules

**File:** `yara_scanner.py` + `rules/`

YARA is an industry-standard pattern matching tool used in malware analysis. Rules define string patterns and conditions that must be met for a match.

Unlike AST analysis which understands code structure, YARA performs **raw text matching** on the file content. This makes it effective for detecting obfuscated code that breaks the Python parser, encoded strings, and multi-file patterns.

**How it works:**
1. All `.yar` files in the `rules/` directory are loaded at startup
2. Each Python file in the package is scanned against every rule
3. Matches are collected with rule name, file path, and severity
4. Results are merged with AST and entropy findings

**Complementarity with AST:**
The `exo-steal` package demonstrated why both are needed: the package contained invalid Python syntax that crashed the AST parser, but YARA successfully detected the hardcoded Telegram token and exfiltration pattern in the raw file content.

---

## 5. YARA Rules Reference

### exec_base64.yar

**`Exec_Base64`** — severity: high  
Detects the classic `base64.b64decode` + `exec()` or `eval()` pattern. This is one of the most common obfuscation techniques in PyPI malware.

```
base64.b64decode  +  exec( or eval(  →  MATCH
```

**`Marshal_Load`** — severity: high  
Detects deserialization of Python bytecode via `marshal.loads`, often combined with base64 decoding to hide compiled code.

**`Multilevel_Obfuscation`** — severity: high  
Detects multiple encoding layers: `base64.b64decode` + `zlib.decompress` + `exec`. Indicates deliberate evasion.

**`Exec_Chr_Obfuscation`** — severity: critical  
Detects the `exec("".join(map(chr, [...])))` pattern — hiding payloads as lists of ASCII character codes. Discovered while testing the `colorating` package.

```python
# Example from real malware (colorating):
exec("".join(map(chr, [102,114,111,109,32,115,101,116,117,112,116,111,111,108,115...])))
```

**`BlankOBF_Obfuscation`** — severity: critical  
Detects packages obfuscated with the BlankOBF tool, identified by its signature comment and variable naming pattern (`_____=eval`). Discovered while testing the `loggerbyxolo` package.

---

### network_in_setup.yar

**`Network_Call_In_Setup`** — severity: high  
Detects direct network calls via `socket.connect`, `socket.create_connection`, or `urllib.request.urlopen`. A legitimate package installation should never make outbound network connections.

**`Reverse_Shell`** — severity: critical  
Detects the combination of `socket.socket` + `connect(` + `subprocess` — the classic reverse shell pattern.

**`DNS_Exfiltration`** — severity: high  
Detects DNS-based data exfiltration: using `socket.gethostbyname` or `socket.getaddrinfo` combined with base64 encoding to encode stolen data in DNS queries.

**`Hardcoded_Token`** — severity: critical  
Detects hardcoded Telegram bot tokens using a regex pattern matching the Telegram API token format (`[0-9]{9,10}:AA[A-Za-z0-9_-]{33}`). Discovered while testing the `exo-steal` package which contained a real active bot token.

**`MAC_Address_Theft`** — severity: critical  
Detects MAC address collection for device fingerprinting: `getmac` or `ifconfig` combined with `base64.b64encode`. Discovered while testing the `distpro` package.

---

### env_steal.yar

**`AWS_Credentials_Steal`** — severity: critical  
Detects attempts to read AWS credentials from environment variables: `os.environ` combined with `AWS_SECRET_ACCESS_KEY`, `AWS_ACCESS_KEY_ID`, or `AWS_SESSION_TOKEN`.

**`Generic_Token_Steal`** — severity: high  
Detects environment variable reading (`os.environ` or `os.getenv`) combined with network calls — indicating tokens or secrets are being exfiltrated. Requires both env access AND network call to reduce false positives.

**`Env_Exfiltration`** — severity: critical  
Detects the specific pattern of reading `os.environ` and immediately sending the data over the network via `requests.post`, `urllib`, or `socket.connect`.

**`Telegram_Exfiltration`** — severity: critical  
Detects data exfiltration via the Telegram Bot API (`api.telegram.org` + `sendDocument` or `sendMessage`). Discovered while testing the `exo-steal` package which used Telegram to receive stolen Exodus wallet files.

**`System_Info_Exfiltration`** — severity: critical  
Detects system reconnaissance: collecting hostname (`platform.node`), username (`getpass.getuser`), and making network calls — the pattern used by `distpro` to fingerprint victims.

---

### suspicious_subprocess.yar

**`Subprocess_Shell`** — severity: high  
Detects subprocess calls with `shell=True` combined with network-related strings — indicating a shell is being spawned for network operations.

**`OS_System_Call`** — severity: high  
Detects `os.system()` and `os.popen()` — direct shell command execution.

**`Persistence_Mechanism`** — severity: critical  
Detects attempts to establish persistence by writing to `crontab`, `.bashrc`, `.bash_profile`, or `/etc/rc`.

---

## 6. Scoring System

Each finding contributes to the final risk score based on its severity:

| Severity | Points |
|----------|--------|
| critical | 35 |
| high | 20 |
| medium | 10 |
| low | 5 |

**Minimum score rule:** If any finding has `critical` severity, the score is automatically set to at least 70, regardless of the number of findings. This ensures a single critical indicator always triggers a block verdict.

**Score cap:** Maximum score is 100.

**Score interpretation:**

| Score | Risk Level | Verdict | Action |
|-------|-----------|---------|--------|
| 0–30 | Low | allow | Package is probably safe |
| 31–69 | Medium | review | Manual review recommended |
| 70–100 | High | block | Installation blocked |

---

## 7. Dataset & Testing

### Malicious packages

All malicious packages used for testing come from the **Datadog Malicious Software Packages Dataset**:  
`https://github.com/DataDog/malicious-software-packages-dataset`

This repository archives confirmed malicious PyPI packages with their original tarballs (password-protected with `infected`). All packages in the dataset were confirmed malicious by security researchers before being removed from PyPI.

**Malware categories tested:**

| Category | Example | Technique |
|----------|---------|-----------|
| Base64 + exec obfuscation | `colurama` | `exec(base64.b64decode(...))` in `color.py` |
| chr() map obfuscation | `colorating` | `exec("".join(map(chr, [...])))` in `setup.py` |
| BlankOBF obfuscation | `loggerbyxolo` | Multi-layer octal/hex escape obfuscation |
| Telegram exfiltration | `exo-steal` | Steals Exodus wallet files, sends via Telegram bot |
| System fingerprinting | `distpro` | Collects MAC address, hostname, username |
| Env var exfiltration | `discconnect` | Steals environment variables via HTTP |
| High entropy payload | `androidspyeye` | Large base64 payload in `setup.py` |
| Telegram exfiltration | `detection-telegram` | Same attacker pattern as `androidspyeye` |

### Legitimate packages

Legitimate packages were downloaded directly from PyPI using `pip download` and tested to verify the absence of false positives.

**Packages tested:** `requests`, `flask`, `numpy`, `django`, `cryptography`

These packages were chosen because they represent edge cases likely to produce false positives:
- `flask` and `django` use `exec()` legitimately for interactive shells and config loading
- `numpy` uses `subprocess` extensively for build tooling
- `cryptography` has compiled C extensions with high-entropy binary strings
- `requests` makes HTTP calls by design

---

## 8. Test Results

### Malicious packages

| Package | Version | Score | Verdict | Key findings |
|---------|---------|-------|---------|-------------|
| `androidspyeye` | 2.5 | 100 | 🔴 block | exec×2 + high entropy payload in setup.py |
| `detection-telegram` | 5.6 | 100 | 🔴 block | exec×2 + high entropy payload in setup.py |
| `distpro` | 92.6 | 90 | 🔴 block | MAC address theft + system info exfiltration |
| `discconnect` | 0.5 | 75 | 🔴 block | Env var exfiltration via network |
| `loggerbyxolo` | 0.0.0 | 70 | 🔴 block | BlankOBF obfuscation + eval in \_\_init\_\_.py |
| `colorating` | 1.0.0 | 70 | 🔴 block | chr() map obfuscation + exec in setup.py |
| `exo-steal` | 5 | 70 | 🔴 block | Hardcoded Telegram token + wallet theft |
| `colurama` | 0.0.3 | 60 | 🟡 review | exec + base64 obfuscation in color.py |

**Detection rate:** 8/8 malicious packages detected (100%)  
**Block rate:** 7/8 packages scored ≥ 70 (87.5%)  
**Review rate:** 1/8 packages scored in review zone (12.5%)

### Legitimate packages

| Package | Version | Score | Verdict | Notes |
|---------|---------|-------|---------|-------|
| `django` | 6.0.5 | 0 | 🟢 allow | Perfect — no findings |
| `cryptography` | latest | 0 | 🟢 allow | Perfect — no findings |
| `requests` | 2.33.1 | 20 | 🟢 allow | 1 finding: exec in config loader |
| `flask` | latest | 20 | 🟢 allow | 1 finding: exec in config loader |
| `numpy` | latest | 20 | 🟢 allow | 1 finding: subprocess in build backend |

**False positive rate:** 0/5 legitimate packages incorrectly blocked (0%)  
All legitimate packages score ≤ 20, well below the 70 block threshold.

---

## 9. Installation & Usage

### Requirements

```bash
pip install yara-python
```

Python 3.11+ required.

### Run on a package

```bash
# Scan an extracted package directory
python static_module.py <path_to_package> <package_name> <version>

# Example
python static_module.py ~/packages/colourama/ colourama 0.3.6
```

### Run individual analyzers

```bash
# AST analysis only
python ast_analyzer.py <path_to_package>

# Entropy analysis only
python entropy.py <path_to_package>

# YARA scanning only
python yara_scanner.py <path_to_package>
```

### Integration with DepthCharge pipeline

```python
from modules.static.static_module import analyze

result = analyze(
    package_path="/tmp/extracted/colourama",
    package_name="colourama",
    version="0.3.6"
)

print(result["score"])    # 75
print(result["status"])   # "completed"
```

---

## 10. Output Format

The module produces a JSON object conforming to the DepthCharge inter-module schema:

```json
{
  "package": "colourama",
  "version": "0.3.6",
  "ecosystem": "pypi",
  "module": "static",
  "status": "completed",
  "score": 75,
  "findings": [
    {
      "type": "dangerous_call",
      "pattern": "exec",
      "file": "/path/to/setup.py",
      "line": 12,
      "severity": "critical",
      "description": "Dangerous call 'exec' detected"
    },
    {
      "type": "high_entropy_string",
      "file": "/path/to/setup.py",
      "line": 8,
      "entropy": 5.8,
      "length": 1024,
      "preview": "aGVsbG8gd29ybGQ...",
      "severity": "critical",
      "description": "High entropy string detected (entropy=5.8)"
    },
    {
      "type": "yara_match",
      "rule": "Exec_Base64",
      "rule_file": "exec_base64",
      "file": "/path/to/setup.py",
      "severity": "high",
      "description": "Detects base64 decode combined with exec or eval"
    }
  ],
  "summary": {
    "total_findings": 3,
    "ast_findings": 1,
    "entropy_findings": 1,
    "yara_findings": 1,
    "critical": 2,
    "high": 1,
    "medium": 0
  }
}
```

**Status values:** `completed` | `error`  
**Severity values:** `critical` | `high` | `medium` | `low`  
**Finding types:** `dangerous_call` | `suspicious_call` | `high_entropy_string` | `yara_match`

---

## 11. Known Limitations

**1. Obfuscation evasion**  
Sufficiently sophisticated obfuscation can bypass AST analysis if it generates invalid Python syntax. YARA rules provide a fallback but may not cover all obfuscation variants.

**2. Runtime-only malicious behavior**  
Malware that downloads and executes a second-stage payload at runtime cannot be detected statically. The payload does not exist in the package source code.

**3. Python only**  
This module analyzes `.py` files only. Compiled extensions (`.so`, `.pyd`) are not analyzed. YARA provides partial coverage for binary patterns.

**4. npm not covered**  
The current implementation covers PyPI packages only. npm support is out of scope for this module (handled by the sandbox module).

**5. False negatives on heavily obfuscated code**  
The `exo-steal` package demonstrated that malware with Python syntax errors crashes the AST analyzer. YARA compensated in that case, but more exotic evasion techniques may evade both.

**6. Score calibration**  
The scoring weights and thresholds were calibrated on a limited dataset of 8 malicious and 5 legitimate packages. A larger dataset would improve calibration accuracy.

---

*DepthCharge Static Analysis Module — ENSA Marrakech 2025–2026*