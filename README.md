# DepthCharge

**Détecteur d'Attaques sur la Chaîne d'Approvisionnement Logicielle**  
Supply Chain Attack Detector for Python (PyPI) and JavaScript (npm) packages


---

## Team

| Member | Role | Module |
|--------|------|--------|
| Yousra Zarri | Static Analysis | `modules/static/` |
| Mohammed Ait Ourajli | Behavioral Sandbox | `modules/sandbox/` |
| Wiam Baba | Reputation & Intelligence | `modules/reputation/` |
| Yasser Chettour | Dashboard & CI/CD | `modules/dashboard/` |

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [What DepthCharge Does](#2-what-depthcharge-does)
3. [Architecture](#3-architecture)
4. [Modules](#4-modules)
5. [Risk Scoring](#5-risk-scoring)
6. [Project Structure](#6-project-structure)
7. [Installation](#7-installation)
8. [Usage](#8-usage)
9. [Output Format](#9-output-format)
10. [Technology Stack](#10-technology-stack)
11. [Dataset](#11-dataset)
12. [Test Results](#12-test-results)
13. [Scope and Limitations](#13-scope-and-limitations)
14. [References](#14-references)

---

## 1. Problem Statement

The software supply chain is one of the most critical and difficult-to-defend attack vectors in modern cybersecurity. Developers implicitly trust thousands of open-source libraries they integrate daily through package managers like `pip` and `npm`. Attackers exploit this trust by compromising or creating malicious packages to infect downstream systems.

**Recent major incidents:**

- **XZ Utils backdoor (2024)** — An attacker infiltrated the open source community over two years before injecting a backdoor into a compression library used by millions of Linux systems.
- **SolarWinds (2020)** — The build chain was compromised, embedding malware into signed updates distributed to over 18,000 organizations including US government agencies.
- **PyPI malware campaigns (2023–2024)** — Hundreds of malicious packages are published monthly on PyPI using typosquatting and obfuscated install scripts to steal credentials and execute remote code.

**The gap in existing tools:**

Current security tools such as Dependabot, Snyk, and OWASP Dependency-Check rely exclusively on known vulnerability databases (CVE). They are blind to zero-day supply chain attacks — recently published malicious packages with no associated CVE pass undetected and install without warning. No accessible open-source solution currently analyzes the actual behavior of a package at install time, before it enters a production codebase.

---

## 2. What DepthCharge Does

DepthCharge is a **behavioral and static detection tool** that identifies malicious or suspicious open-source packages before installation by combining multiple complementary analysis layers and integrating into developer CI/CD pipelines.

```
Developer runs: depthcharge scan requests==2.31.0
                          |
         Download package from PyPI
                          |
    +-------------------------------------------------+
    |  Module 1: Static Analysis    (reads code)      |
    |  Module 2: Behavioral Sandbox (installs safely) |
    |  Module 3: Reputation & Intel (checks metadata) |
    +-------------------------------------------------+
                          |
         Aggregated Risk Score (0-100)
                          |
         allow / review / BLOCK
```

**What makes it different from existing tools:**
- Does not rely on a CVE database — detects unknown malicious packages
- Analyzes actual code behavior, not just version numbers
- Combines three independent detection layers for higher accuracy
- Integrates directly into CI/CD pipelines via GitHub Actions

---

## 3. Architecture

DepthCharge is structured as four independent modules communicating via a standardized JSON schema, orchestrated by a central pipeline that produces a final risk report.

```
Package name/path
        |
        v
+----------------+   +------------------+   +---------------------+
| Module 1       |   | Module 2         |   | Module 3            |
| Static         |   | Sandbox          |   | Reputation &        |
| Analysis       |   | Behavioral       |   | Intelligence        |
| (Yousra)       |   | (Mohammed)       |   | (Wiam)              |
+-------+--------+   +--------+---------+   +-----------+---------+
        |                     |                         |
        +---------------------+-------------------------+
                              |
                       JSON findings
                              |
                       +------+------+
                       | Risk Score  |
                       | Aggregator  |
                       +------+------+
                              |
                 +------------+------------+
                 | Module 4               |
                 | Dashboard & CI/CD      |
                 | (Yasser)               |
                 +------------------------+
```

Each module outputs a JSON object with a score (0–100) and a list of findings. Module 3 aggregates all scores using weighted averaging to produce the final verdict.

---

## 4. Modules

### Module 1 — Static Analysis (Yousra)

Analyzes the package source code **without executing it**. Detects malicious patterns using three complementary techniques:

**AST Analysis** — Parses Python code into its abstract syntax tree and detects dangerous function calls:
- `eval()`, `exec()`, `compile()` — arbitrary code execution
- `subprocess.Popen()`, `os.system()` — shell command execution
- `socket.connect()`, `urllib.request.urlopen()` — outbound network calls
- `os.environ` + network calls — credential theft pattern

**Shannon Entropy Analysis** — Measures the randomness of string literals in the code. Strings with entropy > 5.5 and length > 50 characters are likely encoded payloads.

**YARA Rules** — Pattern matching on raw file content for known malicious signatures:
- Base64 + exec obfuscation patterns
- `chr()` map obfuscation (ASCII code arrays)
- BlankOBF tool signatures
- Hardcoded Telegram bot tokens
- MAC address theft patterns
- System fingerprinting patterns
- Telegram exfiltration patterns

No execution required. No sandbox needed. Runs on any machine.

See `modules/static/README.md` for full documentation.

---

### Module 2 — Behavioral Sandbox (Mohammed)

Executes the package installation inside an **isolated Docker container** with no network access and a restricted filesystem. A monitoring agent captures all system activity during and after installation.

**What is monitored:**
- System calls via `strace` — file writes, process creation, socket operations
- Outbound network connection attempts (destination IPs and domains)
- Files written outside the expected installation directory
- Child processes spawned during or after installation

**Docker isolation:**
```bash
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp/install \
  --security-opt no-new-privileges \
  depthcharge-sandbox \
  strace -f -e trace=network,file,process \
  pip install --no-deps <package>
```

---

### Module 3 — Reputation & Intelligence (Wiam)

Queries external sources to evaluate the trustworthiness of a package:

- **Typosquatting detection** — Levenshtein distance comparison against the 5,000 most popular packages (e.g., `requesTs` vs `requests`, distance = 1)
- **Metadata analysis** — Package age, version history, maintainer changes, download velocity
- **Version diff** — Compares current vs previous version to detect injected code in install hooks
- **Vulnerability database cross-reference** — OSV API and NVD for known CVEs
- **Score aggregation** — Collects signals from all three modules and computes the final weighted risk score

---

### Module 4 — Dashboard & CI/CD (Yasser)

Makes the tool usable by development teams:

- **Web interface** — Displays analysis results with per-module score breakdown and finding severity
- **CLI tool** — `depthcharge scan --lockfile requirements.txt --threshold 70`
- **GitHub Actions plugin** — Scans every Pull Request modifying a dependency file, comments the full report, blocks merge if score exceeds threshold
- **Demo environment** — Pre-loaded malicious packages for live demonstration

---

## 5. Risk Scoring

Each module contributes a weighted signal to the final score (0–100):

| Signal | Source | Priority | Max Points |
|--------|--------|----------|-----------|
| Obfuscated code / high entropy | Static | High | 25 |
| Dangerous AST patterns | Static | High | 20 |
| Suspicious runtime behavior | Sandbox | High | 25 |
| Typosquatting detected | Reputation | Medium | 15 |
| Suspicious metadata | Reputation | Low | 10 |
| Known malware database match | Database | Critical | +50 |

**Aggregation formula:**
```
final_score = (static × 0.35) + (sandbox × 0.40) + (reputation × 0.25)
```

**Score interpretation:**

| Score | Risk Level | Verdict | Action |
|-------|-----------|---------|--------|
| 0–30 | Low | allow | Package is probably safe |
| 31–69 | Medium | review | Manual review recommended |
| 70–100 | High | block | Installation blocked |

---

## 6. Project Structure

```
depthcharge/
├── modules/
│   ├── static/                    # Module 1 — Yousra
│   │   ├── static_module.py       # Main entry point
│   │   ├── ast_analyzer.py        # AST-based detection
│   │   ├── entropy.py             # Shannon entropy analysis
│   │   ├── yara_scanner.py        # YARA rule matching
│   │   ├── rules/
│   │   │   ├── exec_base64.yar
│   │   │   ├── network_in_setup.yar
│   │   │   ├── env_steal.yar
│   │   │   └── suspicious_subprocess.yar
│   │   └── README.md
│   ├── sandbox/                   # Module 2 — Mohammed
│   ├── reputation/                # Module 3 — Wiam
│   └── dashboard/                 # Module 4 — Yasser
├── shared/
│   ├── schema.py                  # Shared JSON schema / dataclasses
│   └── fetcher.py                 # PyPI/npm package downloader
├── tests/
│   ├── malicious/                 # Malicious samples (gitignored)
│   └── benign/                    # Legitimate packages (gitignored)
├── data/
│   └── pypi_malware_archive/      # Local malware archive (gitignored)
├── docker/
│   └── sandbox/                   # Sandbox Docker image
├── .gitignore
└── README.md
```

---

## 7. Installation

### Requirements

- Python 3.11+
- Docker (for sandbox module)
- pip

### Setup

```bash
git clone https://github.com/rainisveryswag/depthcharge
cd depthcharge

# Install Python dependencies
pip install yara-python requests python-Levenshtein flask

# Build sandbox Docker image
docker build -t depthcharge-sandbox docker/sandbox/
```

---

## 8. Usage

### Scan a single package

```bash
python modules/dashboard/cli.py scan requests==2.31.0
```

### Scan a lockfile

```bash
python modules/dashboard/cli.py scan --lockfile requirements.txt --threshold 70
```

### Static analysis only

```bash
cd modules/static/
python static_module.py /path/to/extracted/package package_name version
```

### GitHub Actions

```yaml
name: DepthCharge Supply Chain Scan

on:
  pull_request:
    paths:
      - 'requirements*.txt'
      - 'package*.json'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run DepthCharge
        uses: your-org/depthcharge-action@v1
        with:
          lockfile: requirements.txt
          threshold: 70
          fail-on-block: true
```

---

## 9. Output Format

All modules produce JSON conforming to the shared inter-module schema:

```json
{
  "meta": {
    "package": "colourama",
    "version": "0.3.6",
    "ecosystem": "pypi",
    "analyzed_at": "2026-04-22T14:30:00Z"
  },
  "modules": {
    "static": {
      "status": "completed",
      "score": 75,
      "findings": [
        {
          "id": "S001",
          "type": "dangerous_call",
          "pattern": "exec",
          "file": "setup.py",
          "line": 12,
          "severity": "critical",
          "description": "Dangerous call 'exec' detected in install hook"
        }
      ]
    },
    "sandbox": {
      "status": "completed",
      "score": 80,
      "findings": [
        {
          "id": "D001",
          "type": "network_connection",
          "destination": "192.168.1.100:4444",
          "severity": "critical",
          "description": "Outbound connection attempt during install"
        }
      ]
    },
    "reputation": {
      "status": "completed",
      "score": 60,
      "findings": [
        {
          "id": "R001",
          "type": "typosquatting",
          "target": "colorama",
          "distance": 1,
          "severity": "high",
          "description": "Package name 1 edit away from popular package"
        }
      ]
    }
  },
  "risk": {
    "score": 78,
    "level": "high",
    "verdict": "block",
    "breakdown": {
      "static": 75,
      "sandbox": 80,
      "reputation": 60
    },
    "summary": "Package exhibits obfuscated code execution and outbound network connection during install."
  }
}
```

---

## 10. Technology Stack

| Technology | Usage | Module |
|-----------|-------|--------|
| Python `ast` | AST parsing and pattern detection | Static |
| YARA | Pattern matching on raw file content | Static |
| Shannon entropy | Obfuscation detection | Static |
| Docker | Isolated sandbox environment | Sandbox |
| `strace` | System call monitoring | Sandbox |
| PyPI API / npm Registry | Package metadata retrieval | Reputation |
| OSV API / NVD | Known vulnerability lookup | Reputation |
| `python-Levenshtein` | Typosquatting detection | Reputation |
| Flask | Web dashboard backend | Dashboard |
| GitHub Actions YAML | CI/CD pipeline integration | Dashboard |
| argparse | CLI interface | Dashboard |

---

## 11. Dataset

### Malicious packages

All malicious packages used for testing come from the **Datadog Malicious Software Packages Dataset**:

```
https://github.com/DataDog/malicious-software-packages-dataset
```

Archives are password-protected with `infected`. All packages were confirmed malicious before removal from PyPI.

To download a specific package for testing:
```bash
# Get the download URL
curl -s "https://api.github.com/repos/DataDog/malicious-software-packages-dataset/contents/samples/pypi/malicious_intent/<package>/<version>" \
  | python3 -c "import sys,json; [print(x['download_url']) for x in json.load(sys.stdin)]"

# Download and extract
curl -L -o package.zip "<download_url>"
unzip -P "infected" package.zip -d package/
```

### Legitimate packages

```bash
pip download <package> --no-deps -d ./tests/benign/
unzip <package>-*.whl -d ./tests/benign/<package>/
```

**Important:** `tests/`, `data/`, and malware archives are gitignored. Never commit real malware samples to the repository.

---

## 12. Test Results

### Static Analysis — validated on real malicious packages

| Package | Attack Technique | Score | Verdict |
|---------|-----------------|-------|---------|
| `androidspyeye` | exec + high entropy payload in setup.py | 100 | 🔴 block |
| `detection-telegram` | exec + high entropy payload in setup.py | 100 | 🔴 block |
| `distpro` | MAC address theft + system fingerprinting | 90 | 🔴 block |
| `discconnect` | Environment variable exfiltration | 75 | 🔴 block |
| `loggerbyxolo` | BlankOBF multi-layer obfuscation | 70 | 🔴 block |
| `colorating` | chr() map obfuscation in setup.py | 70 | 🔴 block |
| `exo-steal` | Exodus wallet theft via Telegram bot | 70 | 🔴 block |
| `colurama` | base64 + exec obfuscation | 60 | 🟡 review |

### Legitimate packages — false positive check

| Package | Score | Verdict |
|---------|-------|---------|
| `django` | 0 | 🟢 allow |
| `cryptography` | 0 | 🟢 allow |
| `requests` | 20 | 🟢 allow |
| `flask` | 20 | 🟢 allow |
| `numpy` | 20 | 🟢 allow |

**Static module detection rate:** 8/8 malicious packages detected (100%)  
**False positive rate:** 0/5 legitimate packages incorrectly blocked (0%)

---

## 13. Scope and Limitations

### In scope (MVP)

- Static analysis of PyPI Python packages
- Behavioral analysis in an isolated Docker sandbox
- Reputation and metadata verification via PyPI API, OSV, NVD
- Risk score aggregation
- Web dashboard and CLI
- Optional GitHub Actions CI/CD integration

### Out of scope (MVP)

- Package managers other than PyPI and npm (Cargo, Maven, NuGet)
- Analysis of compiled binary artifacts (DLL, ELF) — partial YARA coverage only
- Automatic remediation (package removal or replacement)
- Continuous real-time monitoring of package registries

### Known limitations

- **Runtime-only payloads** — Malware downloading a second-stage payload at runtime cannot be detected statically
- **Advanced sandbox evasion** — Sophisticated malware may detect the sandbox and suppress behavior
- **Python files only** — Static analysis covers `.py` files; compiled extensions are not analyzed
- **Score calibration** — Weights calibrated on a limited test set; larger datasets would improve accuracy

---

## 14. References

1. Freund, J. (2024). *The XZ Utils backdoor: a timeline*. Openwall Security.
2. CISA. (2020). *Alert AA20-352A: APT Compromise via SolarWinds Orion*. US-CERT.
3. PyPI Security Team. (2023–2024). *Malware reports archive*. Python Package Index.
4. Ohm, M., Plate, H., Sykosch, A., & Meier, M. (2020). *Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks*. DIMVA 2020.
5. OWASP. (2023). *Software Component Verification Standard (SCVS) v1.0*.
6. DataDog. *Malicious Software Packages Dataset*. `github.com/DataDog/malicious-software-packages-dataset`

---

*DepthCharge — ENSA Marrakech 2025–2026*
