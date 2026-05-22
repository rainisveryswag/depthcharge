import subprocess
import json
import re
import sys
import os
from datetime import datetime
from pathlib import Path

def parse_strace_output(strace_stderr):
    findings = []
    score = 0
    finding_id = 1

    # Basic regexes for strace
    connect_re = re.compile(r'connect\(\d+,\s*\{sa_family=(AF_INET|AF_INET6),\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)')
    openat_re = re.compile(r'openat\(.*,\s*"([^"]+)",\s*([^,]+)')
    execve_re = re.compile(r'execve\("([^"]+)",\s*\[([^\]]+)\]')

    for line in strace_stderr.splitlines():
        # Check network connections
        m_connect = connect_re.search(line)
        if m_connect:
            family, port, ip = m_connect.groups()
            # Ignore local connections if necessary, but all network out is suspicious here
            findings.append({
                "id": f"D{finding_id:03d}",
                "type": "network_connection",
                "destination": f"{ip}:{port}",
                "severity": "critical",
                "description": f"Outbound connection attempt to {ip}:{port}"
            })
            score += 80  # Increased penalty for network connection during install
            finding_id += 1
            continue

        # Check suspicious file writes
        m_openat = openat_re.search(line)
        if m_openat:
            filepath, flags = m_openat.groups()
            if "O_WRONLY" in flags or "O_RDWR" in flags or "O_CREAT" in flags:
                # Ignore pip internal install paths and temp files
                if not filepath.startswith("/tmp") and not filepath.startswith("/usr/local") and not filepath.startswith("/dev"):
                    findings.append({
                        "id": f"D{finding_id:03d}",
                        "type": "suspicious_file_write",
                        "path": filepath,
                        "severity": "high",
                        "description": f"Suspicious file write outside allowed directories: {filepath}"
                    })
                    score += 40  # Increased penalty for arbitrary file writes
                    finding_id += 1
                    continue

        # Check process creation (execve)
        m_execve = execve_re.search(line)
        if m_execve:
            cmd, args = m_execve.groups()
            # We expect python/pip commands, but shell commands are suspicious
            if "sh" in cmd or "bash" in cmd or "curl" in cmd or "wget" in cmd:
                findings.append({
                    "id": f"D{finding_id:03d}",
                    "type": "suspicious_process",
                    "command": cmd,
                    "severity": "high",
                    "description": f"Suspicious child process spawned: {cmd} with args {args}"
                })
                score += 50  # Increased penalty for shell execution
                finding_id += 1
                continue

    # Cap score at 100
    score = min(score, 100)
    return score, findings

def analyze_package(package_path):
    package_path = Path(package_path).resolve()
    
    # Check if npm or pip
    is_npm = (package_path / "package.json").exists()
    
    install_cmd = ["npm", "install", "--ignore-scripts=false"] if is_npm else ["pip", "install", "--no-deps", "/pkg_to_install"]
    
    # We will mount the package directory into the container
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp/install",
        "--security-opt", "no-new-privileges",
        "-v", f"{package_path}:/pkg_to_install:ro",
        "-w", "/pkg_to_install",
        "depthcharge-sandbox",
        "strace", "-f", "-e", "trace=network,file,process"
    ] + install_cmd

    # Check if we should bypass docker and use mock strace output directly
    if os.environ.get("DEPTHCHARGE_MOCK_STRACE") == "1":
        strace_out = os.environ.get("DEPTHCHARGE_MOCK_STRACE_OUTPUT", "")
    else:
        try:
            # Run docker and capture stderr for strace output
            result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=60)
            strace_out = result.stderr
        except FileNotFoundError:
            return {
                "status": "error",
                "message": "Docker command not found"
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "message": "Sandbox execution timed out"
            }
        except Exception as e:
             return {
                "status": "error",
                "message": str(e)
            }

    score, findings = parse_strace_output(strace_out)

    return {
        "status": "completed",
        "score": score,
        "findings": findings
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sandbox_module.py <package_path>")
        sys.exit(1)
    
    pkg_path = sys.argv[1]
    report = analyze_package(pkg_path)
    print(json.dumps(report, indent=2))
