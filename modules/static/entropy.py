import ast
import math
import os
from collections import Counter


# thresholds
ENTROPY_THRESHOLD = 5.5
MIN_STRING_LENGTH = 50

# priority files
PRIORITY_FILES = ["setup.py", "__init__.py", "setup.cfg"]

# strings that look high-entropy but are benign (alphabets, digit runs, etc.)
ENTROPY_WHITELIST = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz0123456789",
    "!@#$%^&*",
]


def is_whitelisted(s: str) -> bool:
    """
    Return True if the string looks like a charset/character-class
    definition rather than an obfuscated payload.
    """
    # if string contains mostly printable ascii charset characters
    # it's likely a character set definition not a payload
    unique_chars = len(set(s))
    if unique_chars > 40 and len(s) < 100:
        return True
    for safe in ENTROPY_WHITELIST:
        if safe in s:
            return True
    return False


def shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy = more random = possibly encoded/obfuscated.
    """
    if not s:
        return 0.0

    counter = Counter(s)
    length = len(s)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )


def extract_strings(source: str) -> list:
    """
    Extract all string literals from Python source code using AST.
    Returns a list of (string_value, line_number).
    """
    strings = []

    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                strings.append((node.value, node.lineno))
    except SyntaxError:
        pass

    return strings


def analyze_file(filepath: str) -> list:
    """
    Analyze a single file for high entropy strings.
    Returns a list of findings.
    """
    findings = []
    is_priority = os.path.basename(filepath) in PRIORITY_FILES

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        strings = extract_strings(source)

        for string_value, line_number in strings:

            # skip short strings
            if len(string_value) < MIN_STRING_LENGTH:
                continue

            # skip known-benign literals (alphabets, digit runs, etc.)
            if is_whitelisted(string_value):
                continue

            entropy = shannon_entropy(string_value)

            if entropy > ENTROPY_THRESHOLD:
                severity = "critical" if is_priority else "high"
                findings.append({
                    "type": "high_entropy_string",
                    "file": filepath,
                    "line": line_number,
                    "entropy": round(entropy, 2),
                    "length": len(string_value),
                    "preview": string_value[:50] + "..." if len(string_value) > 50 else string_value,
                    "severity": severity,
                    "description": f"High entropy string detected (entropy={round(entropy, 2)})"
                })

    except Exception as e:
        print(f"[ENTROPY] Error analyzing {filepath}: {e}")

    return findings


def analyze_package(package_path: str) -> list:
    """
    Analyze all Python files in a package for high entropy strings.
    Prioritizes setup.py and __init__.py first.
    Returns all findings.
    """
    all_findings = []
    all_py_files = []

    for root, dirs, files in os.walk(package_path):
        # skip test directories
        dirs[:] = [d for d in dirs if d not in ["tests", "test", "testing"]]

        for file in files:
            if file.endswith(".py"):
                # skip test files
                if file.startswith("test_") or file.endswith("_test.py"):
                    continue
                all_py_files.append(os.path.join(root, file))

    # sort priority files first
    def priority_sort(filepath):
        return 0 if os.path.basename(filepath) in PRIORITY_FILES else 1

    all_py_files.sort(key=priority_sort)

    for filepath in all_py_files:
        findings = analyze_file(filepath)
        all_findings.extend(findings)

    return all_findings


# test manually
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python entropy.py <path_to_package>")
        sys.exit(1)

    package_path = sys.argv[1]
    findings = analyze_package(package_path)

    print(json.dumps(findings, indent=2))
    print(f"\nTotal findings: {len(findings)}")
