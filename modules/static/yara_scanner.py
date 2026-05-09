import yara
import os

# path to the rules directory
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def load_rules() -> dict:
    """
    Load all .yar files from the rules directory.
    Returns a dict of {rule_name: compiled_rule}
    """
    rules = {}

    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".yar"):
            rule_name = filename.replace(".yar", "")
            rule_path = os.path.join(RULES_DIR, filename)
            try:
                rules[rule_name] = yara.compile(filepath=rule_path)
            except yara.SyntaxError as e:
                print(f"[YARA] Syntax error in {filename}: {e}")

    return rules


def scan_file(filepath: str, rules: dict) -> list:
    """
    Scan a single file against all loaded YARA rules.
    Returns a list of findings.
    """
    findings = []

    for rule_name, rule in rules.items():
        try:
            matches = rule.match(filepath=filepath)
            for match in matches:
                findings.append({
                    "type": "yara_match",
                    "rule": match.rule,
                    "rule_file": rule_name,
                    "file": filepath,
                    "severity": match.meta.get("severity", "medium"),
                    "description": match.meta.get("description", "")
                })
        except Exception as e:
            print(f"[YARA] Error scanning {filepath} with {rule_name}: {e}")

    return findings


def scan_package(package_path: str) -> list:
    """
    Scan all .py files in a package directory.
    Prioritizes setup.py and __init__.py first.
    Returns a list of all findings across all files.
    """
    all_findings = []
    rules = load_rules()

    # priority files to scan first
    priority_files = ["setup.py", "__init__.py", "setup.cfg"]

    # collect all python files
    all_py_files = []
    for root, dirs, files in os.walk(package_path):
        for file in files:
            if file.endswith(".py"):
                all_py_files.append(os.path.join(root, file))

    # sort so priority files are scanned first
    def priority_sort(filepath):
        filename = os.path.basename(filepath)
        return 0 if filename in priority_files else 1

    all_py_files.sort(key=priority_sort)

    # scan each file
    for filepath in all_py_files:
        findings = scan_file(filepath, rules)
        all_findings.extend(findings)

    return all_findings


# test it manually
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python yara_scanner.py <path_to_package>")
        sys.exit(1)

    package_path = sys.argv[1]
    findings = scan_package(package_path)

    print(json.dumps(findings, indent=2))
    print(f"\nTotal findings: {len(findings)}")
