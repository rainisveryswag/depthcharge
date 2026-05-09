import ast
import os


# dangerous function calls to detect
DANGEROUS_CALLS = [
    "eval",
    "exec",
    "compile",
    # removed __import__ — too many false positives
    "os.system",
    "os.popen",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.run",
    "socket.connect",
    "socket.create_connection",
    "urllib.request.urlopen",
    "requests.get",
    "requests.post",
]

# suspicious calls specifically in setup.py or __init__.py
SUSPICIOUS_IN_SETUP = [
    "os.environ",
    "base64.b64decode",
    "marshal.loads",
    "ctypes.cdll",
    "ctypes.CDLL",
]

# priority files — most malware hides here
PRIORITY_FILES = ["setup.py", "__init__.py", "setup.cfg"]

# known legitimate files that use exec intentionally
EXEC_WHITELIST_FILES = ["shell.py", "repl.py", "console.py"]


class DangerousCallVisitor(ast.NodeVisitor):
    """
    Walks the AST tree and detects dangerous function calls.
    """

    def __init__(self, filename):
        self.filename = filename
        self.findings = []

    def _get_call_name(self, node):
        """
        Extract the full name of a function call.
        Example: subprocess.Popen → 'subprocess.Popen'
        """
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return None

    def visit_Call(self, node):
        call_name = self._get_call_name(node)

        if call_name:
            is_priority = os.path.basename(self.filename) in PRIORITY_FILES

            # these are always critical regardless of file
            always_critical = ["eval", "exec", "compile"]

            # only flag these in priority files
            priority_only = [
                "subprocess.Popen",
                "subprocess.call",
                "subprocess.run",
                "os.system",
                "os.popen",
            ]

            if call_name in DANGEROUS_CALLS:
                if call_name in always_critical:
                    if os.path.basename(self.filename) in EXEC_WHITELIST_FILES:
                        self.generic_visit(node)
                        return
                    if is_priority:
                        severity = "critical"
                    elif call_name == "exec":
                        severity = "high"  # still flag exec anywhere, just not critical
                    else:
                        self.generic_visit(node)
                        return
                elif call_name in priority_only:
                    if not is_priority:
                        self.generic_visit(node)
                        return
                    severity = "high"
                else:
                    severity = "critical" if is_priority else "high"

                self.findings.append({
                    "type": "dangerous_call",
                    "pattern": call_name,
                    "file": self.filename,
                    "line": node.lineno,
                    "severity": severity,
                    "description": f"Dangerous call '{call_name}' detected"
                })

            if call_name in SUSPICIOUS_IN_SETUP and is_priority:
                self.findings.append({
                    "type": "suspicious_call",
                    "pattern": call_name,
                    "file": self.filename,
                    "line": node.lineno,
                    "severity": "high",
                    "description": f"Suspicious call '{call_name}' in install hook"
                })

        self.generic_visit(node)


def analyze_file(filepath: str) -> list:
    """
    Parse a single Python file and detect dangerous calls.
    Returns a list of findings.
    """
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        tree = ast.parse(source)
        visitor = DangerousCallVisitor(filepath)
        visitor.visit(tree)
        findings = visitor.findings

    except SyntaxError as e:
        print(f"[AST] Syntax error in {filepath}: {e}")
    except Exception as e:
        print(f"[AST] Error analyzing {filepath}: {e}")

    return findings


def analyze_package(package_path: str) -> list:
    """
    Analyze all Python files in a package directory.
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
        print("Usage: python ast_analyzer.py <path_to_package>")
        sys.exit(1)

    package_path = sys.argv[1]
    findings = analyze_package(package_path)

    print(json.dumps(findings, indent=2))
    print(f"\nTotal findings: {len(findings)}")
