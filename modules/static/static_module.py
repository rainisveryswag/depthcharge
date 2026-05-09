import os
import sys
import json

from ast_analyzer import analyze_package as ast_analyze
from entropy import analyze_package as entropy_analyze
from yara_scanner import scan_package as yara_scan


def calculate_score(findings: list) -> int:
    score = 0

    severity_weights = {
        "critical": 35,
        "high":     20,
        "medium":   10,
        "low":      5
    }

    for finding in findings:
        severity = finding.get("severity", "medium")
        score += severity_weights.get(severity, 10)

    # if any critical finding exists — minimum score is 70
    has_critical = any(f.get("severity") == "critical" for f in findings)
    if has_critical:
        score = max(score, 70)

    return min(score, 100)


def analyze(package_path: str, package_name: str = "unknown", version: str = "unknown") -> dict:
    """
    Main entry point for static analysis.
    Runs AST, entropy, and YARA analysis on a package.
    Returns a JSON-compatible dict.
    """

    if not os.path.exists(package_path):
        return {
            "module": "static",
            "status": "error",
            "error": f"Path not found: {package_path}",
            "score": 0,
            "findings": []
        }

    # run all 3 analyzers
    print(f"[STATIC] Running AST analysis...")
    ast_findings = ast_analyze(package_path)

    print(f"[STATIC] Running entropy analysis...")
    entropy_findings = entropy_analyze(package_path)

    print(f"[STATIC] Running YARA analysis...")
    yara_findings = yara_scan(package_path)

    # combine all findings
    all_findings = ast_findings + entropy_findings + yara_findings

    # calculate score
    score = calculate_score(all_findings)

    # build final report
    result = {
        "package": package_name,
        "version": version,
        "ecosystem": "pypi",
        "module": "static",
        "status": "completed",
        "score": score,
        "findings": all_findings,
        "summary": {
            "total_findings": len(all_findings),
            "ast_findings": len(ast_findings),
            "entropy_findings": len(entropy_findings),
            "yara_findings": len(yara_findings),
            "critical": len([f for f in all_findings if f.get("severity") == "critical"]),
            "high":     len([f for f in all_findings if f.get("severity") == "high"]),
            "medium":   len([f for f in all_findings if f.get("severity") == "medium"]),
        }
    }

    return result


# test manually
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python static_module.py <path_to_package> [package_name] [version]")
        sys.exit(1)

    package_path = sys.argv[1]
    package_name = sys.argv[2] if len(sys.argv) > 2 else "unknown"
    version      = sys.argv[3] if len(sys.argv) > 3 else "unknown"

    result = analyze(package_path, package_name, version)

    print(json.dumps(result, indent=2))
