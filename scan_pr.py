from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from detector_rules import AISecurityDetectorRules


def git_diff(base_ref: str) -> str:
    cmd = ["git", "diff", base_ref]
    return subprocess.check_output(cmd, text=True)


def parse_diff(diff_text: str):
    snippets = []
    current_file = None
    current_new_line = None

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if line.startswith("@@"):
            try:
                plus = line.split("+", 1)[1].split(" ", 1)[0]
                current_new_line = int(plus.split(",")[0])
            except Exception:
                current_new_line = None
            continue
        if line.startswith("+") and not line.startswith("+++"):
            snippets.append({
                "file": current_file,
                "line_start": current_new_line,
                "line_end": current_new_line,
                "text": line[1:],
            })
            if current_new_line is not None:
                current_new_line += 1
        elif not line.startswith("-"):
            if current_new_line is not None:
                current_new_line += 1
    return snippets


def emit_github_actions(findings):
    for f in findings:
        file = f.get("file") or "unknown"
        line = f.get("line") or 1
        title = f["type"]
        message = f["recommendation"][0] if f.get("recommendation") else f["title"]
        print(f"::warning file={file},line={line},title={title}::{message}")


def main():
    parser = argparse.ArgumentParser(description="Scan PR diffs for AI-specific security risks.")
    parser.add_argument("--diff", help="Path to diff file")
    parser.add_argument("--base", help="Base git ref to diff against")
    parser.add_argument("--github-actions", action="store_true", help="Emit GitHub Actions annotations")
    args = parser.parse_args()

    if args.diff:
        diff_text = Path(args.diff).read_text(encoding="utf-8")
    elif args.base:
        diff_text = git_diff(args.base)
    else:
        print("Provide --diff or --base", file=sys.stderr)
        sys.exit(2)

    snippets = parse_diff(diff_text)
    rules = AISecurityDetectorRules()
    findings = rules.run(snippets)

    print(json.dumps(findings, indent=2))

    if args.github_actions and findings:
        emit_github_actions(findings)

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
