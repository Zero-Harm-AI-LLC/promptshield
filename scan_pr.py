from __future__ import annotations

import argparse
import json
from collections import Counter
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

from detector_rules import AISecurityDetectorRules

FINDING_SCHEMA_VERSION = "1.0.0"


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
        print(
            f"::warning file={_escape_github_annotation(file)},line={line},"
            f"title={_escape_github_annotation(title)}::{_escape_github_annotation(message)}"
        )


def _escape_github_annotation(value: Any) -> str:
    text = str(value)
    return (
        text.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _build_schema(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity = Counter((f.get("severity") or "unknown").lower() for f in findings)
    file_counts = Counter(f.get("file") or "unknown" for f in findings)

    return {
        "schema_version": FINDING_SCHEMA_VERSION,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": dict(sorted(severity.items())),
            "files_touched": len(file_counts),
        },
        "findings": findings,
    }


def format_markdown(findings: Iterable[Dict[str, Any]]) -> str:
    findings_list = list(findings)
    if not findings_list:
        return "# PromptShield\n\nNo AI security findings were detected in this diff.\n"

    lines = [
        "# PromptShield",
        f"Found {len(findings_list)} potential issue(s):",
        "",
        "| Type | Severity | Location | Title |",
        "| --- | --- | --- | --- |",
    ]
    for finding in findings_list:
        file = finding.get("file") or "unknown"
        line = finding.get("line") or 1
        severity = (finding.get("severity") or "unknown").upper()
        type_ = finding.get("type") or "UNKNOWN"
        title = (finding.get("title") or "").replace("|", r"\|")
        lines.append(f"| {type_} | {severity} | `{file}:{line}` | {title} |")
    return "\n".join(lines) + "\n"


def emit_markdown(findings: Iterable[Dict[str, Any]]) -> None:
    print(format_markdown(findings), end="")


def _write_output_file(findings: List[Dict[str, Any]], output_file: str, output_format: str, use_schema: bool) -> None:
    payload = (
        format_markdown(findings)
        if output_format == "markdown"
        else json.dumps(_build_schema(findings) if use_schema else findings, indent=2)
    )
    Path(output_file).write_text(payload + "\n", encoding="utf-8")


def _emit_json(findings: List[Dict[str, Any]], use_schema: bool) -> None:
    payload: Dict[str, Any] = _build_schema(findings) if use_schema else findings
    print(json.dumps(payload, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Scan PR diffs for AI-specific security risks.")
    parser.add_argument("--diff", help="Path to diff file")
    parser.add_argument("--base", help="Base git ref to diff against")
    parser.add_argument(
        "--github-actions",
        action="store_true",
        help="Emit GitHub Actions annotations (deprecated; use --output-format github)",
    )
    parser.add_argument(
        "--output-format",
        choices=("json", "github", "markdown"),
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--schema",
        action="store_true",
        help="Emit schema-wrapped JSON payload when output-format is json",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Limit findings output size",
    )
    parser.add_argument("--output-file", help="Optional path to write findings output")
    args = parser.parse_args()

    output_format = args.output_format
    if args.github_actions:
        output_format = "github"

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
    if args.max_findings is not None:
        findings = findings[: args.max_findings]

    if output_format == "github" and findings:
        emit_github_actions(findings)
    elif output_format == "markdown":
        emit_markdown(findings)
    else:
        _emit_json(findings, args.schema)

    if args.output_file:
        try:
            _write_output_file(findings, args.output_file, output_format, args.schema)
        except Exception as exc:
            print(f"Failed to write output file: {exc}", file=sys.stderr)
            sys.exit(2)

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
