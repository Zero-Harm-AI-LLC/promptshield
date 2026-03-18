from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

from detector_rules import AISecurityDetectorRules

FINDING_SCHEMA_VERSION = "1.0.0"

# Sliding-window parameters for parse_diff.
# WINDOW_SIZE added lines are bundled into one snippet so that patterns
# spread across a multi-line LLM call (e.g. messages= on one line,
# request.json() on another) are detected together.
WINDOW_SIZE = 10
WINDOW_STRIDE = 5  # half-overlap keeps boundary patterns in at least one window


def git_diff(base_ref: str) -> str:
    cmd = ["git", "diff", base_ref]
    return subprocess.check_output(cmd, text=True)


def parse_diff(diff_text: str, window_size: int = WINDOW_SIZE, stride: int = WINDOW_STRIDE):
    """Parse a unified diff into overlapping multi-line window snippets.

    Groups consecutive added lines within each hunk and slides a window of
    *window_size* lines with *stride* step over them.  This lets pattern
    co-occurrence checks span several lines — e.g. an LLM API call spread
    across constructor kwargs and the user-input argument on separate lines.
    """
    # Step 1 – collect added lines keyed by (file, hunk index)
    hunks = defaultdict(list)  # (file, hunk_id) -> [(line_no, text), ...]
    current_file = None
    current_new_line = None
    hunk_id = 0

    for raw in diff_text.splitlines():
        if raw.startswith("+++ b/"):
            current_file = raw[6:]
            continue
        if raw.startswith("---"):
            continue
        if raw.startswith("@@"):
            hunk_id += 1
            try:
                plus = raw.split("+", 1)[1].split(" ", 1)[0]
                current_new_line = int(plus.split(",")[0])
            except Exception:
                current_new_line = None
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            if current_file is not None and current_new_line is not None:
                hunks[(current_file, hunk_id)].append((current_new_line, raw[1:]))
            if current_new_line is not None:
                current_new_line += 1
        elif not raw.startswith("-"):
            if current_new_line is not None:
                current_new_line += 1

    # Step 2 – emit sliding-window snippets over each hunk's added lines
    snippets = []
    effective_stride = max(1, stride)
    for (file, _hunk_id), lines in hunks.items():
        if not lines:
            continue
        for start in range(0, len(lines), effective_stride):
            window = lines[start : start + window_size]
            line_start = window[0][0]
            line_end = window[-1][0]
            text = "\n".join(t for _, t in window)
            snippets.append(
                {
                    "file": file,
                    "line_start": line_start,
                    "line_end": line_end,
                    "text": text,
                }
            )
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
