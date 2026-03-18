from io import StringIO
from contextlib import redirect_stdout
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scan_pr import _build_schema, _escape_github_annotation, _write_output_file, emit_markdown


def test_escape_github_annotation():
    value = "a,b\nc:d%e"
    assert _escape_github_annotation(value) == "a%2Cb%0Ac%3Ad%25e"


def test_build_schema():
    findings = [
        {
            "type": "AI_PROMPT_INJECTION_RISK",
            "severity": "high",
            "title": "Test",
            "file": "app/chat.py",
            "line": 10,
            "evidence": "example",
            "recommendation": ["r1"],
        },
        {
            "type": "PROMPT_LOGGING_RISK",
            "severity": "medium",
            "title": "Test",
            "file": "app/chat.py",
            "line": 20,
            "evidence": "example",
            "recommendation": ["r2"],
        },
    ]
    payload = _build_schema(findings)
    assert payload["schema_version"] == "1.0.0"
    assert payload["summary"]["total_findings"] == 2
    assert payload["summary"]["severity_counts"]["high"] == 1
    assert payload["summary"]["severity_counts"]["medium"] == 1
    assert payload["summary"]["files_touched"] == 1


def test_emit_markdown():
    findings = [{"type": "X", "severity": "low", "file": "x.py", "line": 5, "title": "Example | risk"}]
    out = StringIO()
    with redirect_stdout(out):
        emit_markdown(findings)
    assert "| X | LOW | `x.py:5` | Example \\| risk |" in out.getvalue()


def test_write_markdown_output_file(tmp_path):
    findings = [{"type": "X", "severity": "low", "file": "x.py", "line": 5, "title": "Example | risk"}]
    output_file = tmp_path / "report.md"
    _write_output_file(findings, str(output_file), "markdown", False)
    text = output_file.read_text(encoding="utf-8")
    assert text.startswith("# PromptShield")


def test_write_json_output_file(tmp_path):
    findings = [{"type": "X", "severity": "low"}]
    output_file = tmp_path / "report.json"
    _write_output_file(findings, str(output_file), "json", False)
    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert data == findings
