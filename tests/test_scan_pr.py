from io import StringIO
from contextlib import redirect_stdout
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scan_pr import _build_schema, _escape_github_annotation, _write_output_file, emit_markdown
import detector_rules
from detector_rules import AISecurityDetectorRules


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


def test_detector_calls_zero_harm_pii_for_llm_snippet(monkeypatch):
    calls = []
    detector_payload = {"matches": [{"type": "email", "value": "alice@example.com"}]}

    def fake_detect_pii(text):
        calls.append(text)
        return detector_payload

    monkeypatch.setattr(detector_rules, "detect_pii", fake_detect_pii)
    monkeypatch.setattr(detector_rules, "detect_secrets", lambda text: False)

    findings = AISecurityDetectorRules().run(
        [
            {
                "file": "app/chat.py",
                "line_start": 12,
                "text": 'client.responses.create(input=request.json()["prompt"])',
            }
        ]
    )

    assert calls == ['client.responses.create(input=request.json()["prompt"])']
    pii_findings = [f for f in findings if f["type"] == "PII_TO_LLM_RISK"]
    assert pii_findings
    assert pii_findings[0]["source_details"] == detector_payload
    assert pii_findings[0]["source_summary"] == "email: alice@example.com"


def test_detector_calls_zero_harm_secrets_for_changed_code(monkeypatch):
    calls = []
    detector_payload = {"matches": [{"type": "openai_key", "value": "sk-test-123"}]}

    def fake_detect_secrets(text):
        calls.append(text)
        return detector_payload

    monkeypatch.setattr(detector_rules, "detect_pii", lambda text: False)
    monkeypatch.setattr(detector_rules, "detect_secrets", fake_detect_secrets)

    findings = AISecurityDetectorRules().run(
        [
            {
                "file": "app/chat.py",
                "line_start": 20,
                "text": 'client.responses.create(input="hello")\napi_key = "sk-test-123"',
            }
        ]
    )

    assert calls == ['client.responses.create(input="hello")\napi_key = "sk-test-123"']
    secret_findings = [f for f in findings if f["type"] == "SECRET_EXPOSURE_RISK"]
    assert secret_findings
    assert secret_findings[0]["source_details"] == detector_payload
    assert secret_findings[0]["source_summary"] == "openai_key: sk-test-123"


def test_main_runs_diff_to_github_feedback_pipeline(tmp_path, monkeypatch):
    diff_file = tmp_path / "change.diff"
    diff_file.write_text(
        """diff --git a/app/chat.py b/app/chat.py
index 1111111..2222222 100644
--- a/app/chat.py
+++ b/app/chat.py
@@ -0,0 +1,3 @@
+from openai import OpenAI
+client = OpenAI()
+client.responses.create(input=request.json()["prompt"])
""",
        encoding="utf-8",
    )

    calls = []

    detector_payload = {"matches": [{"type": "email", "value": "alice@example.com"}]}

    def fake_detect_pii(text):
        calls.append(text)
        return detector_payload

    monkeypatch.setattr(detector_rules, "detect_pii", fake_detect_pii)
    monkeypatch.setattr(detector_rules, "detect_secrets", lambda text: False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scan_pr.py", "--diff", str(diff_file), "--output-format", "github", "--fail-on", "never"],
    )

    out = StringIO()
    with redirect_stdout(out):
        try:
            from scan_pr import main

            main()
        except SystemExit as exc:
            assert exc.code == 0

    output = out.getvalue()
    assert calls
    assert "AI_PROMPT_INJECTION_RISK" in output
    assert "PII_TO_LLM_RISK" in output
    assert "::warning file=app/chat.py,line=1," in output
    assert "Detector match: email%3A alice@example.com" in output


def test_main_runs_diff_to_json_feedback_with_detector_source_details(tmp_path, monkeypatch):
    diff_file = tmp_path / "change.diff"
    diff_file.write_text(
        """diff --git a/app/chat.py b/app/chat.py
index 1111111..2222222 100644
--- a/app/chat.py
+++ b/app/chat.py
@@ -0,0 +1,3 @@
+from openai import OpenAI
+client = OpenAI()
+client.responses.create(input=request.json()["prompt"])
""",
        encoding="utf-8",
    )

    detector_payload = {"matches": [{"type": "email", "value": "alice@example.com"}]}
    monkeypatch.setattr(detector_rules, "detect_pii", lambda text: detector_payload)
    monkeypatch.setattr(detector_rules, "detect_secrets", lambda text: False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scan_pr.py", "--diff", str(diff_file), "--output-format", "json", "--fail-on", "never"],
    )

    out = StringIO()
    with redirect_stdout(out):
        try:
            from scan_pr import main

            main()
        except SystemExit as exc:
            assert exc.code == 0

    findings = json.loads(out.getvalue())
    pii_findings = [f for f in findings if f["type"] == "PII_TO_LLM_RISK"]
    assert pii_findings
    assert pii_findings[0]["source_details"] == detector_payload
    assert pii_findings[0]["source_summary"] == "email: alice@example.com"


def test_main_runs_diff_to_markdown_feedback_pipeline(tmp_path, monkeypatch):
    diff_file = tmp_path / "change.diff"
    diff_file.write_text(
        """diff --git a/app/chat.py b/app/chat.py
index 1111111..2222222 100644
--- a/app/chat.py
+++ b/app/chat.py
@@ -0,0 +1,4 @@
+from openai import OpenAI
+client = OpenAI()
+logger.info("prompt=%s", request.json()["prompt"])
+client.responses.create(input=request.json()["prompt"])
""",
        encoding="utf-8",
    )

    monkeypatch.setattr(detector_rules, "detect_pii", lambda text: False)
    monkeypatch.setattr(detector_rules, "detect_secrets", lambda text: False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scan_pr.py", "--diff", str(diff_file), "--output-format", "markdown", "--fail-on", "never"],
    )

    out = StringIO()
    with redirect_stdout(out):
        try:
            from scan_pr import main

            main()
        except SystemExit as exc:
            assert exc.code == 0

    output = out.getvalue()
    assert output.startswith("# PromptShield")
    assert "| AI_PROMPT_INJECTION_RISK | HIGH | `app/chat.py:1` |" in output
    assert "| PROMPT_LOGGING_RISK | MEDIUM | `app/chat.py:1` |" in output


def test_emit_markdown_includes_detector_summary():
    findings = [
        {
            "type": "PII_TO_LLM_RISK",
            "severity": "high",
            "file": "app/chat.py",
            "line": 7,
            "title": "Potential PII detected in LLM-related code or payload",
            "source_summary": "email: alice@example.com",
        }
    ]
    out = StringIO()
    with redirect_stdout(out):
        emit_markdown(findings)
    assert "Detector match: email: alice@example.com" in out.getvalue()


def test_main_runs_diff_to_sarif_feedback_pipeline(tmp_path, monkeypatch):
    diff_file = tmp_path / "change.diff"
    diff_file.write_text(
        """diff --git a/app/chat.py b/app/chat.py
index 1111111..2222222 100644
--- a/app/chat.py
+++ b/app/chat.py
@@ -0,0 +1,3 @@
+from openai import OpenAI
+client = OpenAI()
+client.responses.create(input=request.json()["prompt"])
""",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        detector_rules,
        "detect_pii",
        lambda text: {"matches": [{"type": "email", "value": "alice@example.com"}]},
    )
    monkeypatch.setattr(detector_rules, "detect_secrets", lambda text: False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scan_pr.py", "--diff", str(diff_file), "--output-format", "sarif", "--fail-on", "never"],
    )

    out = StringIO()
    with redirect_stdout(out):
        try:
            from scan_pr import main

            main()
        except SystemExit as exc:
            assert exc.code == 0

    payload = json.loads(out.getvalue())
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "PromptShield"
    results = payload["runs"][0]["results"]
    assert any(result["ruleId"] == "AI_PROMPT_INJECTION_RISK" for result in results)
    assert any(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/chat.py"
        for result in results
    )
    assert any(
        "Detector match: email: alice@example.com" in result["message"]["text"]
        for result in results
        if result["ruleId"] == "PII_TO_LLM_RISK"
    )
