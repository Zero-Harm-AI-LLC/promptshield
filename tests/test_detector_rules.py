import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detector_rules import AISecurityDetectorRules
from scan_pr import parse_diff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_snippet(text, file="test.py", line=1):
    return {"file": file, "line_start": line, "line_end": line, "text": text}


def finding_types(findings):
    return {f["type"] for f in findings}


def run(text, file="test.py", line=1):
    return AISecurityDetectorRules().run([make_snippet(text, file, line)])


# ---------------------------------------------------------------------------
# parse_diff tests
# ---------------------------------------------------------------------------

SIMPLE_DIFF = """\
diff --git a/app/chat.py b/app/chat.py
index 111..222 100644
--- a/app/chat.py
+++ b/app/chat.py
@@ -1,1 +1,1 @@
+response = client.chat.completions.create(messages=[{"role":"user","content":request.json()}])
"""


def test_parse_diff_basic():
    snippets = parse_diff(SIMPLE_DIFF)
    assert len(snippets) == 1
    assert snippets[0]["file"] == "app/chat.py"
    assert snippets[0]["line_start"] == 1
    assert "request.json" in snippets[0]["text"]


def test_parse_diff_ignores_removed_lines():
    diff = """\
diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,1 +1,1 @@
-old_line = client.messages.create(messages=[{"role":"user","content":request.json()}])
+new_line = "safe"
"""
    snippets = parse_diff(diff)
    assert len(snippets) == 1
    assert "old_line" not in snippets[0]["text"]
    assert "new_line" in snippets[0]["text"]


def test_parse_diff_sliding_window():
    # 12 added lines should produce at least 2 overlapping windows (stride=5)
    added = "\n".join(f"+line{i} = {i}" for i in range(12))
    diff = f"diff --git a/big.py b/big.py\n--- a/big.py\n+++ b/big.py\n@@ -1,12 +1,12 @@\n{added}\n"
    snippets = parse_diff(diff)
    assert len(snippets) >= 2


def test_parse_diff_multi_hunk():
    diff = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,1 +1,1 @@
+line_a = 1
@@ -10,1 +10,1 @@
+line_b = 2
"""
    snippets = parse_diff(diff)
    assert len(snippets) == 2
    texts = [s["text"] for s in snippets]
    assert any("line_a" in t for t in texts)
    assert any("line_b" in t for t in texts)


# ---------------------------------------------------------------------------
# Detection rule tests
# ---------------------------------------------------------------------------

def test_run_prompt_injection():
    text = 'response = openai.chat.completions.create(messages=[{"role":"user","content":request.json()["q"]}])'
    types = finding_types(run(text))
    assert "AI_PROMPT_INJECTION_RISK" in types


def test_run_prompt_logging():
    text = 'logger.info(prompt)\nresponse = client.messages.create(messages=[{"role":"user","content":"hi"}])'
    types = finding_types(run(text))
    assert "PROMPT_LOGGING_RISK" in types


def test_run_secrets_in_prompt():
    text = 'openai.chat.completions.create(messages=[{"role":"system","content":os.environ["API_KEY"]}])'
    types = finding_types(run(text))
    assert "SECRETS_IN_PROMPT_RISK" in types


def test_run_database_data():
    text = 'anthropic.messages.create(messages=[{"role":"user","content":customer.email}])'
    types = finding_types(run(text))
    assert "DATABASE_DATA_TO_LLM_RISK" in types


def test_run_unsafe_tool_usage():
    text = "response = openai.chat.completions.create(tools=tools)\nresult = subprocess.run(cmd)"
    types = finding_types(run(text))
    assert "UNSAFE_TOOL_USAGE_RISK" in types


def test_run_unrestricted_tool_selection():
    text = 'client.chat.completions.create(tool_choice="auto", tools=tools)'
    types = finding_types(run(text))
    assert "UNRESTRICTED_TOOL_SELECTION_RISK" in types


def test_run_system_prompt_secret():
    text = 'messages=[{"role":"system","content":os.environ["SECRET_KEY"]}]'
    types = finding_types(run(text))
    assert "SYSTEM_PROMPT_SECRET_RISK" in types


def test_run_prompt_concatenation():
    text = 'prompt = "Answer: " + request.form["q"]\nclient.messages.create(messages=[{"role":"user","content":prompt}])'
    types = finding_types(run(text))
    assert "PROMPT_CONCATENATION_RISK" in types


def test_run_request_body_logging():
    text = "logger.info(request.json())"
    types = finding_types(run(text))
    assert "REQUEST_BODY_LOGGING_RISK" in types


def test_run_document_to_llm():
    text = 'openai.chat.completions.create(messages=[{"role":"user","content":file.read()}])'
    types = finding_types(run(text))
    assert "DOCUMENT_TO_LLM_RISK" in types


# ---------------------------------------------------------------------------
# Deduplication tests
# ---------------------------------------------------------------------------

def test_dedupe_collapses_nearby_same_type():
    # Two snippets of same type within 10 lines → deduped to 1
    snippets = [
        make_snippet('openai.chat.completions.create(messages=[{"role":"user","content":request.json()}])', line=1),
        make_snippet('openai.chat.completions.create(messages=[{"role":"user","content":request.json()}])', line=5),
    ]
    findings = AISecurityDetectorRules().run(snippets)
    injection = [f for f in findings if f["type"] == "AI_PROMPT_INJECTION_RISK"]
    assert len(injection) == 1


def test_dedupe_keeps_distinct_locations():
    # Same rule, >10 lines apart → kept as 2 separate findings
    snippets = [
        make_snippet('openai.chat.completions.create(messages=[{"role":"user","content":request.json()}])', line=1),
        make_snippet('openai.chat.completions.create(messages=[{"role":"user","content":request.body}])', line=25),
    ]
    findings = AISecurityDetectorRules().run(snippets)
    injection = [f for f in findings if f["type"] == "AI_PROMPT_INJECTION_RISK"]
    assert len(injection) == 2
