"""
detector_rules.py

Heuristic AI security detector rules for PR diffs / code snippets.

Designed to complement `zero-harm-ai-detectors` with AI/LLM-specific checks.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

try:
    from zero_harm_ai_detectors import detect_pii, detect_secrets
except Exception:
    detect_pii = None
    detect_secrets = None


Finding = Dict[str, Any]

# Findings of the same type in the same file within this many source lines
# are treated as duplicates — important for overlapping window snippets.
_DEDUP_LINE_BUCKET = 10


def _matches_any(patterns: List[str], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _make_finding(
    finding_type: str,
    severity: str,
    title: str,
    evidence: str,
    recommendation: List[str],
    file: Optional[str] = None,
    line: Optional[int] = None,
) -> Finding:
    return {
        "type": finding_type,
        "severity": severity,
        "title": title,
        "file": file,
        "line": line,
        "evidence": evidence[:400],
        "recommendation": recommendation,
    }


class AISecurityDetectorRules:
    LLM_API_PATTERNS = [
        r"\bopenai\b",
        r"\banthropic\b",
        r"\bgemini\b",
        r"\bcohere\b",
        r"\bchat\.completions\.create\b",
        r"\bresponses\.create\b",
        r"\bmessages\.create\b",
        r"\bgeneratetext\b",
        r"\bstreamtext\b",
        r"\bapi\.openai\.com\b",
        r"\bapi\.anthropic\.com\b",
        r"\bgenerativelanguage\.googleapis\.com\b",
    ]

    PROMPT_FIELD_PATTERNS = [
        r"\bmessages\s*[:=]",
        r"\bprompt\s*[:=]",
        r"\binput\s*[:=]",
        r"\bsystem\s*[:=]",
        r"\bcontent\s*[:=]",
    ]

    USER_INPUT_PATTERNS = [
        r"\brequest\.",
        r"\breq\.",
        r"\brequest\.json\(",
        r"\brequest\.body\b",
        r"\brequest\.form\b",
        r"\buser_input\b",
        r"\binput_text\b",
        r"\bprompt_input\b",
        r"\bparams\.",
        r"\bquery\.",
    ]

    LOGGING_PATTERNS = [
        r"\blogger\.(info|debug|warning|error|exception)\(",
        r"\bconsole\.log\(",
        r"\bprint\(",
        r"\btelemetry\.",
        r"\btrack\(",
    ]

    # Patterns for LLM tool/function definitions in API calls.
    TOOL_DEFINITION_PATTERNS = [
        r"\btools\s*[:=]",
        r"\btool_choice\b",
        r"\bfunction_call\b",
    ]

    # Patterns for dangerous host-side execution that could be
    # triggered by LLM output (command injection, code execution).
    DANGEROUS_EXEC_PATTERNS = [
        r"\bsubprocess\.",
        r"\bos\.system\(",
        r"\beval\(",
        r"\bexec\(",
    ]

    DB_DATA_PATTERNS = [
        # ORM / object-attribute access
        r"\bcustomer\.",
        r"\buser\.",
        r"\baccount\.",
        r"\bprofile\.",
        # Highly sensitive standalone field names
        r"\bssn\b",
        r"\bdob\b",
        # Raw DB access
        r"\bdb\.",
        r"\bqueryset\b",
        r"\b\.objects\.",       # Django ORM queryset
        r"\bcursor\.execute\(",
        r"\bfetchall\(",
        r"\bfetchone\(",
    ]

    FILE_READ_PATTERNS = [
        r"\bopen\(",
        # Removed bare r"\bread\(" — too broad (sockets, cursors, etc.)
        r"\bfile\.read\(",
        r"\bpathlib\.",
        r"\bloadtxt\(",
        r"\bread_text\(",
        r"\bread_file\(",
    ]

    SECRET_SOURCE_PATTERNS = [
        r"\bos\.environ\b",
        r"\bgetenv\(",
        r"\bsecret\b",
        r"\bapi[_-]?key\b",
        # Removed bare r"\btoken\b" — matches max_tokens, num_tokens, cancel tokens, etc.
        # Replaced with specific token patterns that indicate real credentials.
        r"\b(?:access|auth|api)[_\-]?token\b",
        r"\bpassword\b",
        r"\bcredential\b",
        r"\bprivate[_\-]?key\b",
    ]

    def run(self, snippets: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []

        for snippet in snippets:
            text = snippet.get("text", "")
            file = snippet.get("file")
            line = snippet.get("line_start")

            has_llm = _matches_any(self.LLM_API_PATTERNS, text)
            has_prompt = _matches_any(self.PROMPT_FIELD_PATTERNS, text)
            has_user_input = _matches_any(self.USER_INPUT_PATTERNS, text)
            has_logging = _matches_any(self.LOGGING_PATTERNS, text)
            has_tool_def = _matches_any(self.TOOL_DEFINITION_PATTERNS, text)
            has_dangerous_exec = _matches_any(self.DANGEROUS_EXEC_PATTERNS, text)
            has_tooling = has_tool_def or has_dangerous_exec
            has_db_data = _matches_any(self.DB_DATA_PATTERNS, text)
            has_file_read = _matches_any(self.FILE_READ_PATTERNS, text)
            has_secret_source = _matches_any(self.SECRET_SOURCE_PATTERNS, text)

            if has_llm and has_prompt and has_user_input:
                findings.append(
                    _make_finding(
                        "AI_PROMPT_INJECTION_RISK",
                        "high",
                        "User-controlled input appears to flow directly into an LLM prompt",
                        text,
                        [
                            "Validate or constrain user input before prompt construction.",
                            "Use structured prompt templates instead of direct interpolation.",
                        ],
                        file,
                        line,
                    )
                )

            if has_logging and ("prompt" in text.lower() or "messages" in text.lower() or "input" in text.lower()):
                findings.append(
                    _make_finding(
                        "PROMPT_LOGGING_RISK",
                        "medium",
                        "Prompt or LLM message content may be logged",
                        text,
                        [
                            "Avoid logging raw prompts or message payloads.",
                            "Redact sensitive content before telemetry or logs.",
                        ],
                        file,
                        line,
                    )
                )

            if (has_llm or has_prompt) and has_secret_source:
                findings.append(
                    _make_finding(
                        "SECRETS_IN_PROMPT_RISK",
                        "high",
                        "Potential secret or credential source appears in LLM-related code",
                        text,
                        [
                            "Do not include secrets in prompts or model context.",
                            "Use secret managers and keep credentials out of LLM payloads.",
                        ],
                        file,
                        line,
                    )
                )

            if (has_llm or has_prompt) and has_db_data:
                findings.append(
                    _make_finding(
                        "DATABASE_DATA_TO_LLM_RISK",
                        "high",
                        "Potential database or customer data appears to be sent to an LLM",
                        text,
                        [
                            "Minimize data sent to the model.",
                            "Redact PII and sensitive fields before prompt construction.",
                        ],
                        file,
                        line,
                    )
                )

            if has_llm and has_tooling:
                findings.append(
                    _make_finding(
                        "UNSAFE_TOOL_USAGE_RISK",
                        "high",
                        "Potential unsafe LLM tool or function execution path detected",
                        text,
                        [
                            "Validate tool inputs before execution.",
                            "Restrict tool scope to allow-listed operations only.",
                        ],
                        file,
                        line,
                    )
                )

            if re.search(r"\btool_choice\s*[:=]\s*[\"']?auto", text, re.IGNORECASE) or re.search(
                r"\bfunction_call\s*[:=]\s*[\"']?auto", text, re.IGNORECASE
            ):
                findings.append(
                    _make_finding(
                        "UNRESTRICTED_TOOL_SELECTION_RISK",
                        "medium",
                        "LLM appears to have automatic tool/function selection",
                        text,
                        [
                            "Use explicit tool allow-lists and validation.",
                            "Avoid unrestricted automatic tool execution in sensitive flows.",
                        ],
                        file,
                        line,
                    )
                )

            # Require an actual system-prompt indicator, not just the word "system"
            # (avoids false positives from os.system(), system_name variables, etc.)
            if re.search(
                r'["\']system["\']|\bsystem_prompt\b|\bsystem_message\b',
                text,
                re.IGNORECASE,
            ) and has_secret_source:
                findings.append(
                    _make_finding(
                        "SYSTEM_PROMPT_SECRET_RISK",
                        "high",
                        "Potential secret appears in a system prompt or system-level LLM context",
                        text,
                        [
                            "Never place credentials or secrets into system prompts.",
                            "Move secret-dependent logic outside the model context.",
                        ],
                        file,
                        line,
                    )
                )

            if has_prompt and (
                re.search(r"\+", text) or re.search(r"f[\"']", text) or re.search(r"\.format\(", text)
            ) and has_user_input:
                findings.append(
                    _make_finding(
                        "PROMPT_CONCATENATION_RISK",
                        "medium",
                        "Prompt appears to be built using direct string concatenation or interpolation",
                        text,
                        [
                            "Use structured templates and explicit validation for inserted values.",
                            "Avoid raw concatenation of user-controlled content into prompts.",
                        ],
                        file,
                        line,
                    )
                )

            if has_logging and re.search(r"\brequest\b|\breq\b|\bbody\b|\bjson\(", text, re.IGNORECASE):
                findings.append(
                    _make_finding(
                        "REQUEST_BODY_LOGGING_RISK",
                        "medium",
                        "Request or request-derived content may be logged",
                        text,
                        [
                            "Avoid logging full request bodies.",
                            "Redact sensitive inputs before any logging or telemetry.",
                        ],
                        file,
                        line,
                    )
                )

            if (has_llm or has_prompt) and has_file_read:
                findings.append(
                    _make_finding(
                        "DOCUMENT_TO_LLM_RISK",
                        "medium",
                        "A file or document may be read and sent into LLM context",
                        text,
                        [
                            "Send only the minimum required content to the model.",
                            "Review whether documents contain confidential or regulated data.",
                        ],
                        file,
                        line,
                    )
                )

            if detect_pii and (has_llm or has_prompt):
                try:
                    if detect_pii(text):
                        findings.append(
                            _make_finding(
                                "PII_TO_LLM_RISK",
                                "high",
                                "Potential PII detected in LLM-related code or payload",
                                text,
                                [
                                    "Remove or redact PII before sending content to an LLM.",
                                    "Prefer IDs, tokens, or structured references instead of raw personal data.",
                                ],
                                file,
                                line,
                            )
                        )
                except Exception:
                    pass

            if detect_secrets:
                try:
                    if detect_secrets(text):
                        findings.append(
                            _make_finding(
                                "SECRET_EXPOSURE_RISK",
                                "high",
                                "Potential secret detected in changed code",
                                text,
                                [
                                    "Remove hardcoded secrets from code.",
                                    "Use environment variables or a secret manager instead.",
                                ],
                                file,
                                line,
                            )
                        )
                except Exception:
                    pass

        return self._dedupe(findings)

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings, bucketing by coarse line position.

        Overlapping window snippets from parse_diff can produce the same
        logical finding at slightly different line numbers.  Bucketing by
        ``line // _DEDUP_LINE_BUCKET`` collapses those into one entry while
        still preserving genuinely distinct findings in different parts of
        the same file.
        """
        seen: set = set()
        unique: List[Finding] = []

        for f in findings:
            line = f.get("line") or 0
            key = (
                f["type"],
                f.get("file"),
                line // _DEDUP_LINE_BUCKET,
            )
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
