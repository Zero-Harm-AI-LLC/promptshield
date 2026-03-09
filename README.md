# PromptShield — AI Security PR Reviewer (Standalone)

Detect prompt injection, PII leaks, secrets exposure, and unsafe LLM usage in pull requests.

PromptShield is a **free standalone GitHub Action and CLI tool** powered by
[`zero-harm-ai-detectors`](https://pypi.org/project/zero-harm-ai-detectors/).

It scans PR diffs locally or in CI and flags **AI-specific security risks** before code is merged.

## What it detects

- User input flowing directly into LLM prompts
- Prompt/message logging
- Secrets in prompts or LLM context
- Database / customer data sent to LLMs
- Unsafe tool or function usage
- Unrestricted tool auto-selection
- System prompts containing secrets
- Prompt concatenation with user input
- Logging request bodies
- Sending files/documents to LLMs
- Plus PII and secret detection from `zero-harm-ai-detectors`

## Quick start

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Scan a diff file

```bash
git diff origin/main > diff.txt
python scan_pr.py --diff diff.txt
```

### Scan against a base branch directly

```bash
python scan_pr.py --base origin/main
```

### GitHub Actions annotations

```bash
python scan_pr.py --base origin/main --github-actions
```

## Example output

```json
[
  {
    "type": "AI_PROMPT_INJECTION_RISK",
    "severity": "high",
    "title": "User-controlled input appears to flow directly into an LLM prompt",
    "file": "app/chat.py",
    "line": 42,
    "evidence": "client.chat.completions.create(messages=[{\"role\":\"user\",\"content\":request.json()[\"prompt\"]}])",
    "recommendation": [
      "Validate or constrain user input before prompt construction.",
      "Use structured prompt templates instead of direct interpolation."
    ]
  }
]
```

## GitHub Action usage

Use the included `action.yml` from this repo, or add a workflow like:

```yaml
name: PromptShield

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install PromptShield dependencies
        run: |
          pip install -r requirements.txt

      - name: Run PromptShield
        run: |
          python scan_pr.py --base origin/${{ github.base_ref }} --github-actions
```

## Exit codes

- `0` = no findings
- `1` = findings detected
- `2` = usage/runtime error

## Future hosted version

A hosted GitHub App version with PR comments, explanations, and multi-repo support is under development.

ScalApps
