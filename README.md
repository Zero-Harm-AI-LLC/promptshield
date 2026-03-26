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
pip install -r requirements-lock.txt
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

### Schema-aware JSON output

```bash
python scan_pr.py --base origin/main --output-format json --schema
```

### Markdown output

```bash
python scan_pr.py --base origin/main --output-format markdown
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
      - uses: actions/checkout@v5

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install PromptShield dependencies
        run: |
          pip install -r requirements-lock.txt

      - name: Run PromptShield
        run: |
          python scan_pr.py --base origin/${{ github.base_ref }} --output-format github --github-actions
```

### Reviewer-style bootstrap

If you want PromptShield to behave like a pull request reviewer when developers push new commits, use a workflow like this:

```yaml
name: PromptShield Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - name: Run PromptShield
        uses: Zero-Harm-AI-LLC/promptshield@v1
        with:
          base-ref: origin/${{ github.base_ref }}
          output-format: json
          output-file: ${{ runner.temp }}/promptshield-findings.json
          fail-on: never

      - name: Post or update PR review summary
        uses: actions/github-script@v7
        env:
          PROMPTSHIELD_FINDINGS: ${{ runner.temp }}/promptshield-findings.json
        with:
          script: |
            const fs = require("fs");
            const marker = "<!-- promptshield-review -->";
            const findings = JSON.parse(fs.readFileSync(process.env.PROMPTSHIELD_FINDINGS, "utf8"));

            function summarizeFinding(f) {
              const location = `${f.file || "unknown"}:${f.line || 1}`;
              const detector = f.source_summary ? ` Detector match: ${f.source_summary}.` : "";
              return `- \`${(f.severity || "unknown").toUpperCase()}\` \`${f.type}\` at \`${location}\` - ${f.title}.${detector}`;
            }

            const body = findings.length
              ? [marker, "", "## PromptShield Review", "", findings.map(summarizeFinding).join("\n")].join("\n")
              : [marker, "", "## PromptShield Review", "", "No AI security findings detected in the current pull request diff."].join("\n");

            const comments = await github.paginate(github.rest.issues.listComments, {
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              per_page: 100,
            });

            const existing = comments.find(comment =>
              comment.user?.type === "Bot" && comment.body?.includes(marker)
            );

            if (existing) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: existing.id,
                body,
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body,
              });
            }
```

This keeps a single sticky PR comment updated as the pull request changes.

### Composite action usage

```yaml
name: PromptShield
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: Run PromptShield
        uses: ./
        with:
          base-ref: origin/${{ github.base_ref }}
          output-format: github
          github-actions: true
          max-findings: 10
          output-file: ${{ runner.temp }}/promptshield-findings.json
```

### Action inputs

- `base-ref`: base git ref (default: `origin/${{ github.base_ref }}` or `origin/main`).
- `diff`: optional local diff file path.
- `output-format`: `json`, `github`, `markdown`, or `sarif`.
- `schema`: when true with JSON output, emits a schema-wrapped payload.
- `max-findings`: optional integer cap.
- `github-actions`: emit GitHub Actions annotations.
- `python-version`: runtime Python version (default: `3.11`).
- `output-file`: optional path where structured output is written.
- `fail-on`: minimum severity that causes a non-zero exit code: `high`, `medium`, `low`, `any`, or `never`.

### Minimum GitHub permissions

PromptShield only needs read access to repository contents for checkout and `git diff`:

```yaml
permissions:
  contents: read
```

If your workflow posts PR comments or review summaries, add:

```yaml
permissions:
  pull-requests: write
```

## Exit codes

- `0` = no findings
- `1` = findings detected
- `2` = usage/runtime error

## Future hosted version

A hosted GitHub App version with PR comments, explanations, and multi-repo support is under development.

ScalApps
