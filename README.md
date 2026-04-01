# PromptShield — AI Security GitHub Action

PromptShield is a GitHub Action and CLI tool for detecting AI-specific security risks in pull requests.

It scans changed code for issues such as prompt injection risk, secrets exposure, PII leaks, unsafe LLM tool usage, prompt logging, and sensitive data flowing into LLMs. PromptShield also incorporates
[`zero-harm-ai-detectors`](https://pypi.org/project/zero-harm-ai-detectors/).

PromptShield is distributed as a GitHub Action, not a hosted GitHub App. Teams use it by adding a workflow to their repository and referencing the published action version.

## What PromptShield Can Do

- Scan pull request diffs before merge
- Emit GitHub Actions annotations
- Generate JSON, Markdown, and SARIF outputs
- Support reviewer-style PR feedback through GitHub Actions workflows

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

### Marketplace install

PromptShield is consumed directly from GitHub Marketplace or by repository reference. Users do not need to fork or copy the PromptShield repository.

In a consuming repository, use:

```yaml
- uses: Zero-Harm-AI-LLC/promptshield@v1
```

### Reviewer-style bootstrap

If you want PromptShield to behave like a pull request reviewer when developers push new commits, add a workflow like this to the consuming repository. This gives you reviewer-style feedback through GitHub Actions.

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

      - name: Post PR review comments
        uses: actions/github-script@v7
        env:
          PROMPTSHIELD_FINDINGS: ${{ runner.temp }}/promptshield-findings.json
        with:
          script: |
            const fs = require("fs");
            const marker = "<!-- promptshield-inline-review -->";
            const findings = JSON.parse(fs.readFileSync(process.env.PROMPTSHIELD_FINDINGS, "utf8"));
            const pull = context.payload.pull_request;
            const headSha = pull.head.sha;

            function summarizeFinding(f) {
              const location = `${f.file || "unknown"}:${f.line || 1}`;
              const detector = f.source_summary ? ` Detector match: ${f.source_summary}.` : "";
              return `- \`${(f.severity || "unknown").toUpperCase()}\` \`${f.type}\` at \`${location}\` - ${f.title}.${detector}`;
            }

            const reviewBody = findings.length
              ? [marker, "", "## PromptShield Review", "", findings.map(summarizeFinding).join("\n")].join("\n")
              : [marker, "", "## PromptShield Review", "", "No AI security findings detected in the current pull request diff."].join("\n");

            const existingComments = await github.paginate(github.rest.pulls.listReviewComments, {
              owner: context.repo.owner,
              repo: context.repo.repo,
              pull_number: pull.number,
              per_page: 100,
            });

            for (const comment of existingComments) {
              if (comment.user?.type === "Bot" && comment.body?.includes(marker)) {
                await github.rest.pulls.deleteReviewComment({
                  owner: context.repo.owner,
                  repo: context.repo.repo,
                  comment_id: comment.id,
                });
              }
            }

            const inlineComments = findings
              .filter(f => f.file && f.line)
              .slice(0, 10)
              .map(f => ({
                path: f.file,
                line: f.line,
                side: "RIGHT",
                body: [
                  marker,
                  `**${(f.severity || "unknown").toUpperCase()}** \`${f.type}\``,
                  "",
                  f.title,
                  f.source_summary ? `\nDetector match: ${f.source_summary}` : "",
                ].join("\n"),
              }));

            await github.rest.pulls.createReview({
              owner: context.repo.owner,
              repo: context.repo.repo,
              pull_number: pull.number,
              commit_id: headSha,
              event: "COMMENT",
              body: reviewBody,
              comments: inlineComments,
            });
```

This posts a PR review with inline comments on changed lines, plus a short review summary.

### Repository-local sample

This repository also includes a repo-local sample workflow for self-testing and development:

- [`.github/workflows/promptshield-sample.yml`](/Users/dztran/Projects/zero-harm-ai/promptshield/.github/workflows/promptshield-sample.yml)

That sample uses `uses: ./` because it runs the local checked-out action code from this repository. Marketplace consumers should use `uses: Zero-Harm-AI-LLC/promptshield@v1` instead.

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

## Positioning

PromptShield is currently packaged and published as a GitHub Action. It is not yet a hosted GitHub App.

ScalApps
