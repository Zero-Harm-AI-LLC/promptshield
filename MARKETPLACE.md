# PromptShield Marketplace Copy

## Tagline

AI security review for pull requests

## Short Description

GitHub Action for detecting prompt injection, PII leaks, secrets exposure, and unsafe LLM usage in pull requests

## Long Description

PromptShield is a GitHub Action for reviewing pull request diffs for AI-specific security risks before code is merged.

It scans changed code for issues such as prompt injection risk, prompt logging, secrets in prompts, PII exposure, database or customer data sent to LLMs, unsafe tool usage, unrestricted tool selection, and other risky LLM integration patterns. PromptShield also incorporates `zero-harm-ai-detectors` to identify redacted PII and secret findings in changed code.

PromptShield is distributed as a GitHub Action, not a hosted GitHub App. Teams install it by adding a workflow to their repository and referencing the published action version.

PromptShield supports multiple output modes:

- GitHub Actions annotations for CI feedback
- Reviewer-style pull request comments through GitHub Actions workflows
- JSON output for downstream automation
- Markdown reports for summaries
- SARIF output for GitHub code scanning

Typical use cases:

- Reviewing OpenAI, Anthropic, Gemini, Cohere, and other LLM integrations in pull requests
- Preventing prompt injection and unsafe prompt construction patterns
- Detecting secret, PII, or sensitive data exposure before merge
- Adding AI security review signals to CI and pull request workflows

## Getting Started

Add PromptShield to a workflow in your repository:

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
```

For reviewer-style pull request feedback, use the full workflow example from the repository README.

## Suggested Keywords

- ai-security
- llm-security
- prompt-injection
- pii-detection
- secret-detection
- pull-request
- code-review
- sarif
- github-actions
- security

## Positioning

PromptShield is a GitHub Action for AI security review in pull requests.
