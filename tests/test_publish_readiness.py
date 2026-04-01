from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_action_has_marketplace_fields():
    action_yaml = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert 'name: "PromptShield AI Security"' in action_yaml
    assert "actions/setup-python@v5" in action_yaml
    assert "branding:" in action_yaml
    assert "author:" in action_yaml
    assert "findings-path" in action_yaml
    assert "output-file" in action_yaml


def test_requirements_lock_is_pinned():
    lock_lines = [
        line.strip()
        for line in (ROOT / "requirements-lock.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert lock_lines
    requirement_lines = [line for line in lock_lines if not line.startswith("--hash=")]
    assert all("==" in line for line in requirement_lines)
    assert all("--hash=" in line for line in lock_lines if line.startswith("--hash="))


def test_action_requires_hashed_lockfile_installs():
    action_yaml = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "--require-hashes" in action_yaml


def test_sample_workflow_supports_reviewer_bootstrap():
    sample_workflow = (ROOT / ".github" / "workflows" / "promptshield-sample.yml").read_text(encoding="utf-8")
    assert "uses: ./" in sample_workflow
    assert "pull-requests: write" in sample_workflow
    assert "actions/github-script@v7" in sample_workflow
    assert "promptshield-inline-review" in sample_workflow
    assert "github.rest.pulls.createReview" in sample_workflow


def test_readme_and_action_use_github_action_wording():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    action_yaml = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "GitHub Action" in readme
    assert "GitHub App" in readme
    assert "distributed as a GitHub Action" in readme
    assert "not a hosted GitHub App" in readme
    assert 'description: "GitHub Action' in action_yaml
