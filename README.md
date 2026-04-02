# uv-lock-supply-chain-claude

A GitHub Action that audits uv.lock dependency changes for supply chain attacks using Claude.

When a PR modifies `uv.lock`, this action:

1. Diffs the lockfile to find every added, upgraded, or downgraded registry dependency
2. Downloads the old and new sdist tarballs from PyPI (URLs are embedded in uv.lock)
3. Extracts and diffs the actual source code between versions
4. Sends each diff to Claude for security analysis
5. Posts a single PR comment with per-dependency risk verdicts

## What it detects

- `setup.py` install hooks that run code at install time (cmdclass overrides, custom build commands)
- `__init__.py` modules that execute code on import (network calls, file writes, process spawning)
- Obfuscated code (base64, XOR, exec/eval of encoded strings, marshal/pickle loads, compile())
- Network calls to suspicious domains in non-networking packages
- File system writes to credential locations (~/.ssh, ~/.aws, browser profiles)
- Unexpected new dependencies injected in pyproject.toml/setup.py
- Binary blobs, .so/.dll/.pyd files, or encoded payloads
- Environment variable harvesting for secrets/tokens
- subprocess/os.system usage for shell execution
- CI-conditional behavior (code that runs differently in CI vs local)
- ctypes/cffi dynamic native code loading
- Monkey-patching of stdlib modules (ssl, socket, http)
- Data exfiltration via DNS, HTTP POST, or temp files

## Usage

Add this workflow to your repository at `.github/workflows/supply-chain-audit.yml`:

```yaml
name: Supply Chain Audit

on:
  pull_request:
    paths:
      - "uv.lock"

permissions:
  contents: read
  pull-requests: write

jobs:
  audit:
    name: Audit dependency changes
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: originsec/uv-lock-supply-chain-claude@main
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `anthropic_api_key` | Yes | - | Anthropic API key for Claude |
| `model` | No | `claude-sonnet-4-20250514` | Claude model to use |
| `base_ref` | No | Auto-detected from PR | Git ref to diff against |

### Secrets

Add `ANTHROPIC_API_KEY` to your repository secrets (Settings > Secrets and variables > Actions).

## How it works

uv.lock embeds direct sdist URLs from PyPI for each dependency. The script uses these URLs
to download the exact source archives, extracts them, and performs a local file-by-file diff
using Python's `difflib`. When no sdist URL is in the lockfile, it falls back to the PyPI
JSON API.

The diff is then sent to Claude with a system prompt tuned for Python-specific supply chain
attack indicators, based on real-world attacks like the
[axios npm supply chain attack](https://unit42.paloaltonetworks.com/axios-supply-chain-attack/).

## Suppression

Add `[supply-chain-audit-ok]` to your PR description to skip the audit for a specific PR.

## Requirements

- Python 3.11+ (available on `ubuntu-latest` runners)
- `fetch-depth: 0` on checkout (needed to diff against the base branch)

## License

Prelude Research License — see [LICENSE](LICENSE) for details.
