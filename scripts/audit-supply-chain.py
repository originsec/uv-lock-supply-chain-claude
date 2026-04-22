"""Audit changed uv.lock dependencies for supply chain attacks.

Downloads old and new sdist tarballs from PyPI, diffs them locally,
and feeds each diff to Claude for security analysis. Outputs a Markdown
PR comment to stdout.

Usage:
    python3 scripts/audit-supply-chain.py [base-ref]

base-ref defaults to origin/main.
Requires ANTHROPIC_API_KEY in the environment.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
ANTHROPIC_API_VERSION = "2023-06-01"
USER_AGENT = "uv-lock-supply-chain-audit/1.0 (github.com/originsec/uv-lock-supply-chain-claude)"
DOWNLOAD_DELAY = 0.25  # courtesy delay between PyPI downloads (seconds)
MAX_COMMENT_CHARS = 60_000  # GitHub comment limit is 65536; leave headroom
SUPPRESS_MARKER = "[supply-chain-audit-ok]"

SYSTEM_PROMPT = """\
You are a supply chain security auditor for Python packages published on PyPI. \
You analyze diffs between versions of package dependencies to detect signs of supply \
chain attacks, malicious code injection, or suspicious changes.

Evaluate the diff and produce a JSON verdict with these fields:
- "risk": one of "none", "low", "medium", "high", "critical"
- "summary": a 1-2 sentence summary of your findings
- "findings": an array of objects, each with:
    - "severity": "low", "medium", "high", or "critical"
    - "description": what you found and why it is suspicious
    - "evidence": the relevant code snippet, file path, or pattern

Signals to look for (non-exhaustive):
1. setup.py / setup.cfg / pyproject.toml changes that run code at install time \
   (cmdclass overrides, custom build commands, or install hooks)
2. __init__.py or top-level modules that execute code on import with side effects \
   (network calls, file writes, process spawning)
3. Obfuscated code: base64 decoding, XOR operations, hex-encoded strings, string reversal, \
   character-by-character string building, exec/eval of encoded strings, marshal/pickle loads, \
   compile() with encoded bytecode, or intentionally confusing variable names
4. Network calls to unfamiliar or suspicious domains, especially in non-networking packages
5. File system access outside the package's own directory, especially writes to well-known \
   credential locations (~/.ssh, ~/.aws, ~/.gnupg, ~/.config, browser profile directories, \
   keychain/credential stores, .git/config)
6. New unexpected dependencies added in pyproject.toml/setup.py (dependency injection)
7. Binary blobs, .so/.dll/.pyd files, encoded payloads, or large opaque data literals
8. Environment variable reading for sensitive values (API keys, tokens, credentials, SSH keys)
9. Use of subprocess, os.system, os.popen, or similar to execute shell commands, especially \
   with dynamically constructed command strings
10. Changes that look like dependency confusion (name squatting, typosquatting)
11. Conditional logic that behaves differently in CI environments vs local builds \
    (checking CI, GITHUB_ACTIONS, TRAVIS, JENKINS, etc.)
12. Code that collects and exfiltrates system information (hostname, username, IP, \
    installed software, running processes, pip list output)
13. Postinstall hooks or entry_points/console_scripts that execute unexpected code
14. Significant functionality changes that don't match the package's stated purpose \
    (e.g., a JSON parser suddenly including HTTP client code)
15. Removal or weakening of security checks, cryptographic operations, or input validation
16. Use of ctypes/cffi to load or inject native code dynamically
17. Monkey-patching of stdlib or other packages (e.g., overriding ssl, socket, or http modules)
18. Data exfiltration via DNS, HTTP POST to external servers, or writing to /tmp for pickup

For "none" risk: the changes look routine (version bumps, docs, bug fixes, new features \
consistent with the package's purpose).
For "low" risk: minor concerns worth noting but likely benign.
For "medium" risk: unusual patterns that warrant manual review.
For "high" risk: strong indicators of potentially malicious behavior.
For "critical" risk: clear evidence of malicious code or supply chain attack techniques.

Respond ONLY with the JSON object. No markdown fences, no commentary.\
"""

# ---------------------------------------------------------------------------
# uv.lock parsing
# ---------------------------------------------------------------------------


def parse_lockfile(text: str) -> dict[str, dict[str, str | None]]:
    """Parse a uv.lock into {name: {version: sdist_url}} for registry packages.

    Uses tomllib for correct TOML parsing. Only includes packages sourced from
    a registry (path and git dependencies are excluded).
    """
    if not text.strip():
        return {}

    data = tomllib.loads(text)
    packages: dict[str, dict[str, str | None]] = {}

    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source")
        if not name or not version:
            continue
        # Only include registry deps — source is a dict like {registry = "https://pypi.org/simple"}
        if not isinstance(source, dict) or "registry" not in source:
            continue
        # Extract the sdist URL if available (preferred for diffing source code)
        sdist = pkg.get("sdist")
        sdist_url = None
        if isinstance(sdist, dict):
            sdist_url = sdist.get("url")
        packages.setdefault(name, {})[version] = sdist_url

    return packages


def parse_version(v: str) -> tuple[int, ...]:
    """Parse a PEP 440 version string into a comparable tuple.

    Handles versions like 1.2.3, 1.2.3a1, 1.2.3.post1, etc. by extracting
    only the numeric release segments for comparison.
    """
    match = re.match(r"(\d+(?:\.\d+)*)", v)
    if not match:
        return (0,)
    return tuple(int(x) for x in match.group(1).split("."))


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------

LOCKFILE_RE = re.compile(r"(?:^|/)uv\.lock$")


def discover_changed_lockfiles(base_ref: str) -> list[str]:
    """Return every uv.lock path (root or nested) changed since base_ref."""
    try:
        output = subprocess.check_output(
            ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        print(
            f"::warning::git diff against {base_ref} failed: {e.stderr.strip()}",
            file=sys.stderr,
        )
        return []
    return [line for line in output.splitlines() if LOCKFILE_RE.search(line)]


@dataclass
class Change:
    name: str
    old_version: str | None
    new_version: str | None
    change_type: str  # "added", "upgraded", "downgraded"
    old_sdist_url: str | None = None
    new_sdist_url: str | None = None


def compute_changes(
    base_pkgs: dict[str, dict[str, str | None]],
    head_pkgs: dict[str, dict[str, str | None]],
) -> list[Change]:
    """Compute the list of dependency changes between base and head."""
    changes: list[Change] = []
    all_names = set(base_pkgs) | set(head_pkgs)

    for name in sorted(all_names):
        base_versions = set(base_pkgs.get(name, {}).keys())
        head_versions = set(head_pkgs.get(name, {}).keys())

        if base_versions == head_versions:
            continue

        # Skip removed deps entirely — no supply chain risk
        if name not in head_pkgs:
            continue

        removed = base_versions - head_versions
        added = head_versions - base_versions

        if name not in base_pkgs:
            # Entirely new dependency
            for ver in sorted(added, key=parse_version):
                sdist_url = head_pkgs[name].get(ver)
                changes.append(Change(name, None, ver, "added", None, sdist_url))
        else:
            # Version changed — pair up removed/added versions
            removed_sorted = sorted(removed, key=parse_version)
            added_sorted = sorted(added, key=parse_version)

            if len(removed_sorted) == 1 and len(added_sorted) == 1:
                old_v = removed_sorted[0]
                new_v = added_sorted[0]
                change_type = (
                    "downgraded"
                    if parse_version(new_v) < parse_version(old_v)
                    else "upgraded"
                )
                old_url = base_pkgs[name].get(old_v)
                new_url = head_pkgs[name].get(new_v)
                changes.append(Change(name, old_v, new_v, change_type, old_url, new_url))
            else:
                # Multiple version changes — pair by position, extras are adds
                added_sorted_copy = list(added_sorted)
                for old_v in removed_sorted:
                    if added_sorted_copy:
                        new_v = added_sorted_copy.pop(0)
                        change_type = (
                            "downgraded"
                            if parse_version(new_v) < parse_version(old_v)
                            else "upgraded"
                        )
                        old_url = base_pkgs[name].get(old_v)
                        new_url = head_pkgs[name].get(new_v)
                        changes.append(Change(name, old_v, new_v, change_type, old_url, new_url))
                for new_v in added_sorted_copy:
                    new_url = head_pkgs[name].get(new_v)
                    changes.append(Change(name, None, new_v, "added", None, new_url))

    return changes


# ---------------------------------------------------------------------------
# Package downloading and extraction
# ---------------------------------------------------------------------------


def download_sdist(name: str, version: str, sdist_url: str | None, dest_dir: Path) -> Path | None:
    """Download a sdist from PyPI. Returns path or None on failure.

    If sdist_url is provided (from the lockfile), use it directly.
    Otherwise, fall back to the PyPI JSON API to find the sdist URL.
    """
    if not sdist_url:
        # Fall back to PyPI JSON API
        api_url = f"https://pypi.org/pypi/{name}/{version}/json"
        req = urllib.request.Request(api_url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            for entry in data.get("urls", []):
                if entry.get("packagetype") == "sdist":
                    sdist_url = entry["url"]
                    break
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as e:
            print(f"::warning::Failed to query PyPI for {name}-{version}: {e}", file=sys.stderr)
            return None

    if not sdist_url:
        print(f"::warning::No sdist found for {name}-{version}", file=sys.stderr)
        return None

    # Determine filename from URL
    filename = sdist_url.rsplit("/", 1)[-1]
    dest = dest_dir / filename
    req = urllib.request.Request(sdist_url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            dest.write_bytes(resp.read())
        return dest
    except (urllib.error.URLError, OSError) as e:
        print(f"::warning::Failed to download {name}-{version}: {e}", file=sys.stderr)
        return None


def extract_sdist(archive: Path, dest_dir: Path) -> Path | None:
    """Extract a sdist archive (.tar.gz or .zip). Returns the extracted directory path."""
    try:
        if archive.name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(archive, "r:gz") as tf:
                if hasattr(tarfile, "data_filter"):
                    tf.extractall(dest_dir, filter="data")
                else:
                    for member in tf.getmembers():
                        resolved = (dest_dir / member.name).resolve()
                        if not str(resolved).startswith(str(dest_dir.resolve())):
                            print(
                                f"::warning::Path traversal in {archive.name}: {member.name}",
                                file=sys.stderr,
                            )
                            return None
                    tf.extractall(dest_dir)
        elif archive.name.endswith(".zip"):
            with zipfile.ZipFile(archive, "r") as zf:
                for info in zf.infolist():
                    resolved = (dest_dir / info.filename).resolve()
                    if not str(resolved).startswith(str(dest_dir.resolve())):
                        print(
                            f"::warning::Path traversal in {archive.name}: {info.filename}",
                            file=sys.stderr,
                        )
                        return None
                zf.extractall(dest_dir)
        else:
            print(f"::warning::Unknown archive format: {archive.name}", file=sys.stderr)
            return None

        # Find the top-level directory (sdists typically extract to {name}-{version}/)
        dirs = [item for item in dest_dir.iterdir() if item.is_dir()]
        if len(dirs) == 1:
            return dirs[0]
        # If multiple dirs or no dirs, use dest_dir itself
        return dest_dir if any(dest_dir.iterdir()) else None
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as e:
        print(f"::warning::Failed to extract {archive.name}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


def is_binary(path: Path) -> bool:
    """Heuristic: file is binary if first 8KB contains null bytes."""
    try:
        chunk = path.read_bytes()[:8192]
        return b"\x00" in chunk
    except OSError:
        return True


def collect_files(directory: Path) -> dict[str, Path]:
    """Collect all files in a directory as {relative_path: absolute_path}."""
    files = {}
    if directory is None:
        return files
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(directory)).replace("\\", "/")
            files[rel] = path
    return files


def diff_packages(old_dir: Path | None, new_dir: Path) -> str:
    """Produce a unified diff between two extracted package directories."""
    old_files = collect_files(old_dir) if old_dir else {}
    new_files = collect_files(new_dir)

    all_paths = sorted(set(old_files) | set(new_files))
    diff_parts: list[str] = []

    for rel_path in all_paths:
        old_path = old_files.get(rel_path)
        new_path = new_files.get(rel_path)

        if old_path and new_path:
            if is_binary(old_path) or is_binary(new_path):
                old_size = old_path.stat().st_size
                new_size = new_path.stat().st_size
                if old_size != new_size:
                    diff_parts.append(
                        f"Binary file {rel_path} changed ({old_size} -> {new_size} bytes)\n"
                    )
                continue
            try:
                old_lines = old_path.read_text(errors="replace").splitlines(keepends=True)
                new_lines = new_path.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            diff = difflib.unified_diff(
                old_lines, new_lines, fromfile=f"a/{rel_path}", tofile=f"b/{rel_path}"
            )
            diff_text = "".join(diff)
            if diff_text:
                diff_parts.append(diff_text)

        elif new_path:
            if is_binary(new_path):
                size = new_path.stat().st_size
                diff_parts.append(f"Binary file {rel_path} added ({size} bytes)\n")
                continue
            try:
                lines = new_path.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            diff = difflib.unified_diff(
                [], lines, fromfile="/dev/null", tofile=f"b/{rel_path}"
            )
            diff_parts.append("".join(diff))

        elif old_path:
            if is_binary(old_path):
                size = old_path.stat().st_size
                diff_parts.append(f"Binary file {rel_path} removed ({size} bytes)\n")
                continue
            try:
                lines = old_path.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            diff = difflib.unified_diff(
                lines, [], fromfile=f"a/{rel_path}", tofile="/dev/null"
            )
            diff_parts.append("".join(diff))

    return "\n".join(diff_parts)


# ---------------------------------------------------------------------------
# Claude API
# ---------------------------------------------------------------------------


def call_claude(
    name: str,
    old_version: str | None,
    new_version: str,
    change_type: str,
    diff_text: str,
    api_key: str,
    model: str,
) -> dict:
    """Call Claude to audit a package diff. Returns the parsed verdict dict."""
    if change_type == "added":
        user_msg = (
            f'Analyze the following contents for the newly added Python package dependency "{name}" '
            f"version {new_version}.\n\n"
            f"This is a new dependency being added to the project. All file contents are shown "
            f"as additions. Pay special attention to whether this package's purpose matches its "
            f"stated description and whether it contains any suspicious functionality.\n\n"
            f"<diff>\n{diff_text}\n</diff>"
        )
    else:
        user_msg = (
            f'Analyze the following diff for the Python package "{name}" '
            f"({change_type} from {old_version} to {new_version}).\n\n"
            f"The diff shows all file changes between the old and new versions of this package "
            f"as published on PyPI.\n\n"
            f"<diff>\n{diff_text}\n</diff>"
        )

    body = json.dumps(
        {
            "model": model,
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_msg}],
        }
    ).encode()

    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
        "Anthropic-Version": ANTHROPIC_API_VERSION,
        "User-Agent": USER_AGENT,
    }

    req = urllib.request.Request(CLAUDE_API_URL, data=body, headers=headers, method="POST")

    last_err = None
    for attempt in range(2):
        if attempt > 0:
            time.sleep(5)
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                result = json.loads(resp.read())
            text = ""
            for block in result.get("content", []):
                if block.get("type") == "text":
                    text += block["text"]
            # Strip markdown fences if Claude included them despite instructions
            text = text.strip()
            if text.startswith("```"):
                text = re.sub(r"^```\w*\n?", "", text)
                text = re.sub(r"\n?```$", "", text)
                text = text.strip()
            # Use raw_decode so trailing commentary after the JSON object
            # doesn't cause json.loads to raise "Extra data".
            parsed, _ = json.JSONDecoder().raw_decode(text)
            return parsed
        except json.JSONDecodeError as e:
            last_err = f"Invalid JSON from Claude: {e}\nRaw response: {text[:500]}"
        except (urllib.error.URLError, OSError) as e:
            last_err = f"API request failed: {e}"

    # All retries exhausted
    return {
        "risk": "high",
        "summary": f"Audit failed — manual review required. Error: {last_err}",
        "findings": [],
    }


# ---------------------------------------------------------------------------
# Comment formatting
# ---------------------------------------------------------------------------

RISK_EMOJI = {
    "none": "\u2705",
    "low": "\u2705",
    "medium": "\u26a0\ufe0f",
    "high": "\U0001f534",
    "critical": "\U0001f534",
}

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


@dataclass
class Verdict:
    change: Change
    risk: str
    summary: str
    findings: list[dict]
    error: str | None = None


def format_comment(verdicts: list[Verdict]) -> str:
    """Format all verdicts into a single Markdown PR comment."""
    verdicts.sort(key=lambda v: RISK_ORDER.get(v.risk, 5))

    high_risk_count = sum(1 for v in verdicts if v.risk in ("high", "critical"))
    total = len(verdicts)

    lines: list[str] = []
    lines.append("## Supply Chain Audit\n")

    if high_risk_count > 0:
        lines.append(
            f"> **{high_risk_count}** of **{total}** dependency changes flagged "
            f"as high/critical risk.\n"
        )
    else:
        lines.append(
            f"> Analyzed **{total}** dependency changes. No high-risk findings.\n"
        )

    for v in verdicts:
        emoji = RISK_EMOJI.get(v.risk, "\u2753")
        change = v.change
        if change.old_version:
            version_str = f"`{change.old_version}` \u2192 `{change.new_version}`"
        else:
            version_str = f"`{change.new_version}` (new)"

        header = f"{emoji} **`{change.name}`** {version_str} \u2014 **{v.risk}**"

        if v.risk in ("high", "critical"):
            lines.append(f"### {header}\n")
            lines.append(f"{v.summary}\n")
            if v.findings:
                for f in v.findings:
                    sev = f.get("severity", "?")
                    desc = f.get("description", "")
                    evidence = f.get("evidence", "")
                    lines.append(f"- **[{sev}]** {desc}")
                    if evidence:
                        lines.append(f"  ```\n  {evidence}\n  ```")
                lines.append("")
        else:
            lines.append(f"<details>\n<summary>{header}</summary>\n")
            lines.append(f"{v.summary}\n")
            if v.findings:
                for f in v.findings:
                    sev = f.get("severity", "?")
                    desc = f.get("description", "")
                    evidence = f.get("evidence", "")
                    lines.append(f"- **[{sev}]** {desc}")
                    if evidence:
                        lines.append(f"  ```\n  {evidence}\n  ```")
            lines.append("\n</details>\n")

    lines.append("---")
    lines.append(
        f"*Audit performed by Claude (`{os.environ.get('AUDIT_MODEL', DEFAULT_MODEL)}`) "
        f"via [uv-lock-supply-chain-claude]"
        f"(https://github.com/originsec/uv-lock-supply-chain-claude)*"
    )

    comment = "\n".join(lines)

    if len(comment) > MAX_COMMENT_CHARS:
        truncation_note = (
            "\n\n> **Note:** This comment was truncated due to GitHub's size limit. "
            "See CI logs for the full audit output.\n"
        )
        comment = comment[: MAX_COMMENT_CHARS - len(truncation_note)] + truncation_note

    return comment


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    base_ref = sys.argv[1] if len(sys.argv) > 1 else "origin/main"

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("::error::ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 1

    model = os.environ.get("AUDIT_MODEL", DEFAULT_MODEL)

    # Check for suppression marker in PR body
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            with open(event_path) as f:
                event = json.load(f)
            pr_body = event.get("pull_request", {}).get("body") or ""
            if SUPPRESS_MARKER in pr_body:
                print(
                    f"Supply chain audit suppressed via '{SUPPRESS_MARKER}' in PR body.",
                    file=sys.stderr,
                )
                return 0
        except (OSError, json.JSONDecodeError):
            pass

    lockfiles = discover_changed_lockfiles(base_ref)
    if not lockfiles:
        print("No uv.lock changes detected.", file=sys.stderr)
        return 0

    print(
        f"Auditing {len(lockfiles)} changed uv.lock file(s): {', '.join(lockfiles)}",
        file=sys.stderr,
    )

    # Merge changes across all lockfiles, deduping by (name, old_version, new_version).
    # A monorepo may have the same package upgrade in multiple lockfiles — the source
    # diff is identical, so auditing once is sufficient.
    merged: dict[tuple[str, str | None, str | None], Change] = {}
    for lockfile in lockfiles:
        try:
            base_text = subprocess.check_output(
                ["git", "show", f"{base_ref}:{lockfile}"],
                text=True,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError:
            print(
                f"::warning::Could not read {lockfile} from {base_ref}, "
                f"treating all deps as new.",
                file=sys.stderr,
            )
            base_text = ""

        try:
            with open(lockfile) as f:
                head_text = f.read()
        except OSError as e:
            print(f"::warning::Could not read {lockfile}: {e}", file=sys.stderr)
            continue

        base_pkgs = parse_lockfile(base_text)
        head_pkgs = parse_lockfile(head_text)
        for change in compute_changes(base_pkgs, head_pkgs):
            merged.setdefault(
                (change.name, change.old_version, change.new_version), change
            )

    changes = sorted(merged.values(), key=lambda c: c.name)

    if not changes:
        print("No registry dependency changes detected.", file=sys.stderr)
        return 0

    print(
        f"Found {len(changes)} unique dependency change(s) to audit.",
        file=sys.stderr,
    )

    verdicts: list[Verdict] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        for i, change in enumerate(changes):
            print(
                f"[{i+1}/{len(changes)}] Auditing {change.name} "
                f"({change.old_version} -> {change.new_version})...",
                file=sys.stderr,
            )

            # Download and extract new version
            new_archive = download_sdist(change.name, change.new_version, change.new_sdist_url, tmp)
            if not new_archive:
                verdicts.append(
                    Verdict(
                        change=change,
                        risk="high",
                        summary=f"Could not download {change.name}-{change.new_version} sdist "
                        f"from PyPI. Manual review required.",
                        findings=[],
                        error="download_failed",
                    )
                )
                continue

            new_extract_dir = tmp / f"new-{change.name}-{change.new_version}"
            new_extract_dir.mkdir()
            new_dir = extract_sdist(new_archive, new_extract_dir)
            if not new_dir:
                verdicts.append(
                    Verdict(
                        change=change,
                        risk="high",
                        summary=f"Could not extract {change.name}-{change.new_version} sdist. "
                        f"Manual review required.",
                        findings=[],
                        error="extract_failed",
                    )
                )
                continue

            # Download and extract old version (if upgrading/downgrading)
            old_dir = None
            if change.old_version:
                if DOWNLOAD_DELAY > 0:
                    time.sleep(DOWNLOAD_DELAY)
                old_archive = download_sdist(
                    change.name, change.old_version, change.old_sdist_url, tmp
                )
                if old_archive:
                    old_extract_dir = tmp / f"old-{change.name}-{change.old_version}"
                    old_extract_dir.mkdir()
                    old_dir = extract_sdist(old_archive, old_extract_dir)

            if DOWNLOAD_DELAY > 0:
                time.sleep(DOWNLOAD_DELAY)

            # Diff
            diff_text = diff_packages(old_dir, new_dir)
            if not diff_text.strip():
                verdicts.append(
                    Verdict(
                        change=change,
                        risk="none",
                        summary="No source changes detected between versions.",
                        findings=[],
                    )
                )
                continue

            # Call Claude
            verdict_data = call_claude(
                name=change.name,
                old_version=change.old_version,
                new_version=change.new_version,
                change_type=change.change_type,
                diff_text=diff_text,
                api_key=api_key,
                model=model,
            )

            verdicts.append(
                Verdict(
                    change=change,
                    risk=verdict_data.get("risk", "medium"),
                    summary=verdict_data.get("summary", "No summary provided."),
                    findings=verdict_data.get("findings", []),
                )
            )

    # Format and output the comment
    comment = format_comment(verdicts)
    print(comment)

    # Exit with non-zero if any critical findings
    has_critical = any(v.risk == "critical" for v in verdicts)
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
