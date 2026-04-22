"""Unit tests for audit-supply-chain.py."""

from __future__ import annotations

import importlib
import json
import re
import sys
import tarfile
import textwrap
import zipfile
from pathlib import Path

import pytest

# Add scripts/ to path so we can import the module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

audit = importlib.import_module("audit-supply-chain")

parse_lockfile = audit.parse_lockfile
parse_version = audit.parse_version
compute_changes = audit.compute_changes
Change = audit.Change
Verdict = audit.Verdict
is_binary = audit.is_binary
collect_files = audit.collect_files
diff_packages = audit.diff_packages
format_comment = audit.format_comment
extract_sdist = audit.extract_sdist
LOCKFILE_RE = audit.LOCKFILE_RE
cache_key = audit.cache_key
load_verdict_cache = audit.load_verdict_cache
save_verdict_cache = audit.save_verdict_cache
CACHE_VERSION = audit.CACHE_VERSION


# ---------------------------------------------------------------------------
# Verdict cache
# ---------------------------------------------------------------------------


class TestCacheKey:
    def test_includes_all_identifiers(self):
        assert cache_key("requests", "http://a", "http://b") == "requests|http://a|http://b"

    def test_none_old_id_encodes_as_empty(self):
        assert cache_key("requests", None, "http://b") == "requests||http://b"


class TestVerdictCache:
    def test_returns_empty_when_path_none(self):
        assert load_verdict_cache(None) == {}

    def test_malformed_json_returns_empty(self, tmp_path):
        p = tmp_path / "cache.json"
        p.write_text("{not json")
        assert load_verdict_cache(str(p)) == {}

    def test_wrong_version_returns_empty(self, tmp_path):
        p = tmp_path / "cache.json"
        p.write_text(json.dumps({"version": 999, "entries": {"k": {"risk": "none"}}}))
        assert load_verdict_cache(str(p)) == {}

    def test_roundtrip(self, tmp_path):
        p = str(tmp_path / "cache.json")
        entries = {"requests|a|b": {"risk": "none", "summary": "OK", "findings": []}}
        save_verdict_cache(p, entries)
        assert load_verdict_cache(p) == entries

    def test_save_no_path_is_noop(self):
        save_verdict_cache(None, {"x": {"risk": "none"}})


# ---------------------------------------------------------------------------
# LOCKFILE_RE (nested uv.lock discovery)
# ---------------------------------------------------------------------------


class TestLockfileRegex:
    def test_matches_root(self):
        assert LOCKFILE_RE.search("uv.lock")

    def test_matches_nested(self):
        assert LOCKFILE_RE.search("backend/uv.lock")

    def test_matches_deeply_nested(self):
        assert LOCKFILE_RE.search("services/api/subdir/uv.lock")

    def test_rejects_pyproject(self):
        assert not LOCKFILE_RE.search("pyproject.toml")
        assert not LOCKFILE_RE.search("backend/pyproject.toml")

    def test_rejects_similar_suffix(self):
        assert not LOCKFILE_RE.search("myuv.lock")
        assert not LOCKFILE_RE.search("uv.lock.bak")


# ---------------------------------------------------------------------------
# Claude response parsing — tolerates trailing commentary after JSON
# ---------------------------------------------------------------------------


class TestClaudeResponseParsing:
    def _parse(self, raw: str) -> dict:
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```\w*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
            text = text.strip()
        parsed, _ = json.JSONDecoder().raw_decode(text)
        return parsed

    def test_plain_json(self):
        raw = '{"risk": "none", "summary": "OK", "findings": []}'
        assert self._parse(raw)["risk"] == "none"

    def test_json_with_trailing_commentary(self):
        raw = (
            '{"risk": "none", "summary": "Routine.", "findings": []}\n\n'
            "The diff shows a standard version increment with no concerns."
        )
        result = self._parse(raw)
        assert result["risk"] == "none"
        assert result["summary"] == "Routine."

    def test_fenced_json_with_trailing_commentary(self):
        raw = (
            '```json\n{"risk": "low", "summary": "Minor.", "findings": []}\n```\n'
            "Additional notes from the model."
        )
        assert self._parse(raw)["risk"] == "low"


# ---------------------------------------------------------------------------
# parse_lockfile
# ---------------------------------------------------------------------------


class TestParseLockfile:
    def test_empty_string(self):
        assert parse_lockfile("") == {}

    def test_whitespace_only(self):
        assert parse_lockfile("   \n\n  ") == {}

    def test_single_registry_package(self):
        text = textwrap.dedent("""\
            version = 1

            [[package]]
            name = "requests"
            version = "2.31.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://files.pythonhosted.org/packages/.../requests-2.31.0.tar.gz", hash = "sha256:abc123", size = 12345 }
        """)
        result = parse_lockfile(text)
        assert "requests" in result
        assert "2.31.0" in result["requests"]
        assert result["requests"]["2.31.0"].startswith("https://")

    def test_package_without_sdist(self):
        text = textwrap.dedent("""\
            version = 1

            [[package]]
            name = "wheel-only"
            version = "1.0.0"
            source = { registry = "https://pypi.org/simple" }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/.../wheel_only-1.0.0-py3-none-any.whl", hash = "sha256:abc", size = 100 },
            ]
        """)
        result = parse_lockfile(text)
        assert result == {"wheel-only": {"1.0.0": None}}

    def test_skips_path_dependencies(self):
        text = textwrap.dedent("""\
            version = 1

            [[package]]
            name = "my-local-pkg"
            version = "0.1.0"
            source = { editable = "." }

            [[package]]
            name = "requests"
            version = "2.31.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://example.com/requests-2.31.0.tar.gz", hash = "sha256:abc", size = 100 }
        """)
        result = parse_lockfile(text)
        assert "my-local-pkg" not in result
        assert "requests" in result

    def test_skips_git_dependencies(self):
        text = textwrap.dedent("""\
            version = 1

            [[package]]
            name = "git-dep"
            version = "0.1.0"
            source = { git = "https://github.com/example/repo.git" }

            [[package]]
            name = "requests"
            version = "2.31.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://example.com/requests-2.31.0.tar.gz", hash = "sha256:abc", size = 100 }
        """)
        result = parse_lockfile(text)
        assert "git-dep" not in result
        assert "requests" in result

    def test_multiple_packages(self):
        text = textwrap.dedent("""\
            version = 1

            [[package]]
            name = "requests"
            version = "2.31.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://example.com/requests-2.31.0.tar.gz", hash = "sha256:aaa", size = 100 }

            [[package]]
            name = "flask"
            version = "3.0.0"
            source = { registry = "https://pypi.org/simple" }
            sdist = { url = "https://example.com/flask-3.0.0.tar.gz", hash = "sha256:bbb", size = 200 }

            [[package]]
            name = "my-app"
            version = "0.1.0"
            source = { editable = "." }
        """)
        result = parse_lockfile(text)
        assert len(result) == 2
        assert "requests" in result
        assert "flask" in result
        assert "my-app" not in result

    def test_package_with_dependencies(self):
        text = textwrap.dedent("""\
            version = 1

            [[package]]
            name = "aiohttp"
            version = "3.9.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "aiosignal" },
                { name = "attrs" },
            ]
            sdist = { url = "https://example.com/aiohttp-3.9.0.tar.gz", hash = "sha256:abc", size = 100 }
        """)
        result = parse_lockfile(text)
        assert result == {"aiohttp": {"3.9.0": "https://example.com/aiohttp-3.9.0.tar.gz"}}

    def test_real_uv_lock_format(self):
        """Test against actual uv.lock structure from the skwach repo."""
        text = textwrap.dedent("""\
            version = 1
            revision = 3
            requires-python = ">=3.14"

            [manifest]
            members = [
                "my-app",
            ]

            [[package]]
            name = "ag-ui-protocol"
            version = "0.1.13"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [
                { name = "pydantic" },
            ]
            sdist = { url = "https://files.pythonhosted.org/packages/04/b5/ag_ui_protocol-0.1.13.tar.gz", hash = "sha256:811d7d7dcce4783dec252918f40b717ebfa559399bf6b071c4ba47c0c1e21bcb", size = 5671, upload-time = "2026-02-19T18:40:38.602Z" }
            wheels = [
                { url = "https://files.pythonhosted.org/packages/cd/9f/ag_ui_protocol-0.1.13-py3-none-any.whl", hash = "sha256:1393fa894c1e8416efe184168a50689e760d05b32f4646eebb8ff423dddf8e8f", size = 8053, upload-time = "2026-02-19T18:40:37.27Z" },
            ]
        """)
        result = parse_lockfile(text)
        assert "ag-ui-protocol" in result
        assert "0.1.13" in result["ag-ui-protocol"]


# ---------------------------------------------------------------------------
# parse_version
# ---------------------------------------------------------------------------


class TestParseVersion:
    def test_normal_version(self):
        assert parse_version("1.2.3") == (1, 2, 3)

    def test_two_part_version(self):
        assert parse_version("1.2") == (1, 2)

    def test_four_part_version(self):
        assert parse_version("1.2.3.4") == (1, 2, 3, 4)

    def test_zero_version(self):
        assert parse_version("0.0.0") == (0, 0, 0)

    def test_prerelease_suffix_ignored(self):
        assert parse_version("1.2.3a1") == (1, 2, 3)

    def test_post_release(self):
        assert parse_version("1.2.3.post1") == (1, 2, 3)

    def test_invalid_version(self):
        assert parse_version("not-a-version") == (0,)

    def test_ordering(self):
        assert parse_version("1.0.0") < parse_version("2.0.0")
        assert parse_version("1.0.0") < parse_version("1.1.0")
        assert parse_version("1.0.0") < parse_version("1.0.1")
        assert parse_version("0.9.9") < parse_version("1.0.0")


# ---------------------------------------------------------------------------
# compute_changes
# ---------------------------------------------------------------------------


class TestComputeChanges:
    def test_no_changes(self):
        pkgs = {"requests": {"2.31.0": "url"}}
        assert compute_changes(pkgs, pkgs) == []

    def test_new_dependency(self):
        base = {}
        head = {"requests": {"2.31.0": "https://example.com/requests-2.31.0.tar.gz"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].name == "requests"
        assert changes[0].old_version is None
        assert changes[0].new_version == "2.31.0"
        assert changes[0].change_type == "added"
        assert changes[0].new_sdist_url == "https://example.com/requests-2.31.0.tar.gz"

    def test_removed_dependency_skipped(self):
        base = {"requests": {"2.31.0": "url"}}
        head = {}
        assert compute_changes(base, head) == []

    def test_upgrade(self):
        base = {"requests": {"2.31.0": "old_url"}}
        head = {"requests": {"2.32.0": "new_url"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].change_type == "upgraded"
        assert changes[0].old_sdist_url == "old_url"
        assert changes[0].new_sdist_url == "new_url"

    def test_downgrade(self):
        base = {"requests": {"2.32.0": "new_url"}}
        head = {"requests": {"2.31.0": "old_url"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].change_type == "downgraded"

    def test_multiple_deps_changed(self):
        base = {"requests": {"2.31.0": "a"}, "flask": {"2.3.0": "b"}}
        head = {"requests": {"2.32.0": "c"}, "flask": {"3.0.0": "d"}}
        changes = compute_changes(base, head)
        assert len(changes) == 2
        names = {c.name for c in changes}
        assert names == {"requests", "flask"}

    def test_unchanged_deps_excluded(self):
        base = {"requests": {"2.31.0": "a"}, "flask": {"3.0.0": "b"}}
        head = {"requests": {"2.32.0": "c"}, "flask": {"3.0.0": "b"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].name == "requests"

    def test_sorted_output(self):
        base = {}
        head = {"zebra": {"1.0.0": "z"}, "alpha": {"1.0.0": "a"}, "mid": {"1.0.0": "m"}}
        changes = compute_changes(base, head)
        names = [c.name for c in changes]
        assert names == ["alpha", "mid", "zebra"]


# ---------------------------------------------------------------------------
# is_binary
# ---------------------------------------------------------------------------


class TestIsBinary:
    def test_text_file(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("print('hello')\n")
        assert is_binary(f) is False

    def test_binary_file(self, tmp_path):
        f = tmp_path / "test.so"
        f.write_bytes(b"\x00\x01\x02\x03")
        assert is_binary(f) is True

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert is_binary(f) is False

    def test_nonexistent_file(self, tmp_path):
        f = tmp_path / "nope"
        assert is_binary(f) is True


# ---------------------------------------------------------------------------
# collect_files
# ---------------------------------------------------------------------------


class TestCollectFiles:
    def test_empty_directory(self, tmp_path):
        assert collect_files(tmp_path) == {}

    def test_flat_files(self, tmp_path):
        (tmp_path / "a.py").write_text("a")
        (tmp_path / "b.py").write_text("b")
        result = collect_files(tmp_path)
        assert set(result.keys()) == {"a.py", "b.py"}

    def test_nested_files(self, tmp_path):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "__init__.py").write_text("")
        result = collect_files(tmp_path)
        assert "pkg/__init__.py" in result

    def test_uses_forward_slashes(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "b").mkdir()
        (tmp_path / "a" / "b" / "c.py").write_text("c")
        result = collect_files(tmp_path)
        assert "a/b/c.py" in result


# ---------------------------------------------------------------------------
# diff_packages
# ---------------------------------------------------------------------------


class TestDiffPackages:
    def test_identical_directories(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "main.py").write_text("print('hello')\n")
        (new / "main.py").write_text("print('hello')\n")
        assert diff_packages(old, new).strip() == ""

    def test_modified_file(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "main.py").write_text("print('hello')\n")
        (new / "main.py").write_text("print('world')\n")
        result = diff_packages(old, new)
        assert "-print('hello')" in result
        assert "+print('world')" in result

    def test_new_file(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (new / "new_file.py").write_text("import os\n")
        result = diff_packages(old, new)
        assert "+import os" in result

    def test_new_dep_none_old_dir(self, tmp_path):
        new = tmp_path / "new"
        new.mkdir()
        (new / "setup.py").write_text("from setuptools import setup\n")
        result = diff_packages(None, new)
        assert "+from setuptools import setup" in result

    def test_binary_file_change(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "lib.so").write_bytes(b"\x00" * 100)
        (new / "lib.so").write_bytes(b"\x00" * 200)
        result = diff_packages(old, new)
        assert "Binary file lib.so changed (100 -> 200 bytes)" in result


# ---------------------------------------------------------------------------
# extract_sdist
# ---------------------------------------------------------------------------


class TestExtractSdist:
    def test_tar_gz(self, tmp_path):
        # Create a fake sdist tarball
        build = tmp_path / "build"
        build.mkdir()
        inner = build / "foo-1.0.0"
        inner.mkdir()
        (inner / "setup.py").write_text("from setuptools import setup; setup()")
        (inner / "foo").mkdir()
        (inner / "foo" / "__init__.py").write_text("__version__ = '1.0.0'\n")

        tarball = tmp_path / "foo-1.0.0.tar.gz"
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(inner, arcname="foo-1.0.0")

        dest = tmp_path / "extract"
        dest.mkdir()
        result = extract_sdist(tarball, dest)
        assert result is not None
        assert (result / "setup.py").exists()
        assert (result / "foo" / "__init__.py").exists()

    def test_zip(self, tmp_path):
        # Create a fake sdist zip
        build = tmp_path / "build"
        build.mkdir()

        archive = tmp_path / "bar-2.0.0.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("bar-2.0.0/setup.py", "from setuptools import setup; setup()")
            zf.writestr("bar-2.0.0/bar/__init__.py", "__version__ = '2.0.0'\n")

        dest = tmp_path / "extract"
        dest.mkdir()
        result = extract_sdist(archive, dest)
        assert result is not None
        assert (result / "setup.py").exists()

    def test_invalid_archive(self, tmp_path):
        bad = tmp_path / "bad.tar.gz"
        bad.write_bytes(b"not a tarball")
        dest = tmp_path / "extract"
        dest.mkdir()
        assert extract_sdist(bad, dest) is None


# ---------------------------------------------------------------------------
# format_comment
# ---------------------------------------------------------------------------


class TestFormatComment:
    def _make_verdict(self, name, old, new, risk, summary="Test.", findings=None):
        change_type = "added" if old is None else "upgraded"
        change = Change(name, old, new, change_type)
        return Verdict(change, risk, summary, findings or [])

    def test_no_high_risk(self):
        verdicts = [self._make_verdict("requests", "2.31.0", "2.32.0", "none")]
        comment = format_comment(verdicts)
        assert "## Supply Chain Audit" in comment
        assert "No high-risk findings" in comment

    def test_high_risk_expanded(self):
        verdicts = [
            self._make_verdict(
                "evil-pkg", "1.0.0", "1.0.1", "critical",
                "Obfuscated code found.",
                [{"severity": "critical", "description": "exec(base64.decode(...))", "evidence": "exec(b64decode(payload))"}],
            )
        ]
        comment = format_comment(verdicts)
        assert "### " in comment
        assert "exec(base64.decode(...))" in comment

    def test_low_risk_collapsed(self):
        verdicts = [self._make_verdict("requests", "2.31.0", "2.32.0", "low")]
        comment = format_comment(verdicts)
        assert "<details>" in comment

    def test_new_dep_formatting(self):
        verdicts = [self._make_verdict("new-pkg", None, "1.0.0", "none")]
        comment = format_comment(verdicts)
        assert "`1.0.0` (new)" in comment

    def test_sorted_by_risk(self):
        verdicts = [
            self._make_verdict("safe", "1.0.0", "1.0.1", "none"),
            self._make_verdict("danger", "1.0.0", "1.0.1", "critical"),
            self._make_verdict("maybe", "1.0.0", "1.0.1", "medium"),
        ]
        comment = format_comment(verdicts)
        crit_pos = comment.index("danger")
        med_pos = comment.index("maybe")
        none_pos = comment.index("safe")
        assert crit_pos < med_pos < none_pos

    def test_truncation(self):
        long_summary = "x" * 70_000
        verdicts = [self._make_verdict("big", "1.0.0", "1.0.1", "low", long_summary)]
        comment = format_comment(verdicts)
        assert len(comment) <= audit.MAX_COMMENT_CHARS
        assert "truncated" in comment

    def test_footer_present(self):
        verdicts = [self._make_verdict("requests", "2.31.0", "2.32.0", "none")]
        comment = format_comment(verdicts)
        assert "uv-lock-supply-chain-claude" in comment


# ---------------------------------------------------------------------------
# Claude response parsing
# ---------------------------------------------------------------------------


class TestClaudeResponseParsing:
    def test_strips_markdown_fences(self):
        raw = '```json\n{"risk": "none", "summary": "OK", "findings": []}\n```'
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```\w*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
            text = text.strip()
        result = json.loads(text)
        assert result["risk"] == "none"

    def test_plain_json(self):
        raw = '{"risk": "low", "summary": "Minor.", "findings": []}'
        result = json.loads(raw.strip())
        assert result["risk"] == "low"
