"""Tests for 3B shared utilities."""

from __future__ import annotations

import os

from sentinelguard_agent.collectors.utils import (
    is_world_writable,
    parse_sudoers_lines,
    scan_content_for_patterns,
)

# ── scan_content_for_patterns ────────────────────────────────────────────────

_AWS_PATTERN = [("AWS Access Key ID", r"AKIA[0-9A-Z]{16}")]
_PASSWORD_PATTERN = [("Hardcoded Password", r'(?i)password\s*=\s*"([^"]{8,64})"')]


def test_scan_finds_aws_key():
    content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    results = scan_content_for_patterns(content, _AWS_PATTERN)
    assert len(results) == 1
    label, raw, redacted = results[0]
    assert label == "AWS Access Key ID"
    assert "AKIA" in raw
    assert "***" in redacted


def test_scan_finds_password():
    content = 'db_password = "supersecret123"\n'
    results = scan_content_for_patterns(content, _PASSWORD_PATTERN)
    assert len(results) == 1
    assert results[0][0] == "Hardcoded Password"


def test_scan_no_match_returns_empty():
    content = "nothing sensitive here\n"
    results = scan_content_for_patterns(content, _AWS_PATTERN)
    assert results == []


def test_scan_deduplicates_same_prefix():
    content = "AKIAIOSFODNN7EXAMPLE\nAKIAIOSFODNN7EXAMPLE\n"
    results = scan_content_for_patterns(content, _AWS_PATTERN)
    assert len(results) == 1


def test_scan_redacts_long_value():
    content = "AKIAIOSFODNN7EXAMPLE\n"
    results = scan_content_for_patterns(content, _AWS_PATTERN)
    _, raw, redacted = results[0]
    assert len(redacted) < len(raw)
    assert "***" in redacted


def test_scan_handles_empty_content():
    assert scan_content_for_patterns("", _AWS_PATTERN) == []


def test_scan_case_insensitive():
    content = 'PASSWORD = "MySecret123"\n'
    results = scan_content_for_patterns(content, _PASSWORD_PATTERN)
    assert len(results) == 1


# ── parse_sudoers_lines ──────────────────────────────────────────────────────


def test_parse_sudoers_basic_rule():
    content = "admin ALL=(ALL) ALL\n"
    lines = parse_sudoers_lines(content)
    assert "admin ALL=(ALL) ALL" in lines


def test_parse_sudoers_ignores_comments():
    content = "# This is a comment\nadmin ALL=(ALL) ALL\n"
    lines = parse_sudoers_lines(content)
    assert len(lines) == 1
    assert lines[0] == "admin ALL=(ALL) ALL"


def test_parse_sudoers_ignores_blank_lines():
    content = "\nadmin ALL=(ALL) ALL\n\n"
    lines = parse_sudoers_lines(content)
    assert len(lines) == 1


def test_parse_sudoers_joins_continuations():
    content = "admin ALL=(ALL) \\\n    NOPASSWD: /usr/bin/systemctl\n"
    lines = parse_sudoers_lines(content)
    assert len(lines) == 1
    assert "NOPASSWD" in lines[0]
    assert "\\" not in lines[0]


def test_parse_sudoers_multiple_rules():
    content = "alice ALL=(ALL) ALL\nbob ALL=(ALL) NOPASSWD: /usr/bin/apt\n"
    lines = parse_sudoers_lines(content)
    assert len(lines) == 2


def test_parse_sudoers_empty_content():
    assert parse_sudoers_lines("") == []
    assert parse_sudoers_lines("# only comments\n") == []


# ── is_world_writable ────────────────────────────────────────────────────────


def test_is_world_writable_true(tmp_path):
    f = tmp_path / "test.conf"
    f.write_text("content")
    os.chmod(f, 0o777)
    assert is_world_writable(str(f)) is True


def test_is_world_writable_false(tmp_path):
    f = tmp_path / "test.conf"
    f.write_text("content")
    os.chmod(f, 0o640)
    assert is_world_writable(str(f)) is False


def test_is_world_writable_missing_returns_false():
    assert is_world_writable("/nonexistent/path/xyz") is False
