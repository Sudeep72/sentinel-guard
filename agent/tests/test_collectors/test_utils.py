"""Tests for shared Guardian collector utilities."""

from __future__ import annotations

import os

from sentinelguard_agent.collectors.utils import (
    file_mode_octal,
    file_owner_ids,
    file_stat,
    parse_key_value_config,
    path_exists,
    read_file,
    run_command,
    walk_directory,
)


def test_file_stat_existing_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello")
    result = file_stat(f)
    assert result is not None
    assert isinstance(result, os.stat_result)


def test_file_stat_missing_file():
    assert file_stat("/nonexistent/path/xyz") is None


def test_file_mode_octal_existing_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello")
    os.chmod(f, 0o644)
    result = file_mode_octal(f)
    assert result == "0o644"


def test_file_mode_octal_missing_file():
    assert file_mode_octal("/nonexistent/path") is None


def test_file_owner_ids_existing_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello")
    result = file_owner_ids(f)
    assert result is not None
    uid, gid = result
    assert isinstance(uid, int)
    assert isinstance(gid, int)


def test_file_owner_ids_missing_file():
    assert file_owner_ids("/nonexistent/path") is None


def test_read_file_success(tmp_path):
    f = tmp_path / "config.txt"
    f.write_text("key=value\n")
    assert read_file(f) == "key=value\n"


def test_read_file_missing():
    assert read_file("/nonexistent/path") is None


def test_path_exists_existing(tmp_path):
    assert path_exists(tmp_path) is True


def test_path_exists_missing():
    assert path_exists("/nonexistent/path/xyz") is False


def test_walk_directory_finds_files(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.txt").write_text("b")
    files = walk_directory(tmp_path)
    names = {f.name for f in files}
    assert names == {"a.txt", "b.txt"}


def test_walk_directory_respects_max_depth(tmp_path):
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "deep.txt").write_text("deep")
    (tmp_path / "shallow.txt").write_text("shallow")
    files = walk_directory(tmp_path, max_depth=1)
    names = {f.name for f in files}
    assert "shallow.txt" in names
    assert "deep.txt" not in names


def test_walk_directory_missing_root():
    assert walk_directory("/nonexistent/path") == []


def test_run_command_success():
    result = run_command(["echo", "hello"])
    assert result is not None
    assert "hello" in result


def test_run_command_missing_binary():
    assert run_command(["nonexistent_binary_xyz"]) is None


def test_run_command_timeout():
    result = run_command(["sleep", "10"], timeout=0.1)
    assert result is None


def test_parse_key_value_config_basic():
    content = "PermitRootLogin no\nPasswordAuthentication no\n"
    result = parse_key_value_config(content)
    assert result["PermitRootLogin"] == "no"
    assert result["PasswordAuthentication"] == "no"


def test_parse_key_value_config_ignores_comments():
    content = "# This is a comment\nKey value\n"
    result = parse_key_value_config(content)
    assert "Key" in result
    assert len(result) == 1


def test_parse_key_value_config_ignores_blank_lines():
    content = "\nKey value\n\n"
    result = parse_key_value_config(content)
    assert result == {"Key": "value"}


def test_parse_key_value_config_first_occurrence_wins():
    content = "Key first\nKey second\n"
    result = parse_key_value_config(content)
    assert result["Key"] == "first"


def test_parse_key_value_config_custom_delimiter():
    content = "KEY=value\nOTHER=thing\n"
    result = parse_key_value_config(content, delimiter="=")
    assert result["KEY"] == "value"
