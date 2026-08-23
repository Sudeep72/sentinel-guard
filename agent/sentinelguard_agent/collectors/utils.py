"""Shared utilities for Guardian collectors.

Factored here so each of the nine Guardian implementations stays
focused on *what* it checks, not on filesystem boilerplate.  Every
function handles its own PermissionError / FileNotFoundError so
callers never need to, and returns a clear sentinel value (None, [],
empty dict) that the Guardian can inspect without extra try/except
noise in the check logic itself.
"""

from __future__ import annotations

import json as _json
import logging
import os
import platform as _platform
import re as _re
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# File / path helpers
# ---------------------------------------------------------------------------


def file_stat(path: str | Path) -> os.stat_result | None:
    """Return ``os.stat`` result for *path*, or ``None`` on any error."""
    try:
        return os.stat(path)
    except (PermissionError, FileNotFoundError, OSError) as exc:
        logger.debug("stat(%s) failed: %s", path, exc)
        return None


def file_mode_octal(path: str | Path) -> str | None:
    """Return the permission bits of *path* as a 4-digit octal string.

    Example: ``"0644"`` for a world-readable file.
    Returns ``None`` if the path doesn't exist or is inaccessible.
    """
    st = file_stat(path)
    if st is None:
        return None
    return oct(st.st_mode & 0o7777)


def file_owner_ids(path: str | Path) -> tuple[int, int] | None:
    """Return ``(uid, gid)`` for *path*, or ``None`` on error."""
    st = file_stat(path)
    if st is None:
        return None
    return st.st_uid, st.st_gid


def read_file(path: str | Path) -> str | None:
    """Read a text file, returning ``None`` on any error."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (PermissionError, FileNotFoundError, OSError) as exc:
        logger.debug("read_file(%s) failed: %s", path, exc)
        return None


def path_exists(path: str | Path) -> bool:
    """Return ``True`` if *path* exists (regardless of type).

    Returns ``False`` (not an exception) if the path itself or any
    parent directory in its traversal denies access -- e.g. a
    non-root user checking a root-only path like ``/root/.ssh``.
    """
    try:
        return Path(path).exists()
    except (PermissionError, OSError) as exc:
        logger.debug("path_exists(%s) failed: %s", path, exc)
        return False


def walk_directory(
    root: str | Path,
    max_depth: int = 3,
) -> list[Path]:
    """Yield all regular files under *root* up to *max_depth* levels deep.

    Silently skips sub-paths that raise ``PermissionError``.
    Returns an empty list if *root* does not exist.
    """
    root = Path(root)
    try:
        if not root.exists():
            return []
    except (PermissionError, OSError):
        return []
    results: list[Path] = []

    def _walk(current: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            for entry in current.iterdir():
                try:
                    st = entry.lstat()
                    import stat as _stat

                    if _stat.S_ISREG(st.st_mode):
                        results.append(entry)
                    elif _stat.S_ISDIR(st.st_mode):
                        _walk(entry, depth + 1)
                except OSError:
                    continue
        except PermissionError as exc:
            logger.debug("walk_directory: skipping %s: %s", current, exc)

    _walk(root, 0)
    return results


# ---------------------------------------------------------------------------
# Process / command helpers
# ---------------------------------------------------------------------------


def run_command(
    args: list[str],
    timeout: float = 5.0,
) -> str | None:
    """Run a command and return its stdout as a string.

    Returns ``None`` if the binary is not found, times out, or exits
    non-zero — collectors should treat ``None`` as "feature not
    available on this host" rather than a hard error.
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except FileNotFoundError:
        logger.debug("command not found: %s", args[0])
        return None
    except subprocess.TimeoutExpired:
        logger.debug("command timed out: %s", args)
        return None
    except OSError as exc:
        logger.debug("run_command(%s) failed: %s", args, exc)
        return None


# ---------------------------------------------------------------------------
# Config file helpers
# ---------------------------------------------------------------------------


def parse_key_value_config(content: str, delimiter: str = " ") -> dict[str, str]:
    """Parse a simple ``KEY<delimiter>VALUE`` config file (like sshd_config).

    - Lines starting with ``#`` are comments and are skipped.
    - Only the *first* occurrence of each key is kept (matches how
      sshd reads its config — first match wins).
    - Leading/trailing whitespace is stripped from both key and value.
    """
    result: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(delimiter, 1)
        if len(parts) == 2:
            key, value = parts[0].strip(), parts[1].strip()
            if key and key not in result:
                result[key] = value
    return result


# ---------------------------------------------------------------------------
# Pattern / regex helpers (used by Secret Guardian)
# ---------------------------------------------------------------------------


def scan_content_for_patterns(
    content: str,
    patterns: list[tuple[str, str]],
) -> list[tuple[str, str, str]]:
    """Scan *content* against a list of (name, regex_pattern) tuples.

    Returns a list of ``(name, matched_value, redacted_value)`` triples
    — one per unique match.  The *redacted_value* replaces the middle
    portion of the match with ``***`` so findings can be safely stored
    without persisting a live credential verbatim.

    Args:
        content: Text to scan.
        patterns: List of ``(label, regex)`` pairs.  Each regex should
            have exactly one capture group containing the sensitive value.
    """
    results: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    for label, pattern in patterns:
        try:
            for match in _re.finditer(pattern, content, _re.IGNORECASE | _re.MULTILINE):
                raw = match.group(1) if match.lastindex else match.group(0)
                key = (label, raw[:12])  # dedup on label + prefix
                if key in seen:
                    continue
                seen.add(key)
                redacted = _redact(raw)
                results.append((label, raw, redacted))
        except _re.error:
            logger.debug("Invalid regex pattern for label %r — skipping", label)

    return results


def _redact(value: str) -> str:
    """Redact the middle portion of *value*, keeping a few chars at each end."""
    if len(value) <= 8:
        return "***"
    keep = max(3, len(value) // 6)
    return f"{value[:keep]}***{value[-keep:]}"


# ---------------------------------------------------------------------------
# Sudoers parsing helpers (used by Sudo Guardian)
# ---------------------------------------------------------------------------


def parse_sudoers_lines(content: str) -> list[str]:
    """Return non-empty, non-comment lines from sudoers content.

    Handles line continuations (backslash at end of line).
    """
    lines: list[str] = []
    current = ""
    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
        else:
            current += stripped
            if current and not current.startswith("#"):
                lines.append(current)
            current = ""
    if current and not current.startswith("#"):
        lines.append(current)
    return lines


def is_world_writable(path: str | Path) -> bool:
    """Return True if *path* exists and has the world-write bit set."""
    st = file_stat(path)
    if st is None:
        return False
    return bool(st.st_mode & 0o002)


# ---------------------------------------------------------------------------
# Sysctl helpers (used by Kernel Guardian)
# ---------------------------------------------------------------------------


def read_sysctl(key: str) -> str | None:
    """Read a single sysctl value.

    Returns the trimmed string value, or ``None`` if the key is unknown
    or the sysctl binary is unavailable.
    """
    result = run_command(["sysctl", "-n", key])
    return result.strip() if result else None


def read_sysctl_all() -> dict[str, str]:
    """Read all sysctl values as a dict ``{key: value}``.

    Falls back to an empty dict if ``sysctl -a`` is unavailable.
    """
    output = run_command(["sysctl", "-a"], timeout=10.0)
    if not output:
        return {}

    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


# ---------------------------------------------------------------------------
# JSON command runner (used by Docker Guardian)
# ---------------------------------------------------------------------------


def run_command_json(
    args: list[str], timeout: float = 5.0
) -> list[dict[str, Any]] | dict[str, Any] | None:
    """Run a command and parse its stdout as JSON.

    Returns the parsed object, or ``None`` if the command fails or the
    output is not valid JSON.
    """
    output = run_command(args, timeout=timeout)
    if not output:
        return None
    try:
        result: list[dict[str, Any]] | dict[str, Any] = _json.loads(output)
        return result
    except _json.JSONDecodeError as exc:
        logger.debug("run_command_json: invalid JSON from %s: %s", args[0], exc)
        return None


# ---------------------------------------------------------------------------
# Kernel version helpers
# ---------------------------------------------------------------------------


def get_kernel_version() -> str | None:
    """Return the running kernel version string (from uname -r)."""
    result = run_command(["uname", "-r"])
    if result:
        return result.strip()
    # Fallback to platform module
    ver = _platform.release()
    return ver if ver else None


def parse_kernel_version(version_str: str) -> tuple[int, int, int]:
    r"""Parse ``major.minor.patch`` from a kernel version string.

    Linux kernel version strings always start with the dotted numeric
    version, but what follows it varies by distro convention:

        parse_kernel_version("5.15.0-91-generic")     -> (5, 15, 0)  # Ubuntu
        parse_kernel_version("4.18.0-477.el8.x86_64") -> (4, 18, 0)  # RHEL-family
        parse_kernel_version("6.16.8+kali-amd64")     -> (6, 16, 8)  # Kali (+ suffix)
        parse_kernel_version("6.1.0")                  -> (6, 1, 0)

    Matches the leading ``\d+.\d+.\d+`` regardless of what separator
    (``-``, ``+``, or nothing) follows -- rather than only stripping
    content after the first ``-``, which fails on Kali/Arch-style
    ``+localversion`` suffixes and silently produces a wrong (0, 0, 0)
    that then misreports every kernel as EOL.

    Returns ``(0, 0, 0)`` if the string doesn't start with a
    recognizable dotted version.
    """
    match = _re.match(r"^(\d+)\.(\d+)\.(\d+)", version_str)
    if not match:
        return 0, 0, 0
    return int(match.group(1)), int(match.group(2)), int(match.group(3))
