"""Detect the running Linux distribution from ``/etc/os-release``.

Keeping this parsing isolated (rather than inline in each collector)
means every Guardian gets a consistent, tested view of "what distro am
I on" instead of nine separate ad-hoc parsers.
"""

from __future__ import annotations

from pathlib import Path

from sentinelguard_contracts import Distro

_ID_MAP: dict[str, Distro] = {
    "ubuntu": Distro.UBUNTU,
    "debian": Distro.DEBIAN,
    "fedora": Distro.FEDORA,
    "rocky": Distro.ROCKY,
    "centos": Distro.CENTOS,
}

DEFAULT_OS_RELEASE_PATH = "/etc/os-release"


def parse_os_release(content: str) -> dict[str, str]:
    """Parse the ``KEY=value`` (optionally quoted) format of os-release files.

    Blank lines and ``#``-prefixed comments are ignored, matching the
    os-release spec.
    """
    data: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def detect_distro(
    os_release_path: Path | str = DEFAULT_OS_RELEASE_PATH,
) -> tuple[Distro, str | None]:
    """Detect distro + version from an os-release file.

    Falls back through ``ID_LIKE`` when ``ID`` isn't one of the five
    directly-supported distros (e.g. AlmaLinux reports
    ``ID_LIKE="rhel centos fedora"`` and should resolve toward a
    supported RHEL-family adapter rather than UNKNOWN).

    Returns:
        A ``(Distro, version_string_or_None)`` tuple. ``Distro.UNKNOWN``
        with ``None`` version if the file is missing or unparseable.
    """
    path = Path(os_release_path)
    if not path.exists():
        return Distro.UNKNOWN, None

    data = parse_os_release(path.read_text(encoding="utf-8"))
    version = data.get("VERSION_ID")

    distro_id = data.get("ID", "").lower()
    distro = _ID_MAP.get(distro_id)

    if distro is None:
        id_like = data.get("ID_LIKE", "").lower().split()
        for candidate in id_like:
            if candidate in _ID_MAP:
                distro = _ID_MAP[candidate]
                break

    return distro or Distro.UNKNOWN, version
