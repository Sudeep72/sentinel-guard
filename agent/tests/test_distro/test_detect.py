import pytest
from sentinelguard_contracts import Distro

from sentinelguard_agent.distro.detect import detect_distro, parse_os_release

UBUNTU_OS_RELEASE = """\
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
"""

DEBIAN_OS_RELEASE = """\
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
"""

FEDORA_OS_RELEASE = """\
NAME="Fedora Linux"
VERSION_ID="40"
ID=fedora
"""

ROCKY_OS_RELEASE = """\
NAME="Rocky Linux"
VERSION_ID="9.4"
ID="rocky"
ID_LIKE="rhel centos fedora"
"""

CENTOS_OS_RELEASE = """\
NAME="CentOS Stream"
VERSION_ID="9"
ID="centos"
"""

# AlmaLinux isn't directly supported but is RHEL-family; should resolve via
# ID_LIKE fallback to one of the supported RHEL-family distros.
ALMALINUX_OS_RELEASE = """\
NAME="AlmaLinux"
VERSION_ID="9.4"
ID="almalinux"
ID_LIKE="rhel centos fedora"
"""

MALFORMED_OS_RELEASE = """\
# just a comment

not a key value line at all
ID
"""


def test_parse_os_release_basic():
    data = parse_os_release(UBUNTU_OS_RELEASE)
    assert data["ID"] == "ubuntu"
    assert data["VERSION_ID"] == "24.04"
    assert data["ID_LIKE"] == "debian"


def test_parse_os_release_ignores_comments_and_blank_lines():
    data = parse_os_release(MALFORMED_OS_RELEASE)
    assert data == {}


def test_parse_os_release_strips_quotes():
    data = parse_os_release('FOO="bar baz"\n')
    assert data["FOO"] == "bar baz"


@pytest.mark.parametrize(
    "content,expected_distro,expected_version",
    [
        (UBUNTU_OS_RELEASE, Distro.UBUNTU, "24.04"),
        (DEBIAN_OS_RELEASE, Distro.DEBIAN, "12"),
        (FEDORA_OS_RELEASE, Distro.FEDORA, "40"),
        (ROCKY_OS_RELEASE, Distro.ROCKY, "9.4"),
        (CENTOS_OS_RELEASE, Distro.CENTOS, "9"),
    ],
)
def test_detect_distro_supported_distros(tmp_path, content, expected_distro, expected_version):
    os_release = tmp_path / "os-release"
    os_release.write_text(content)

    distro, version = detect_distro(os_release)

    assert distro == expected_distro
    assert version == expected_version


def test_detect_distro_falls_back_via_id_like(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text(ALMALINUX_OS_RELEASE)

    distro, version = detect_distro(os_release)

    # almalinux isn't a direct ID match; ID_LIKE contains "rhel centos fedora",
    # and "centos" is the first supported match found.
    assert distro == Distro.CENTOS
    assert version == "9.4"


def test_detect_distro_missing_file_returns_unknown(tmp_path):
    missing_path = tmp_path / "does-not-exist"
    distro, version = detect_distro(missing_path)
    assert distro == Distro.UNKNOWN
    assert version is None


def test_detect_distro_unparseable_content_returns_unknown(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text(MALFORMED_OS_RELEASE)
    distro, version = detect_distro(os_release)
    assert distro == Distro.UNKNOWN
    assert version is None


def test_detect_distro_accepts_path_object_and_string(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text(UBUNTU_OS_RELEASE)

    distro_from_path, _ = detect_distro(os_release)
    distro_from_str, _ = detect_distro(str(os_release))

    assert distro_from_path == distro_from_str == Distro.UBUNTU
