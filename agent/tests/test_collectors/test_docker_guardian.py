"""Tests for the Docker Guardian collector."""

from __future__ import annotations

from unittest.mock import patch

from sentinelguard_contracts import GuardianCategory, GuardianRunStatus, Severity

from sentinelguard_agent.collectors.docker_guardian import DockerGuardian


def test_category_is_docker():
    assert DockerGuardian.category == GuardianCategory.DOCKER


def test_returns_empty_when_docker_unavailable():
    guardian = DockerGuardian()
    with patch.object(guardian, "_docker_available", return_value=False):
        findings = guardian._collect()
    assert findings == []


def test_run_returns_guardian_result_no_docker():
    result = DockerGuardian().run()
    assert result.module == GuardianCategory.DOCKER
    assert result.status in (GuardianRunStatus.OK, GuardianRunStatus.ERROR)


# ── DOCKER-001: World-writable socket ────────────────────────────────────────


def test_docker_001_world_writable_socket(tmp_path):
    sock = tmp_path / "docker.sock"
    sock.write_bytes(b"")
    import os

    os.chmod(sock, 0o777)

    guardian = DockerGuardian()
    with (
        patch.object(guardian, "_docker_available", return_value=True),
        patch("sentinelguard_agent.collectors.docker_guardian.DOCKER_SOCKET_PATH", str(sock)),
        patch.object(guardian, "_check_tcp_socket_exposure", return_value=[]),
        patch.object(guardian, "_check_daemon_config", return_value=[]),
        patch.object(guardian, "_check_containers", return_value=[]),
    ):
        findings = guardian._collect()

    d001 = [f for f in findings if f.check_id == "DOCKER-001"]
    assert len(d001) == 1
    assert d001[0].severity == Severity.CRITICAL


def test_docker_001_not_fired_on_safe_socket(tmp_path):
    sock = tmp_path / "docker.sock"
    sock.write_bytes(b"")
    import os

    os.chmod(sock, 0o660)

    guardian = DockerGuardian()
    with (
        patch.object(guardian, "_docker_available", return_value=True),
        patch("sentinelguard_agent.collectors.docker_guardian.DOCKER_SOCKET_PATH", str(sock)),
        patch.object(guardian, "_check_tcp_socket_exposure", return_value=[]),
        patch.object(guardian, "_check_daemon_config", return_value=[]),
        patch.object(guardian, "_check_containers", return_value=[]),
    ):
        findings = guardian._collect()

    d001 = [f for f in findings if f.check_id == "DOCKER-001"]
    assert len(d001) == 0


# ── DOCKER-003: TCP socket exposure ─────────────────────────────────────────


def test_docker_003_tcp_without_tls():
    daemon_cfg = {"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}
    guardian = DockerGuardian()
    with patch.object(guardian, "_load_daemon_json", return_value=daemon_cfg):
        findings = guardian._check_tcp_socket_exposure()

    d003 = [f for f in findings if f.check_id == "DOCKER-003"]
    assert len(d003) == 1
    assert d003[0].severity == Severity.CRITICAL


def test_docker_003_tcp_with_tls_is_medium():
    daemon_cfg = {
        "hosts": ["tcp://0.0.0.0:2376"],
        "tlsverify": True,
    }
    guardian = DockerGuardian()
    with patch.object(guardian, "_load_daemon_json", return_value=daemon_cfg):
        findings = guardian._check_tcp_socket_exposure()

    d003 = [f for f in findings if f.check_id == "DOCKER-003"]
    assert len(d003) == 1
    assert d003[0].severity == Severity.MEDIUM


def test_docker_003_no_tcp_no_finding():
    daemon_cfg = {"hosts": ["unix:///var/run/docker.sock"]}
    guardian = DockerGuardian()
    with patch.object(guardian, "_load_daemon_json", return_value=daemon_cfg):
        findings = guardian._check_tcp_socket_exposure()

    assert all(f.check_id != "DOCKER-003" for f in findings)


# ── DOCKER-004/005: Daemon config ────────────────────────────────────────────


def test_docker_004_no_new_privileges_not_set():
    daemon_cfg = {}
    guardian = DockerGuardian()
    with patch.object(guardian, "_load_daemon_json", return_value=daemon_cfg):
        findings = guardian._check_daemon_config()

    d004 = [f for f in findings if f.check_id == "DOCKER-004"]
    assert len(d004) == 1
    assert d004[0].severity == Severity.MEDIUM


def test_docker_004_no_new_privileges_set():
    daemon_cfg = {"no-new-privileges": True}
    guardian = DockerGuardian()
    with patch.object(guardian, "_load_daemon_json", return_value=daemon_cfg):
        findings = guardian._check_daemon_config()

    d004 = [f for f in findings if f.check_id == "DOCKER-004"]
    assert len(d004) == 0


def test_docker_005_userland_proxy_enabled():
    daemon_cfg = {"userland-proxy": True}
    guardian = DockerGuardian()
    with patch.object(guardian, "_load_daemon_json", return_value=daemon_cfg):
        findings = guardian._check_daemon_config()

    d005 = [f for f in findings if f.check_id == "DOCKER-005"]
    assert len(d005) == 1
    assert d005[0].severity == Severity.LOW


def test_docker_005_userland_proxy_disabled():
    daemon_cfg = {"userland-proxy": False, "no-new-privileges": True}
    guardian = DockerGuardian()
    with patch.object(guardian, "_load_daemon_json", return_value=daemon_cfg):
        findings = guardian._check_daemon_config()

    d005 = [f for f in findings if f.check_id == "DOCKER-005"]
    assert len(d005) == 0


# ── DOCKER-006: Privileged containers ────────────────────────────────────────


def _make_inspect(
    name="web",
    privileged=False,
    user="",
    pid_mode="",
    network_mode="bridge",
    ipc_mode="private",
    cap_add=None,
    mounts=None,
    image="nginx:1.25",
):
    return {
        "Name": f"/{name}",
        "Config": {"User": user, "Image": image},
        "HostConfig": {
            "Privileged": privileged,
            "PidMode": pid_mode,
            "NetworkMode": network_mode,
            "IpcMode": ipc_mode,
            "CapAdd": cap_add or [],
        },
        "Mounts": mounts or [],
    }


def test_docker_006_privileged_container():
    inspect = _make_inspect(privileged=True)
    guardian = DockerGuardian()
    findings = guardian._check_privileged(inspect, "abc123def456")
    assert len(findings) == 1
    assert findings[0].check_id == "DOCKER-006"
    assert findings[0].severity == Severity.CRITICAL


def test_docker_006_non_privileged_no_finding():
    inspect = _make_inspect(privileged=False)
    guardian = DockerGuardian()
    findings = guardian._check_privileged(inspect, "abc123def456")
    assert findings == []


# ── DOCKER-007/008/009: Host namespaces ──────────────────────────────────────


def test_docker_007_host_pid_namespace():
    inspect = _make_inspect(pid_mode="host")
    guardian = DockerGuardian()
    findings = guardian._check_host_namespaces(inspect, "abc123")
    d007 = [f for f in findings if f.check_id == "DOCKER-007"]
    assert len(d007) == 1
    assert d007[0].severity == Severity.HIGH


def test_docker_008_host_network():
    inspect = _make_inspect(network_mode="host")
    guardian = DockerGuardian()
    findings = guardian._check_host_namespaces(inspect, "abc123")
    d008 = [f for f in findings if f.check_id == "DOCKER-008"]
    assert len(d008) == 1


def test_docker_009_host_ipc():
    inspect = _make_inspect(ipc_mode="host")
    guardian = DockerGuardian()
    findings = guardian._check_host_namespaces(inspect, "abc123")
    d009 = [f for f in findings if f.check_id == "DOCKER-009"]
    assert len(d009) == 1


def test_no_host_namespace_findings_for_isolated_container():
    inspect = _make_inspect()
    guardian = DockerGuardian()
    findings = guardian._check_host_namespaces(inspect, "abc123")
    assert findings == []


# ── DOCKER-010: Dangerous capabilities ──────────────────────────────────────


def test_docker_010_sys_admin_capability():
    inspect = _make_inspect(cap_add=["SYS_ADMIN"])
    guardian = DockerGuardian()
    findings = guardian._check_dangerous_capabilities(inspect, "abc123")
    assert len(findings) == 1
    assert findings[0].check_id == "DOCKER-010"
    assert findings[0].severity == Severity.HIGH


def test_docker_010_multiple_dangerous_caps():
    inspect = _make_inspect(cap_add=["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"])
    guardian = DockerGuardian()
    findings = guardian._check_dangerous_capabilities(inspect, "abc123")
    assert len(findings) == 1
    assert "SYS_ADMIN" in findings[0].current_value


def test_docker_010_safe_capability_no_finding():
    inspect = _make_inspect(cap_add=["CHOWN", "DAC_OVERRIDE"])
    guardian = DockerGuardian()
    findings = guardian._check_dangerous_capabilities(inspect, "abc123")
    assert findings == []


# ── DOCKER-011: Root user ────────────────────────────────────────────────────


def test_docker_011_root_user_empty():
    inspect = _make_inspect(user="")
    guardian = DockerGuardian()
    findings = guardian._check_root_user(inspect, "abc123")
    assert len(findings) == 1
    assert findings[0].check_id == "DOCKER-011"
    assert findings[0].severity == Severity.HIGH


def test_docker_011_explicit_root():
    inspect = _make_inspect(user="root")
    guardian = DockerGuardian()
    findings = guardian._check_root_user(inspect, "abc123")
    assert len(findings) == 1


def test_docker_011_uid_zero():
    inspect = _make_inspect(user="0")
    guardian = DockerGuardian()
    findings = guardian._check_root_user(inspect, "abc123")
    assert len(findings) == 1


def test_docker_011_non_root_no_finding():
    inspect = _make_inspect(user="nginx")
    guardian = DockerGuardian()
    findings = guardian._check_root_user(inspect, "abc123")
    assert findings == []


# ── DOCKER-012: Dangerous host mounts ───────────────────────────────────────


def test_docker_012_etc_mount():
    inspect = _make_inspect(mounts=[{"Type": "bind", "Source": "/etc", "Destination": "/host/etc"}])
    guardian = DockerGuardian()
    findings = guardian._check_host_mounts(inspect, "abc123")
    d012 = [f for f in findings if f.check_id == "DOCKER-012"]
    assert len(d012) == 1
    assert d012[0].severity == Severity.CRITICAL


def test_docker_012_root_mount():
    inspect = _make_inspect(mounts=[{"Type": "bind", "Source": "/", "Destination": "/host"}])
    guardian = DockerGuardian()
    findings = guardian._check_host_mounts(inspect, "abc123")
    assert any(f.check_id == "DOCKER-012" for f in findings)


def test_docker_012_safe_data_mount_no_finding():
    inspect = _make_inspect(
        mounts=[{"Type": "bind", "Source": "/opt/data", "Destination": "/data"}]
    )
    guardian = DockerGuardian()
    findings = guardian._check_host_mounts(inspect, "abc123")
    assert all(f.check_id != "DOCKER-012" for f in findings)


def test_docker_012_volume_type_not_flagged():
    inspect = _make_inspect(
        mounts=[{"Type": "volume", "Source": "/var/lib/docker/volumes/...", "Destination": "/data"}]
    )
    guardian = DockerGuardian()
    findings = guardian._check_host_mounts(inspect, "abc123")
    assert all(f.check_id != "DOCKER-012" for f in findings)


# ── DOCKER-013: Latest tag ───────────────────────────────────────────────────


def test_docker_013_latest_tag():
    inspect = _make_inspect(image="nginx:latest")
    guardian = DockerGuardian()
    findings = guardian._check_latest_tag(inspect, "abc123")
    assert len(findings) == 1
    assert findings[0].check_id == "DOCKER-013"
    assert findings[0].severity == Severity.LOW


def test_docker_013_no_tag_at_all():
    inspect = _make_inspect(image="nginx")
    guardian = DockerGuardian()
    findings = guardian._check_latest_tag(inspect, "abc123")
    assert len(findings) == 1


def test_docker_013_pinned_tag_no_finding():
    inspect = _make_inspect(image="nginx:1.25.3")
    guardian = DockerGuardian()
    findings = guardian._check_latest_tag(inspect, "abc123")
    assert findings == []


# ── Full copilot payload ─────────────────────────────────────────────────────


def test_all_findings_have_full_copilot_payload():
    inspect = _make_inspect(
        privileged=True,
        user="",
        pid_mode="host",
        cap_add=["SYS_ADMIN"],
        image="nginx:latest",
        mounts=[{"Type": "bind", "Source": "/etc", "Destination": "/host/etc"}],
    )
    guardian = DockerGuardian()
    findings = (
        guardian._check_privileged(inspect, "abc")
        + guardian._check_host_namespaces(inspect, "abc")
        + guardian._check_dangerous_capabilities(inspect, "abc")
        + guardian._check_root_user(inspect, "abc")
        + guardian._check_host_mounts(inspect, "abc")
        + guardian._check_latest_tag(inspect, "abc")
    )

    for f in findings:
        assert f.check_id
        assert f.title
        assert f.description
        assert f.why_it_matters
        assert f.attack_scenario
        assert f.recommendation
        assert f.current_value is not None
        assert f.expected_value is not None


# ── Registry ─────────────────────────────────────────────────────────────────


def test_registered_in_registry():
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    categories = [g.category for g in GUARDIAN_REGISTRY]
    assert GuardianCategory.DOCKER in categories


# ── Coverage: _docker_available ──────────────────────────────────────────────


def test_docker_available_via_socket(tmp_path):
    sock = tmp_path / "docker.sock"
    sock.write_bytes(b"")
    guardian = DockerGuardian()
    with patch("sentinelguard_agent.collectors.docker_guardian.DOCKER_SOCKET_PATH", str(sock)):
        assert guardian._docker_available() is True


def test_docker_available_via_cli():
    guardian = DockerGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.docker_guardian.DOCKER_SOCKET_PATH",
            "/nonexistent/docker.sock",
        ),
        patch(
            "sentinelguard_agent.collectors.docker_guardian.run_command",
            return_value="Docker version 24.0.0",
        ),
    ):
        assert guardian._docker_available() is True


def test_docker_not_available():
    guardian = DockerGuardian()
    with (
        patch(
            "sentinelguard_agent.collectors.docker_guardian.DOCKER_SOCKET_PATH",
            "/nonexistent/docker.sock",
        ),
        patch(
            "sentinelguard_agent.collectors.docker_guardian.run_command",
            return_value=None,
        ),
    ):
        assert guardian._docker_available() is False


# ── Coverage: _check_socket_permissions with group ownership ────────────────


def test_socket_permissions_missing_socket_returns_empty():
    guardian = DockerGuardian()
    with patch(
        "sentinelguard_agent.collectors.docker_guardian.DOCKER_SOCKET_PATH",
        "/nonexistent/docker.sock",
    ):
        findings = guardian._check_socket_permissions()
    assert findings == []


def test_docker_002_unexpected_group_ownership(tmp_path):
    sock = tmp_path / "docker.sock"
    sock.write_bytes(b"")
    import os

    os.chmod(sock, 0o660)

    guardian = DockerGuardian()

    class _FakeGrEntry:
        gr_name = "wheel"

    with (
        patch("sentinelguard_agent.collectors.docker_guardian.DOCKER_SOCKET_PATH", str(sock)),
        patch("grp.getgrgid", return_value=_FakeGrEntry()),
    ):
        findings = guardian._check_socket_permissions()

    d002 = [f for f in findings if f.check_id == "DOCKER-002"]
    assert len(d002) == 1
    assert d002[0].severity == Severity.HIGH


def test_docker_002_docker_group_ownership_no_finding(tmp_path):
    sock = tmp_path / "docker.sock"
    sock.write_bytes(b"")
    import os

    os.chmod(sock, 0o660)

    guardian = DockerGuardian()

    class _FakeGrEntry:
        gr_name = "docker"

    with (
        patch("sentinelguard_agent.collectors.docker_guardian.DOCKER_SOCKET_PATH", str(sock)),
        patch("grp.getgrgid", return_value=_FakeGrEntry()),
    ):
        findings = guardian._check_socket_permissions()

    d002 = [f for f in findings if f.check_id == "DOCKER-002"]
    assert len(d002) == 0


# ── Coverage: _load_daemon_json ──────────────────────────────────────────────


def test_load_daemon_json_missing_file():
    guardian = DockerGuardian()
    with patch(
        "sentinelguard_agent.collectors.docker_guardian.DOCKER_DAEMON_JSON",
        "/nonexistent/daemon.json",
    ):
        assert guardian._load_daemon_json() is None


def test_load_daemon_json_invalid_json(tmp_path):
    daemon_json = tmp_path / "daemon.json"
    daemon_json.write_text("not valid json {{{")

    guardian = DockerGuardian()
    with patch(
        "sentinelguard_agent.collectors.docker_guardian.DOCKER_DAEMON_JSON",
        str(daemon_json),
    ):
        assert guardian._load_daemon_json() is None


def test_load_daemon_json_valid(tmp_path):
    daemon_json = tmp_path / "daemon.json"
    daemon_json.write_text('{"no-new-privileges": true}')

    guardian = DockerGuardian()
    with patch(
        "sentinelguard_agent.collectors.docker_guardian.DOCKER_DAEMON_JSON",
        str(daemon_json),
    ):
        result = guardian._load_daemon_json()
    assert result == {"no-new-privileges": True}


# ── Coverage: full _check_containers and _collect flow ──────────────────────


def test_check_containers_no_running_containers():
    guardian = DockerGuardian()
    with patch.object(guardian, "_get_running_container_ids", return_value=[]):
        findings = guardian._check_containers()
    assert findings == []


def test_check_containers_inspect_returns_none():
    guardian = DockerGuardian()
    with (
        patch.object(guardian, "_get_running_container_ids", return_value=["abc123"]),
        patch.object(guardian, "_inspect_container", return_value=None),
    ):
        findings = guardian._check_containers()
    assert findings == []


def test_check_containers_full_flow():
    guardian = DockerGuardian()
    inspect_data = _make_inspect(privileged=True, user="root")
    with (
        patch.object(guardian, "_get_running_container_ids", return_value=["abc123"]),
        patch.object(guardian, "_inspect_container", return_value=inspect_data),
    ):
        findings = guardian._check_containers()

    assert any(f.check_id == "DOCKER-006" for f in findings)  # privileged
    assert any(f.check_id == "DOCKER-011" for f in findings)  # root user


def test_get_running_container_ids_parses_output():
    guardian = DockerGuardian()
    with patch(
        "sentinelguard_agent.collectors.docker_guardian.run_command",
        return_value="abc123\ndef456\n",
    ):
        ids = guardian._get_running_container_ids()
    assert ids == ["abc123", "def456"]


def test_get_running_container_ids_empty():
    guardian = DockerGuardian()
    with patch("sentinelguard_agent.collectors.docker_guardian.run_command", return_value=None):
        ids = guardian._get_running_container_ids()
    assert ids == []


def test_inspect_container_returns_first_item():
    guardian = DockerGuardian()
    with patch(
        "sentinelguard_agent.collectors.docker_guardian.run_command_json",
        return_value=[{"Id": "abc123"}],
    ):
        result = guardian._inspect_container("abc123")
    assert result == {"Id": "abc123"}


def test_inspect_container_returns_none_for_empty_list():
    guardian = DockerGuardian()
    with patch("sentinelguard_agent.collectors.docker_guardian.run_command_json", return_value=[]):
        result = guardian._inspect_container("abc123")
    assert result is None


def test_full_collect_flow_with_docker_available(tmp_path):
    """Exercise the full _collect() -> all sub-checks path end-to-end."""
    sock = tmp_path / "docker.sock"
    sock.write_bytes(b"")

    guardian = DockerGuardian()
    with (
        patch("sentinelguard_agent.collectors.docker_guardian.DOCKER_SOCKET_PATH", str(sock)),
        patch("sentinelguard_agent.collectors.docker_guardian.DOCKER_DAEMON_JSON", "/nonexistent"),
        patch.object(guardian, "_get_running_container_ids", return_value=[]),
    ):
        findings = guardian._collect()

    # Should complete without error; findings list is valid (may be empty or not)
    assert isinstance(findings, list)
