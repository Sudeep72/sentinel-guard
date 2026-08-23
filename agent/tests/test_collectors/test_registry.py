from sentinelguard_contracts import GuardianCategory


def test_registry_contains_three_phase_3a_guardians():
    """Registry now contains exactly the three Phase 3A Guardians."""
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    categories = {g.category for g in GUARDIAN_REGISTRY}
    assert GuardianCategory.PERMISSION in categories
    assert GuardianCategory.OWNERSHIP in categories
    assert GuardianCategory.SSH in categories


def test_registry_is_a_plain_list():
    from sentinelguard_agent.collectors.registry import GUARDIAN_REGISTRY

    assert isinstance(GUARDIAN_REGISTRY, list)
