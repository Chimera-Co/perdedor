from perdedor_common.catalog import load_catalog
from perdedor_common.equivalents import RULES, ToolMap, as_findings


def test_every_rule_targets_a_catalogued_technique():
    techniques = load_catalog().techniques
    assert [r for r in RULES if r[2] not in techniques] == []


def test_known_upstream_ids_map():
    tm = ToolMap()
    assert tm.technique("alkhaser", "alkhaser.timing.rdtsc_diff_vmexit") == "timing.cpuid_vmexit"
    assert (
        tm.technique(
            "pafish", "pafish.cpu_information_based_detections.checking_hypervisor_bit_in_cpuid_feature_bits"
        )
        == "cpu.hypervisor_bit"
    )
    assert tm.technique("vmaware", "vmaware.technique.HYPERVISOR_STR") == "cpu.hypervisor_vendor_leaf"
    assert tm.technique("alkhaser", "alkhaser.nonexistent") is None


def test_as_findings_keeps_explicit_technique_and_drops_unmapped():
    out = as_findings(
        "alkhaser",
        [
            {"id": "alkhaser.environment_artifact.cpu_fan_wmi", "status": "detected"},
            {"id": "alkhaser.unknown", "status": "clean"},
            {"id": "x", "status": "clean", "technique": "cpu.brand_string"},
        ],
    )
    assert [f["technique"] for f in out] == ["hardware.thermal_sensors", "cpu.brand_string"]
    assert all(f["tool"] == "alkhaser" for f in out)
