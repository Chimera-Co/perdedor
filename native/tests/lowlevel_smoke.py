"""Run the native CPU/timing selection and validate observable report contracts."""

import json
import re
import subprocess
import sys
from pathlib import Path


SRC = Path(__file__).resolve().parent.parent / "src"
REGISTER = re.compile(r'PERDEDOR_REGISTER\([^;]*?"[^"]*", "(?:fast|medium|slow)", (?:true|false), ([^;]*)\);', re.S)


def lowlevel_ids():
    """Ids registered by the low-level sources; other jobs' cpu/timing checks have their own contracts."""
    ids = set()
    for src in list((SRC / "common").glob("*.cpp")) + list((SRC / "linux").glob("lowlevel_*.cpp")):
        for args in REGISTER.findall(src.read_text()):
            ids.update("linux." + i for i in re.findall(r'"([^"]+)"', args))
    return ids


def main():
    binary = Path(sys.argv[1]).resolve()
    completed = subprocess.run(
        [str(binary), "--only", "class:cpu,class:timing", "--param", "timing.long_sleep_ms=50"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    report = json.loads(completed.stdout)
    findings = {finding["id"]: finding for finding in report["findings"]}
    assert len(findings) == len(report["findings"]), "duplicate emitted ids"
    assert findings
    owned = lowlevel_ids()
    assert owned, "no low-level ids found in the sources"
    for finding in findings.values():
        assert finding["status"] != "error", finding
        assert finding["class"] in {"cpu", "timing"}, finding
        if finding["id"] not in owned:
            continue
        if finding["status"] == "skipped":
            assert finding["error_detail"], finding
        else:
            assert isinstance(finding["measurement"], dict), finding
            assert 0 <= finding["confidence"] <= 1, finding

    vmexit = findings["linux.timing.rdtsc_cpuid_vmexit"]
    if vmexit["status"] != "skipped":
        measurement = vmexit["measurement"]
        for key in ("rdtsc_rdtsc", "rdtsc_cpuid_rdtsc", "alkhaser_style_avg10"):
            stats = measurement[key]
            assert stats["samples"] > 0
            assert stats["min"] <= stats["p5"] <= stats["p25"] <= stats["median"] <= stats["p75"]
            assert stats["p75"] <= stats["p90"] <= stats["p95"] <= stats["p99"] <= stats["max"]
            assert stats["min"] <= stats["mean"] <= stats["max"]
            assert stats["mad"] >= 0
            assert stats["min"] <= stats["trimmed_mean"] <= stats["max"]
        assert measurement["requested_iterations"] == 100000
        trials = measurement["alkhaser_trial_averages"]
        assert 0 < len(trials) <= 10
        hits = sum(value == 0 or value >= measurement["threshold_cycles"] for value in trials)
        assert measurement["alkhaser_style_detected"] == f"{hits}/{len(trials)}"
        assert isinstance(vmexit["evidence"]["units"], str)
        assert measurement["warmup_rounds"] == 2000
        assert measurement["classification"] in {
            "cpuid_trapped_to_monitor",
            "vm_exit",
            "counter_frozen",
            "native_range",
        }
    for finding in findings.values():
        if finding["id"].endswith("cpu_brand_string") and finding["status"] != "skipped":
            assert isinstance(finding["evidence"]["brand"], str)
        if "sleep_acceleration" in finding["id"] and finding["status"] != "skipped":
            assert len(finding["measurement"]["waits"]) == 2
    print(f"lowlevel: {len(findings)} CPU/timing findings validated")


if __name__ == "__main__":
    main()
