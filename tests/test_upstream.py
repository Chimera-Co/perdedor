"""Upstream watcher: parsers on recorded source excerpts, the HTTP layer, the check/pin/refresh flow against a
fake GitHub (no network) and the coverage inventories."""

from __future__ import annotations

import io
import json
import shutil
import urllib.error
from pathlib import Path

import pytest
from perdedor_cli import inventory_parsers as P
from perdedor_cli import upstream as U
from perdedor_cli.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "upstream"
CATALOG = ROOT / "catalog"


def fx(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def names(items):
    return [i["name"] for i in items]


# ------------------------------------------------------------------------------------------ parsers


def test_vmaware_enum_platforms_and_points():
    items = {i["name"]: i for i in P.parse_vmaware_enum({"src/vmaware.hpp": fx("vmaware.hpp")})}
    assert list(items) == [
        "GPU_CAPABILITIES",
        "ACPI_SIGNATURE",
        "SMBIOS_VM_BIT",
        "DMIDECODE",
        "THREAD_COUNT",
        "HYPERVISOR_BIT",
        "TIMER",
    ]
    assert items["GPU_CAPABILITIES"]["platforms"] == ["windows"] and items["GPU_CAPABILITIES"]["score"] == 20
    assert items["THREAD_COUNT"]["platforms"] == ["linux", "macos"]
    assert items["TIMER"]["platforms"] == ["linux", "macos", "windows"] and items["TIMER"]["score"] == 45
    assert items["SMBIOS_VM_BIT"]["score"] is None  # not in the trimmed table


def test_alkhaser_exec_checks_and_grouped_calls():
    got = {i["name"]: i for i in P.parse_alkhaser_checks({"al-khaser/Al-khaser.cpp": fx("Al-khaser.cpp")})}
    assert "NumberOfProcessors" in got and "vbox_dir" in got and "rdtsc_diff_vmexit" in got
    assert "vbox_reg_keys" in got and "known_usernames" in got  # bare grouped calls
    assert "print_os" not in got and "API::Init" not in got
    assert got["vbox_check_mac"]["detail"].startswith("VirtualBox Detection: Checking Mac Address")


def test_pafish_function_names_and_groups():
    got = {i["name"]: i for i in P.parse_pafish_checks({"pafish/main.c": fx("pafish_main.c")})}
    assert {"debug_isdebuggerpresent", "cpu_rdtsc_force_vmexit", "cpu_hv", "cpu_known_vm_vendors"} <= set(got)
    assert got["cpu_hv"]["detail"].startswith("CPU information based detections:")


def test_checkpoint_headings_become_chapter_anchors():
    files = {
        "_src/Evasions/techniques/cpu.md": fx("cp/Evasions_techniques_cpu.md"),
        "_src/Android/techniques/anti-analysis.md": fx("cp/Android_techniques_anti-analysis.md"),
    }
    got = {i["name"]: i for i in P.parse_checkpoint_evasions(files)}
    assert "evasions/cpu/check-vendor-id-via-cpuid" in got
    assert got["evasions/cpu/check-vendor-id-via-cpuid"]["platforms"] == ["windows"]
    assert got["android/anti-analysis/wrong-zip-header-values"]["platforms"] == ["android"]
    assert not any("signature-recommendations" in n for n in got)  # unnumbered heading is not a technique
    assert len(got) == 5


def test_invizzzible_keys_scored():
    got = P.parse_invizzzible({"config/kvm.conf": fx("kvm.conf"), "config/readme.txt": "x"})
    assert names(got) == ["kvm/KVM CPU HypervisorID", "kvm/KVM CPU VendorID"]
    assert got[0]["score"] == 10 and "KVMKVMKVM" in got[0]["detail"]


def test_mbc_behaviour_with_methods():
    got = P.parse_mbc({"anti-behavioral-analysis/emulator-detection.md": fx("emulator-detection.md")})
    assert names(got) == ["B0004"]
    assert got[0]["detail"].startswith("Emulator Detection; 4 methods")


def test_attack_stream_and_parse_skips_revoked_and_counts_examples():
    chunks = io.BytesIO(fx("attack-bundle.json").encode())
    objs = list(P.iter_json_array(chunks, chunk_size=7))  # tiny chunks split objects and the key
    assert len(objs) == 10 and objs[5]["description"].startswith("has }")
    got = {i["name"]: i for i in P.parse_attack_techniques(objs)}
    assert list(got) == ["T1497", "T1497.001", "T1622"]
    assert got["T1497.001"]["procedure_examples"] == ["Agent Tesla", "Group X"]
    assert got["T1497.001"]["platforms"] == ["linux", "windows"]


def test_iter_json_array_without_key_yields_nothing():
    assert list(P.iter_json_array(io.BytesIO(b'{"a": [1]}'))) == []


def test_java_freerasp_ios_systemd_parsers():
    assert "hasQEmuFiles" in names(P.parse_java_detectors({"FindEmulator.java": fx("FindEmulator.java")}))
    fr = names(
        P.parse_freerasp(
            {"a/TalsecApplication.kt": fx("TalsecApplication.kt"), "t/threat.dart": fx("threat.dart")}
        )
    )
    assert fr == ["onPrivilegedAccess", "onDebug", "onSimulator", "hooks", "debug", "simulator", "systemVPN"]
    ios = names(P.parse_ios_security_suite({"IOSSecuritySuite.swift": fx("IOSSecuritySuite.swift")}))
    assert "amIJailbroken" in ios and "amIDebugged" in ios and "denyDebugger" not in ios
    virt = {i["name"]: i for i in P.parse_systemd_virt({"virt.h": fx("virt.h")})}
    assert "VIRTUALIZATION_KVM" in virt and "VIRTUALIZATION_DOCKER" in virt
    assert "VIRTUALIZATION_NONE" not in virt and "VIRTUALIZATION_VM_FIRST" not in virt
    assert virt["VIRTUALIZATION_DOCKER"]["detail"].startswith("container:")


def test_generic_list_filters_directory_listing():
    src = {"paths": ["rules/"], "name_filter": "^anti", "name_prefix": "cape/"}
    files = {"rules/antivm_x.py": "", "rules/other.py": "", "elsewhere/antivm_y.py": ""}
    assert names(P.parse_generic_list(files, src)) == ["cape/rules/antivm_x"]


def test_glob_match_is_case_insensitive():
    assert P.glob_match("*_Reg_Keys", "vbox_reg_keys") and not P.glob_match("cpu_*", "gpu_x")


# ---------------------------------------------------------------------------------------- HTTP layer


class FakeResp(io.BytesIO):
    def __init__(self, body: bytes, headers=None, status=200):
        super().__init__(body)
        self.headers = headers or {}
        self.status = status


class FakeOpener:
    def __init__(self, script):
        self.script = list(script)
        self.requests = []

    def open(self, req, timeout=None):
        self.requests.append(req)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def http_error(code, headers=None):
    return urllib.error.HTTPError("https://api.github.com/x", code, "reason", headers or {}, None)


def test_http_retries_server_errors_with_backoff_then_succeeds():
    sleeps = []
    opener = FakeOpener([http_error(502), urllib.error.URLError("down"), FakeResp(b"ok")])
    http = U.Http(opener=opener, sleep=sleeps.append)
    assert http.get("https://api.github.com/x").text == "ok"
    assert sleeps == [2.0, 4.0]


def test_http_rate_limit_waits_short_retry_after_and_gives_up_on_long_reset():
    sleeps = []
    ok = FakeOpener([http_error(429, {"Retry-After": "3"}), FakeResp(b"fine")])
    assert U.Http(opener=ok, sleep=sleeps.append).get("https://api.github.com/x").text == "fine"
    assert sleeps == [3.0]
    limited = FakeOpener([http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "9999999999"})])
    with pytest.raises(U.RateLimited):
        U.Http(opener=limited, sleep=sleeps.append, now=lambda: 0).get("https://api.github.com/x")
    with pytest.raises(U.HttpError) as exc:  # a plain 403 is not a rate limit
        U.Http(opener=FakeOpener([http_error(403)]), sleep=sleeps.append).get("https://api.github.com/x")
    assert exc.value.status == 403


def test_http_not_modified_and_token_only_to_github_api():
    opener = FakeOpener([http_error(304), FakeResp(b"x"), FakeResp(b"y")])
    http = U.Http(token="secret-token", opener=opener, sleep=lambda s: None)
    assert http.get("https://api.github.com/a", etag='"e1"').status == 304
    http.get("https://api.github.com/b")
    http.get("https://example.org/page")
    api1, api2, other = opener.requests
    assert api1.get_header("If-none-match") == '"e1"'
    assert api2.unredirected_hdrs["Authorization"] == "Bearer secret-token"
    assert "Authorization" not in other.unredirected_hdrs and "Authorization" not in other.headers


def test_http_gives_up_after_retries_with_a_readable_error():
    http = U.Http(opener=FakeOpener([urllib.error.URLError("no route")] * 4), sleep=lambda s: None)
    with pytest.raises(U.HttpError, match="network error"):
        http.get("https://example.org/")


# ------------------------------------------------------------------------------------ fake GitHub


class FakeHttp:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, etag=None, accept=None):
        self.calls.append((url, etag))
        if url not in self.routes:
            raise U.HttpError(404, url)
        value = self.routes[url]
        if isinstance(value, Exception):
            raise value
        body, headers = value if isinstance(value, tuple) else (value, {})
        if etag and headers.get("etag") == etag:
            return U.Response(304, {})
        data = body if isinstance(body, bytes) else (json.dumps(body) if not isinstance(body, str) else body)
        return U.Response(200, headers, data.encode() if isinstance(data, str) else data)

    def stream(self, url):
        return io.BytesIO(self.routes[url])


def api(path):
    return f"{U.API}/{path}"


def raw(repo, ref, path):
    return f"{U.RAW}/{repo}/{ref}/{path}"


def commit_doc(sha, date="2026-11-01T00:00:00Z"):
    return {
        "sha": sha,
        "html_url": f"https://github.com/x/commit/{sha}",
        "commit": {"committer": {"date": date}},
    }


def make_catalog(tmp_path: Path, upstreams: list[dict], inventories: dict[str, list[str]]) -> Path:
    cat = tmp_path / "catalog"
    shutil.copytree(CATALOG, cat, ignore=shutil.ignore_patterns("inventory", "upstreams.json"))
    (cat / "inventory").mkdir()
    (cat / "upstreams.json").write_text(json.dumps({"catalog_format": 2, "upstreams": upstreams}))
    for sid, tech in inventories.items():
        doc = {
            "source_id": sid,
            "revision": "old",
            "fetched": "2026-01-01",
            "techniques": [{"name": n, "detail": "", "platforms": [], "score": None} for n in tech],
        }
        (cat / "inventory" / f"{sid}.json").write_text(json.dumps(doc))
    return cat


def pinned(version, commit=None):
    return {"version": version, "commit": commit, "date": "2026-01-01"}


UPSTREAMS = [
    {
        "id": "vmaware",
        "name": "VMAware",
        "kind": "github-release",
        "repo": "o/vm",
        "url": "u",
        "paths": ["src/v.hpp"],
        "parser": "vmaware_enum",
        "why": "w",
        "pinned": pinned("v1"),
        "equivalents_key": "vmaware",
    },
    {
        "id": "tool",
        "name": "Tool",
        "kind": "github-commits",
        "repo": "o/tool",
        "url": "u",
        "paths": ["a.c"],
        "parser": "none",
        "why": "w",
        "pinned": pinned("aaaaaaaaaaaa", "a" * 40),
    },
    {
        "id": "page",
        "name": "Page",
        "kind": "web-page",
        "url": "https://example.org/p",
        "paths": [],
        "parser": "none",
        "why": "w",
        "pinned": pinned("sha256:0000000000000000"),
    },
    {
        "id": "tags",
        "name": "Tags",
        "kind": "github-tag",
        "repo": "o/tags",
        "url": "u",
        "paths": [],
        "parser": "none",
        "why": "w",
        "pinned": pinned("R-1.2.3"),
        "tag_regex": r"R-\d+\.\d+\.\d+",
    },
]
VM_HPP = "enum enum_flags : u8 {\n /* Windows */\n ZZ_FIXTURE_TRAP,\n ZZ_FIXTURE_MSR,\n /* Cross-platform */\n TIMER,\n DEFAULT\n };\n"
CATALOG_CHECKS_MAP = ("TIMER",)  # catalog already lists vmaware TIMER (windows-core cpuid_qpc_jitter)


def routes(**over):
    r = {
        api("repos/o/vm/releases/latest"): {
            "tag_name": "v2",
            "published_at": "2026-11-02T00:00:00Z",
            "html_url": "rel",
        },
        api("repos/o/vm/commits/v2"): commit_doc("b" * 40),
        raw("o/vm", "v2", "src/v.hpp"): VM_HPP,
        api("repos/o/tool/commits?per_page=1&path=a.c"): [commit_doc("c" * 40)],
        "https://example.org/p": "<html>same</html>",
        api("repos/o/tags/tags?per_page=100"): [
            {"name": "R-1.2.3"},
            {"name": "R-1.10.0"},
            {"name": "R-1.10.0-rc1"},
        ],
        api("repos/o/tags/commits/R-1.10.0"): commit_doc("d" * 40),
    }
    r.update(over)
    return r


def run_check(tmp_path, fake, upstreams=None, inventories=None):
    cat = make_catalog(tmp_path, upstreams or UPSTREAMS, inventories or {"vmaware": ["TIMER", "OLDONE"]})
    state = tmp_path / "state.json"
    code = U.cmd_check(
        _args(catalog=str(cat), state=str(state), json=True, offline=False, token_env=None), http=fake
    )
    return code, json.loads(state.read_text())["last_result"], cat, state


def _args(**kw):
    import argparse

    return argparse.Namespace(**kw)


def test_check_reports_updates_new_unmapped_techniques_and_exit_10(tmp_path, capsys):
    fake = FakeHttp(routes())
    code, res, _cat, state = run_check(tmp_path, fake)
    assert code == U.EXIT_UPDATES
    by = {s["id"]: s for s in res["sources"]}
    assert by["vmaware"]["status"] == "update" and by["vmaware"]["change"] == {"from": "v1", "to": "v2"}
    new = {t["name"]: t for t in by["vmaware"]["new_techniques"]}
    assert set(new) == {"ZZ_FIXTURE_TRAP", "ZZ_FIXTURE_MSR"}
    assert by["vmaware"]["removed_techniques"] == ["OLDONE"]
    assert all(t["unmapped"] for t in new.values())
    assert by["tool"]["status"] == "update" and by["tool"]["latest"]["commit"] == "c" * 40
    assert by["page"]["status"] == "update" and by["page"]["latest"]["version"].startswith("sha256:")
    assert by["tags"]["latest"]["version"] == "R-1.10.0"  # numeric order, release candidates filtered out
    assert res["summary"]["unmapped_new_techniques"] == len(res["unmapped_upstream_techniques"]) >= 2
    assert json.loads(capsys.readouterr().out)["summary"]["update"] == 4
    assert json.loads(state.read_text())["seen"]["vmaware"]["version"] == "v2"


def test_check_current_when_pins_match_and_exit_0(tmp_path):
    ups = json.loads(json.dumps(UPSTREAMS))
    ups[0]["pinned"] = pinned("v2")
    ups[1]["pinned"] = pinned("cccccccccccc", "c" * 40)
    ups[2]["pinned"] = pinned("sha256:" + __import__("hashlib").sha256(b"<html>same</html>").hexdigest()[:16])
    ups[3]["pinned"] = pinned("R-1.10.0")
    code, res, *_ = run_check(tmp_path, FakeHttp(routes()), ups)
    assert code == U.EXIT_OK and res["summary"]["update"] == 0 and res["summary"]["current"] == 4


def test_check_error_exit_1_and_rate_limit_skips_rest(tmp_path):
    r = routes()
    del r[api("repos/o/vm/releases/latest")]
    r[api("repos/o/vm/git/matching-refs/tags/")] = []
    r[api("repos/o/vm/tags?per_page=100")] = []
    ups = json.loads(json.dumps(UPSTREAMS))
    ups[0]["pinned"] = pinned("v2")
    code, res, *_ = run_check(tmp_path, FakeHttp(r), ups[:1])
    assert code == U.EXIT_ERROR and res["sources"][0]["status"] == "error"

    limited = routes(**{api("repos/o/vm/releases/latest"): U.RateLimited(api("x"), None)})
    code, res, *_ = run_check(tmp_path / "again", FakeHttp(limited))
    assert res["sources"][0]["status"] == "error" and "not checked" in res["sources"][0]["error"]
    assert [s["status"] for s in res["sources"][1:]] == ["skipped"] * 3


def test_check_uses_etag_cache_for_api_responses(tmp_path):
    r = routes(
        **{
            api("repos/o/vm/releases/latest"): (
                {"tag_name": "v2", "published_at": "2026-11-02T00:00:00Z"},
                {"etag": '"abc"'},
            )
        }
    )
    ups = UPSTREAMS[:1]
    fake = FakeHttp(r)
    _code, _res, cat, state = run_check(tmp_path, fake, ups)
    fake2 = FakeHttp(r)
    U.cmd_check(
        _args(catalog=str(cat), state=str(state), json=True, offline=False, token_env=None), http=fake2
    )
    assert (api("repos/o/vm/releases/latest"), '"abc"') in fake2.calls


def test_pin_updates_catalog_and_refreshes_inventory(tmp_path):
    fake = FakeHttp(routes())
    _code, _res, cat, state = run_check(tmp_path, fake)
    rc = U.cmd_pin(
        _args(catalog=str(cat), state=str(state), ids=["vmaware"], all=False, inventory=True, token_env=None),
        http=fake,
    )
    assert rc == 0
    doc = json.loads((cat / "upstreams.json").read_text())
    vm = doc["upstreams"][0]["pinned"]
    assert vm["version"] == "v2" and vm["commit"] == "b" * 40 and vm["released"] == "2026-11-02"
    assert doc["upstreams"][1]["pinned"]["version"] == "aaaaaaaaaaaa"  # untouched
    inv = json.loads((cat / "inventory" / "vmaware.json").read_text())
    assert [t["name"] for t in inv["techniques"]] == ["TIMER", "ZZ_FIXTURE_MSR", "ZZ_FIXTURE_TRAP"] and inv[
        "revision"
    ] == "v2"
    bad = U.cmd_pin(
        _args(catalog=str(cat), state=str(state), ids=["nope"], all=False, inventory=False, token_env=None)
    )
    assert bad == U.EXIT_ERROR


def test_refresh_builds_inventory_at_pinned_revision(tmp_path):
    ups = json.loads(json.dumps(UPSTREAMS[:1]))
    cat = make_catalog(tmp_path, ups, {})
    fake = FakeHttp({raw("o/vm", "v1", "src/v.hpp"): VM_HPP})
    rc = U.cmd_refresh(_args(catalog=str(cat), ids=[], at="pinned", token_env=None), http=fake)
    assert rc == 0
    assert json.loads((cat / "inventory" / "vmaware.json").read_text())["revision"] == "v1"


def test_directory_paths_use_the_tree_listing(tmp_path):
    src = {
        "id": "caps",
        "name": "C",
        "kind": "github-release",
        "repo": "o/c",
        "url": "u",
        "paths": ["rules/"],
        "parser": "generic_list",
        "why": "w",
        "pinned": pinned("v1"),
        "suffixes": [".yml"],
        "name_prefix": "capa/",
    }
    tree = {
        "truncated": False,
        "tree": [
            {"path": "rules/a.yml", "type": "blob"},
            {"path": "rules/b.txt", "type": "blob"},
            {"path": "rules", "type": "tree"},
        ],
    }
    gh = U.GitHub(FakeHttp({api("repos/o/c/git/trees/v1?recursive=1"): tree}))
    inv = U.build_inventory(src, {"version": "v1", "commit": None}, gh, "2026-11-08")
    assert names(inv["techniques"]) == ["capa/rules/a"]


def test_attack_inventory_streams_from_raw(tmp_path):
    src = {
        "id": "attack",
        "name": "A",
        "kind": "attack-stix",
        "repo": "o/a",
        "url": "u",
        "paths": ["e.json", "m.json"],
        "parser": "attack_techniques",
        "why": "w",
        "pinned": pinned("v1"),
    }
    bundle = fx("attack-bundle.json").encode()
    http = FakeHttp({raw("o/a", "v1", "e.json"): bundle, raw("o/a", "v1", "m.json"): b'{"objects": []}'})
    inv = U.build_inventory(src, {"version": "v1", "commit": None}, U.GitHub(http), "2026-11-08")
    assert names(inv["techniques"]) == ["T1497", "T1497.001", "T1622"]


def test_status_prints_last_result(tmp_path, capsys):
    _code, _res, _cat, state = run_check(tmp_path, FakeHttp(routes()))
    capsys.readouterr()
    assert main(["upstream", "status", "--state", str(state)]) == U.EXIT_UPDATES
    assert "UPDATE  vmaware" in capsys.readouterr().out
    assert main(["upstream", "status", "--state", str(tmp_path / "missing.json")]) == U.EXIT_ERROR


# ---------------------------------------------------------------------------------------- coverage


def test_coverage_classifies_with_globs_status_priority_and_rollup(tmp_path):
    mapper = U.Mapper(
        checks=[
            {
                "id": "a",
                "status": "implemented",
                "technique": "t1",
                "equivalents": {"tool": ["foo_*", "exact"]},
            },
            {"id": "b", "status": "not_feasible", "technique": "t2", "equivalents": {"tool": ["foo_kernel"]}},
            {"id": "c", "status": "planned", "technique": "t2", "equivalents": {"tool": ["later"]}},
            {"id": "d", "status": "implemented", "technique": "t1", "equivalents": {}},
        ],
        techniques={"t1": {"attack": ["T1497.001"], "mbc": ["B0009"]}, "t2": {}},
    )
    items = [{"name": n} for n in ("foo_x", "foo_kernel", "later", "other", "exact")]
    rows = {r["name"]: r for r in U.classify({"id": "tool"}, items, mapper)}
    assert rows["foo_x"]["status"] == "covered" and rows["foo_x"]["checks"] == ["a"]
    assert rows["foo_kernel"]["status"] == "covered"  # implemented glob beats not_feasible
    assert rows["later"]["status"] == "planned" and rows["other"]["status"] == "missing"
    att = U.classify(
        {"id": "attack", "parser": "attack_techniques"},
        [{"name": "T1497"}, {"name": "T1497.001"}, {"name": "T1622"}],
        mapper,
    )
    assert [r["status"] for r in att] == ["covered", "covered", "missing"]  # parent rolls up from child
    s = U.summarize(U.classify({"id": "tool"}, items, mapper))
    assert s["total"] == 5 and s["covered"] == 3 and s["planned"] == 1 and s["covered_percent"] == 60.0


def test_not_feasible_is_excluded_from_feasible_percentage():
    rows = [{"status": "covered"}, {"status": "not_feasible"}, {"status": "missing"}, {"status": "missing"}]
    s = U.summarize(rows)
    assert s["covered_percent"] == 25.0 and s["feasible_covered_percent"] == round(100 / 3, 1)


def test_out_of_scope_items_are_not_feasible_with_reason_but_never_override_a_check():
    mapper = U.Mapper(
        checks=[{"id": "a", "status": "implemented", "technique": "t1", "equivalents": {"tool": ["packer/upx"]}}],
        techniques={"t1": {}},
    )
    source = {"id": "tool", "out_of_scope": [{"pattern": "packer/*", "reason": "property of the sample"}]}
    items = [{"name": n} for n in ("packer/upx", "packer/themida", "anti-vm/cpuid")]
    rows = {r["name"]: r for r in U.classify(source, items, mapper)}
    assert rows["packer/upx"]["status"] == "covered" and "reason" not in rows["packer/upx"]
    assert rows["packer/themida"]["status"] == "not_feasible"
    assert rows["packer/themida"]["reason"] == "property of the sample"
    assert rows["anti-vm/cpuid"]["status"] == "missing"


def test_shipped_out_of_scope_patterns_each_match_an_inventory_item():
    cat = Path(__file__).resolve().parents[1] / "catalog"
    for src in U.load_upstreams(cat):
        inv = U.load_inventory(cat, src["id"])
        for entry in src.get("out_of_scope", []):
            assert entry["reason"].strip(), (src["id"], entry)
            assert inv and any(
                P.glob_match(entry["pattern"], t["name"]) for t in inv["techniques"]
            ), f"{src['id']}: out_of_scope pattern {entry['pattern']!r} matches nothing"


# ------------------------------------------------------------------------- the shipped catalog data


def test_shipped_upstreams_are_valid_and_pinned():
    ups = U.load_upstreams(CATALOG)
    assert len(ups) >= 25
    assert U.validate_upstreams(ups, CATALOG) == []
    assert all(u["pinned"]["date"] and u["pinned"]["version"] for u in ups)
    kinds = {u["kind"] for u in ups}
    assert {"github-release", "github-commits", "github-tag", "web-page", "attack-stix"} <= kinds


def test_shipped_inventories_are_substantial():
    floor = {"vmaware": 60, "al-khaser": 100, "pafish": 40, "checkpoint-evasions": 80, "attack": 5, "mbc": 5}
    for sid, n in floor.items():
        inv = U.load_inventory(CATALOG, sid)
        assert inv and inv["source_id"] == sid and len(inv["techniques"]) >= n, sid
        assert {"name", "detail", "platforms", "score"} <= set(inv["techniques"][0])


def test_cli_offline_check_and_coverage(capsys):
    assert main(["upstream", "check", "--offline", "--json"]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["offline"] and res["summary"]["problems"] == 0
    assert main(["coverage", "--tool", "vmaware", "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    inv = rep["inventories"][0]
    assert inv["source_id"] == "vmaware" and inv["covered"] > 0 and inv["total"] == len(inv["techniques"])
    assert main(["coverage", "--markdown"]) == 0
    assert "| VMAware" in capsys.readouterr().out
    assert main(["coverage", "--tool", "nonexistent"]) == U.EXIT_ERROR
