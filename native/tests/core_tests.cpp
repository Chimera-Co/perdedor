// Core tests. The selection cases mirror tests/test_registry.py so the native
// agent and the Python/PowerShell agents select identically.
#include <algorithm>
#include <cstdio>
#include <random>
#include <stdexcept>

#include "../src/core/perdedor.hpp"

using namespace perdedor;

static int failures = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                          \
        }                                                                        \
    } while (0)

static CheckSpec mk(const char* id, const char* tech, const char* cost, bool net = false) {
    CheckSpec c;
    c.ids = {id};
    c.technique = tech;
    c.klass = std::string(tech).substr(0, std::string(tech).find('.'));
    c.category = class_category(c.klass);
    c.cost = cost;
    c.network = net;
    c.fn = [](Context&) { return std::vector<Finding>{}; };
    return c;
}

static std::vector<std::string> ids(const std::vector<const CheckSpec*>& v) {
    std::vector<std::string> out;
    for (auto* c : v) out.push_back(c->ids[0]);
    return out;
}

int main() {
    CHECK(glob_match("linux.timing.*", "linux.timing.uptime"));
    CHECK(!glob_match("linux.timing.*", "linux.env.x"));
    CHECK(glob_match("*.env.dmi_[bs]*", "linux.env.dmi_sys_vendor"));
    CHECK(!glob_match("*.env.dmi_[!bs]*", "linux.env.dmi_sys_vendor"));
    CHECK(glob_match("a?c", "abc"));

    std::vector<CheckSpec> checks = {
        mk("linux.env.a", "cpu.hypervisor_bit", "fast"),
        mk("linux.timing.b", "timing.cpuid_vmexit", "medium"),
        mk("linux.behavioural.c", "human.mouse_activity", "slow"),
        mk("linux.design.d", "network.dns_sinkhole", "fast", true),
    };
    CHECK((ids(select_checks(checks, "quick", {}, {}, true)) == std::vector<std::string>{"linux.env.a", "linux.design.d"}));
    CHECK(ids(select_checks(checks, "standard", {}, {}, true)).size() == 3);
    CHECK(ids(select_checks(checks, "deep", {}, {}, true)).size() == 4);
    CHECK((ids(select_checks(checks, "quick", {"class:human"}, {}, true)) == std::vector<std::string>{"linux.behavioural.c"}));
    CHECK(ids(select_checks(checks, "deep", {"linux.*"}, {"category:timing"}, true)).size() == 3);
    CHECK(ids(select_checks(checks, "deep", {}, {}, false)).size() == 3);
    CHECK(ids(select_checks(checks, "deep", {"technique:cpu.*"}, {}, true)).size() == 1);
    bool threw = false;
    try {
        select_checks(checks, "deep", {"bogus:x"}, {}, true);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);

    CHECK(json_escape(std::string("a\"b\\\n\x01")) == "a\\\"b\\\\\\n\\u0001");
    CHECK(json_escape(std::string("caf\xc3\xa9")) == "caf\xc3\xa9");
    CHECK(json_escape(std::string("bad\xff")) == "bad\\ufffd");

    std::vector<Finding> fs = {clean("env.a", "a", "", Severity::Low), detected("env.b", "b", "", Severity::Critical),
                               skipped("env.c", "c", "", Severity::Low, "n/a")};
    Json s = summary_of(fs);
    CHECK(s["raw_score"].str() == "1/2");
    CHECK(s["weighted_score"].number() == 50.0);
    CHECK(full_id("env.a") == "linux.env.a");

    Json j = Json::object();
    j.set("x", 1);
    j.set("y", Json::array());
    j["y"].push("z");
    CHECK(j.dump() == "{\"x\":1,\"y\":[\"z\"]}");

    // Test platform host_facts
    Json facts = platform::host_facts();
    CHECK(!facts["os_build"].str().empty());
    CHECK(!facts["cpu_model"].str().empty());
    CHECK(facts["core_count"].number() >= 1);

    // Test seeded check order reproducibility and determinism
    std::vector<CheckSpec> order_checks = {
        mk("linux.env.1", "cpu.hypervisor_bit", "fast"),
        mk("linux.env.2", "firmware.smbios_vendor", "fast"),
        mk("linux.env.3", "hardware.pci_devices", "fast"),
        mk("linux.env.4", "guest_tools.drivers", "fast"),
        mk("linux.env.5", "artifacts.registry", "fast"),
        mk("linux.env.6", "container.docker", "fast"),
        mk("linux.env.7", "timing.clock_source", "fast"),
        mk("linux.env.8", "human.mouse_activity", "fast"),
        mk("linux.env.9", "identity.hostname", "fast"),
        mk("linux.env.10", "network.dns_sinkhole", "fast"),
    };
    std::vector<const CheckSpec*> base_ptrs;
    for (const auto& c : order_checks) base_ptrs.push_back(&c);

    std::vector<const CheckSpec*> run1 = base_ptrs;
    std::vector<const CheckSpec*> run2 = base_ptrs;
    std::vector<const CheckSpec*> run3 = base_ptrs;

    uint64_t seed1 = 42ULL;
    uint64_t seed2 = 9999ULL;

    {
        std::mt19937_64 rng(seed1);
        std::shuffle(run1.begin(), run1.end(), rng);
    }
    {
        std::mt19937_64 rng(seed1);
        std::shuffle(run2.begin(), run2.end(), rng);
    }
    {
        std::mt19937_64 rng(seed2);
        std::shuffle(run3.begin(), run3.end(), rng);
    }

    CHECK(ids(run1) == ids(run2));  // Same seed gives identical check order
    CHECK(ids(run1) != ids(run3));  // Different seed gives different check order
    CHECK(run1.size() == order_checks.size());

    // Test v3 report fields serialization
    Json report = Json::object();
    report.set("schema_version", 3);
    report.set("scan_id", "test-scan-id-1234");
    report.set("perdedor_version", kVersion);
    report.set("agent_version", kVersion);
    report.set("catalog_version", kVersion);
    report.set("seed", static_cast<unsigned long long>(seed1));
    report.set("host_facts", facts);

    Json env = Json::object();
    env.set("name", "test-env");
    env.set("os", platform::name());
    env.set("image_id", "img-123");
    env.set("hypervisor", "xen");
    env.set("monitor", "out-of-guest");
    env.set("instrumentation", "drakvuf");
    Json labels = Json::object();
    labels.set("tier", "staging");
    env.set("labels", labels);
    report.set("environment", env);

    CHECK(report["schema_version"].number() == 3.0);
    CHECK(report["scan_id"].str() == "test-scan-id-1234");
    CHECK(report["seed"].number() == 42.0);
    CHECK(report["environment"]["monitor"].str() == "out-of-guest");
    CHECK(report["environment"]["labels"]["tier"].str() == "staging");

    if (failures) {
        std::fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    std::puts("core tests: all passed");
    return 0;
}
