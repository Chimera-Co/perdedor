// Core tests. The selection cases mirror tests/test_registry.py so the native
// agent and the Python/PowerShell agents select identically.
#include <cstdio>
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

    if (failures) {
        std::fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    std::puts("core tests: all passed");
    return 0;
}
