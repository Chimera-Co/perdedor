// Perdedor native agent: findings, check registry, operator selection.
//
// A check is a function `std::vector<Finding> fn(Context&)` registered with
//
//   PERDEDOR_REGISTER(fn, "cpu.hypervisor_bit", "fast", false, "env.cpuid_hypervisor_bit");
//
// arguments: function, technique key (catalog/techniques.json), cost
// (fast|medium|slow), sends-network-traffic, then one or more ids *without*
// the platform prefix. The prefix (win./linux.) is added for the platform
// the binary is built for, so code under src/common/ registers once and runs
// on both. Selection semantics are identical to
// common/python/perdedor_common/registry.py (tests pin both).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "json.hpp"

namespace perdedor {

enum class Status { Clean, Detected, Error, Skipped };
enum class Severity { Info, Low, Medium, High, Critical };

const char* to_string(Status s);
const char* to_string(Severity s);

struct Finding {
    std::string id;           // full id, e.g. win.env.cpuid_hypervisor_bit
    std::string name;
    std::string description;
    Status status = Status::Skipped;
    Severity severity = Severity::Info;
    Json evidence;            // null when absent
    std::string remediation;  // empty -> null
    std::string error_detail; // empty -> null
    double confidence = -1;   // <0 -> omitted
    Json measurement;         // null -> omitted
    // Filled in by the runner from the registration:
    std::string technique, klass, category;
    double duration_ms = -1;
};

// Builders. `id` is relative ("env.foo"); the platform prefix is added.
std::string full_id(const std::string& relative_id);
Finding clean(const std::string& id, const std::string& name, const std::string& description, Severity sev,
              Json evidence = Json());
Finding detected(const std::string& id, const std::string& name, const std::string& description, Severity sev,
                 Json evidence = Json(), const std::string& remediation = "");
Finding bool_check(const std::string& id, const std::string& name, const std::string& description, Severity sev,
                   bool is_detected, Json evidence = Json(), const std::string& remediation = "");
Finding skipped(const std::string& id, const std::string& name, const std::string& description, Severity sev,
                const std::string& detail);
Finding error(const std::string& id, const std::string& name, const std::string& description, Severity sev,
              const std::string& detail);

struct Context {
    std::string profile = "standard";
    std::map<std::string, std::string> params;
    bool network = true;

    bool deep() const { return profile == "deep"; }
    std::string param(const std::string& key, const std::string& def) const;
    long long param_int(const std::string& key, long long def) const;
    double param_double(const std::string& key, double def) const;
    bool param_bool(const std::string& key, bool def) const;
};

using CheckFn = std::function<std::vector<Finding>(Context&)>;

struct CheckSpec {
    std::vector<std::string> ids;  // full ids
    std::string technique;
    std::string klass;
    std::string category;
    std::string cost;  // fast|medium|slow
    bool network = false;
    std::vector<std::string> tags;
    CheckFn fn;
    std::string source;  // file:function, for diagnostics
};

class Registry {
  public:
    static Registry& instance();
    void add(CheckSpec spec);
    const std::vector<CheckSpec>& all() const { return checks_; }

  private:
    std::vector<CheckSpec> checks_;
};

struct Registrar {
    Registrar(CheckFn fn, const char* technique, const char* cost, bool network, std::vector<std::string> ids,
              const char* source);
};

#define PERDEDOR_CAT2(a, b) a##b
#define PERDEDOR_CAT(a, b) PERDEDOR_CAT2(a, b)
#define PERDEDOR_REGISTER(fn, technique, cost, network, ...)                                              \
    static ::perdedor::Registrar PERDEDOR_CAT(perdedor_reg_, __LINE__)(fn, technique, cost, network, \
                                                                       {__VA_ARGS__}, __FILE__ ":" #fn)

// Selection (mirrors perdedor_common.registry.select).
bool glob_match(const std::string& pattern, const std::string& text);
bool pattern_matches(const std::string& pattern, const CheckSpec& check);  // throws std::invalid_argument
std::vector<const CheckSpec*> select_checks(const std::vector<CheckSpec>& checks, const std::string& profile,
                                            const std::vector<std::string>& only,
                                            const std::vector<std::string>& skip, bool network);
std::string class_category(const std::string& klass);  // "" if unknown

// Running with a watchdog: a probe that hangs is reported as an error and
// abandoned (the process exits without joining it).
std::vector<Finding> run_checks(const std::vector<const CheckSpec*>& checks, Context& ctx);
double timeout_seconds_for(const std::string& cost, const Context& ctx);

// Legacy v1 summary (perdedor_common.scoring.score_report).
Json summary_of(const std::vector<Finding>& findings);
Json finding_json(const Finding& f);

// Platform hooks (src/windows/platform_win.cpp, src/linux/platform_linux.cpp).
namespace platform {
const char* name();       // "windows" | "linux"
const char* id_prefix();  // "win" | "linux"
std::string hostname();
Json metadata();          // os, os_release, machine, ...
// Run fn on a separate thread; false if it did not finish within seconds.
bool run_with_timeout(const std::function<void()>& fn, double seconds);
[[noreturn]] void hard_exit(int code);
}  // namespace platform

constexpr const char* kVersion = "2.0.0";

}  // namespace perdedor
