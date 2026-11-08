#include <algorithm>
#include <chrono>
#include <cmath>
#include <memory>
#include <stdexcept>

#include "perdedor.hpp"

namespace perdedor {

const char* to_string(Status s) {
    switch (s) {
        case Status::Clean: return "clean";
        case Status::Detected: return "detected";
        case Status::Error: return "error";
        case Status::Skipped: return "skipped";
    }
    return "error";
}

const char* to_string(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "info";
}

std::string full_id(const std::string& relative_id) {
    std::string prefix = std::string(platform::id_prefix()) + ".";
    if (relative_id.rfind(prefix, 0) == 0) return relative_id;
    return prefix + relative_id;
}

static Finding make(const std::string& id, const std::string& name, const std::string& description, Status st,
                    Severity sev) {
    Finding f;
    f.id = full_id(id);
    f.name = name;
    f.description = description;
    f.status = st;
    f.severity = sev;
    return f;
}

Finding clean(const std::string& id, const std::string& name, const std::string& description, Severity sev,
              Json evidence) {
    Finding f = make(id, name, description, Status::Clean, sev);
    f.evidence = std::move(evidence);
    return f;
}

Finding detected(const std::string& id, const std::string& name, const std::string& description, Severity sev,
                 Json evidence, const std::string& remediation) {
    Finding f = make(id, name, description, Status::Detected, sev);
    f.evidence = std::move(evidence);
    f.remediation = remediation;
    return f;
}

Finding bool_check(const std::string& id, const std::string& name, const std::string& description, Severity sev,
                   bool is_detected, Json evidence, const std::string& remediation) {
    return is_detected ? detected(id, name, description, sev, std::move(evidence), remediation)
                       : clean(id, name, description, sev, std::move(evidence));
}

Finding skipped(const std::string& id, const std::string& name, const std::string& description, Severity sev,
                const std::string& detail) {
    Finding f = make(id, name, description, Status::Skipped, sev);
    f.error_detail = detail;
    return f;
}

Finding error(const std::string& id, const std::string& name, const std::string& description, Severity sev,
              const std::string& detail) {
    Finding f = make(id, name, description, Status::Error, sev);
    f.error_detail = detail.empty() ? "unspecified error" : detail;
    return f;
}

std::string Context::param(const std::string& key, const std::string& def) const {
    auto it = params.find(key);
    return it == params.end() ? def : it->second;
}

long long Context::param_int(const std::string& key, long long def) const {
    auto it = params.find(key);
    if (it == params.end()) return def;
    try { return std::stoll(it->second); } catch (...) { return def; }
}

double Context::param_double(const std::string& key, double def) const {
    auto it = params.find(key);
    if (it == params.end()) return def;
    try { return std::stod(it->second); } catch (...) { return def; }
}

bool Context::param_bool(const std::string& key, bool def) const {
    auto it = params.find(key);
    if (it == params.end()) return def;
    std::string v = it->second;
    std::transform(v.begin(), v.end(), v.begin(), ::tolower);
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

Registry& Registry::instance() {
    static Registry r;
    return r;
}

void Registry::add(CheckSpec spec) {
    for (const auto& existing : checks_) {
        for (const auto& id : existing.ids) {
            if (std::find(spec.ids.begin(), spec.ids.end(), id) != spec.ids.end()) {
                throw std::logic_error("check id registered twice: " + id);
            }
        }
    }
    checks_.push_back(std::move(spec));
}

std::string class_category(const std::string& k) {
    static const std::map<std::string, std::string> m = {
        {"cpu", "environment_artifact"},       {"firmware", "environment_artifact"},
        {"hardware", "environment_artifact"},  {"resources", "environment_artifact"},
        {"guest_tools", "environment_artifact"}, {"artifacts", "environment_artifact"},
        {"container", "environment_artifact"}, {"emulator", "environment_artifact"},
        {"mobile_device", "environment_artifact"}, {"timing", "timing"},
        {"human", "behavioural_interaction"},  {"wear_and_tear", "behavioural_interaction"},
        {"identity", "design_specific"},       {"analysis_tools", "design_specific"},
        {"debugger", "design_specific"},       {"instrumentation", "design_specific"},
        {"network", "design_specific"},        {"os_config", "design_specific"},
        {"integrity", "design_specific"},
    };
    auto it = m.find(k);
    return it == m.end() ? "" : it->second;
}

Registrar::Registrar(CheckFn fn, const char* technique, const char* cost, bool network,
                     std::vector<std::string> ids, const char* source) {
    CheckSpec spec;
    for (auto& id : ids) spec.ids.push_back(full_id(id));
    spec.technique = technique;
    spec.klass = spec.technique.substr(0, spec.technique.find('.'));
    spec.category = class_category(spec.klass);
    spec.cost = cost;
    spec.network = network;
    spec.fn = std::move(fn);
    spec.source = source;
    if (spec.category.empty()) throw std::logic_error(std::string("unknown class in technique ") + technique);
    if (spec.cost != "fast" && spec.cost != "medium" && spec.cost != "slow")
        throw std::logic_error(std::string("bad cost for ") + source);
    Registry::instance().add(std::move(spec));
}

// fnmatchcase-compatible subset: * ? [seq] [!seq]
static bool glob_at(const char* p, const char* t) {
    while (*p) {
        if (*p == '*') {
            while (*p == '*') ++p;
            if (!*p) return true;
            for (; *t; ++t)
                if (glob_at(p, t)) return true;
            return glob_at(p, t);
        }
        if (!*t) return false;
        if (*p == '?') { ++p; ++t; continue; }
        if (*p == '[') {
            const char* q = p + 1;
            bool neg = (*q == '!');
            if (neg) ++q;
            bool matched = false;
            const char* start = q;
            while (*q && (*q != ']' || q == start)) {
                if (q[1] == '-' && q[2] && q[2] != ']') {
                    if (*t >= q[0] && *t <= q[2]) matched = true;
                    q += 3;
                } else {
                    if (*t == *q) matched = true;
                    ++q;
                }
            }
            if (*q != ']') {  // unterminated: literal '['
                if (*t != '[') return false;
                ++p; ++t; continue;
            }
            if (matched == neg) return false;
            p = q + 1; ++t;
            continue;
        }
        if (*p != *t) return false;
        ++p; ++t;
    }
    return !*t;
}

bool glob_match(const std::string& pattern, const std::string& text) { return glob_at(pattern.c_str(), text.c_str()); }

bool pattern_matches(const std::string& pattern, const CheckSpec& c) {
    auto colon = pattern.find(':');
    if (colon == std::string::npos) {
        for (const auto& id : c.ids)
            if (glob_match(pattern, id)) return true;
        return false;
    }
    std::string kind = pattern.substr(0, colon);
    std::string value = pattern.substr(colon + 1);
    while (!value.empty() && value.front() == ' ') value.erase(value.begin());
    while (!value.empty() && value.back() == ' ') value.pop_back();
    if (kind == "class") return glob_match(value, c.klass);
    if (kind == "category") return glob_match(value, c.category);
    if (kind == "technique") return glob_match(value, c.technique);
    if (kind == "cost") return c.cost == value;
    if (kind == "tag") return std::find(c.tags.begin(), c.tags.end(), value) != c.tags.end();
    if (kind == "id") {
        for (const auto& id : c.ids)
            if (glob_match(value, id)) return true;
        return false;
    }
    throw std::invalid_argument("unknown selector '" + kind + ":' in pattern '" + pattern + "'");
}

static int cost_rank(const std::string& cost) { return cost == "fast" ? 0 : cost == "medium" ? 1 : 2; }

std::vector<const CheckSpec*> select_checks(const std::vector<CheckSpec>& checks, const std::string& profile,
                                            const std::vector<std::string>& only,
                                            const std::vector<std::string>& skip, bool network) {
    int ceiling;
    if (profile == "quick") ceiling = 0;
    else if (profile == "standard") ceiling = 1;
    else if (profile == "deep") ceiling = 2;
    else throw std::invalid_argument("profile '" + profile + "' not in [deep, quick, standard]");
    std::vector<const CheckSpec*> out;
    for (const auto& c : checks) {
        bool explicitly = false;
        if (!only.empty()) {
            for (const auto& p : only)
                if (pattern_matches(p, c)) { explicitly = true; break; }
            if (!explicitly) continue;
        }
        if (!explicitly && cost_rank(c.cost) > ceiling) continue;
        bool skipped_it = false;
        for (const auto& p : skip)
            if (pattern_matches(p, c)) { skipped_it = true; break; }
        if (skipped_it) continue;
        if (c.network && !network) continue;
        out.push_back(&c);
    }
    return out;
}

double timeout_seconds_for(const std::string& cost, const Context& ctx) {
    double base = cost == "fast" ? 10 : cost == "medium" ? 45 : 240;
    return ctx.param_double("watchdog." + cost + "_s", base);
}

std::vector<Finding> run_checks(const std::vector<const CheckSpec*>& checks, Context& ctx) {
    std::vector<Finding> all;
    for (const CheckSpec* c : checks) {
        // Heap-held so an abandoned (timed-out) probe thread never touches a dead stack frame.
        auto produced = std::make_shared<std::vector<Finding>>();
        auto failure = std::make_shared<std::string>();
        auto started = std::chrono::steady_clock::now();
        CheckFn fn = c->fn;
        Context* cptr = &ctx;
        bool finished = platform::run_with_timeout(
            [produced, failure, fn, cptr]() {
                try {
                    *produced = fn(*cptr);
                } catch (const std::exception& e) {
                    *failure = std::string("exception: ") + e.what();
                } catch (...) {
                    *failure = "unknown exception";
                }
            },
            timeout_seconds_for(c->cost, ctx));
        double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
        std::vector<Finding> results;
        if (!finished) {
            results.push_back(error(c->ids[0], c->ids[0], "Probe exceeded its watchdog budget and was abandoned.",
                                    Severity::Info,
                                    "timed out after " + std::to_string(static_cast<int>(
                                                             timeout_seconds_for(c->cost, ctx))) + " s"));
        } else if (!failure->empty()) {
            results.push_back(error(c->ids[0], c->ids[0], "Probe raised before producing a result.", Severity::Info,
                                    *failure));
        } else {
            results = *produced;
        }
        double share = std::round(ms * 100.0 / std::max<size_t>(1, results.size())) / 100.0;
        for (auto& f : results) {
            if (f.technique.empty()) f.technique = c->technique;
            if (f.klass.empty()) f.klass = c->klass;
            if (f.category.empty()) f.category = c->category;
            if (f.duration_ms < 0) f.duration_ms = share;
            all.push_back(std::move(f));
        }
    }
    return all;
}

Json finding_json(const Finding& f) {
    Json j = Json::object();
    j.set("id", f.id);
    j.set("category", f.category);
    j.set("platform", platform::name());
    j.set("name", f.name);
    j.set("description", f.description);
    j.set("status", to_string(f.status));
    j.set("severity", to_string(f.severity));
    j.set("evidence", f.evidence);
    j.set("remediation", f.remediation.empty() || f.status != Status::Detected ? Json() : Json(f.remediation));
    j.set("error_detail", f.error_detail.empty() ? Json() : Json(f.error_detail));
    if (!f.technique.empty()) j.set("technique", f.technique);
    if (!f.klass.empty()) j.set("class", f.klass);
    if (f.confidence >= 0) j.set("confidence", std::min(1.0, f.confidence));
    if (!f.measurement.is_null()) j.set("measurement", f.measurement);
    if (f.duration_ms >= 0) j.set("duration_ms", f.duration_ms);
    return j;
}

Json summary_of(const std::vector<Finding>& findings) {
    static const std::map<Severity, double> w = {{Severity::Info, 0.05}, {Severity::Low, 0.15},
                                                 {Severity::Medium, 0.35}, {Severity::High, 0.65},
                                                 {Severity::Critical, 1.0}};
    long clean_n = 0, det = 0, err = 0, skip = 0;
    double penalty = 0;
    for (const auto& f : findings) {
        switch (f.status) {
            case Status::Clean: ++clean_n; break;
            case Status::Detected: ++det; penalty += w.at(f.severity); break;
            case Status::Error: ++err; break;
            case Status::Skipped: ++skip; break;
        }
    }
    long applicable = clean_n + det;
    double weighted = applicable ? std::max(0.0, 100.0 * (1.0 - penalty / applicable)) : 100.0;
    Json s = Json::object();
    s.set("total", static_cast<long>(findings.size()));
    s.set("clean", clean_n);
    s.set("detected", det);
    s.set("errored", err);
    s.set("skipped", skip);
    s.set("raw_score", applicable ? std::to_string(clean_n) + "/" + std::to_string(applicable) : "0/0");
    s.set("weighted_score", std::round(weighted * 100.0) / 100.0);
    return s;
}

}  // namespace perdedor
