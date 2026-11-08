#pragma once
#include "../core/perdedor.hpp"
#include "winutil.hpp"
namespace perdedor {
namespace winsys {
// Evidence builder. Json::set returns the inserted child (core API), so chaining it
// nests values; Ev::set returns the builder and converts to Json when handed on.
class Ev {
    Json j_ = Json::object();

  public:
    template <class T> Ev &set(const std::string &key, T &&value) {
        j_.set(key, Json(std::forward<T>(value)));
        return *this;
    }
    Ev &set(const std::string &key, const Ev &value) {
        j_.set(key, value.j_);
        return *this;
    }
    operator Json() const { return j_; }
};
inline Finding
result(const char *id, const char *name, bool hit, Json evidence, Severity severity = Severity::Low,
       double confidence = 0.35,
       const char *fix = "Review the check's catalog fix and provision a consistent, used desktop image.") {
    auto f = bool_check(id, name, name, severity, hit, std::move(evidence), fix);
    f.confidence = confidence;
    return f;
}
inline Finding fail(const char *id, const char *name, const std::string &detail,
                    Severity severity = Severity::Low) {
    return error(id, name, name, severity, detail);
}
inline Finding absent(const char *id, const char *name, const std::string &why,
                      Severity severity = Severity::Low) {
    return skipped(id, name, name, severity, why);
}
inline Ev counts(uint64_t count) { return Ev().set("count", count); }
inline Ev matched(const std::vector<std::string> &hits, uint64_t examined) {
    Ev j;
    j.set("examined", examined).set("matched_count", static_cast<unsigned long long>(hits.size()));
    Json a = Json::array();
    for (size_t i = 0; i < hits.size() && i < 16; ++i)
        a.push(hits[i]);
    return j.set("signatures", a);
}
} // namespace winsys
} // namespace perdedor
