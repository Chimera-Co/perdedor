// Minimal JSON value + serializer for the Perdedor native agent (no dependencies).
#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace perdedor {

class Json {
  public:
    enum class Kind { Null, Bool, Number, String, Array, Object };

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool b) : kind_(Kind::Bool), bool_(b) {}
    Json(int v) : kind_(Kind::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(long v) : kind_(Kind::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(long long v) : kind_(Kind::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(unsigned v) : kind_(Kind::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(unsigned long v) : kind_(Kind::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(unsigned long long v) : kind_(Kind::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(double v) : kind_(Kind::Number), num_(v) {}
    Json(const char* s) : kind_(Kind::String), str_(s ? s : "") {}
    Json(std::string s) : kind_(Kind::String), str_(std::move(s)) {}
    Json(const std::vector<std::string>& items) : kind_(Kind::Array) {
        for (const auto& s : items) arr_.emplace_back(s);
    }

    static Json object() { Json j; j.kind_ = Kind::Object; return j; }
    static Json array() { Json j; j.kind_ = Kind::Array; return j; }

    Kind kind() const { return kind_; }
    bool is_null() const { return kind_ == Kind::Null; }

    // Object: insertion-ordered keys.
    Json& set(const std::string& key, Json value);
    Json& operator[](const std::string& key);
    // Array
    Json& push(Json value);
    size_t size() const { return kind_ == Kind::Array ? arr_.size() : obj_.size(); }

    std::string dump(int indent = -1) const;

    double number() const { return num_; }
    const std::string& str() const { return str_; }

  private:
    void dump_to(std::string& out, int indent, int depth) const;
    Kind kind_ = Kind::Null;
    bool bool_ = false;
    double num_ = 0;
    bool integral_ = false;
    std::string str_;
    std::vector<Json> arr_;
    std::vector<std::pair<std::string, Json>> obj_;
};

// Escape a byte string as a JSON string literal body. Invalid UTF-8 is
// replaced with U+FFFD so the report always parses.
std::string json_escape(const std::string& s);

}  // namespace perdedor
