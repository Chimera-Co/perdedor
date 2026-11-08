#include "json.hpp"

#include <cmath>
#include <cstdio>

namespace perdedor {

Json& Json::set(const std::string& key, Json value) {
    if (kind_ != Kind::Object) { *this = object(); }
    for (auto& kv : obj_) {
        if (kv.first == key) { kv.second = std::move(value); return kv.second; }
    }
    obj_.emplace_back(key, std::move(value));
    return obj_.back().second;
}

Json& Json::operator[](const std::string& key) {
    if (kind_ != Kind::Object) { *this = object(); }
    for (auto& kv : obj_) {
        if (kv.first == key) return kv.second;
    }
    obj_.emplace_back(key, Json());
    return obj_.back().second;
}

Json& Json::push(Json value) {
    if (kind_ != Kind::Array) { *this = array(); }
    arr_.push_back(std::move(value));
    return arr_.back();
}

static void append_codepoint(std::string& out, uint32_t cp) {
    char buf[8];
    std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(cp));
    out += buf;
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) append_codepoint(out, c); else out += static_cast<char>(c);
            }
            ++i;
            continue;
        }
        // Validate a UTF-8 sequence; copy it through if well formed.
        size_t len = (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 0;
        bool ok = len && i + len <= s.size();
        for (size_t k = 1; ok && k < len; ++k) {
            ok = (static_cast<unsigned char>(s[i + k]) >> 6) == 0x2;
        }
        if (ok) { out.append(s, i, len); i += len; }
        else { out += "\\ufffd"; ++i; }
    }
    return out;
}

static void newline(std::string& out, int indent, int depth) {
    if (indent < 0) return;
    out += '\n';
    out.append(static_cast<size_t>(indent * depth), ' ');
}

void Json::dump_to(std::string& out, int indent, int depth) const {
    switch (kind_) {
        case Kind::Null: out += "null"; break;
        case Kind::Bool: out += bool_ ? "true" : "false"; break;
        case Kind::Number: {
            if (!std::isfinite(num_)) { out += "null"; break; }
            char buf[64];
            if (integral_ || (std::floor(num_) == num_ && std::fabs(num_) < 9.0e15)) {
                std::snprintf(buf, sizeof buf, "%.0f", num_);
            } else {
                std::snprintf(buf, sizeof buf, "%.6g", num_);
            }
            out += buf;
            break;
        }
        case Kind::String: out += '"'; out += json_escape(str_); out += '"'; break;
        case Kind::Array: {
            if (arr_.empty()) { out += "[]"; break; }
            out += '[';
            for (size_t i = 0; i < arr_.size(); ++i) {
                if (i) out += ',';
                newline(out, indent, depth + 1);
                arr_[i].dump_to(out, indent, depth + 1);
            }
            newline(out, indent, depth);
            out += ']';
            break;
        }
        case Kind::Object: {
            if (obj_.empty()) { out += "{}"; break; }
            out += '{';
            for (size_t i = 0; i < obj_.size(); ++i) {
                if (i) out += ',';
                newline(out, indent, depth + 1);
                out += '"'; out += json_escape(obj_[i].first); out += "\":";
                if (indent >= 0) out += ' ';
                obj_[i].second.dump_to(out, indent, depth + 1);
            }
            newline(out, indent, depth);
            out += '}';
            break;
        }
    }
}

std::string Json::dump(int indent) const {
    std::string out;
    dump_to(out, indent, 0);
    return out;
}

}  // namespace perdedor
