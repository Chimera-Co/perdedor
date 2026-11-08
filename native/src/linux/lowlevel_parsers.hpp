#pragma once
#include <cerrno>
#include <cstdlib>
#include <sstream>
#include <string>

namespace perdedor::linux_lowlevel {
inline bool status_number(const std::string& text, const std::string& key, long& out) {
    std::istringstream input(text); std::string line;
    while (std::getline(input, line)) {
        if (line.compare(0, key.size() + 1, key + ":") != 0) continue;
        const char* start = line.c_str() + key.size() + 1; char* end = nullptr;
        errno = 0; const long value = std::strtol(start, &end, 10);
        if (errno || end == start) return false;
        while (*end == ' ' || *end == '\t' || *end == '\r') ++end;
        if (*end) return false;
        out = value; return true;
    }
    return false;
}
inline std::string mapped_path(const std::string& line) {
    std::istringstream input(line); std::string field;
    for (unsigned i = 0; i < 5; ++i) if (!(input >> field)) return {};
    std::getline(input, field); const auto start = field.find_first_not_of(" \t");
    return start == std::string::npos ? std::string() : field.substr(start);
}
}  // namespace perdedor::linux_lowlevel
