#include <cstdlib>

#include "../src/core/perdedor.hpp"

namespace perdedor {
namespace platform {
const char* name() { return "linux"; }
const char* id_prefix() { return "linux"; }
std::string hostname() { return "test-host"; }
Json metadata() { return Json::object(); }
Json host_facts() {
    Json facts = Json::object();
    facts.set("os_build", "6.1.0-fake");
    facts.set("cpu_model", "Fake CPU @ 2.40GHz");
    facts.set("core_count", 4);
    return facts;
}
bool run_with_timeout(const std::function<void()>& fn, double) {
    fn();
    return true;
}
void hard_exit(int code) { std::exit(code); }
}  // namespace platform
}  // namespace perdedor
