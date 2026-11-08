#include <cstdlib>

#include "../src/core/perdedor.hpp"

namespace perdedor {
namespace platform {
const char* name() { return "linux"; }
const char* id_prefix() { return "linux"; }
std::string hostname() { return "test-host"; }
Json metadata() { return Json::object(); }
bool run_with_timeout(const std::function<void()>& fn, double) {
    fn();
    return true;
}
void hard_exit(int code) { std::exit(code); }
}  // namespace platform
}  // namespace perdedor
