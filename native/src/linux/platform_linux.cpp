#include <pthread.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <memory>

#include "../core/perdedor.hpp"

namespace perdedor {
namespace platform {

const char* name() { return "linux"; }
const char* id_prefix() { return "linux"; }

std::string hostname() {
    char buf[256] = {0};
    if (gethostname(buf, sizeof buf - 1) != 0) return "unknown";
    return buf;
}

Json metadata() {
    Json m = Json::object();
    struct utsname u {};
    if (uname(&u) == 0) {
        m.set("os", u.sysname);
        m.set("os_release", u.release);
        m.set("machine", u.machine);
        m.set("os_version", u.version);
    } else {
        m.set("os", "Linux");
    }
    return m;
}

namespace {
struct Job {
    std::function<void()> fn;
};
void* trampoline(void* arg) {
    std::unique_ptr<Job> job(static_cast<Job*>(arg));
    job->fn();
    return nullptr;
}
}  // namespace

bool run_with_timeout(const std::function<void()>& fn, double seconds) {
    pthread_t th;
    auto* job = new Job{fn};
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    if (pthread_create(&th, &attr, trampoline, job) != 0) {
        pthread_attr_destroy(&attr);
        delete job;
        fn();  // no threads available: run inline, without a watchdog
        return true;
    }
    pthread_attr_destroy(&attr);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    long long ns = deadline.tv_nsec + static_cast<long long>((seconds - static_cast<long long>(seconds)) * 1e9);
    deadline.tv_sec += static_cast<time_t>(seconds) + ns / 1000000000LL;
    deadline.tv_nsec = ns % 1000000000LL;
    int rc = pthread_timedjoin_np(th, nullptr, &deadline);
    if (rc == 0) return true;
    pthread_detach(th);
    return false;
}

void hard_exit(int code) {
    std::fflush(nullptr);
    _exit(code);
}

}  // namespace platform
}  // namespace perdedor
