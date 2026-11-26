#include <fcntl.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <fstream>
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

Json host_facts() {
    Json facts = Json::object();
    struct utsname u {};
    if (uname(&u) == 0) {
        facts.set("os_build", u.release);
    } else {
        facts.set("os_build", "unknown");
    }

    std::string cpu_model = "unknown";
    std::ifstream f("/proc/cpuinfo");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("model name", 0) == 0) {
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                cpu_model = line.substr(colon + 1);
                while (!cpu_model.empty() && (cpu_model.front() == ' ' || cpu_model.front() == '\t')) cpu_model.erase(0, 1);
                break;
            }
        }
    }
    if (cpu_model == "unknown" && u.machine[0]) {
        cpu_model = u.machine;
    }
    facts.set("cpu_model", cpu_model);

    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores <= 0) cores = 1;
    facts.set("core_count", static_cast<long long>(cores));
    return facts;
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

std::FILE* open_for_write(const std::string& path) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0) return nullptr;
    std::FILE* f = fdopen(fd, "wb");
    if (!f) ::close(fd);
    return f;
}

void flush_to_disk(std::FILE* f) {
    if (!f) return;
    std::fflush(f);
    fsync(fileno(f));
}

}  // namespace platform
}  // namespace perdedor
