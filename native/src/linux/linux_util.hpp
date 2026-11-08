#pragma once

#include "../core/perdedor.hpp"

#include <sys/stat.h>
#include <map>
#include <string>
#include <vector>

namespace perdedor { namespace linuxutil {

// Resource limits are engineering bounds, not detection thresholds. See
// docs/DESIGN-V2.md (bounded runtime and compact evidence).
constexpr size_t kReadLimit = 256 * 1024;
constexpr size_t kTableLimit = 1024 * 1024;
constexpr size_t kPackageLimit = 8 * 1024 * 1024;
constexpr size_t kEntryLimit = 4096;
constexpr size_t kEvidenceLimit = 8;
constexpr unsigned kWalkDepth = 6;
constexpr int kCommandTimeoutMs = 1500;

struct Read {
    bool ok = false;
    std::string value;
    int err = 0;
    bool truncated = false;
};
struct Listing {
    bool ok = false;
    std::vector<std::string> names;
    int err = 0;
    bool truncated = false;
};
struct Metadata {
    bool ok = false;
    struct stat st {};
    int err = 0;
    long long birth = 0;
};

// All check filesystem access goes through this object, including stat,
// directory traversal, symlinks and /proc/self. Absolute symlink targets are
// relative to the selected root; '..' never escapes it. No fixture executes
// programs or sends packets. --param root takes precedence over the environment.
class Root {
  public:
    explicit Root(const Context& ctx);
    ~Root();
    Root(const Root&) = delete;
    Root& operator=(const Root&) = delete;
    bool fixture() const { return fixture_; }
    Read read(const std::string& path, size_t limit = kReadLimit, bool kmsg = false) const;
    Read link(const std::string& path) const;
    Metadata stat(const std::string& path, bool follow = true) const;
    Listing list(const std::string& path) const;
    Listing walk(const std::string& path, unsigned depth = kWalkDepth) const;
    bool exists(const std::string& path) const { return stat(path, false).ok; }
    std::map<std::string, std::string> environment() const;
    std::string home() const;
    std::string username() const;
    std::string hostname() const;
    long long uid() const;  // effective uid of this process, -1 if unknown
    long long now() const;
    Read command(const std::vector<std::string>& argv) const;
  private:
    int fd_ = -1;
    bool fixture_ = false;
    int open_path(const std::string& path, int flags, bool follow = true) const;
};

std::string lower(std::string s);
std::string trim(const std::string& s);
std::vector<std::string> lines(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);
std::string basename(const std::string& s);
bool number(const std::string& s, long long& value, int base = 10);
std::string match(const std::string& s, const std::vector<std::string>& signatures);
std::map<std::string, std::string> fields(const std::string& s, char separator = ':');
const std::vector<std::string>& vm_signatures();
const std::vector<std::string>& guest_names();
const std::vector<std::string>& tool_names();

// A negative result is clean only after complete inspection. Missing optional
// interfaces are skipped; permission failures and malformed input are errors.
struct Evidence {
    size_t observed = 0, unavailable = 0;
    bool partial = false;
    std::vector<std::string> hits;
    void add(const std::string& hit);
    void scan(const Read& r, const std::vector<std::string>& signatures, const std::string& label);
    void paths(const Root& root, const std::vector<std::string>& paths);
    Json json() const;
    Finding finding(const std::string& id, const std::string& name, const std::string& desc,
                    Severity severity, const std::string& fix, double confidence = -1) const;
};
Finding unavailable(const std::string& id, const std::string& name, Severity severity,
                    int err, const std::string& detail);
Finding measured(const std::string& id, const std::string& name, const std::string& desc,
                 double value, double threshold, bool detected, const std::string& unit,
                 const std::string& fix, Severity severity = Severity::Low, double confidence = 0.35);
std::vector<Finding> scan_file(Context& ctx, const char* id, const char* name, const char* path,
                               const std::vector<std::string>& signatures, Severity severity,
                               const char* fix);
struct Packages {
    bool ok = false, partial = false;
    std::string manager;
    std::vector<std::string> names;
};
Packages packages(const Root& root);
Evidence process_matches(const Root& root, const std::vector<std::string>& signatures);

// One running process: comm, argv[0] basename and the basename of argv[1]
// (interpreted tools such as `python3 agent.py`). Never full command lines.
struct Proc {
    std::string pid, comm, argv0, argv1;
    long long ppid = -1;
};
struct ProcList {
    bool ok = false, partial = false;
    int err = 0;
    std::vector<Proc> procs;
};
ProcList processes(const Root& root, bool with_cmdline);
// Proc entry of a pid ("self" allowed), from /proc/<pid>/{comm,cmdline,stat}.
bool process(const Root& root, const std::string& pid, Proc& out);

std::map<std::string, std::string> os_release(const Root& root);
std::string read_value(const Root& root, const std::string& path, bool& ok);  // trimmed, ok=false if unreadable
bool hex_string(const std::string& s);
bool has_word(const std::string& text, const std::string& word);  // case-insensitive, word boundary
// Directory entries of `path` that match a name predicate; missing directory -> ok=false, err=ENOENT.
Listing entries(const Root& root, const std::string& path);
// Count of regular files below path (bounded walk) whose name ends with one of the suffixes.
struct Count {
    bool ok = false, partial = false;
    long long files = 0, bytes = 0, oldest = 0, newest = 0;  // mtimes (epoch s), 0 if none
};
Count count_files(const Root& root, const std::string& path, const std::vector<std::string>& suffixes,
                  unsigned depth = kWalkDepth);
std::string join(const std::vector<std::string>& items, const std::string& sep);
// Finding for an interface that could not be read: absent -> skipped, permission -> skipped
// (needs root), anything else -> error.
Finding unreadable(const std::string& id, const std::string& name, const std::string& desc, Severity severity,
                   int err, const std::string& what);
// Systemd unit files installed in the standard unit directories (names only).
std::vector<std::string> unit_files(const Root& root, bool& ok);

} }  // namespace perdedor::linuxutil
