#include "system_checks.hpp"
#include <shlobj.h>
#include <shellapi.h>
#include <lm.h>
#include <wlanapi.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <set>
namespace perdedor {
namespace {
using namespace winsys;
std::vector<Finding> registry_count(const char *id, const char *name, HKEY root, const wchar_t *path,
                                    bool values, int depth) {
    uint64_t count = 0;
    std::vector<std::pair<std::wstring, int>> todo{{path, depth}};
    size_t visited = 0;
    auto end = GetTickCount64() + winlogic::kTreeScanMs;
    bool truncated = false;
    while (!todo.empty()) {
        auto item = todo.back();
        todo.pop_back();
        if (++visited > winlogic::kMaxEntries || GetTickCount64() >= end) {
            truncated = true; // the count is already a lower bound above the minimum
            break;
        }
        if (item.second == 0) {
            auto v = win::registry_names(root, item.first, values);
            if (!v.ok() && v.value.empty())
                return {fail(id, name, v.error)};
            for (const auto &n : v.value)
                if (n != L"MRUList" && n != L"MRUListEx")
                    ++count;
        } else {
            auto v = win::registry_names(root, item.first);
            if (!v.ok())
                return {fail(id, name, v.error)};
            for (const auto &n : v.value)
                todo.push_back({item.first + L"\\" + n, item.second - 1});
        }
    }
    auto ev = counts(count);
    ev.set("truncated", truncated);
    return {result(id, name, !truncated && count < winlogic::kMinTraceCount, ev)};
}
std::vector<Finding> directory_count(const char *id, const char *name, const wchar_t *path,
                                     bool recurse = false, const wchar_t *pattern = L"*") {
    auto v = win::file_count(path, recurse, pattern);
    if (!v.ok() && v.code == ERROR_ACCESS_DENIED)
        return {absent(id, name, "folder requires elevated rights")};
    if (!v.ok())
        return {fail(id, name, v.error)};
    if (v.absent)
        return {result(id, name, true, counts(0).set("folder_present", false))};
    auto ev = counts(v.value.count);
    ev.set("truncated", v.value.truncated).set("access_denied_folders", v.value.denied);
    return {result(id, name, !v.value.truncated && v.value.count < winlogic::kMinTraceCount, ev)};
}
struct Browser {
    const char *name;
    const wchar_t *root;
    bool firefox;
};
const Browser browsers[] = {{"chrome", L"%LOCALAPPDATA%\\Google\\Chrome\\User Data", false},
                            {"edge", L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data", false},
                            {"firefox", L"%APPDATA%\\Mozilla\\Firefox\\Profiles", true},
                            {"brave", L"%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data", false},
                            {"opera", L"%APPDATA%\\Opera Software\\Opera Stable", false}};
win::Result<std::pair<uint64_t, uint64_t>> browser_files(const Browser &b, bool cookies) {
    win::Result<std::pair<uint64_t, uint64_t>> r;
    auto root = win::expand_env(b.root);
    WIN32_FIND_DATAW d{};
    HANDLE h = FindFirstFileW((root + L"\\*").c_str(), &d);
    std::vector<std::wstring> dirs;
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        r.absent = e == ERROR_PATH_NOT_FOUND || e == ERROR_FILE_NOT_FOUND;
        if (!r.absent)
            r.error = win::last_error_message(e);
        return r;
    }
    struct Find {
        HANDLE h;
        ~Find() { FindClose(h); }
    } close{h};
    if (std::string(b.name) == "opera")
        dirs.push_back(root);
    do {
        if (d.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;
        if ((d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && d.cFileName[0] != L'.')
            dirs.push_back(root + L"\\" + d.cFileName);
        if (dirs.size() > winlogic::kMaxRows) {
            r.error = "browser profile limit exceeded";
            return r;
        }
    } while (FindNextFileW(h, &d));
    if (GetLastError() != ERROR_NO_MORE_FILES) {
        r.error = win::last_error_message();
        return r;
    }
    for (const auto &p : dirs) {
        std::vector<std::wstring> names =
            b.firefox ? std::vector<std::wstring>{cookies ? L"cookies.sqlite" : L"places.sqlite"}
                      : (cookies ? std::vector<std::wstring>{L"Cookies", L"Network\\Cookies"}
                                 : std::vector<std::wstring>{L"History"});
        for (const auto &n : names) {
            auto v = win::file_size(p + L"\\" + n);
            if (!v.ok()) {
                r.error = v.error;
                return r;
            }
            if (!v.absent) {
                ++r.value.first;
                if (v.value > winlogic::kHistoryBytes)
                    ++r.value.second;
            }
        }
    }
    return r;
}
std::vector<Finding> browser_probe(const char *id, const char *name, int index, bool cookies) {
    auto v = browser_files(browsers[index], cookies);
    if (!v.ok())
        return {fail(id, name, v.error)};
    if (v.absent)
        return {absent(id, name, "browser profile root absent")};
    return {result(id, name, v.value.second == 0,
                   Ev()
                       .set("files", v.value.first)
                       .set("above_size_floor", v.value.second)
                       .set("size_floor_bytes", winlogic::kHistoryBytes))};
}
std::vector<Finding> browser_history(Context &) {
    const char *id = "behavioural.browser_history", *name = "Populated browser history files";
    uint64_t count = 0, files = 0;
    for (const auto &b : browsers) {
        auto v = browser_files(b, false);
        if (!v.ok())
            return {fail(id, name, v.error)};
        files += v.value.first;
        count += v.value.second;
    }
    return {result(id, name, count == 0,
                   Ev()
                       .set("files", files)
                       .set("above_size_floor", count)
                       .set("size_floor_bytes", winlogic::kHistoryBytes))};
}
std::wstring user_folder(int index) {
    const KNOWNFOLDERID *ids[] = {&FOLDERID_Desktop, &FOLDERID_Documents, &FOLDERID_Downloads,
                                  &FOLDERID_Pictures};
    PWSTR raw = nullptr;
    HRESULT h = SHGetKnownFolderPath(*ids[index], KF_FLAG_DONT_VERIFY, nullptr, &raw);
    if (FAILED(h))
        return {};
    std::wstring path(raw);
    CoTaskMemFree(raw);
    return path;
}
std::vector<Finding> user_files(const char *id, const char *name, int index) {
    auto path = user_folder(index);
    if (path.empty())
        return {absent(id, name, "user known-folder location unavailable")};
    return directory_count(id, name, path.c_str(), true);
}
std::vector<Finding> aged_files(Context &) {
    const char *id = "behavioural.aged_files", *name = "Aged files in user folders";
    uint64_t count = 0;
    bool truncated = false;
    for (int i = 0; i < 4; ++i) {
        auto p = user_folder(i);
        if (p.empty())
            return {absent(id, name, "user known-folder location unavailable")};
        auto v = win::file_count(p, true);
        if (!v.ok())
            return {fail(id, name, v.error)};
        count += v.value.aged;
        truncated |= v.value.truncated;
    }
    return {result(id, name, count < winlogic::kMinAgedFiles,
                   Ev()
                       .set("aged_files", count)
                       .set("minimum_age_days", winlogic::kAgedDays)
                       .set("truncated", truncated))};
}
std::vector<Finding> installed_programs(Context &) {
    const char *id = "behavioural.installed_programs", *name = "Installed program count";
    auto v = win::programs();
    if (!v.ok())
        return {fail(id, name, v.error)};
    return {result(id, name, v.value.size() < winlogic::kMinPrograms, counts(v.value.size()))};
}
std::vector<Finding> program_dates(Context &) {
    const char *id = "behavioural.program_install_spread", *name = "Program installation date spread";
    auto v = win::programs();
    if (!v.ok())
        return {fail(id, name, v.error)};
    int64_t first = INT64_MAX, last = 0;
    unsigned dated = 0;
    for (const auto &p : v.value) {
        auto d = winlogic::date_days(p.date);
        if (d >= 0) {
            first = std::min(first, d);
            last = std::max(last, d);
            ++dated;
        }
    }
    if (!dated)
        return {absent(id, name, "installed programs have no parseable installation dates")};
    return {result(
        id, name, last - first < winlogic::kYoungDays,
        Ev().set("dated_programs", dated).set("span_days", static_cast<long long>(last - first)))};
}
std::vector<Finding> installed_signatures(Context &, bool guest) {
    const char *id = guest ? "env.guest_additions_installed" : "design.analysis_tools_installed",
               *name = guest ? "Installed guest additions" : "Installed analysis tools";
    auto v = win::programs();
    if (!v.ok())
        return {fail(id, name, v.error)};
    std::vector<std::string> hits;
    const std::vector<std::string> tools = {"wireshark", "fiddler", "process hacker", "system informer",
                                            "ida pro",   "x64dbg",  "ollydbg",        "api monitor",
                                            "npcap",     "winpcap"};
    for (const auto &p : v.value) {
        auto s = winlogic::match(p.name, guest ? winlogic::vendors() : tools);
        if (!s.empty())
            hits.push_back(s);
    }
    return {result(id, name, !hits.empty(), matched(hits, v.value.size()), Severity::Medium, 0.8)};
}
namespace {
int CALLBACK font_cb(const LOGFONTW *f, const TEXTMETRICW *, DWORD, LPARAM data) {
    reinterpret_cast<std::set<std::wstring> *>(data)->insert(f->lfFaceName);
    return 1;
}
} // namespace
std::vector<Finding> fonts(Context &) {
    const char *id = "behavioural.font_count", *name = "Installed font families";
    HDC dc = GetDC(nullptr);
    if (!dc)
        return {fail(id, name, win::last_error_message(), Severity::Info)};
    LOGFONTW font{};
    font.lfCharSet = DEFAULT_CHARSET;
    std::set<std::wstring> names;
    EnumFontFamiliesExW(dc, &font, font_cb, reinterpret_cast<LPARAM>(&names), 0);
    ReleaseDC(nullptr, dc);
    if (names.empty())
        return {absent(id, name, "font enumeration produced no families", Severity::Info)};
    return {result(id, name, names.size() < winlogic::kMinFonts, counts(names.size()), Severity::Info)};
}
std::vector<Finding> process_count(Context &) {
    const char *id = "behavioural.running_process_count", *name = "Running process count";
    auto v = win::processes();
    if (!v.ok())
        return {fail(id, name, v.error, Severity::Info)};
    return {
        result(id, name, v.value.size() < winlogic::kMinProcesses, counts(v.value.size()), Severity::Info)};
}
std::vector<Finding> profile_age(Context &) {
    const char *id = "behavioural.profile_age", *name = "User profile directory age";
    WIN32_FILE_ATTRIBUTE_DATA d{};
    if (!GetFileAttributesExW(win::expand_env(L"%USERPROFILE%").c_str(), GetFileExInfoStandard, &d))
        return {fail(id, name, win::last_error_message())};
    int64_t day = static_cast<int64_t>((uint64_t(d.ftCreationTime.dwHighDateTime) << 32) |
                                       d.ftCreationTime.dwLowDateTime) /
                      864000000000LL -
                  134774;
    auto age = win::now_days() - day;
    if (age < 0)
        return {fail(id, name, "profile creation time is in the future")};
    return {result(id, name, age < winlogic::kYoungDays,
                   Ev().set("age_days", static_cast<long long>(age)))};
}
std::vector<Finding> recycle(Context &) {
    const char *id = "behavioural.recycle_bin", *name = "Recycle Bin item count";
    SHQUERYRBINFO info{};
    info.cbSize = sizeof info;
    HRESULT h = SHQueryRecycleBinW(nullptr, &info);
    if (FAILED(h))
        return {fail(id, name, win::last_error_message(h))};
    return {result(id, name, info.i64NumItems == 0, counts(static_cast<uint64_t>(info.i64NumItems)))};
}
std::vector<Finding> clipboard(Context &) {
    const char *id = "behavioural.clipboard_formats", *name = "Clipboard format count";
    if (!OpenClipboard(nullptr))
        return {fail(id, name, win::last_error_message())};
    unsigned count = 0, format = 0;
    SetLastError(ERROR_SUCCESS);
    while ((format = EnumClipboardFormats(format)) != 0 && count < winlogic::kMaxEntries)
        ++count;
    DWORD e = GetLastError();
    CloseClipboard();
    if (e != ERROR_SUCCESS)
        return {fail(id, name, win::last_error_message(e))};
    if (count == winlogic::kMaxEntries)
        return {fail(id, name, "clipboard format limit exceeded")};
    return {result(id, name, count == 0, counts(count))};
}
std::vector<Finding> event_log(const char *id, const char *name, const wchar_t *log, bool vmware = false) {
    HANDLE h = OpenEventLogW(nullptr, log);
    if (!h) {
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED || e == ERROR_PRIVILEGE_NOT_HELD)
            return {absent(id, name, "log requires elevated rights (Event Log Readers or administrator)")};
        return {fail(id, name, win::last_error_message(e))};
    }
    struct Log {
        HANDLE h;
        ~Log() { CloseEventLog(h); }
    } close{h};
    DWORD count = 0, oldest = 0;
    if (!GetNumberOfEventLogRecords(h, &count) || !GetOldestEventLogRecord(h, &oldest))
        return {fail(id, name, win::last_error_message())};
    if (!count)
        return {result(id, name, !vmware, counts(0))};
    std::vector<BYTE> b(65536);
    DWORD got = 0, needed = 0;
    size_t examined = 0;
    int64_t age = -1;
    std::vector<std::string> hits;
    const auto end = GetTickCount64() + winlogic::kScanMs;
    do {
        if (!ReadEventLogW(h, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ, 0, b.data(),
                           static_cast<DWORD>(b.size()), &got, &needed)) {
            DWORD e = GetLastError();
            if (e == ERROR_HANDLE_EOF)
                break;
            if (e == ERROR_INSUFFICIENT_BUFFER && needed <= winlogic::kMaxBlob) {
                b.resize(needed);
                continue;
            }
            return {fail(id, name, win::last_error_message(e))};
        }
        for (size_t p = 0; p + sizeof(EVENTLOGRECORD) <= got;) {
            EVENTLOGRECORD rec{};
            std::memcpy(&rec, b.data() + p, sizeof rec);
            if (rec.Length < sizeof rec || rec.Length > got - p)
                return {fail(id, name, "malformed event log record")};
            if (age < 0)
                age = win::now_days() - rec.TimeGenerated / 86400;
            if (vmware) {
                const BYTE *start = b.data() + p + sizeof rec;
                size_t chars = (rec.Length - sizeof rec) / sizeof(wchar_t);
                std::wstring source;
                for (size_t i = 0; i < chars; ++i) {
                    wchar_t c = 0;
                    std::memcpy(&c, start + i * 2, 2);
                    if (!c)
                        break;
                    source += c;
                }
                if (winlogic::contains(win::narrow(source), "vmware") ||
                    winlogic::contains(win::narrow(source), "vmtools"))
                    hits.push_back("VMware event provider");
            }
            ++examined;
            p += rec.Length;
        }
        if (!vmware)
            break;
        if (examined >= winlogic::kMaxEntries || GetTickCount64() >= end) {
            if (hits.empty())
                return {fail(id, name, "event log scan limit exceeded")};
            break;
        }
    } while (vmware);
    auto ev = counts(count);
    ev.set("oldest_record_age_days", static_cast<long long>(age))
        .set("examined", static_cast<unsigned long long>(examined));
    return {result(id, name, vmware ? !hits.empty() : (age >= 0 && age < winlogic::kYoungDays), ev)};
}
std::vector<Finding> wifi_profiles(Context &) {
    const char *id = "behavioural.wifi_profiles", *name = "Saved Wi-Fi profile count";
    HMODULE lib = win::system_library(L"wlanapi.dll");
    if (!lib)
        return {absent(id, name, "WLAN API unavailable")};
    struct Lib {
        HMODULE h;
        ~Lib() { FreeLibrary(h); }
    } cleanup{lib};
    auto open = win::proc<decltype(&WlanOpenHandle)>(lib, "WlanOpenHandle");
    auto close = win::proc<decltype(&WlanCloseHandle)>(lib, "WlanCloseHandle");
    auto interfaces = win::proc<decltype(&WlanEnumInterfaces)>(lib, "WlanEnumInterfaces");
    auto profiles = win::proc<decltype(&WlanGetProfileList)>(lib, "WlanGetProfileList");
    auto free = win::proc<decltype(&WlanFreeMemory)>(lib, "WlanFreeMemory");
    if (!open || !close || !interfaces || !profiles || !free)
        return {absent(id, name, "WLAN exports unavailable")};
    HANDLE h = nullptr;
    DWORD version = 0, e = open(2, nullptr, &version, &h);
    if (e == ERROR_SERVICE_NOT_ACTIVE)
        return {absent(id, name, "WLAN service is not active")};
    if (e)
        return {fail(id, name, win::last_error_message(e))};
    struct Client {
        HANDLE h;
        decltype(close) f;
        ~Client() { f(h, nullptr); }
    } client{h, close};
    WLAN_INTERFACE_INFO_LIST *list = nullptr;
    e = interfaces(h, nullptr, &list);
    if (e)
        return {fail(id, name, win::last_error_message(e))};
    unsigned total = 0;
    std::string failure;
    unsigned n = list->dwNumberOfItems;
    if (n > winlogic::kMaxRows) {
        free(list);
        return {fail(id, name, "WLAN interface limit exceeded")};
    }
    for (unsigned i = 0; i < n; ++i) {
        WLAN_PROFILE_INFO_LIST *p = nullptr;
        e = profiles(h, &list->InterfaceInfo[i].InterfaceGuid, nullptr, &p);
        if (e) {
            failure = win::last_error_message(e);
            break;
        }
        total += p->dwNumberOfItems;
        free(p);
    }
    free(list);
    if (!failure.empty())
        return {fail(id, name, failure)};
    if (!n)
        return {absent(id, name, "no wireless interfaces")};
    return {result(id, name, total == 0, counts(total))};
}
std::vector<Finding> shares(Context &, bool mapped) {
    const char *id = mapped ? "behavioural.mapped_drives" : "behavioural.network_shares",
               *name = mapped ? "Mapped drive count" : "Local share count";
    LPBYTE buffer = nullptr;
    DWORD read = 0, total = 0, resume = 0;
    NET_API_STATUS e = mapped
                           ? NetUseEnum(nullptr, 0, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume)
                           : NetShareEnum(nullptr, 1, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
    if (e != NERR_Success && e != ERROR_MORE_DATA) {
        if (buffer)
            NetApiBufferFree(buffer);
        if (e == NERR_ServerNotStarted || e == NERR_WkstaNotStarted || e == ERROR_NOT_SUPPORTED)
            return {absent(id, name, "Server/Workstation service is not running")};
        return {fail(id, name, win::last_error_message(e))};
    }
    DWORD user = read;
    if (!mapped && buffer) {
        // Administrative shares (C$, ADMIN$, IPC$) exist on every install; only user shares count.
        user = 0;
        auto *rows = reinterpret_cast<SHARE_INFO_1 *>(buffer);
        for (DWORD i = 0; i < read; ++i)
            user += (rows[i].shi1_type & STYPE_SPECIAL) == 0 && (rows[i].shi1_type & 0xff) != STYPE_IPC;
    }
    if (buffer)
        NetApiBufferFree(buffer);
    return {result(id, name, user == 0, counts(user).set("including_special", read))};
}
struct Human {
    std::vector<winlogic::Point> points;
    unsigned clicks = 0, keys = 0, foreground = 0, seconds = 0;
    std::string error;
    bool absent = false;
};
Human observe(Context &ctx) {
    static SRWLOCK lock = SRWLOCK_INIT;
    static Human cache;
    static bool ready = false;
    unsigned seconds = static_cast<unsigned>(std::clamp<long long>(
        ctx.param_int("human.wait_s", winlogic::kWaitSeconds), 1, winlogic::kMaxWaitSeconds));
    AcquireSRWLockShared(&lock);
    bool reuse = ready && cache.seconds == seconds;
    Human r = reuse ? cache : Human{};
    ReleaseSRWLockShared(&lock);
    if (reuse)
        return r;
    r.seconds = seconds;
    HDESK desk = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!desk) {
        r.absent = true;
        r.error = "interactive input desktop unavailable";
        return r;
    }
    CloseDesktop(desk);
    HWND previous = GetForegroundWindow();
    bool held[256]{};
    for (unsigned iteration = 0; iteration <= seconds * 1000 / winlogic::kSampleMs; ++iteration) {
        POINT p{};
        if (!GetCursorPos(&p)) {
            r.error = win::last_error_message();
            return r;
        }
        r.points.push_back({p.x, p.y});
        for (int key = 1; key < 256; ++key) {
            bool down = (GetAsyncKeyState(key) & 0x8000) != 0;
            if (iteration && down && !held[key]) {
                if (key == VK_LBUTTON || key == VK_RBUTTON || key == VK_MBUTTON)
                    ++r.clicks;
                else if (key >= VK_BACK)
                    ++r.keys;
            }
            held[key] = down;
        }
        HWND current = GetForegroundWindow();
        if (current != previous && current)
            ++r.foreground;
        previous = current;
        if (iteration < seconds * 1000 / winlogic::kSampleMs)
            Sleep(winlogic::kSampleMs);
    }
    AcquireSRWLockExclusive(&lock);
    cache = r;
    ready = true;
    ReleaseSRWLockExclusive(&lock);
    return r;
}
std::vector<Finding> human_wait(Context &ctx, const char *id, const char *name, int kind) {
    auto r = observe(ctx);
    if (r.absent)
        return {absent(id, name, r.error)};
    if (!r.error.empty())
        return {fail(id, name, r.error)};
    auto m = winlogic::motion(r.points, std::hypot(double(GetSystemMetrics(SM_CXVIRTUALSCREEN)),
                                                   double(GetSystemMetrics(SM_CYVIRTUALSCREEN))));
    bool hit = false;
    Ev ev = Ev().set("window_seconds", r.seconds);
    if (kind <= 2) {
        ev.set("moves", static_cast<unsigned long long>(m.moves))
            .set("unique_positions", static_cast<unsigned long long>(m.unique))
            .set("direction_entropy", m.entropy)
            .set("straight_segments", static_cast<unsigned long long>(m.straight))
            .set("teleports", static_cast<unsigned long long>(m.teleports));
        if (kind > 0 && m.moves < winlogic::kMinMotionSegments)
            return {absent(id, name, "not enough movement for a trajectory estimate")};
        hit = kind == 0   ? m.moves == 0
              : kind == 1 ? (m.entropy < winlogic::kLowEntropy && m.straight + 1 == m.moves)
                          : m.teleports > 0;
    } else {
        unsigned n = kind == 3 ? r.clicks : kind == 4 ? r.keys : r.foreground;
        ev.set("transitions", n);
        hit = n == 0;
    }
    return {result(id, name, hit, ev)};
}
std::vector<Finding> idle(Context &) {
    const char *id = "behavioural.input_idle", *name = "Input idle interval";
    LASTINPUTINFO li{};
    li.cbSize = sizeof li;
    if (!GetLastInputInfo(&li))
        return {fail(id, name, win::last_error_message())};
    DWORD seconds = (GetTickCount() - li.dwTime) / 1000; // modular arithmetic handles GetTickCount wrap
    return {result(id, name, seconds > winlogic::kIdleSeconds, Ev().set("idle_seconds", seconds))};
}
std::vector<Finding> visible_windows(Context &) {
    const char *id = "behavioural.visible_windows", *name = "Visible top-level windows";
    auto v = win::windows();
    if (!v.ok())
        return {fail(id, name, v.error)};
    unsigned n = 0;
    for (const auto &w : v.value)
        if (w.visible)
            ++n;
    return {result(id, name, n < winlogic::kMinVisibleWindows, counts(n))};
}

std::vector<Finding> usage_chrome_history(Context &ctx) {
    return browser_probe("behavioural.chrome_history", "Chrome history", 0, false);
}

std::vector<Finding> usage_chrome_cookies(Context &ctx) {
    return browser_probe("behavioural.chrome_cookies", "Chrome cookies", 0, true);
}

std::vector<Finding> usage_edge_history(Context &ctx) {
    return browser_probe("behavioural.edge_history", "Edge history", 1, false);
}

std::vector<Finding> usage_edge_cookies(Context &ctx) {
    return browser_probe("behavioural.edge_cookies", "Edge cookies", 1, true);
}

std::vector<Finding> usage_firefox_history(Context &ctx) {
    return browser_probe("behavioural.firefox_history", "Firefox history", 2, false);
}

std::vector<Finding> usage_firefox_cookies(Context &ctx) {
    return browser_probe("behavioural.firefox_cookies", "Firefox cookies", 2, true);
}

std::vector<Finding> usage_brave_history(Context &ctx) {
    return browser_probe("behavioural.brave_history", "Brave history", 3, false);
}

std::vector<Finding> usage_brave_cookies(Context &ctx) {
    return browser_probe("behavioural.brave_cookies", "Brave cookies", 3, true);
}

std::vector<Finding> usage_opera_history(Context &ctx) {
    return browser_probe("behavioural.opera_history", "Opera history", 4, false);
}

std::vector<Finding> usage_opera_cookies(Context &ctx) {
    return browser_probe("behavioural.opera_cookies", "Opera cookies", 4, true);
}

std::vector<Finding> usage_desktop(Context &ctx) {
    return user_files("behavioural.desktop_files", "desktop file count", 0);
}

std::vector<Finding> usage_documents(Context &ctx) {
    return user_files("behavioural.documents_files", "documents file count", 1);
}

std::vector<Finding> usage_downloads(Context &ctx) {
    return user_files("behavioural.downloads_files", "downloads file count", 2);
}

std::vector<Finding> usage_pictures(Context &ctx) {
    return user_files("behavioural.pictures_files", "pictures file count", 3);
}

std::vector<Finding> usage_recent_docs(Context &ctx) {
    return registry_count("behavioural.recent_docs", "recent docs", HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", true, 0);
}

std::vector<Finding> usage_run_mru(Context &ctx) {
    return registry_count("behavioural.run_mru", "run mru", HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", true, 0);
}

std::vector<Finding> usage_userassist(Context &ctx) {
    return registry_count("behavioural.userassist", "userassist", HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", true, 2);
}

std::vector<Finding> usage_muicache(Context &ctx) {
    return registry_count("behavioural.muicache", "muicache", HKEY_CURRENT_USER,
                          L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
                          true, 0);
}

std::vector<Finding> usage_shellbags(Context &ctx) {
    return registry_count("behavioural.shellbags", "shellbags", HKEY_CURRENT_USER,
                          L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                          false, 0);
}

std::vector<Finding> usage_typed_paths(Context &ctx) {
    return registry_count("behavioural.typed_paths", "typed paths", HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", true, 0);
}

std::vector<Finding> usage_usb_storage_history(Context &ctx) {
    return registry_count("behavioural.usb_storage_history", "usb storage history", HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", false, 1);
}

std::vector<Finding> usage_bluetooth_history(Context &ctx) {
    return registry_count("behavioural.bluetooth_history", "bluetooth history", HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices", false, 0);
}

std::vector<Finding> usage_prefetch(Context &ctx) {
    return directory_count("behavioural.prefetch", "prefetch", L"%WINDIR%\\Prefetch", false, L"*.pf");
}

std::vector<Finding> usage_temp_files(Context &ctx) {
    return directory_count("behavioural.temp_files", "temp files", L"%TEMP%", false, L"*");
}

std::vector<Finding> usage_recent_shortcuts(Context &ctx) {
    return directory_count("behavioural.recent_shortcuts", "recent shortcuts",
                           L"%APPDATA%\\Microsoft\\Windows\\Recent", false, L"*.lnk");
}

std::vector<Finding> usage_font_files(Context &ctx) {
    return directory_count("behavioural.font_files", "font files", L"%WINDIR%\\Fonts", false, L"*");
}

std::vector<Finding> usage_event_System(Context &ctx) {
    return event_log("behavioural.eventlog_system", "System event log age and count", L"System");
}

std::vector<Finding> usage_event_Application(Context &ctx) {
    return event_log("behavioural.eventlog_application", "Application event log age and count",
                     L"Application");
}

std::vector<Finding> usage_event_Security(Context &ctx) {
    return event_log("behavioural.eventlog_security", "Security event log age and count", L"Security");
}

// Event sources registered under Services\EventLog\System and \Application. al-khaser
// vbox_eventlogfile_wmi reads the same list through Win32_NTEventlogFile.Sources.
std::vector<Finding> event_sources(const char *id, const char *name, const std::vector<std::string> &tokens) {
    std::vector<std::string> hits;
    size_t examined = 0;
    for (const wchar_t *log : {L"System", L"Application"}) {
        auto v = win::registry_names(HKEY_LOCAL_MACHINE,
                                     std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\") + log);
        if (!v.ok())
            return {fail(id, name, v.error)};
        for (const auto &source : v.value) {
            ++examined;
            auto sig = winlogic::match(win::narrow(source), tokens, true);
            if (!sig.empty())
                hits.push_back(win::narrow(log) + ": " + sig);
        }
    }
    return {result(id, name, !hits.empty(), matched(hits, examined), Severity::High, 0.85,
                   "Uninstall the guest tools whose drivers registered these event sources, or remove the "
                   "stale source keys from the golden image.")};
}
std::vector<Finding> usage_vmware_events(Context &ctx) {
    return event_sources("env.vmware_event_logs", "VMware event log sources",
                         {"VMware Tools", "vmtools", "vmci", "vmhgfs", "vmmouse", "vmusbmouse", "vm3dmp",
                          "vmmemctl", "vmrawdsk", "vmxnet", "vmxnet3ndis6", "vsepflt", "VGAuth"});
}
std::vector<Finding> usage_vbox_events(Context &ctx) {
    return event_sources("env.vbox_eventlogfile", "VirtualBox event log sources",
                         {"vboxvideo", "VBoxVideoW8", "VBoxWddm", "VBoxGuest", "VBoxSF", "VBoxMouse",
                          "VBoxService"});
}

std::vector<Finding> usage_mouse_movement(Context &ctx) {
    return human_wait(ctx, "behavioural.mouse_movement", "mouse movement", 0);
}

std::vector<Finding> usage_mouse_straight_lines(Context &ctx) {
    return human_wait(ctx, "behavioural.mouse_straight_lines", "mouse straight lines", 1);
}

std::vector<Finding> usage_mouse_teleports(Context &ctx) {
    return human_wait(ctx, "behavioural.mouse_teleports", "mouse teleports", 2);
}

std::vector<Finding> usage_mouse_clicks(Context &ctx) {
    return human_wait(ctx, "behavioural.mouse_clicks", "mouse clicks", 3);
}

std::vector<Finding> usage_keyboard_activity(Context &ctx) {
    return human_wait(ctx, "behavioural.keyboard_activity", "keyboard activity", 4);
}

std::vector<Finding> usage_foreground_changes(Context &ctx) {
    return human_wait(ctx, "behavioural.foreground_changes", "foreground changes", 5);
}

std::vector<Finding> usage_guest_install(Context &ctx) { return installed_signatures(ctx, true); }

std::vector<Finding> usage_tools_install(Context &ctx) { return installed_signatures(ctx, false); }

std::vector<Finding> usage_shares(Context &ctx) { return shares(ctx, false); }

std::vector<Finding> usage_mapped(Context &ctx) { return shares(ctx, true); }
} // namespace
PERDEDOR_REGISTER(browser_history, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.browser_history");
PERDEDOR_REGISTER(aged_files, "wear_and_tear.user_files", "medium", false, "behavioural.aged_files");
PERDEDOR_REGISTER(installed_programs, "wear_and_tear.installed_software", "medium", false,
                  "behavioural.installed_programs");
PERDEDOR_REGISTER(program_dates, "wear_and_tear.installed_software", "medium", false,
                  "behavioural.program_install_spread");
PERDEDOR_REGISTER(fonts, "wear_and_tear.fonts", "fast", false, "behavioural.font_count");
PERDEDOR_REGISTER(process_count, "wear_and_tear.process_count", "fast", false,
                  "behavioural.running_process_count");
PERDEDOR_REGISTER(profile_age, "wear_and_tear.system_age", "fast", false, "behavioural.profile_age");
PERDEDOR_REGISTER(recycle, "wear_and_tear.usage_traces", "medium", false, "behavioural.recycle_bin");
PERDEDOR_REGISTER(clipboard, "wear_and_tear.usage_traces", "fast", false, "behavioural.clipboard_formats");
PERDEDOR_REGISTER(wifi_profiles, "wear_and_tear.network_history", "medium", false,
                  "behavioural.wifi_profiles");
PERDEDOR_REGISTER(idle, "human.idle_time", "fast", false, "behavioural.input_idle");
PERDEDOR_REGISTER(visible_windows, "human.foreground_activity", "fast", false, "behavioural.visible_windows");
PERDEDOR_REGISTER(usage_chrome_history, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.chrome_history");
PERDEDOR_REGISTER(usage_chrome_cookies, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.chrome_cookies");
PERDEDOR_REGISTER(usage_edge_history, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.edge_history");
PERDEDOR_REGISTER(usage_edge_cookies, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.edge_cookies");
PERDEDOR_REGISTER(usage_firefox_history, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.firefox_history");
PERDEDOR_REGISTER(usage_firefox_cookies, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.firefox_cookies");
PERDEDOR_REGISTER(usage_brave_history, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.brave_history");
PERDEDOR_REGISTER(usage_brave_cookies, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.brave_cookies");
PERDEDOR_REGISTER(usage_opera_history, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.opera_history");
PERDEDOR_REGISTER(usage_opera_cookies, "wear_and_tear.browser_history", "medium", false,
                  "behavioural.opera_cookies");
PERDEDOR_REGISTER(usage_desktop, "wear_and_tear.user_files", "medium", false, "behavioural.desktop_files");
PERDEDOR_REGISTER(usage_documents, "wear_and_tear.user_files", "medium", false,
                  "behavioural.documents_files");
PERDEDOR_REGISTER(usage_downloads, "wear_and_tear.user_files", "medium", false,
                  "behavioural.downloads_files");
PERDEDOR_REGISTER(usage_pictures, "wear_and_tear.user_files", "medium", false, "behavioural.pictures_files");
PERDEDOR_REGISTER(usage_recent_docs, "wear_and_tear.recent_files", "medium", false,
                  "behavioural.recent_docs");
PERDEDOR_REGISTER(usage_run_mru, "wear_and_tear.recent_files", "medium", false, "behavioural.run_mru");
PERDEDOR_REGISTER(usage_userassist, "wear_and_tear.usage_traces", "medium", false, "behavioural.userassist");
PERDEDOR_REGISTER(usage_muicache, "wear_and_tear.usage_traces", "medium", false, "behavioural.muicache");
PERDEDOR_REGISTER(usage_shellbags, "wear_and_tear.usage_traces", "medium", false, "behavioural.shellbags");
PERDEDOR_REGISTER(usage_typed_paths, "wear_and_tear.recent_files", "medium", false,
                  "behavioural.typed_paths");
PERDEDOR_REGISTER(usage_usb_storage_history, "wear_and_tear.peripherals_history", "medium", false,
                  "behavioural.usb_storage_history");
PERDEDOR_REGISTER(usage_bluetooth_history, "wear_and_tear.peripherals_history", "medium", false,
                  "behavioural.bluetooth_history");
PERDEDOR_REGISTER(usage_prefetch, "wear_and_tear.usage_traces", "medium", false, "behavioural.prefetch");
PERDEDOR_REGISTER(usage_temp_files, "wear_and_tear.user_files", "medium", false, "behavioural.temp_files");
PERDEDOR_REGISTER(usage_recent_shortcuts, "wear_and_tear.recent_files", "medium", false,
                  "behavioural.recent_shortcuts");
PERDEDOR_REGISTER(usage_font_files, "wear_and_tear.fonts", "medium", false, "behavioural.font_files");
PERDEDOR_REGISTER(usage_event_System, "wear_and_tear.system_logs", "medium", false,
                  "behavioural.eventlog_system");
PERDEDOR_REGISTER(usage_event_Application, "wear_and_tear.system_logs", "medium", false,
                  "behavioural.eventlog_application");
PERDEDOR_REGISTER(usage_event_Security, "wear_and_tear.system_logs", "medium", false,
                  "behavioural.eventlog_security");
PERDEDOR_REGISTER(usage_vmware_events, "artifacts.registry", "fast", false, "env.vmware_event_logs");
PERDEDOR_REGISTER(usage_vbox_events, "artifacts.registry", "fast", false, "env.vbox_eventlogfile");
PERDEDOR_REGISTER(usage_mouse_movement, "human.mouse_activity", "slow", false, "behavioural.mouse_movement");
PERDEDOR_REGISTER(usage_mouse_straight_lines, "human.mouse_activity", "slow", false,
                  "behavioural.mouse_straight_lines");
PERDEDOR_REGISTER(usage_mouse_teleports, "human.mouse_activity", "slow", false,
                  "behavioural.mouse_teleports");
PERDEDOR_REGISTER(usage_mouse_clicks, "human.clicks_keyboard", "slow", false, "behavioural.mouse_clicks");
PERDEDOR_REGISTER(usage_keyboard_activity, "human.clicks_keyboard", "slow", false,
                  "behavioural.keyboard_activity");
PERDEDOR_REGISTER(usage_foreground_changes, "human.foreground_activity", "slow", false,
                  "behavioural.foreground_changes");
PERDEDOR_REGISTER(usage_guest_install, "guest_tools.services", "medium", false,
                  "env.guest_additions_installed");
PERDEDOR_REGISTER(usage_tools_install, "analysis_tools.files", "medium", false,
                  "design.analysis_tools_installed");
PERDEDOR_REGISTER(usage_shares, "wear_and_tear.network_history", "medium", false,
                  "behavioural.network_shares");
PERDEDOR_REGISTER(usage_mapped, "wear_and_tear.network_history", "medium", false,
                  "behavioural.mapped_drives");
} // namespace perdedor
