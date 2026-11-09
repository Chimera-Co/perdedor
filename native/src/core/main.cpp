// perdedor (native agent) command line.
//
//   perdedor [-o FILE] [--profile quick|standard|deep] [--only PAT ...] [--skip PAT ...]
//            [--param KEY=VALUE ...] [--no-network] [--list-checks] [--pretty] [--version]
//            [--args-file FILE]   (one argument per line; '#' starts a comment line)
//
// Lists accept repeated flags or comma-separated values. The JSON report goes to
// FILE or stdout; a one-line summary goes to stderr.
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "perdedor.hpp"

using namespace perdedor;

static void split_into(const std::string& arg, std::vector<std::string>& out) {
    size_t start = 0;
    while (start <= arg.size()) {
        size_t comma = arg.find(',', start);
        std::string part = arg.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        if (!part.empty()) out.push_back(part);
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
}

static std::string iso_now() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

static int usage(const char* why) {
    if (why) std::fprintf(stderr, "perdedor: %s\n", why);
    std::fprintf(stderr,
                 "usage: perdedor [-o FILE] [--profile quick|standard|deep] [--only PATTERN ...]\n"
                 "                [--skip PATTERN ...] [--param KEY=VALUE ...] [--no-network]\n"
                 "                [--list-checks] [--pretty] [--version] [--args-file FILE]\n"
                 "PATTERN: id glob (win.timing.*) or class:X, category:X, technique:X, cost:X, tag:X\n");
    return 2;
}

// Expands --args-file FILE into the arguments it lists (one per line, '#' comment lines and blank
// lines ignored). Hosts use it to pass long selections that would not fit a guest command line.
static bool expand_args(int argc, char** argv, std::vector<std::string>& out, std::string& err) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a != "--args-file") {
            out.push_back(a);
            continue;
        }
        if (++i >= argc) {
            err = "--args-file needs a file";
            return false;
        }
        std::ifstream in(argv[i], std::ios::binary);
        if (!in) {
            err = std::string("cannot read args file ") + argv[i];
            return false;
        }
        std::string line;
        bool first = true;
        while (std::getline(in, line)) {
            if (first && line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB && static_cast<unsigned char>(line[2]) == 0xBF)
                line.erase(0, 3);  // UTF-8 byte order mark
            first = false;
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
            size_t start = line.find_first_not_of(" \t");
            if (start == std::string::npos || line[start] == '#') continue;
            out.push_back(line.substr(start));
        }
    }
    return true;
}

int main(int argc, char** argv) {
    std::vector<std::string> args;
    {
        std::string err;
        if (!expand_args(argc, argv, args, err)) return usage(err.c_str());
    }
    std::string output, profile = "standard";
    std::vector<std::string> only, skip;
    std::map<std::string, std::string> params;
    bool network = true, list = false, pretty = false;
    std::vector<std::string>* current = nullptr;  // list flag consuming following values
    bool current_is_param = false;

    const int nargs = static_cast<int>(args.size());
    for (int i = 0; i < nargs; ++i) {
        std::string a = args[i];
        bool is_flag = a.size() > 1 && a[0] == '-' && !(a.size() > 1 && (std::isdigit(static_cast<unsigned char>(a[1]))));
        if (!is_flag && (current || current_is_param)) {
            if (current_is_param) {
                std::vector<std::string> pairs;
                split_into(a, pairs);
                for (auto& p : pairs) {
                    auto eq = p.find('=');
                    if (eq == std::string::npos || eq == 0) return usage(("--param expects key=value, got '" + p + "'").c_str());
                    params[p.substr(0, eq)] = p.substr(eq + 1);
                }
            } else {
                split_into(a, *current);
            }
            continue;
        }
        current = nullptr;
        current_is_param = false;
        if (a == "-o" || a == "--output") {
            if (++i >= nargs) return usage("-o needs a file");
            output = args[i];
        } else if (a == "--profile") {
            if (++i >= nargs) return usage("--profile needs a value");
            profile = args[i];
        } else if (a == "--only") {
            current = &only;
        } else if (a == "--skip") {
            current = &skip;
        } else if (a == "--param") {
            current_is_param = true;
        } else if (a == "--no-network") {
            network = false;
        } else if (a == "--list-checks") {
            list = true;
        } else if (a == "--pretty") {
            pretty = true;
        } else if (a == "--version") {
            std::printf("perdedor %s (%s)\n", kVersion, platform::name());
            return 0;
        } else if (a == "-h" || a == "--help") {
            usage(nullptr);
            return 0;
        } else {
            return usage(("unknown argument " + a).c_str());
        }
    }

    std::vector<const CheckSpec*> chosen;
    try {
        chosen = select_checks(Registry::instance().all(), profile, only, skip, network);
    } catch (const std::exception& e) {
        return usage(e.what());
    }

    if (list) {
        Json arr = Json::array();
        for (const auto* c : chosen) {
            Json j = Json::object();
            j.set("ids", Json(c->ids));
            j.set("technique", c->technique);
            j.set("class", c->klass);
            j.set("category", c->category);
            j.set("cost", c->cost);
            j.set("network", c->network);
            j.set("tags", Json(c->tags));
            arr.push(j);
        }
        std::cout << arr.dump(2) << "\n";
        std::cout.flush();
        platform::hard_exit(0);
    }

    Context ctx;
    ctx.profile = profile;
    ctx.params = params;
    ctx.network = network;
    std::vector<Finding> findings = run_checks(chosen, ctx);

    Json report = Json::object();
    report.set("schema_version", 2);
    report.set("perdedor_version", kVersion);
    report.set("platform", platform::name());
    report.set("hostname", platform::hostname());
    report.set("generated_at", iso_now());
    Json meta = platform::metadata();
    meta.set("agent", "native");
    report.set("agent_metadata", meta);
    Json sel = Json::object();
    sel.set("profile", profile);
    sel.set("only", Json(only));
    sel.set("skip", Json(skip));
    Json pj = Json::object();
    for (const auto& kv : params) pj.set(kv.first, kv.second);
    sel.set("params", pj);
    sel.set("network", network);
    report.set("selection", sel);
    Json arr = Json::array();
    for (const auto& f : findings) arr.push(finding_json(f));
    report.set("findings", arr);
    Json summary = summary_of(findings);
    report.set("summary", summary);

    std::string text = report.dump(pretty || output.empty() ? 2 : -1);
    if (!output.empty()) {
        std::ofstream out(output, std::ios::binary);
        out << text << "\n";
        out.close();
        if (!out) {
            std::fprintf(stderr, "perdedor: could not write %s\n", output.c_str());
            platform::hard_exit(1);
        }
        std::fprintf(stderr, "Wrote report to %s\n", output.c_str());
    } else {
        std::cout << text << "\n";
        std::cout.flush();
    }
    // The exposure score needs the catalog, which lives on the analyst host: point there.
    std::fprintf(stderr,
                 "PERDEDOR %s scan: %s clean, %g detected (%g errored, %g skipped). "
                 "Exposure score: perdedor score <report.json>\n",
                 platform::name(), summary["raw_score"].str().c_str(), summary["detected"].number(),
                 summary["errored"].number(), summary["skipped"].number());
    std::fflush(stderr);
    // Abandoned (timed-out) probe threads must not keep the process alive.
    platform::hard_exit(0);
}
