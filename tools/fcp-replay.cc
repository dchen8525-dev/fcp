// fcp-replay: offline controller replay (M3控制设计.md §5, #28).
//
// Loads a JSONL controller trace recorded by a live session (SessionConfig::
// trace) and re-runs the reports through a fresh FecStrategy built from the
// trace's config snapshot, with any option on this command line overriding
// that snapshot. Prints the candidate's k trajectory summary and how much it
// agrees with the recording — the calibration loop of spec §14.1 without
// touching a live link.
//
// usage: fcp-replay --trace=FILE [--d=N] [--p-max=N] [--target=F]
//                   [--budget=F] [--initial-k=N] [--k=N|--pinned=N]
//                   [--dump] [--require-exact]

#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "cli_parse.h"
#include "fcp/trace.h"

namespace {

// Range-checked numbers come from tools/cli_parse.h, the same code the proxy
// CLI and fcp-bench use; --k/--pinned below only differ in which flag they name.
using fcp::tools::ParseDouble;
using fcp::tools::ParseLong;

// P5-11: read errors must not look like an empty trace, and a line longer than
// the 4 KiB chunk must be reassembled instead of being split into bogus lines.
// P8' N5: the reassembly buffer needs a ceiling — one unterminated 2 GB line
// used to grow `pending` until std::bad_alloc escaped main().
bool ReadLines(const char* path, std::vector<std::string>* lines, int* err_out) {
  if (err_out != nullptr) {
    *err_out = 0;
  }
  std::FILE* f = std::fopen(path, "rb");
  if (f == nullptr) {
    if (err_out != nullptr) {
      *err_out = errno;
    }
    return false;
  }
  constexpr size_t kMaxLineBytes = 1u << 20;  // far above any real trace line
  char buf[4096];
  std::string pending;
  bool ok = true;
  while (std::fgets(buf, sizeof(buf), f) != nullptr) {
    pending += buf;
    if (pending.size() > kMaxLineBytes) {
      std::fprintf(stderr, "trace %s: line longer than %zu bytes, giving up\n", path,
                   kMaxLineBytes);
      ok = false;
      break;
    }
    if (!pending.empty() && pending.back() != '\n' && !std::feof(f)) {
      continue;
    }
    while (!pending.empty() && (pending.back() == '\n' || pending.back() == '\r')) {
      pending.pop_back();
    }
    lines->push_back(std::move(pending));
    pending.clear();
  }
  if (ok) {
    ok = std::ferror(f) == 0;
    if (!ok && err_out != nullptr) {
      // ferror does not promise a useful errno; keep the message honest.
      *err_out = errno != 0 ? errno : EIO;
    }
  } else if (err_out != nullptr) {
    *err_out = EOVERFLOW;
  }
  if (ok && !pending.empty()) {
    // A final line without a newline is still a line.
    lines->push_back(std::move(pending));
  }
  std::fclose(f);
  return ok;
}

const std::string* Find(const std::map<std::string, std::string>& opts,
                        const char* name) {
  const auto it = opts.find(name);
  return it == opts.end() ? nullptr : &it->second;
}

// Both are probabilities / ratios: target is compared against a CDF in
// [0,1], and a budget above 1 is the same dead setting the proxy CLI rejects
// (the controller clamps it to 1). A non-finite value must never reach the
// replay either.
constexpr double kRatioMin = 0.0;
constexpr double kRatioMax = 1.0;

void Usage(const char* argv0) {
  std::printf(
      "usage: %s --trace=FILE [overrides] [--dump] [--require-exact]\n"
      "  --trace=FILE      JSONL controller trace (SessionConfig::trace)\n"
      "  --d=N             group size override (1..255)\n"
      "  --p-max=N         parity ceiling override (0..7)\n"
      "  --target=F        recovery target override (default 0.8)\n"
      "  --budget=F        byte-budget ratio override (0 = off)\n"
      "  --initial-k=N     warm-up k override (-1 = cold)\n"
      "  --k=N             pinned parity override (-1 = adaptive; --pinned still works)\n"
      "  --dump            print the per-report trajectory\n"
      "  --require-exact   exit 1 unless replay matches the recording\n",
      argv0);
}

// Every spelling this tool understands. An unknown --name=value used to be
// stored in the map and silently ignored, so a typo (--targe=0.9) replayed the
// trace's recorded value while the operator believed it was overridden.
bool KnownOption(const std::string& name) {
  return name == "help" || name == "trace" || name == "d" || name == "p-max" ||
         name == "target" || name == "budget" || name == "initial-k" ||
         name == "pinned" || name == "k" || name == "dump" ||
         name == "require-exact";
}

// Split argv into "--name=value" pairs plus the three bare flags. -h/--help
// becomes "help" and is acted on by the caller.
bool CollectOptions(int argc, char** argv, const char* argv0,
                    std::map<std::string, std::string>* opts) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    std::string name;
    std::string value;
    if (arg == "-h" || arg == "--help") {
      // Help wins over values elsewhere in the line, as in the proxy CLI: a
      // stale option must not turn a diagnostic into a usage error.
      (*opts)["help"] = "1";
      return true;
    } else if (arg == "--dump" || arg == "--require-exact") {
      name = arg.substr(2);
      value = "1";
    } else {
      const size_t eq = arg.find('=');
      if (arg.rfind("--", 0) != 0 || eq == std::string::npos) {
        std::fprintf(stderr, "bad argument: %s\n", arg.c_str());
        Usage(argv0);
        return false;
      }
      name = arg.substr(2, eq - 2);
      value = arg.substr(eq + 1);
    }
    if (!KnownOption(name)) {
      std::fprintf(stderr, "unknown option: --%s\n", name.c_str());
      Usage(argv0);
      return false;
    }
    // Last-one-wins would hide a stale script. Repeating --help is harmless.
    if (name != "help" && opts->count(name) != 0) {
      std::fprintf(stderr, "--%s given more than once\n", name.c_str());
      return false;
    }
    (*opts)[name] = std::move(value);
  }
  return true;
}

// Reads the JSONL trace: blank and '#' lines are skipped, undecodable lines are
// counted and dropped, and the first decodable entry supplies the config
// snapshot the rest of the run is replayed against.
bool LoadTrace(const std::string& path, std::vector<fcp::TraceEntry>* entries,
               fcp::TraceConfigSnapshot* snapshot, size_t* skipped) {
  std::vector<std::string> lines;
  int read_err = 0;
  if (!ReadLines(path.c_str(), &lines, &read_err)) {
    std::fprintf(stderr, "cannot read trace %s: %s\n", path.c_str(),
                 std::strerror(read_err != 0 ? read_err : EIO));
    return false;
  }
  bool have_snapshot = false;
  for (const std::string& line : lines) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    fcp::TraceEntry e;
    if (!fcp::decode_trace_line(line, &e)) {
      ++*skipped;
      continue;
    }
    if (!have_snapshot) {
      *snapshot = e.snapshot;
      have_snapshot = true;
    }
    entries->push_back(e);
  }
  if (!have_snapshot) {
    std::fprintf(stderr, "no usable entries in %s\n", path.c_str());
    return false;
  }
  return true;
}

// Applies the command-line overrides on top of the trace's own snapshot.
// Each present option replaces one snapshot field; a malformed value is fatal.
bool ApplyOverrides(const std::map<std::string, std::string>& opts,
                    fcp::TraceConfigSnapshot* snapshot) {
  struct LongField {
    const char* name;
    long lo;
    long hi;
    uint8_t* u8;
    int* i32;
  };
  const LongField long_fields[] = {
      {"d", 1, 255, &snapshot->d, nullptr},
      {"p-max", 0, 7, &snapshot->p_max, nullptr},
      {"initial-k", -1, 7, nullptr, &snapshot->initial_k},
  };
  // --k is the name the engine, the proxy CLI and fcp-bench all use for the
  // pinned parity. --pinned predates them and keeps working; giving both is one
  // setting twice, and a silent last-one-wins would hide a stale script.
  const std::string* pinned = Find(opts, "pinned");
  const std::string* k = Find(opts, "k");
  if (pinned != nullptr && k != nullptr) {
    std::fprintf(stderr, "--k and --pinned are the same setting; give one of them\n");
    return false;
  }
  const char* pinned_name = "pinned";
  if (pinned == nullptr) {
    pinned = k;
    pinned_name = "k";
  }
  if (pinned != nullptr) {
    long n = 0;
    const std::string flag = std::string("--") + pinned_name;
    if (!ParseLong(flag.c_str(), pinned->c_str(), -1, 7, &n)) {
      return false;
    }
    snapshot->pinned = static_cast<int>(n);
  }
  for (const LongField& f : long_fields) {
    const std::string* v = Find(opts, f.name);
    if (v == nullptr) {
      continue;
    }
    long n = 0;
    const std::string flag = std::string("--") + f.name;
    if (!ParseLong(flag.c_str(), v->c_str(), f.lo, f.hi, &n)) {
      return false;
    }
    if (f.u8 != nullptr) {
      *f.u8 = static_cast<uint8_t>(n);
    } else {
      *f.i32 = static_cast<int>(n);
    }
  }
  if (const std::string* v = Find(opts, "target")) {
    if (!ParseDouble("--target", v->c_str(), kRatioMin, kRatioMax,
                     &snapshot->target_recovery)) {
      return false;
    }
  }
  if (const std::string* v = Find(opts, "budget")) {
    if (!ParseDouble("--budget", v->c_str(), kRatioMin, kRatioMax, &snapshot->budget)) {
      return false;
    }
  }
  // FecStrategy clamps both k values to p_max without saying so. Printing
  // "pinned=5" over a replay that actually ran at k<=p_max would calibrate
  // against a controller that was never simulated, so fail loudly instead --
  // the proxy CLI rejects the same combination rather than clamping it.
  const int ceiling = static_cast<int>(snapshot->p_max);
  if (snapshot->pinned > ceiling) {
    std::fprintf(stderr,
                 "pinned k=%d can never be honoured: p-max is %d (give --p-max=%d "
                 "or a k in -1..%d)\n",
                 snapshot->pinned, ceiling, snapshot->pinned, ceiling);
    return false;
  }
  // A pinned k owns the controller, so FecStrategy ignores initial_k entirely
  // (it sets it to -1); only complain about a warm-up value that would run.
  if (snapshot->pinned < 0 && snapshot->initial_k > ceiling) {
    std::fprintf(stderr,
                 "initial k=%d can never be honoured: p-max is %d (give --p-max=%d "
                 "or an initial k in -1..%d)\n",
                 snapshot->initial_k, ceiling, snapshot->initial_k, ceiling);
    return false;
  }
  return true;
}

// What the replay produced, summarised against the recording.
struct Summary {
  uint32_t k_hist[8] = {};
  uint8_t k_max = 0;
  size_t capped = 0;
  size_t agree = 0;
  double ratio_peak = 0.0;
};

Summary Summarise(const std::vector<fcp::TraceEntry>& entries,
                  const std::vector<fcp::ReplayStep>& steps) {
  Summary s;
  for (const fcp::ReplayStep& step : steps) {
    ++s.k_hist[std::min<uint8_t>(step.k, 7)];
    s.k_max = std::max(s.k_max, step.k);
    if (step.state == fcp::FecState::kCapped) {
      ++s.capped;
    }
  }
  for (size_t i = 0; i < entries.size(); ++i) {
    const fcp::TraceEntry& e = entries[i];
    if (e.stat.data_bytes_rx > 0) {
      const double ratio = static_cast<double>(e.stat.parity_bytes_rx) /
                           static_cast<double>(e.stat.data_bytes_rx);
      s.ratio_peak = std::max(s.ratio_peak, ratio);
    }
    if (steps[i].k == e.k_after && steps[i].state == e.state_after) {
      ++s.agree;
    }
  }
  return s;
}

}  // namespace

// Runs the replay and prints the candidate's k trajectory against the
// recording. --require-exact turns "mostly agrees" into a hard failure: the
// golden trace uses it so a drifting controller can never pass silently.
int main(int argc, char** argv) {
  std::map<std::string, std::string> opts;
  if (!CollectOptions(argc, argv, argv[0], &opts)) {
    return 1;
  }
  if (Find(opts, "help") != nullptr) {
    Usage(argv[0]);
    return 0;
  }
  const std::string* path = Find(opts, "trace");
  if (path == nullptr || path->empty()) {
    Usage(argv[0]);
    return 1;
  }

  std::vector<fcp::TraceEntry> entries;
  fcp::TraceConfigSnapshot snapshot{};
  size_t skipped = 0;
  if (!LoadTrace(*path, &entries, &snapshot, &skipped)) {
    return 1;
  }
  if (!ApplyOverrides(opts, &snapshot)) {
    return 1;
  }

  // One ReplayStep per TraceEntry, in the same order (trace.cc replay_trace
  // reserves entries.size()). Summarise() reads steps[i] by entry and
  // steps.back(); both rely on that 1:1 mapping, so assert it here rather than
  // trusting the callee forever.
  const std::vector<fcp::ReplayStep> steps = fcp::replay_trace(entries, snapshot);
  if (steps.size() != entries.size()) {
    std::fprintf(stderr, "internal: replay produced %zu steps for %zu entries\n",
                 steps.size(), entries.size());
    return 1;
  }

  const Summary s = Summarise(entries, steps);
  if (Find(opts, "dump") != nullptr) {
    for (size_t i = 0; i < entries.size(); ++i) {
      const fcp::TraceEntry& e = entries[i];
      std::printf("now=%lld k=%u state=%s (recorded k=%u %s)\n",
                  static_cast<long long>(e.now_ms), steps[i].k,
                  fcp::fec_state_name(steps[i].state), e.k_after,
                  fcp::fec_state_name(e.state_after));
    }
  }

  std::printf("trace=%s entries=%zu skipped=%zu span_ms=%lld\n", path->c_str(),
              entries.size(), skipped,
              entries.empty()
                  ? 0LL
                  : static_cast<long long>(entries.back().now_ms -
                                           entries.front().now_ms));
  std::printf("config d=%u pmax=%u target=%.3f budget=%.3f ik=%d pinned=%d\n",
              snapshot.d, snapshot.p_max, snapshot.target_recovery,
              snapshot.budget, snapshot.initial_k, snapshot.pinned);
  std::printf("k final=%u max=%u capped=%zu hist", steps.back().k, s.k_max,
              s.capped);
  for (int k = 0; k < 8; ++k) {
    if (s.k_hist[k] != 0) {
      std::printf(" k%d=%u", k, s.k_hist[k]);
    }
  }
  std::printf("\n");
  std::printf("bytes ratio_peak=%.4f agree=%zu/%zu\n", s.ratio_peak, s.agree,
              entries.size());
  if (Find(opts, "require-exact") != nullptr && s.agree != entries.size()) {
    std::fprintf(stderr, "replay diverged: %zu/%zu steps match the recording\n",
                 s.agree, entries.size());
    return 1;
  }
  return 0;
}
