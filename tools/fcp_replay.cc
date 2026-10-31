// fcp_replay: offline controller replay (FCP_M3_CONTROL.md §5, #28).
//
// Loads a JSONL controller trace recorded by a live session (SessionConfig::
// trace) and re-runs the reports through a fresh FecStrategy built from the
// trace's config snapshot, with any option on this command line overriding
// that snapshot. Prints the candidate's k trajectory summary and how much it
// agrees with the recording — the calibration loop of spec §14.1 without
// touching a live link.
//
// usage: fcp_replay --trace=FILE [--d=N] [--p-max=N] [--target=F]
//                   [--budget=F] [--initial-k=N] [--pinned=N]
//                   [--dump] [--require-exact]

#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "fcp/trace.h"

namespace {

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

bool ParseLong(const char* name, const std::string& text, long lo, long hi,
               long* out) {
  char* end = nullptr;
  errno = 0;
  const long v = std::strtol(text.c_str(), &end, 10);
  if (text.empty() || errno != 0 || end == text.c_str() || *end != '\0' ||
      v < lo || v > hi) {
    std::fprintf(stderr, "bad --%s value '%s' (want %ld..%ld)\n", name,
                 text.c_str(), lo, hi);
    return false;
  }
  *out = v;
  return true;
}

bool ParseDouble(const char* name, const std::string& text, double* out) {
  char* end = nullptr;
  const double v = std::strtod(text.c_str(), &end);
  if (text.empty() || end == text.c_str() || *end != '\0' || !std::isfinite(v)) {
    std::fprintf(stderr, "bad --%s value '%s'\n", name, text.c_str());
    return false;
  }
  *out = v;
  return true;
}

void Usage(const char* argv0) {
  std::printf(
      "usage: %s --trace=FILE [overrides] [--dump] [--require-exact]\n"
      "  --trace=FILE      JSONL controller trace (SessionConfig::trace)\n"
      "  --d=N             group size override (1..255)\n"
      "  --p-max=N         parity ceiling override (0..7)\n"
      "  --target=F        recovery target override (default 0.8)\n"
      "  --budget=F        byte-budget ratio override (0 = off)\n"
      "  --initial-k=N     warm-up k override (-1 = cold)\n"
      "  --pinned=N        pinned k override (-1 = adaptive)\n"
      "  --dump            print the per-report trajectory\n"
      "  --require-exact   exit 1 unless replay matches the recording\n",
      argv0);
}

}  // namespace

int main(int argc, char** argv) {
  std::map<std::string, std::string> opts;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      Usage(argv[0]);
      return 0;
    }
    if (arg == "--dump" || arg == "--require-exact") {
      opts[arg.substr(2)] = "1";
      continue;
    }
    const size_t eq = arg.find('=');
    if (arg.rfind("--", 0) != 0 || eq == std::string::npos) {
      std::fprintf(stderr, "bad argument: %s\n", arg.c_str());
      Usage(argv[0]);
      return 1;
    }
    opts[arg.substr(2, eq - 2)] = arg.substr(eq + 1);
  }
  const std::string* path = Find(opts, "trace");
  if (path == nullptr || path->empty()) {
    Usage(argv[0]);
    return 1;
  }

  std::vector<fcp::TraceEntry> entries;
  fcp::TraceConfigSnapshot snapshot{};
  size_t skipped = 0;
  bool have_snapshot = false;
  std::vector<std::string> lines;
  int read_err = 0;
  if (!ReadLines(path->c_str(), &lines, &read_err)) {
    std::fprintf(stderr, "cannot read trace %s: %s\n", path->c_str(),
                 std::strerror(read_err != 0 ? read_err : EIO));
    return 1;
  }
  for (const std::string& line : lines) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    fcp::TraceEntry e;
    if (!fcp::decode_trace_line(line, &e)) {
      ++skipped;
      continue;
    }
    if (!have_snapshot) {
      snapshot = e.snapshot;
      have_snapshot = true;
    }
    entries.push_back(e);
  }
  if (!have_snapshot) {
    std::fprintf(stderr, "no usable entries in %s\n", path->c_str());
    return 1;
  }

  if (const std::string* v = Find(opts, "d")) {
    long n = 0;
    if (!ParseLong("d", *v, 1, 255, &n)) {
      return 1;
    }
    snapshot.d = static_cast<uint8_t>(n);
  }
  if (const std::string* v = Find(opts, "p-max")) {
    long n = 0;
    if (!ParseLong("p-max", *v, 0, 7, &n)) {
      return 1;
    }
    snapshot.p_max = static_cast<uint8_t>(n);
  }
  if (const std::string* v = Find(opts, "target")) {
    if (!ParseDouble("target", *v, &snapshot.target_recovery)) {
      return 1;
    }
  }
  if (const std::string* v = Find(opts, "budget")) {
    if (!ParseDouble("budget", *v, &snapshot.budget)) {
      return 1;
    }
  }
  if (const std::string* v = Find(opts, "initial-k")) {
    long n = 0;
    if (!ParseLong("initial-k", *v, -1, 7, &n)) {
      return 1;
    }
    snapshot.initial_k = static_cast<int>(n);
  }
  if (const std::string* v = Find(opts, "pinned")) {
    long n = 0;
    if (!ParseLong("pinned", *v, -1, 7, &n)) {
      return 1;
    }
    snapshot.pinned = static_cast<int>(n);
  }

  const std::vector<fcp::ReplayStep> steps = fcp::replay_trace(entries, snapshot);

  uint32_t k_hist[8] = {};
  uint8_t k_max = 0;
  size_t capped = 0;
  for (const fcp::ReplayStep& s : steps) {
    ++k_hist[std::min<uint8_t>(s.k, 7)];
    k_max = std::max<uint8_t>(k_max, s.k);
    if (s.state == fcp::FecState::kCapped) {
      ++capped;
    }
  }
  size_t agree = 0;
  double ratio_peak = 0.0;
  for (size_t i = 0; i < entries.size(); ++i) {
    const fcp::TraceEntry& e = entries[i];
    if (e.stat.data_bytes_rx > 0) {
      const double ratio = static_cast<double>(e.stat.parity_bytes_rx) /
                           static_cast<double>(e.stat.data_bytes_rx);
      ratio_peak = std::max(ratio_peak, ratio);
    }
    if (steps[i].k == e.k_after && steps[i].state == e.state_after) {
      ++agree;
    }
    if (Find(opts, "dump") != nullptr) {
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
                  : static_cast<long long>(entries.back().now_ms - entries.front().now_ms));
  std::printf("config d=%u pmax=%u target=%.3f budget=%.3f ik=%d pinned=%d\n",
              snapshot.d, snapshot.p_max, snapshot.target_recovery,
              snapshot.budget, snapshot.initial_k, snapshot.pinned);
  std::printf("k final=%u max=%u capped=%zu hist", steps.back().k, k_max, capped);
  for (int k = 0; k < 8; ++k) {
    if (k_hist[k] != 0) {
      std::printf(" k%d=%u", k, k_hist[k]);
    }
  }
  std::printf("\n");
  std::printf("bytes ratio_peak=%.4f agree=%zu/%zu\n", ratio_peak, agree,
              entries.size());
  if (Find(opts, "require-exact") != nullptr && agree != entries.size()) {
    std::fprintf(stderr, "replay diverged: %zu/%zu steps match the recording\n",
                 agree, entries.size());
    return 1;
  }
  return 0;
}
