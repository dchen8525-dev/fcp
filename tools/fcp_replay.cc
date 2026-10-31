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
//                   [--budget=F] [--initial-k=N] [--pinned=N] [--dump]

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "fcp/trace.h"

namespace {

std::vector<std::string> ReadLines(const char* path) {
  std::vector<std::string> lines;
  std::FILE* f = std::fopen(path, "rb");
  if (f == nullptr) {
    return lines;
  }
  char buf[4096];
  while (std::fgets(buf, sizeof(buf), f) != nullptr) {
    std::string line(buf);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
      line.pop_back();
    }
    lines.push_back(line);
  }
  std::fclose(f);
  return lines;
}

const std::string* Find(const std::map<std::string, std::string>& opts,
                        const char* name) {
  const auto it = opts.find(name);
  return it == opts.end() ? nullptr : &it->second;
}

void Usage(const char* argv0) {
  std::printf(
      "usage: %s --trace=FILE [overrides] [--dump]\n"
      "  --trace=FILE      JSONL controller trace (SessionConfig::trace)\n"
      "  --d=N             group size override\n"
      "  --p-max=N         parity ceiling override\n"
      "  --target=F        recovery target override (default 0.8)\n"
      "  --budget=F        byte-budget ratio override (0 = off)\n"
      "  --initial-k=N     warm-up k override (-1 = cold)\n"
      "  --pinned=N        pinned k override (-1 = adaptive)\n"
      "  --dump            print the per-report trajectory\n",
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
  for (const std::string& line : ReadLines(path->c_str())) {
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
    snapshot.d = static_cast<uint8_t>(std::atoi(v->c_str()));
  }
  if (const std::string* v = Find(opts, "p-max")) {
    snapshot.p_max = static_cast<uint8_t>(std::atoi(v->c_str()));
  }
  if (const std::string* v = Find(opts, "target")) {
    snapshot.target_recovery = std::strtod(v->c_str(), nullptr);
  }
  if (const std::string* v = Find(opts, "budget")) {
    snapshot.budget = std::strtod(v->c_str(), nullptr);
  }
  if (const std::string* v = Find(opts, "initial-k")) {
    snapshot.initial_k = std::atoi(v->c_str());
  }
  if (const std::string* v = Find(opts, "pinned")) {
    snapshot.pinned = std::atoi(v->c_str());
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
  return 0;
}
