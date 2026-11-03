// #28 controller trace + offline replay (M3控制设计.md §5, T39).
//
// The recording side is a two-session in-memory link with injectable loss
// (same shape as session_test's Link, trimmed to one data direction). The
// recorded trace of A's controller goes through encode -> decode ->
// replay_trace: the replay must reproduce the recording exactly, and the
// 5/10/20% + GE profiles must land where the roadmap's M3 acceptance puts
// them ("k 稳定、预算不超").

#include "fcp/trace.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "fcp/session.h"
#include "test_util.h"

namespace {

constexpr uint8_t kKey[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                              9, 10, 11, 12, 13, 14, 15, 16};
constexpr uint8_t kSalt[8] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};

std::vector<uint8_t> Segment(uint32_t sn) {
  std::vector<uint8_t> out(16 + 12, 0);
  out[12] = static_cast<uint8_t>(sn);
  out[13] = static_cast<uint8_t>(sn >> 8);
  out[14] = static_cast<uint8_t>(sn >> 16);
  out[15] = static_cast<uint8_t>(sn >> 24);
  for (size_t i = 16; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(sn * 31 + i * 7);
  }
  return out;
}

// One-directional lossy link: A sends data, B acknowledges; FECSTAT reports
// flow back so A's controller sees B's view of A's traffic. Loss applies to
// data and parity alike (the i.i.d. arms) or to data only in GE stretches —
// parity must survive for the ledger path to be exercised at all (#26).
struct Link {
  fcp::Session* a = nullptr;
  fcp::Session* b = nullptr;
  bool loss_enabled = false;
  uint32_t loss_percent = 20;
  bool ge_enabled = false;
  uint32_t ge_g2b = 3;
  uint32_t ge_b2g = 22;
  bool ge_bad = false;
  uint32_t rng = 0x9E3779B9u;
  int64_t now = 0;
  uint64_t sent = 0;
  std::vector<fcp::TraceEntry> trace;

  bool drop(fcp::SymbolType type) {
    if (type != fcp::SymbolType::kData && type != fcp::SymbolType::kParity) {
      return false;
    }
    if (ge_enabled && type == fcp::SymbolType::kParity) {
      return false;
    }
    if (!loss_enabled && !ge_enabled) {
      return false;
    }
    rng = rng * 1103515245u + 12345u;
    if (ge_enabled) {
      const uint32_t t = (rng >> 16) % 100;
      if (ge_bad) {
        if (t < ge_b2g) {
          ge_bad = false;
        }
      } else if (t < ge_g2b) {
        ge_bad = true;
      }
      rng = rng * 1103515245u + 12345u;
      return ge_bad;
    }
    return ((rng >> 16) % 100) < loss_percent;
  }

  void from_a(const uint8_t* wire, size_t len, fcp::SymbolType type) {
    ++sent;
    if (drop(type)) {
      return;
    }
    b->on_wire(wire, len, now);
  }

  void from_b(const uint8_t* wire, size_t len, fcp::SymbolType type) {
    (void)type;
    a->on_wire(wire, len, now);
  }
};

// Runs one recording arm and returns A's controller trace.
std::vector<fcp::TraceEntry> RecordArm(bool ge, uint32_t loss_percent,
                                       uint32_t segments,
                                       int initial_k = -1) {
  Link link;
  if (ge) {
    link.ge_enabled = true;
  } else {
    link.loss_enabled = true;
    link.loss_percent = loss_percent;
  }
  fcp::SessionConfig cfg_a;
  std::memcpy(cfg_a.key, kKey, sizeof(kKey));
  std::memcpy(cfg_a.salt, kSalt, sizeof(kSalt));
  cfg_a.send_direction = fcp::Direction::kC2S;
  cfg_a.recv_direction = fcp::Direction::kS2C;
  cfg_a.p = 4;  // P' = 4, so k_for(0.20) can reach its 4 answer
  cfg_a.initial_k = initial_k;
  cfg_a.trace = [&link](const fcp::TraceEntry& e) { link.trace.push_back(e); };
  fcp::SessionConfig cfg_b;
  std::memcpy(cfg_b.key, kKey, sizeof(kKey));
  std::memcpy(cfg_b.salt, kSalt, sizeof(kSalt));
  cfg_b.send_direction = fcp::Direction::kS2C;
  cfg_b.recv_direction = fcp::Direction::kC2S;
  cfg_b.p = 4;

  fcp::Session a(cfg_a,
                 [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                   link.from_a(w, n, t);
                 },
                 [](const uint8_t*, size_t) {}, [](const std::string&) {});
  std::vector<uint8_t> delivered;
  fcp::Session b(cfg_b,
                 [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                   link.from_b(w, n, t);
                 },
                 [&delivered](const uint8_t* p, size_t n) {
                   delivered.insert(delivered.end(), p, p + n);
                 },
                 [](const std::string&) {});
  link.a = &a;
  link.b = &b;
  CHECK(a.config_valid());
  CHECK(b.config_valid());
  a.start(0);
  b.start(0);
  a.on_tick(0);
  b.on_tick(0);
  CHECK(a.established());
  CHECK(b.established());

  // Sends and ticks interleave: reports must reach the controller while
  // traffic is still flowing (#26's lesson).
  uint32_t sn = 0;
  for (int64_t t = fcp::kSessionTickMs; t <= 15000; t += fcp::kSessionTickMs) {
    link.now = t;
    while (sn < segments && 100 + static_cast<int64_t>(sn) <= t) {
      const std::vector<uint8_t> seg = Segment(sn);
      a.on_kcp_output(seg.data(), seg.size(), link.now);
      ++sn;
    }
    a.on_tick(t);
    b.on_tick(t);
  }
  CHECK_EQ(sn, segments);
  CHECK(!link.trace.empty());
  return link.trace;
}

void TestRoundTrip() {
  fcp::TraceEntry e;
  e.now_ms = 4210;
  e.window_queued = true;
  e.stat = fcp::MakeFecstatPacket(kSalt);
  e.stat.accounted_through_set_id = 912u;
  e.stat.data_expected = 1964u;
  e.stat.data_rx_orig = 1796u;
  e.stat.data_recovered_dl = 51u;
  e.stat.parity_expected = 400u;
  e.stat.flg = fcp::kFlgDirection | fcp::kFlgLedger;
  e.stat.ledger_groups = 180u;
  e.stat.ledger_fail_ppm = 172222u;
  e.stat.ledger_meta = 2u | (105u << 16);  // dominant k=2, kl=1.05 nat
  e.snapshot = fcp::TraceConfigSnapshot{10, 4, 0.80, 0.50, 2, -1};
  e.k_after = 3;
  e.state_after = fcp::FecState::kOn;
  e.last_loss = 0.0966;

  std::string line;
  fcp::encode_trace_line(e, &line);
  fcp::TraceEntry back;
  CHECK(fcp::decode_trace_line(line, &back));
  CHECK_EQ(back.now_ms, e.now_ms);
  CHECK(back.window_queued);
  CHECK_EQ(back.stat.accounted_through_set_id, e.stat.accounted_through_set_id);
  CHECK_EQ(back.stat.data_expected, e.stat.data_expected);
  CHECK_EQ(back.stat.data_rx_orig, e.stat.data_rx_orig);
  CHECK_EQ(back.stat.data_recovered_dl, e.stat.data_recovered_dl);
  CHECK_EQ(back.stat.parity_expected, e.stat.parity_expected);
  CHECK_EQ(back.stat.flg, e.stat.flg);
  CHECK_EQ(back.stat.ledger_groups, e.stat.ledger_groups);
  CHECK_EQ(back.stat.ledger_fail_ppm, e.stat.ledger_fail_ppm);
  CHECK_EQ(back.stat.ledger_meta, e.stat.ledger_meta);
  CHECK_EQ(back.snapshot.d, 10);
  CHECK_EQ(back.snapshot.p_max, 4);
  CHECK(std::fabs(back.snapshot.target_recovery - 0.80) < 1e-12);
  CHECK(std::fabs(back.snapshot.budget - 0.50) < 1e-12);
  CHECK_EQ(back.snapshot.initial_k, 2);
  CHECK_EQ(back.snapshot.pinned, -1);
  CHECK_EQ(back.k_after, 3);
  CHECK(back.state_after == fcp::FecState::kOn);
  CHECK(std::fabs(back.last_loss - e.last_loss) < 1e-9);

  // Malformed lines are rejected, not half-parsed.
  fcp::TraceEntry junk;
  CHECK(!fcp::decode_trace_line("", &junk));
  CHECK(!fcp::decode_trace_line("{\"ver\":1", &junk));
  CHECK(!fcp::decode_trace_line("{\"ver\":2}", &junk));
  CHECK(!fcp::decode_trace_line("not json at all", &junk));
  // Unknown keys are skipped (forward compatibility).
  std::string extended = line;
  extended.insert(extended.size() - 1, ",\"future_thing\":77");
  CHECK(fcp::decode_trace_line(extended, &back));
  CHECK_EQ(back.stat.ledger_groups, e.stat.ledger_groups);
}

// The whole point: replaying a trace with its own snapshot reproduces the
// recording decision-for-decision.
void TestReplayReproducesRecorded() {
  const auto trace = RecordArm(false, 10, 8000);
  CHECK(trace.size() >= 4);
  fcp::TraceConfigSnapshot snapshot = trace.front().snapshot;
  const auto steps = fcp::replay_trace(trace, snapshot);
  CHECK_EQ(steps.size(), trace.size());
  for (size_t i = 0; i < steps.size(); ++i) {
    if (steps[i].k != trace[i].k_after ||
        steps[i].state != trace[i].state_after) {
      std::fprintf(stderr, "step %zu: replay k=%u/%d recorded k=%u/%d\n", i,
                   steps[i].k, static_cast<int>(steps[i].state),
                   trace[i].k_after, static_cast<int>(trace[i].state_after));
      CHECK(false);
    }
  }
}

// The M3 acceptance's controller half (T39): at 5/10/20% i.i.d. loss the
// controller settles at the k_for answer and stays there, and the default
// byte budget never binds (the wire ratio is k/D, so k <= 4 sits at 40% <
// 50% — the #28 test caught the original 0.40 default binding right there).
void TestReplayLossProfiles() {
  struct Profile {
    uint32_t loss;
    uint8_t expected_k;
  };
  const Profile profiles[] = {{5, 1}, {10, 2}, {20, 4}};
  for (const Profile& p : profiles) {
    const auto trace = RecordArm(false, p.loss, 8000);
    const auto steps = fcp::replay_trace(trace, trace.front().snapshot);
    uint8_t k_max = 0;
    size_t capped = 0;
    double ratio_peak = 0.0;
    for (size_t i = 0; i < steps.size(); ++i) {
      k_max = std::max<uint8_t>(k_max, steps[i].k);
      if (steps[i].state == fcp::FecState::kCapped) {
        ++capped;
      }
      const fcp::TraceEntry& e = trace[i];
      if (e.stat.data_bytes_rx > 0) {
        ratio_peak =
            std::max(ratio_peak, static_cast<double>(e.stat.parity_bytes_rx) /
                                     static_cast<double>(e.stat.data_bytes_rx));
      }
    }
    CHECK(steps.back().k == p.expected_k);
    CHECK(k_max == p.expected_k);  // no overshoot: stable at the k_for answer
    CHECK_EQ(capped, 0u);          // default budget never binds at k <= 4
    CHECK(ratio_peak <= 0.50);     // "预算不超" red line at the default budget
  }
}

// Budget what-if on a recorded 20% trace: the frozen byte evidence (recorded
// at the recording k) drives CAPPED and the walk down to the floor.
void TestReplayBudgetCandidate() {
  const auto trace = RecordArm(false, 20, 8000);
  fcp::TraceConfigSnapshot candidate = trace.front().snapshot;
  candidate.budget = 0.10;
  const auto steps = fcp::replay_trace(trace, candidate);
  size_t capped = 0;
  for (const auto& s : steps) {
    if (s.state == fcp::FecState::kCapped) {
      ++capped;
    }
  }
  CHECK(capped >= 1);
  CHECK_EQ(steps.back().k, 1);  // walk-down hits the §14.11 floor
}

// The GE trace replays into the burst answer: k rises above the binomial
// k_for(mean) and is still up at the end of the run, matching the #26
// session-level finding.
void TestReplayGELiftsK() {
  const auto trace = RecordArm(true, 0, 8000, /*initial_k=*/2);
  const auto steps = fcp::replay_trace(trace, trace.front().snapshot);
  uint8_t k_max = 0;
  size_t held = 0;
  for (const auto& s : steps) {
    k_max = std::max<uint8_t>(k_max, s.k);
    if (s.k >= 3) {
      ++held;
    }
  }
  // The lift is not a blip: above the binomial answer for at least two
  // reports (a mild-texture tail interval may walk it back down — the
  // controller is allowed to follow the evidence both ways there).
  CHECK(k_max >= 3);
  CHECK(held >= 2);
}


// #30 adversarial pass over the trace codec: truncation, giant numbers,
// duplicates — nothing may parse half-baked, and nothing non-finite may
// reach the int casts. Whitespace and defaults-only lines are tolerated on
// purpose (the encoder never emits them); negative numbers are harmless.
void TestTraceCodecFuzz() {
  fcp::TraceEntry e;
  e.now_ms = 123;
  e.stat = fcp::MakeFecstatPacket(kSalt);
  e.stat.data_expected = 42u;
  std::string line;
  fcp::encode_trace_line(e, &line);

  const char* bad[] = {
      "",                                  // empty
      "{",                                 // truncated
      "{\"ver\":1",                        // truncated after value
      "{\"ver\":1,",                       // trailing comma, no close
      "{\"ver\":2}",                       // wrong version
      "{\"ver\":1e}",                      // valueless exponent
      "{\"ver\":1,\"now\":1e999}",         // non-finite: HUGE_VAL rejected
      "{\"ver\":1,\"now\":1,,}",           // double comma
      "{\"ver\":1,now:1}",                 // unquoted key
      "{\"ver\":1,\"now\":\"5\"}",         // string value
      "not json",                          // garbage
      "{\"ver\":1,\"now\":1}{\"ver\":1}",  // trailing garbage
      // Adversarial recheck: values outside the field's wire width must
      // reject, not wrap/truncate through an out-of-range double -> int cast.
      "{\"ver\":1,\"s_exp\":-1}",
      "{\"ver\":1,\"c_d\":1e300}",
      "{\"ver\":1,\"now\":1e30}",
      "{\"ver\":1,\"s_lat50\":70000}",
  };
  for (const char* s : bad) {
    if (fcp::decode_trace_line(s, &e)) {
      std::fprintf(stderr, "accepted bad line: %s\n", s);
      CHECK(false);
    }
  }
  // Tolerated by design: whitespace, defaults-only entries, negatives.
  CHECK(fcp::decode_trace_line("{ \"ver\":1 }", &e));
  CHECK_EQ(e.now_ms, 0);
  CHECK(fcp::decode_trace_line("{\"ver\":1,\"now\":-5}", &e));
  CHECK_EQ(e.now_ms, -5);

  // Giant-but-representable values survive a round trip exactly.
  // Giant-but-representable values survive a round trip exactly.
  fcp::TraceEntry big;
  big.now_ms = (1LL << 52);
  big.stat = fcp::MakeFecstatPacket(kSalt);
  big.stat.data_expected = 0xFFFFFFFFu;
  big.stat.accounted_through_set_id = 0xFFFFFFFFu;
  big.snapshot.budget = 0.5;
  fcp::encode_trace_line(big, &line);
  CHECK(fcp::decode_trace_line(line, &e));
  CHECK_EQ(e.stat.data_expected, 0xFFFFFFFFu);
  CHECK_EQ(e.stat.accounted_through_set_id, 0xFFFFFFFFu);
  // Duplicate keys: last one wins, still well-formed.
  std::string dup = "{\"ver\":1,\"now\":7,\"now\":9}";
  CHECK(fcp::decode_trace_line(dup, &e));
  CHECK_EQ(e.now_ms, 9);
}

// Adversarial recheck: doubles must survive the text format bit-for-bit. %.9g
// collapsed nextafter(0.8) onto 0.8, so a replayed candidate could read a
// different target_recovery/budget than the recording and branch differently
// right at a threshold — the opposite of what replay is for.
void TestTraceDoubleRoundTrip() {
  fcp::TraceEntry e;
  e.stat = fcp::MakeFecstatPacket(kSalt);
  e.snapshot.target_recovery = std::nextafter(0.8, 1.0);
  e.snapshot.budget = std::nextafter(0.5, 0.0);
  e.last_loss = std::nextafter(0.0966, 1.0);
  std::string line;
  fcp::encode_trace_line(e, &line);
  fcp::TraceEntry back;
  CHECK(fcp::decode_trace_line(line, &back));
  CHECK(back.snapshot.target_recovery == e.snapshot.target_recovery);
  CHECK(back.snapshot.budget == e.snapshot.budget);
  CHECK(back.last_loss == e.last_loss);
}

// Golden trace for the fcp-replay ctest smoke: run with
// FCP_WRITE_TRACE_GOLDEN=<path> to (re)generate.
void MaybeWriteGolden(const std::vector<fcp::TraceEntry>& trace) {
  const char* path = std::getenv("FCP_WRITE_TRACE_GOLDEN");
  if (path == nullptr || path[0] == '\0') {
    return;
  }
  std::FILE* f = std::fopen(path, "wb");
  CHECK(f != nullptr);
  for (const auto& e : trace) {
    std::string line;
    fcp::encode_trace_line(e, &line);
    line.push_back('\n');
    std::fwrite(line.data(), 1, line.size(), f);
  }
  std::fclose(f);
  std::printf("golden written to %s (%zu entries)\n", path, trace.size());
}

}  // namespace

int main() {
  TestRoundTrip();
  TestReplayReproducesRecorded();
  TestTraceCodecFuzz();
  TestTraceDoubleRoundTrip();

  // The 20% arm doubles as the golden source: deterministic seed, so the
  // checked-in file only moves when the format or controller changes.
  const auto golden_trace = RecordArm(false, 20, 8000);
  MaybeWriteGolden(golden_trace);

  TestReplayLossProfiles();
  TestReplayBudgetCandidate();
  TestReplayGELiftsK();
  return fcp_test::finish();
}
