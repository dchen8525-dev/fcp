// Soak test (task C3 item ④): bidirectional traffic over real UDP loopback at
// 0%, 5% and 20% loss. Every injected segment is tracked; KCP-style ARQ resends
// whatever the peer has not delivered within 300ms. The settlement identity is
// checked on both endpoints on every tick, payload integrity on every delivery.
//
// Defaults are a fast 8s-simulated run for ctest. The acceptance run is:
//   FCP_SOAK_MS=600000 FCP_SOAK_REALTIME=1 fcp_soak_test
// which paces the shared wall clock so the whole three-level run lasts ten
// minutes.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>
#include <thread>
#include <vector>

#include "e2e_link.h"
#include "test_util.h"

namespace {

using namespace fcp_e2e;

constexpr int64_t kArqDelayMs = 300;
constexpr uint32_t kMaxRetries = 20;
constexpr int64_t kDrainTicks = 1200;  // 30s simulated, retry backstop
constexpr int64_t kDrainSettleTicks = 40;  // 1s of quiet before stopping

int64_t EnvInt(const char* name, int64_t fallback) {
  const char* s = std::getenv(name);
  if (s == nullptr || *s == '\0') {
    return fallback;
  }
  return std::strtoll(s, nullptr, 10);
}

bool EnvFlag(const char* name) {
  const char* s = std::getenv(name);
  return s != nullptr && *s != '\0' && std::strcmp(s, "0") != 0;
}

// One direction's retransmission bookkeeping. `hits` is the peer's per-sn
// delivery count, so a segment that FEC reconstructed never gets resent.
struct Arq {
  struct Pending {
    uint32_t sn;
    int64_t due;
    uint32_t tries;
  };
  std::deque<Pending> queue;
  uint32_t retransmits = 0;
  uint32_t given_up = 0;

  void Track(uint32_t sn, int64_t now) {
    queue.push_back(Pending{sn, now + kArqDelayMs, 0});
  }

  template <typename SendFn>
  void Step(int64_t now, const std::vector<uint32_t>& hits, SendFn send) {
    for (size_t i = 0; i < queue.size();) {
      if (queue[i].sn < hits.size() && hits[queue[i].sn] > 0) {
        queue.erase(queue.begin() + static_cast<std::ptrdiff_t>(i));
        continue;
      }
      if (queue[i].due <= now) {
        if (queue[i].tries >= kMaxRetries) {
          ++given_up;
          queue.erase(queue.begin() + static_cast<std::ptrdiff_t>(i));
          continue;
        }
        send(queue[i].sn, now);
        ++retransmits;
        ++queue[i].tries;
        queue[i].due = now + kArqDelayMs;
      }
      ++i;
    }
  }
};

struct Channel {
  int loss = 0;
  Harness h;
  Arq arq_a;  // A -> B
  Arq arq_b;  // B -> A
  uint32_t next_a = 0;
  uint32_t next_b = 0;
  uint64_t identity_checks = 0;
  uint32_t identity_violations = 0;

  bool Init() {
    if (!h.Init(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 3),
                MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 3))) {
      return false;
    }
    if (!h.Handshake()) {
      return false;
    }
    h.loss_enabled = loss > 0;
    h.loss_percent = static_cast<uint32_t>(loss);
    return true;
  }

  void Tick(int64_t t, uint32_t segs) {
    h.now = t;
    h.a->on_tick(t);
    h.pump();
    h.b->on_tick(t);
    h.pump();
    arq_a.Step(t, h.hits_b, [this](uint32_t sn, int64_t now) { h.SendA(sn, now); });
    arq_b.Step(t, h.hits_a, [this](uint32_t sn, int64_t now) { h.SendB(sn, now); });
    for (uint32_t i = 0; i < segs; ++i) {
      const uint32_t sn_a = next_a++;
      h.SendA(sn_a, t);
      arq_a.Track(sn_a, t);
      const uint32_t sn_b = next_b++;
      h.SendB(sn_b, t);
      arq_b.Track(sn_b, t);
    }
    h.pump();

    ++identity_checks;
    if (!h.a->settle()->identity_ok() || !h.b->settle()->identity_ok()) {
      ++identity_violations;
    }
  }

  uint32_t CountReports() const {
    uint32_t n = 0;
    for (const std::vector<std::string>* logs : {&h.log_a, &h.log_b}) {
      for (const std::string& line : *logs) {
        if (line.rfind("FECSTAT sets=", 0) == 0) {
          ++n;
        }
      }
    }
    return n;
  }

  uint32_t MissingDeliveries() const {
    uint32_t bad = 0;
    for (uint32_t sn = 0; sn < next_a; ++sn) {
      if (sn >= h.hits_b.size() || h.hits_b[sn] != 1) {
        ++bad;
      }
    }
    for (uint32_t sn = 0; sn < next_b; ++sn) {
      if (sn >= h.hits_a.size() || h.hits_a[sn] != 1) {
        ++bad;
      }
    }
    return bad;
  }

  uint32_t DuplicateDeliveries() const {
    uint32_t dup = 0;
    for (uint32_t sn = 0; sn < next_a && sn < h.hits_b.size(); ++sn) {
      if (h.hits_b[sn] > 1) {
        ++dup;
      }
    }
    for (uint32_t sn = 0; sn < next_b && sn < h.hits_a.size(); ++sn) {
      if (h.hits_a[sn] > 1) {
        ++dup;
      }
    }
    return dup;
  }
};

void PrintSummary(const Channel& c, int64_t sim_ms, uint32_t segs, bool realtime) {
  std::printf(
      "SOAK loss=%d%% sim=%llds realtime=%d segs_per_tick=%u ticks=%llu "
      "tx=%u/%u parity=%u/%u delivered=%zu/%zu rxdel=%u/%u retx=%u/%u "
      "recovered=%u/%u k=%u/%u state=%s/%s reports=%u identity=%llu viol=%u "
      "corrupt=%u/%u\n",
      c.loss, static_cast<long long>(sim_ms / 1000), realtime ? 1 : 0, segs,
      static_cast<unsigned long long>(c.identity_checks), c.h.a_data, c.h.b_data,
      c.h.a_parity, c.h.b_parity, c.h.delivered_b.size(), c.h.delivered_a.size(),
      c.h.b->rx()->data_delivered(), c.h.a->rx()->data_delivered(),
      c.arq_a.retransmits, c.arq_b.retransmits, c.h.a->rx()->recovered(),
      c.h.b->rx()->recovered(), c.h.a->k(), c.h.b->k(),
      c.h.a->strategy()->state() == fcp::FecState::kOn ? "ON" : "OFF",
      c.h.b->strategy()->state() == fcp::FecState::kOn ? "ON" : "OFF",
      c.CountReports(), static_cast<unsigned long long>(c.identity_checks),
      c.identity_violations, c.h.corrupt_a, c.h.corrupt_b);
  std::fflush(stdout);
}

void Verify(Channel* c, int64_t sim_ms, uint32_t segs, bool realtime) {
  PrintSummary(*c, sim_ms, segs, realtime);

  CHECK_EQ(c->identity_violations, 0u);
  // Cumulative delivery accounting: FrameRx counts every payload it handed up
  // (original, reconstructed or late), never duplicates. This must equal the
  // injected segment count on both directions.
  CHECK_EQ(c->h.b->rx()->data_delivered(), c->next_a);
  CHECK_EQ(c->h.a->rx()->data_delivered(), c->next_b);
  CHECK_EQ(c->h.corrupt_a, 0u);
  CHECK_EQ(c->h.corrupt_b, 0u);
  CHECK_EQ(c->arq_a.given_up, 0u);
  CHECK_EQ(c->arq_b.given_up, 0u);
  CHECK(c->arq_a.queue.empty());
  CHECK(c->arq_b.queue.empty());
  CHECK_EQ(c->MissingDeliveries(), 0u);
  CHECK_EQ(c->DuplicateDeliveries(), 0u);
  CHECK_EQ(c->h.delivered_b.size(), static_cast<size_t>(c->next_a));
  CHECK_EQ(c->h.delivered_a.size(), static_cast<size_t>(c->next_b));

  if (c->loss == 0) {
    // No loss: the strategy never leaves OFF and no parity is produced.
    CHECK(c->h.a->strategy()->state() == fcp::FecState::kOff);
    CHECK(c->h.b->strategy()->state() == fcp::FecState::kOff);
    CHECK_EQ(c->h.a->k(), 0u);
    CHECK_EQ(c->h.b->k(), 0u);
    CHECK_EQ(c->h.a_parity, 0u);
    CHECK_EQ(c->h.b_parity, 0u);
    CHECK_EQ(c->h.a->rx()->recovered(), 0u);
    CHECK_EQ(c->h.b->rx()->recovered(), 0u);
  } else {
    // Lossy: the closed loop must have turned FEC on in both directions and
    // reconstruction must carry part of the load.
    CHECK(c->h.a->strategy()->state() == fcp::FecState::kOn);
    CHECK(c->h.b->strategy()->state() == fcp::FecState::kOn);
    CHECK(c->h.a->k() >= 1);
    CHECK(c->h.b->k() >= 1);
    CHECK(c->h.a_parity > 0);
    CHECK(c->h.b_parity > 0);
    CHECK(c->h.a->rx()->recovered() > 0);
    CHECK(c->h.b->rx()->recovered() > 0);
  }
}

}  // namespace

int main() {
  const int64_t sim_ms = EnvInt("FCP_SOAK_MS", 8000);
  const int64_t segs = EnvInt("FCP_SOAK_SEGS", 4);
  const bool realtime = EnvFlag("FCP_SOAK_REALTIME");
  CHECK(sim_ms >= 4 * fcp::kSessionTickMs);
  CHECK(segs >= 1);

  constexpr int kLevels = 3;
  const int kLossLevels[kLevels] = {0, 5, 20};
  Channel channels[kLevels];
  for (int i = 0; i < kLevels; ++i) {
    channels[i].loss = kLossLevels[i];
    CHECK(channels[i].Init());
  }

  // All three loss levels share one wall clock, so the whole acceptance run is
  // ten minutes long rather than thirty.
  const auto start = std::chrono::steady_clock::now();
  const int64_t ticks = sim_ms / fcp::kSessionTickMs;
  for (int64_t i = 1; i <= ticks; ++i) {
    const int64_t t = i * fcp::kSessionTickMs;
    for (Channel& c : channels) {
      c.Tick(t, static_cast<uint32_t>(segs));
    }
    // Batch the sleep: one ~100ms wait per four ticks amortises the Windows
    // timer granularity instead of overshooting on every 25ms tick.
    if (realtime && i % 4 == 0) {
      std::this_thread::sleep_until(start + std::chrono::milliseconds(t));
    }
  }

  // Stop injecting and let ARQ, T_flush and settlement drain every channel.
  int64_t t = ticks * fcp::kSessionTickMs;
  int quiet[kLevels] = {};
  bool done[kLevels] = {};
  for (int64_t i = 0; i < kDrainTicks; ++i) {
    if (done[0] && done[1] && done[2]) {
      break;
    }
    t += fcp::kSessionTickMs;
    for (int k = 0; k < kLevels; ++k) {
      if (done[k]) {
        continue;
      }
      channels[k].Tick(t, 0);
      if (channels[k].arq_a.queue.empty() && channels[k].arq_b.queue.empty()) {
        if (++quiet[k] >= kDrainSettleTicks) {
          done[k] = true;
        }
      } else {
        quiet[k] = 0;
      }
    }
  }

  for (Channel& c : channels) {
    Verify(&c, sim_ms, static_cast<uint32_t>(segs), realtime);
  }
  return fcp_test::finish();
}
