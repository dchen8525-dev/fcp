// Link warm-up tests (M2代理设计.md §5, task #19).
//
// Two halves: the library knobs (FecStrategyConfig::initial_k,
// SessionConfig::initial_srtt_ms / initial_k) and the host-side cache that
// feeds them. What matters is that a seed is a starting point and not a
// setting: every scenario is checked against the M1 cold-start behaviour,
// which stays the default for all three fields. Seeding srtt is only allowed
// to move the timers, never the §8 queue guardrail -- its min_rtt baseline
// stays at "no sample yet", because a cached baseline would make the guardrail
// permanently true on any path whose RTT has grown since the snapshot.

#include "fcp/prewarm.h"

#include <string>
#include <vector>

#include "e2e_link.h"
#include "fcp/session.h"
#include "fcp/stream.h"
#include "test_util.h"

namespace {

using fcp_e2e::Harness;
using fcp_e2e::MakeConfig;
using fcp_e2e::Segment;

fcp::FecstatPacket Report(uint32_t set_id, uint32_t expected, uint32_t rx_orig) {
  fcp::FecstatPacket p{};
  p.accounted_through_set_id = set_id;
  p.data_expected = expected;
  p.data_rx_orig = rx_orig;
  p.sets_expected = 10;
  p.sets_k_unknown = 0;
  return p;
}

// A 1000-packet interval with the given loss, i.e. the sample size the §8
// gates accept.
fcp::FecstatPacket LossReport(uint32_t set_id, double loss) {
  const uint32_t rx = 1000 - static_cast<uint32_t>(loss * 1000.0 + 0.5);
  return Report(set_id, 1000, rx);
}

void Feed(fcp::FecStrategy* st, uint32_t* set_id, double loss) {
  st->on_report(LossReport(++*set_id, loss), false);
}

bool HasLog(const std::vector<std::string>& logs, const std::string& needle) {
  for (const std::string& line : logs) {
    if (line.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

// Default configs behave exactly like M1: OFF, k 0, no seed to report.
void TestColdStartUnchanged() {
  fcp::FecStrategy st;
  CHECK(st.state() == fcp::FecState::kOff);
  CHECK_EQ(st.k(), 0u);
  CHECK_EQ(st.initial_k(), -1);
  CHECK(!st.pinned());

  fcp::FecStrategyConfig cfg;
  CHECK_EQ(cfg.initial_k, -1);
  fcp::SessionConfig scfg;
  CHECK_EQ(scfg.initial_srtt_ms, 0);
  CHECK_EQ(scfg.initial_k, -1);
}

// A seed enters ON at that k without pretending to be an operator pin.
void TestInitialKSeedsOn() {
  fcp::FecStrategyConfig cfg;
  cfg.initial_k = 3;
  fcp::FecStrategy st(cfg);
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 3u);
  CHECK_EQ(st.initial_k(), 3);
  CHECK(!st.pinned());

  // k == 0 as a seed is "the link is clean", which is already the cold start.
  fcp::FecStrategyConfig zero;
  zero.initial_k = 0;
  fcp::FecStrategy st2(zero);
  CHECK(st2.state() == fcp::FecState::kOff);
  CHECK_EQ(st2.k(), 0u);
}

// The reports keep driving: a seed the link no longer needs walks back down,
// and the clean streak still retires it.
void TestSeedStillConverges() {
  fcp::FecStrategyConfig cfg;
  cfg.initial_k = 3;
  fcp::FecStrategy st(cfg);

  uint32_t id = 0;
  Feed(&st, &id, 0.002);
  CHECK_EQ(st.k(), 2u);
  Feed(&st, &id, 0.002);
  CHECK_EQ(st.k(), 1u);
  Feed(&st, &id, 0.002);
  CHECK_EQ(st.k(), 1u);
  Feed(&st, &id, 0.002);
  CHECK(st.state() == fcp::FecState::kOn);
  Feed(&st, &id, 0.002);
  CHECK(st.state() == fcp::FecState::kOff);
  CHECK_EQ(st.k(), 0u);
  // The seed is history, not a constraint.
  CHECK_EQ(st.initial_k(), 3);

  // It also still climbs: the link degraded after the cached snapshot.
  fcp::FecStrategyConfig climb;
  climb.initial_k = 1;
  fcp::FecStrategy low(climb);
  id = 0;
  Feed(&low, &id, 0.20);  // k_for = 4, one step per report
  CHECK_EQ(low.k(), 2u);
  Feed(&low, &id, 0.20);
  CHECK_EQ(low.k(), 3u);
}

// A seed never exceeds the parity budget, using the same clamp as pinned_k.
void TestSeedClampedToPmax() {
  fcp::FecStrategyConfig over;
  over.initial_k = 9;
  fcp::FecStrategy st(over);
  CHECK_EQ(st.k(), fcp::kDefaultPmax);
  CHECK_EQ(st.initial_k(), static_cast<int>(fcp::kDefaultPmax));

  fcp::FecStrategyConfig tight;
  tight.p_max = 2;
  tight.initial_k = 5;
  fcp::FecStrategy st2(tight);
  CHECK_EQ(st2.k(), 2u);

  // Stats mode negotiates p_max = 0, so there is nothing to seed.
  fcp::FecStrategyConfig none;
  none.p_max = 0;
  none.initial_k = 3;
  fcp::FecStrategy st3(none);
  CHECK(st3.state() == fcp::FecState::kOff);
  CHECK_EQ(st3.k(), 0u);
  CHECK_EQ(st3.initial_k(), 0);
}

// pinned_k owns the machine, including the "pinned to 0 = stay OFF" case, so a
// seed carried alongside it must not switch parity on.
void TestPinnedWinsOverSeed() {
  fcp::FecStrategyConfig off;
  off.pinned_k = 0;
  off.initial_k = 3;
  fcp::FecStrategy st(off);
  CHECK(st.pinned());
  CHECK(st.state() == fcp::FecState::kOff);
  CHECK_EQ(st.k(), 0u);
  uint32_t id = 0;
  for (int i = 0; i < 5; ++i) {
    Feed(&st, &id, 0.20);
  }
  CHECK_EQ(st.k(), 0u);

  fcp::FecStrategyConfig on;
  on.pinned_k = 1;
  on.initial_k = 4;
  fcp::FecStrategy st2(on);
  CHECK_EQ(st2.k(), 1u);
  CHECK_EQ(st2.initial_k(), -1);
}

void TestPeerKeyFormat() {
  CHECK_EQ(fcp::peer_key("127.0.0.1", 4000), std::string("127.0.0.1:4000"));
  CHECK_EQ(fcp::peer_key("example.com", 443), std::string("example.com:443"));
  CHECK_EQ(fcp::peer_key("::1", 8080), std::string("[::1]:8080"));
  CHECK_EQ(fcp::peer_key("[2001:db8::1]", 8080), std::string("[2001:db8::1]:8080"));
}

void TestCacheTtl() {
  fcp::PrewarmCache cache(1000);
  fcp::PeerProfile got;
  CHECK(!cache.get("k", 0, &got));

  cache.put("k", fcp::PeerProfile{45, 3}, 0);
  CHECK(cache.get("k", 999, &got));
  CHECK_EQ(got.srtt_ms, 45);
  CHECK_EQ(got.initial_k, 3);
  CHECK(!cache.get("k", 1000, &got));

  // The entry is readable again only by being refreshed, not by time travel.
  cache.put("k", fcp::PeerProfile{60, 2}, 1000);
  CHECK(cache.get("k", 1500, &got));
  CHECK_EQ(got.srtt_ms, 60);
  CHECK_EQ(got.initial_k, 2);
}

void TestCachePrune() {
  fcp::PrewarmCache cache(1000);
  cache.put("a", fcp::PeerProfile{10, 1}, 0);
  cache.put("b", fcp::PeerProfile{20, 2}, 500);
  CHECK_EQ(cache.size(), 2u);

  // get() reports expired as absent without erasing; prune() reclaims.
  fcp::PeerProfile got;
  CHECK(!cache.get("a", 1000, &got));
  CHECK_EQ(cache.size(), 2u);
  CHECK_EQ(cache.prune(1000), 1u);
  CHECK_EQ(cache.size(), 1u);
  CHECK(cache.get("b", 1000, &got));
  CHECK_EQ(cache.prune(2000), 1u);
  CHECK_EQ(cache.size(), 0u);

  cache.put("c", fcp::PeerProfile{30, 1}, 0);
  cache.clear();
  CHECK_EQ(cache.size(), 0u);

  // A nonsense ttl falls back to the documented 10 minutes.
  CHECK_EQ(fcp::PrewarmCache().ttl_ms(), fcp::kPrewarmTtlMs);
  CHECK_EQ(fcp::PrewarmCache(0).ttl_ms(), fcp::kPrewarmTtlMs);
}

// Server-side the key is the client's own address, so the entry count has to
// be bounded by the cache rather than by the peer set.
void TestCacheCap() {
  fcp::PrewarmCache cache(1000, 2);
  CHECK(cache.put("a", fcp::PeerProfile{10, 1}, 0));
  CHECK(cache.put("b", fcp::PeerProfile{20, 2}, 0));
  CHECK_EQ(cache.size(), 2u);

  // Refreshing a known key is not an insert.
  CHECK(cache.put("a", fcp::PeerProfile{30, 1}, 0));
  CHECK_EQ(cache.size(), 2u);

  // Full with nothing dead: the new peer simply cold-starts.
  CHECK(!cache.put("c", fcp::PeerProfile{40, 3}, 500));
  CHECK_EQ(cache.size(), 2u);

  // Expired entries make room on the way in, without an explicit prune().
  CHECK(cache.put("c", fcp::PeerProfile{40, 3}, 1000));
  CHECK_EQ(cache.size(), 1u);

  CHECK_EQ(fcp::PrewarmCache(1000, 0).max_entries(), fcp::kPrewarmMaxEntries);
}

void TestApplyPrewarm() {
  fcp::SessionConfig scfg;
  fcp::StreamConfig stream_cfg;
  fcp::apply_prewarm(fcp::PeerProfile{45, 3}, &scfg, &stream_cfg);
  CHECK_EQ(scfg.initial_srtt_ms, 45);
  CHECK_EQ(scfg.initial_k, 3);
  CHECK_EQ(stream_cfg.initial_srtt_ms, 45);

  // An absent profile (or an expired entry read as one) is a no-op.
  fcp::SessionConfig cold;
  fcp::StreamConfig cold_stream;
  fcp::apply_prewarm(fcp::PeerProfile{}, &cold, &cold_stream);
  CHECK_EQ(cold.initial_srtt_ms, 0);
  CHECK_EQ(cold.initial_k, -1);
  CHECK_EQ(cold_stream.initial_srtt_ms, 200);

  // The two priors are independent, and either target may be omitted.
  fcp::SessionConfig only_rtt;
  fcp::apply_prewarm(fcp::PeerProfile{80, -1}, &only_rtt, nullptr);
  CHECK_EQ(only_rtt.initial_srtt_ms, 80);
  CHECK_EQ(only_rtt.initial_k, -1);
}

// The point of the whole exercise: the first set of a brand-new session
// already carries parity, and the timers already know the link.
void TestSessionWarmed() {
  fcp::SessionConfig cfg_a = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 3);
  fcp::SessionConfig cfg_b = MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 3);
  cfg_a.initial_srtt_ms = 45;
  cfg_a.initial_k = 3;
  cfg_b.initial_srtt_ms = 45;
  cfg_b.initial_k = 3;

  Harness h;
  CHECK(h.Init(cfg_a, cfg_b));
  CHECK(h.Handshake());
  CHECK_EQ(h.a->k(), 3u);
  CHECK(h.a->strategy()->state() == fcp::FecState::kOn);
  CHECK(!h.a->strategy()->pinned());
  CHECK_EQ(h.a->srtt_ms(), 45);
  // T_flush follows the cached RTT instead of the 200ms assumption.
  CHECK_EQ(h.a->tx()->flush_timeout_ms(), 45);
  CHECK(HasLog(h.log_a, "FEC warmed: k=3 (prewarm)"));
  CHECK(!HasLog(h.log_a, "FEC pinned"));

  // One data symbol lost, repaired with the seeded parity -- no FECSTAT
  // report has been exchanged yet.
  const fcp_e2e::Bytes seg = Segment(7);
  h.drop_next_data_a = true;
  h.a->on_kcp_output(seg.data(), seg.size(), 0);
  CHECK_EQ(h.a_parity, 0u);  // parity only closes a set
  h.TickAt(45);
  // n == 1 of a 10-symbol set: the parity budget scales down to k_eff == 1.
  CHECK_EQ(h.a_parity, 1u);
  CHECK_EQ(h.b->rx()->recovered(), 1u);
  CHECK_EQ(h.delivered_b.size(), 1u);
  CHECK_EQ(fcp_e2e::SnOf(h.delivered_b[0]), 7u);
}

// A seed above the negotiated P' is truncated, not honoured.
void TestSessionSeedClampedByNegotiation() {
  fcp::SessionConfig cfg_a = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 3);
  fcp::SessionConfig cfg_b = MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 3);
  cfg_a.initial_k = 7;
  cfg_b.initial_k = 7;

  Harness h;
  CHECK(h.Init(cfg_a, cfg_b));
  CHECK(h.Handshake());
  CHECK_EQ(h.a->k(), 3u);
  CHECK_EQ(h.a->strategy()->initial_k(), 3);
  CHECK(HasLog(h.log_a, "FEC warmed: k=3 (prewarm)"));
}

// Without a seed nothing changes on the session path: OFF, 200ms, no parity
// before the first report.
void TestSessionColdStart() {
  Harness h;
  CHECK(h.Init(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 3),
               MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 3)));
  CHECK(h.Handshake());
  CHECK_EQ(h.a->k(), 0u);
  CHECK(h.a->strategy()->state() == fcp::FecState::kOff);
  CHECK_EQ(h.a->srtt_ms(), fcp::kDefaultSrttMs);
  CHECK_EQ(h.a->tx()->flush_timeout_ms(), fcp::kDefaultSrttMs);
  CHECK(!HasLog(h.log_a, "FEC warmed"));

  h.Inject(0, 10, 0);
  h.TickAt(200);
  CHECK_EQ(h.a_parity, 0u);
  CHECK_EQ(h.b->rx()->recovered(), 0u);
}

}  // namespace

int main() {
  TestColdStartUnchanged();
  TestInitialKSeedsOn();
  TestSeedStillConverges();
  TestSeedClampedToPmax();
  TestPinnedWinsOverSeed();
  TestPeerKeyFormat();
  TestCacheTtl();
  TestCachePrune();
  TestCacheCap();
  TestApplyPrewarm();
  TestSessionWarmed();
  TestSessionSeedClampedByNegotiation();
  TestSessionColdStart();
  return fcp_test::finish();
}
