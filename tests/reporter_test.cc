#include "fcp/reporter.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "fcp/fecstat.h"
#include "fcp/frame_rx.h"
#include "fcp/frame_tx.h"
#include "fcp/hdr.h"
#include "fcp/settle.h"
#include "test_util.h"

namespace {

const uint8_t kSalt[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

std::vector<uint8_t> SegPayload(uint32_t sn, size_t len = 4) {
  std::vector<uint8_t> out(len < 4 ? 4 : len, 0);
  out[0] = static_cast<uint8_t>(sn);
  out[1] = static_cast<uint8_t>(sn >> 8);
  out[2] = static_cast<uint8_t>(sn >> 16);
  out[3] = static_cast<uint8_t>(sn >> 24);
  for (size_t i = 4; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(sn + 7 * i);
  }
  return out;
}

bool SnOf(const uint8_t* p, size_t len, uint32_t* sn) {
  if (len < 4) {
    return false;
  }
  *sn = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
  return true;
}

struct Fixture {
  std::vector<std::vector<uint8_t>> delivered;
  std::vector<std::vector<uint8_t>> sent;
  fcp::FrameRx rx;
  fcp::FcpSettle settle;
  fcp::FcpReporter rep;

  Fixture()
      : rx(10, 3,
           [this](const uint8_t* payload, size_t len) {
             delivered.emplace_back(payload, payload + len);
           },
           [](const uint8_t*, size_t, int64_t) {}, &SnOf),
        settle(10),
        rep(&settle,
            [this](const uint8_t* packet, size_t len) { sent.emplace_back(packet, packet + len); }) {
    settle.attach(&rx);
    rep.set_salt(kSalt);
  }

  void feed(uint32_t set_id, uint8_t index, uint8_t type_k, const std::vector<uint8_t>& symbol,
            int64_t now_ms = 0) {
    uint8_t hdr[fcp::kFecHdrLen];
    fcp::pack_hdr(fcp::FecHdr{set_id, index, type_k}, hdr);
    std::vector<uint8_t> dg(hdr, hdr + fcp::kFecHdrLen);
    dg.insert(dg.end(), symbol.begin(), symbol.end());
    rx.on_datagram(dg.data(), dg.size(), now_ms);
  }

  void feed_as(uint32_t set_id, const std::vector<fcp::TxSymbol>& symbols, int64_t now_ms = 0) {
    for (const auto& s : symbols) {
      feed(set_id, s.index, s.type_k, s.symbol, now_ms);
    }
  }

  fcp::FecstatPacket last_packet() const {
    fcp::FecstatPacket packet{};
    const bool ok = fcp::decode_fecstat(sent.back().data(), sent.back().size(), kSalt, &packet) ==
                    fcp::FecstatStatus::kOk;
    CHECK(ok);
    return packet;
  }
};

std::vector<fcp::TxSymbol> BuildSet(uint8_t d, uint8_t k,
                                    const std::vector<std::vector<uint8_t>>& segs) {
  const fcp::MtuLimits limits = fcp::compute_mtu_limits(1400, 20);
  std::vector<fcp::TxSymbol> out;
  fcp::FrameTx tx(d, limits, [&out](const fcp::TxSymbol& s) { out.push_back(s); });
  tx.set_k(k);
  tx.set_srtt_ms(25);
  int64_t now = 0;
  for (const auto& seg : segs) {
    tx.on_kcp_output(seg.data(), seg.size(), now);
    ++now;
  }
  tx.on_tick(now + 1000);
  return out;
}

std::vector<std::vector<uint8_t>> Payloads(uint32_t base, size_t count, size_t len = 4) {
  std::vector<std::vector<uint8_t>> out;
  for (size_t i = 0; i < count; ++i) {
    out.push_back(SegPayload(base + static_cast<uint32_t>(i), len));
  }
  return out;
}

bool IsData(const fcp::TxSymbol& s) { return fcp::hdr_type(s.type_k) == fcp::SymbolType::kData; }
bool IsParity(const fcp::TxSymbol& s) {
  return fcp::hdr_type(s.type_k) == fcp::SymbolType::kParity;
}

void TestTwoSecondCadence() {
  Fixture f;
  f.rep.on_tick(0);  // baseline

  for (uint32_t sid = 0; sid < 30; ++sid) {
    f.feed_as(sid, BuildSet(10, 1, Payloads(100 + 10 * sid, 10)));
  }
  f.settle.tick(100, 100);  // account everything
  CHECK_EQ(f.settle.counters().data_expected, 300u);

  CHECK(!f.rep.on_tick(1999));
  CHECK_EQ(f.sent.size(), 0u);
  CHECK(f.rep.on_tick(2000));
  // #28⑤ (F3): each report is sent twice (dedup on the peer by monotonic key).
  CHECK_EQ(f.sent.size(), 2u);
  CHECK(f.sent[0] == f.sent[1]);
  CHECK(!f.rep.last_forced());

  const fcp::FecstatPacket p = f.last_packet();
  CHECK_EQ(f.sent.back().size(), fcp::kFecstatLen);
  CHECK(std::memcmp(p.magic, fcp::kFecstatMagic, sizeof(p.magic)) == 0);
  CHECK(std::memcmp(p.session_salt, kSalt, sizeof(kSalt)) == 0);
  CHECK_EQ(p.ver, fcp::kFecstatVersion);
  CHECK_EQ(p.flg, static_cast<uint8_t>(fcp::kFlgDirection | fcp::kFlgLedger));
  CHECK_EQ(p.interval_ms, 2000);
  CHECK_EQ(p.accounted_through_set_id, 29u);
  CHECK_EQ(p.sets_expected, 30u);
  CHECK_EQ(p.data_expected, 300u);
  CHECK_EQ(p.data_rx_orig, 300u);
  CHECK_EQ(p.data_recovered_dl, 0u);
  CHECK_EQ(p.data_recovered_late, 0u);
  CHECK_EQ(p.data_delivered, 300u);
  CHECK_EQ(p.parity_rx, 30u);
  CHECK_EQ(p.parity_expected, 30u);
  CHECK_EQ(p.sets_full, 30u);
  CHECK_EQ(p.sets_partial, 0u);
  CHECK_EQ(p.sets_k_unknown, 0u);
  CHECK_EQ(p.repair_lat_p50_ms, 0);
  CHECK_EQ(p.repair_lat_p95_ms, 0);
  // M3 ledger: 30 clean full-size k=1 groups, nothing failed.
  CHECK_EQ(p.ledger_groups, 30u);
  CHECK_EQ(p.ledger_fail_ppm, 0u);
  CHECK_EQ(fcp::ledger_k(p), 1);
  CHECK_EQ(fcp::ledger_burst_kl(p), 0);

  // Interval counters were cleared; the monotonic key survived.
  CHECK_EQ(f.settle.counters().data_expected, 0u);
  CHECK_EQ(f.settle.accounted_through_set_id(), 29u);
  CHECK_EQ(f.rep.reports(), 1u);
  CHECK(!f.rep.on_tick(2001));
}

void TestForcedSixtySeconds() {
  Fixture f;
  f.rep.on_tick(0);

  f.feed_as(0, BuildSet(10, 1, Payloads(500, 10)));
  f.settle.tick(100, 100);
  CHECK_EQ(f.settle.counters().data_expected, 10u);

  CHECK(!f.rep.on_tick(59999));  // below 256 samples and below 60s
  CHECK(f.rep.on_tick(60000));
  CHECK(f.rep.last_forced());
  fcp::FecstatPacket p = f.last_packet();
  CHECK_EQ(p.interval_ms, 60000);
  CHECK_EQ(p.data_expected, 10u);

  // Idle direction: no traffic after the report, so the 60s door stays shut.
  CHECK(!f.rep.on_tick(120000));
  CHECK_EQ(f.rep.reports(), 1u);

  // A 70s span is clamped in interval_ms.
  f.feed_as(1, BuildSet(10, 1, Payloads(600, 10)));
  f.settle.tick(120200, 100);
  CHECK(f.rep.on_tick(190000));
  p = f.last_packet();
  CHECK_EQ(p.interval_ms, 60000);
}

void TestIdleSuppressed() {
  Fixture f;
  f.rep.on_tick(0);
  CHECK(!f.rep.on_tick(60000));
  CHECK(!f.rep.on_tick(600000));
  CHECK_EQ(f.rep.reports(), 0u);
  CHECK_EQ(f.sent.size(), 0u);
}

void TestFlags() {
  Fixture f;
  f.rep.on_tick(0);

  for (uint32_t sid = 0; sid < 25; ++sid) {
    f.feed_as(sid, BuildSet(10, 1, Payloads(1000 + 10 * sid, 10)));
  }
  // Set 25: two data holes, only parity j=0. n is known, nothing decodes yet.
  const auto partial = BuildSet(10, 2, Payloads(2000, 10));
  for (const auto& s : partial) {
    if (IsData(s) && (s.index == 8 || s.index == 9)) {
      continue;
    }
    if (IsParity(s) && fcp::hdr_j(s.type_k) != 0) {
      continue;
    }
    f.feed(25, s.index, s.type_k, s.symbol, 0);
  }
  // Set 26: data only and never superseded -> tail drop.
  for (const auto& s : BuildSet(10, 1, Payloads(3000, 3))) {
    if (IsData(s)) {
      f.feed(26, s.index, s.type_k, s.symbol, 0);
    }
  }

  f.settle.tick(100, 100);
  CHECK_EQ(f.settle.counters().data_expected, 260u);

  // Late parity inside the tombstone recovers both holes.
  for (const auto& s : partial) {
    if (IsParity(s) && fcp::hdr_j(s.type_k) == 1) {
      f.feed(25, s.index, s.type_k, s.symbol, 200);
    }
  }
  CHECK_EQ(f.settle.counters().data_recovered_late, 2u);

  f.settle.tick(1000, 100);
  CHECK_EQ(f.settle.counters().sets_tail_dropped, 1u);

  CHECK(f.rep.on_tick(2000));
  const fcp::FecstatPacket p = f.last_packet();
  CHECK_EQ(p.flg, static_cast<uint8_t>(fcp::kFlgDirection | fcp::kFlgTailDropped |
                                      fcp::kFlgLateRecovery | fcp::kFlgLedger));
  CHECK_EQ(p.data_expected, 260u);
  CHECK_EQ(p.sets_tail_dropped, 1u);
  CHECK_EQ(p.data_recovered_late, 2u);
  CHECK_EQ(p.data_delivered, 263u);  // 258 originals + 3 tail-dropped + 2 late recon
  // Ledger: 25 clean k=1 sets + set 25, whose two holes were still open at
  // settlement (the recovery landed late, inside the tombstone) -> 1 of 26
  // groups failed. Dominant k is 1 (25 vs 1).
  CHECK_EQ(p.ledger_groups, 26u);
  CHECK_EQ(p.ledger_fail_ppm, 38462u);
  CHECK_EQ(fcp::ledger_k(p), 1);
}

void TestPercentiles() {
  Fixture f;
  f.rep.on_tick(0);
  for (uint32_t ms = 1; ms <= 100; ++ms) {
    f.rep.record_repair_latency(ms);
  }
  CHECK(f.rep.on_tick(60000));
  CHECK(f.rep.last_forced());
  fcp::FecstatPacket p = f.last_packet();
  CHECK_EQ(p.repair_lat_p50_ms, 50);
  CHECK_EQ(p.repair_lat_p95_ms, 95);
  CHECK_EQ(p.data_expected, 0u);

  // Samples were cleared with the rest of the interval.
  CHECK(!f.rep.on_tick(120000));

  // Values above 65535 saturate.
  f.rep.record_repair_latency(70000);
  CHECK(f.rep.on_tick(180000));
  p = f.last_packet();
  CHECK_EQ(p.repair_lat_p50_ms, 65535);
  CHECK_EQ(p.repair_lat_p95_ms, 65535);
}

void TestExtraCounters() {
  Fixture f;
  f.rep.on_tick(0);
  f.rep.add_auth_fail(2);
  f.rep.add_struct_fail(3);
  f.rep.add_data_bytes(1000);
  f.rep.add_parity_bytes(200);

  CHECK(f.rep.on_tick(60000));
  const fcp::FecstatPacket p = f.last_packet();
  CHECK_EQ(p.auth_fail, 2u);
  CHECK_EQ(p.struct_fail, 3u);
  CHECK_EQ(p.data_bytes_rx, 1000u);
  CHECK_EQ(p.parity_bytes_rx, 200u);

  // Reset to zero after the report.
  CHECK(!f.rep.on_tick(120000));
}


// §14.6 (#30): a teardown with accounted traffic emits its last report
// immediately; an idle direction stays silent.
void TestFlushOnTeardown() {
  Fixture f;
  f.rep.on_tick(0);
  for (uint32_t sid = 0; sid < 30; ++sid) {
    f.feed_as(sid, BuildSet(10, 1, Payloads(7000 + 10 * sid, 10)));
  }
  f.settle.tick(100, 100);  // accounted, but the 2s cadence has not run
  CHECK_EQ(f.sent.size(), 0u);
  CHECK(f.rep.flush(500));
  CHECK_EQ(f.sent.size(), 2u);  // double-sent per #28⑤ (F3)
  CHECK_EQ(f.last_packet().data_expected, 300u);
  // Flushed counters are cleared; a second flush has nothing to say.
  CHECK(!f.rep.flush(501));
  CHECK_EQ(f.sent.size(), 2u);

  // An idle direction never reports, even on teardown.
  Fixture idle;
  idle.rep.on_tick(0);
  CHECK(!idle.rep.flush(999));
  CHECK_EQ(idle.sent.size(), 0u);
}

}  // namespace

int main() {
  TestTwoSecondCadence();
  TestForcedSixtySeconds();
  TestIdleSuppressed();
  TestFlags();
  TestPercentiles();
  TestExtraCounters();
  TestFlushOnTeardown();
  return fcp_test::finish();
}
