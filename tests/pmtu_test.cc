// Path-MTU discovery by binary search (pmtu.h, capability kCapPmtud); the
// state machine is a port of quic-go's mtuFinder (mtu_discoverer.go).
//
// What is checked here: the probe geometry is exactly the advertised IP size,
// a probe the path drops is recorded and the search narrows around it instead
// of giving up, an ack raises the receive bound before the send bound and
// clears loss records, the search stops when the interval is inside
// kPmtuMaxDiffMtu, and a raised size the path black-holes in bulk falls back
// to the configured base in-session (watchdog + clamp, see
// TestFullSizeDataDropFallsBackToBase).
//
// The harness is the one the e2e tests use, with `path_max_wire` standing in
// for a path MTU: datagrams larger than it are dropped before the peer ever
// sees them, which is exactly the failure upward PMTUD has to survive.
//
// Timing: the harness drives on_tick() explicitly and no RTT samples arrive in
// a loopback session, so srtt stays at the 200ms default. Spacing is 5 x srtt
// = 1000ms and unacked-probe resolution is 2 x srtt = 400ms, so probes go out
// at 1000ms intervals and each resolution fits inside the gap. The search
// starts at negotiation (t=0), so probe N happens near t=(N-1)*1000 + 1000.
// Candidate sizes follow the (min + bound) / 2 integer arithmetic of
// pmtu_next_size(); every expected value below is spelled out.

#include "fcp/pmtu.h"

#include <cstring>
#include <string>
#include <vector>

#include "e2e_link.h"
#include "fcp/session.h"
#include "test_util.h"

namespace {

using fcp_e2e::Bytes;
using fcp_e2e::Harness;
using fcp_e2e::MakeConfig;

// IPv4 (20) and IPv6 (40) header sizes both have to produce a datagram of
// exactly the requested IP length.
void TestProbeGeometry() {
  CHECK_EQ(fcp::pmtu_udp_payload(1500, 20), 1472u);
  CHECK_EQ(fcp::pmtu_probe_len(1500, 20), 1438u);  // 1472 - 28 - 6
  CHECK_EQ(fcp::pmtu_udp_payload(1500, 40), 1452u);
  CHECK_EQ(fcp::pmtu_probe_len(1500, 40), 1418u);
  // A size too small for the headers reports 0 instead of underflowing.
  CHECK_EQ(fcp::pmtu_udp_payload(20, 20), 0u);
  CHECK_EQ(fcp::pmtu_probe_len(20, 20), 0u);
}

void TestMessageCodec() {
  std::vector<uint8_t> probe(fcp::pmtu_probe_len(1500, 20), 0xAA);
  fcp::pmtu_build(fcp::PmtuMessage{fcp::kPmtuProbe, 0xDEADBEEF, 1500}, probe.data(),
                  probe.size());

  fcp::PmtuMessage got;
  CHECK(fcp::pmtu_parse(probe.data(), probe.size(), &got));
  CHECK_EQ(static_cast<int>(got.type), static_cast<int>(fcp::kPmtuProbe));
  CHECK_EQ(got.token, 0xDEADBEEFu);
  CHECK_EQ(got.mtu, 1500u);
  // Everything past the header is padding.
  bool padded = true;
  for (size_t i = fcp::kPmtuHeaderLen; i < probe.size(); ++i) {
    padded = padded && probe[i] == 0;
  }
  CHECK(padded);

  // Short, wrong-magic and unknown-type payloads are "not ours".
  fcp::PmtuMessage bad;
  CHECK(!fcp::pmtu_parse(probe.data(), fcp::kPmtuHeaderLen - 1, &bad));
  std::vector<uint8_t> wrong_magic = probe;
  wrong_magic[0] ^= 0xFF;
  CHECK(!fcp::pmtu_parse(wrong_magic.data(), wrong_magic.size(), &bad));
  std::vector<uint8_t> wrong_type = probe;
  wrong_type[8] = 7;
  CHECK(!fcp::pmtu_parse(wrong_type.data(), wrong_type.size(), &bad));

  // build() zero-fills and writes the header at the front of any buffer.
  std::vector<uint8_t> ack(fcp::kPmtuHeaderLen, 0xAA);
  fcp::pmtu_build(fcp::PmtuMessage{fcp::kPmtuAck, 1, 1400}, ack.data(), ack.size());
  CHECK(fcp::pmtu_parse(ack.data(), ack.size(), &bad));
  CHECK_EQ(static_cast<int>(bad.type), static_cast<int>(fcp::kPmtuAck));
  CHECK_EQ(bad.mtu, 1400u);
}

fcp::SessionConfig PmtuConfig(fcp::Direction send, fcp::Direction recv, bool on = true) {
  fcp::SessionConfig cfg = MakeConfig(send, recv, 3);
  cfg.pmtud = on;
  cfg.pmtu_max_mtu = 1500;
  return cfg;
}

// The path carries the full 1500: the binary search over [1400, 1500] probes
// 1450, 1475, 1487 and stops inside kPmtuMaxDiffMtu of the ceiling -- the
// proven bound is not required to end exactly at the configured ceiling
// (quic-go's CurrentSize stops within maxMTUDiff too). Both directions climb
// in lockstep; each side's probe proves only its own direction.
void TestSearchRaisesBothDirections() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
  CHECK(h.Handshake());
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.b->path_mtu(), 1400u);
  CHECK(!h.a->pmtu_search_done());

  h.TickAt(25);  // before the first spacing window closes
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 0u);

  const int64_t times[] = {1025, 2025, 3025};
  for (int64_t t : times) {
    h.TickAt(t);
  }
  CHECK_EQ(h.a->path_mtu(), 1487u);
  CHECK_EQ(h.b->path_mtu(), 1487u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 3u);
  CHECK_EQ(h.a->pmtu_probes_acked(), 3u);
  CHECK_EQ(h.a->pmtu_probes_lost(), 0u);
  CHECK(h.a->pmtu_search_done());
  // 1487-byte IP packet, 20-byte IPv4 header: 1459 UDP payload, then the
  // envelope/FEC headers; 13 bytes below the 1500 geometry (1436 / 1412).
  CHECK_EQ(h.a->mtu_limits().payload_max, 1423u);
  CHECK_EQ(h.a->mtu_limits().mss, 1399u);

  // Spacing also stops the machine: not one more probe once done.
  h.TickAt(6030);
  CHECK_EQ(h.a->pmtu_probes_sent(), 3u);
}

// Path limit 1400 (probes 1401+ are dropped): the search must converge on the
// true limit through loss records instead of giving up. The recorded sizes
// walk 1450, 1425, 1412, 1406, 1403, 1401 into the ledger, then the
// (min+lost[0])/2 probe at 1400 finally gets an ack and the interval closes
// at max()=1406 - 1400 <= maxMTUDiff+1. quic-go never drops CurrentSize, and
// neither does this: the proven bound stays at the configured 1400 while the
// upper bound walks down to meet it.
void TestBlockedPathConvergesDown() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
  CHECK(h.Handshake());
  // 1372 UDP payload = the 1400-byte datagrams the session already sends; the
  // 1450-byte probe is the first one that no longer fits.
  h.path_max_wire = 1372;

  for (int64_t t = 25; t <= 8025; t += 1000) {
    h.TickAt(t);
  }
  // The interval halved to [1400, 1412] -- inside kPmtuMaxDiffMtu -- so the
  // search stops after five probes. quic-go's done() is the same tolerance:
  // the true limit 1400 is already within 20 bytes of the recorded evidence.
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.b->path_mtu(), 1400u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 5u);
  CHECK_EQ(h.a->pmtu_probes_acked(), 0u);
  CHECK_EQ(h.a->pmtu_probes_lost(), 5u);
  CHECK(h.a->pmtu_search_done());
  CHECK_EQ(h.a->payload_max(), 1336u);

  // No further probes once the interval has closed.
  h.TickAt(20025);
  CHECK_EQ(h.a->pmtu_probes_sent(), 5u);

  // The tunnel itself was never affected by the failed probes.
  h.Inject(0, 3, 6100);
  CHECK_EQ(h.delivered_b.size(), 3u);
  CHECK_EQ(h.corrupt_b, 0u);
}

// The search must also terminate when nothing above the configured MTU is
// ever acknowledged: the interval quickly closes from above (loss push-outs),
// leaving the session at the configured MTU without an unbounded probe loop.
void TestAllProbesLostTerminates() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
  CHECK(h.Handshake());
  // Everything above the 1400 base is dropped: 1370 UDP payload = 1398 IP.
  h.path_max_wire = 1370;

  for (int64_t t = 25; t <= 16025; t += 1000) {
    h.TickAt(t);
  }
  CHECK(h.a->pmtu_search_done());
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.a->pmtu_probes_acked(), 0u);
  CHECK(h.a->pmtu_probes_lost() > 0u);

  const uint32_t frozen = h.a->pmtu_probes_sent();
  h.TickAt(6030);
  CHECK_EQ(h.a->pmtu_probes_sent(), frozen);
}

// Without the peer's capability the flag never negotiates, so neither side
// probes and both keep the configured MTU.
void TestNoProbeWithoutPeerCapability() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, /*on=*/false)));
  CHECK(h.Handshake());
  h.TickAt(25);
  h.TickAt(2025);
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.b->path_mtu(), 1400u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 0u);
  CHECK_EQ(h.b->pmtu_probes_sent(), 0u);
  CHECK_EQ(h.a->payload_max(), 1336u);
}

// The stream may use the new size at once: a full raised-size symbol is
// accepted by the peer, whose receive bound moved when the probe arrived.
void TestFullSizeSymbolAfterRaise() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
  CHECK(h.Handshake());
  h.TickAt(1025);
  h.TickAt(2025);
  h.TickAt(3025);
  CHECK_EQ(h.a->path_mtu(), 1487u);
  CHECK_EQ(h.a->payload_max(), 1423u);

  Bytes seg(1423, 0);
  for (size_t i = 0; i < seg.size(); ++i) {
    seg[i] = static_cast<uint8_t>(i * 13);
  }
  const uint64_t before = h.b->data_payload_rx();
  h.a->on_kcp_output(seg.data(), seg.size(), 50);
  h.now = 50;
  h.pump();
  CHECK_EQ(h.delivered_b.size(), 1u);
  CHECK_EQ(h.delivered_b[0].size(), 1423u);
  CHECK(h.b->data_payload_rx() > before);

  // One byte over the bound is still a mtu_drop, never a silent oversize.
  Bytes too_big(1424, 0);
  h.a->on_kcp_output(too_big.data(), too_big.size(), 60);
  h.now = 60;
  h.pump();
  CHECK_EQ(h.delivered_b.size(), 1u);
  CHECK_EQ(h.a->tx()->mtu_drops(), 1u);
}

// The ceiling is per-config policy, expressed without a wire field: the
// receiver never acks a probe above its own cap, so a peer whose ceiling is
// larger sees silence up there and the search narrows through loss records
// until its probes land inside the receiver's cap. Both sides settle
// precisely: the prober ends at the receiver's ceiling and the receiver
// never accepted a symbol above its own cap.
void TestPeerCeilingDoesNotRaiseOurs() {
  Harness h;
  fcp::SessionConfig a = PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  fcp::SessionConfig b = PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S);
  a.pmtu_max_mtu = 9000;
  CHECK(h.Init(a, b));
  CHECK(h.Handshake());
  h.TickAt(25);

  // First probes: A aims at (1400+9000)/2=5200, B at (1400+1500)/2=1450. A's
  // 5200 probe is silent (B's cap) and enters the ledger; B's own probe acks
  // against A (whose cap is the higher 9000) and proves 1450 for B. B's
  // receive bound has not moved: nothing A sent arrived above the base yet.
  h.TickAt(1025);
  CHECK_EQ(h.b->path_mtu(), 1450u);
  // B's receive bound has not moved above the configured geometry (the
  // 1400-MTU symbol bound) yet: A's first probe (5200) is over B's cap and
  // consumed without an ack.
  CHECK_EQ(h.b->recv_symbol_max(), 1338u);

  // The search narrows tick by tick until A lands exactly on B's cap of 1500
  // without a single ack above it, then stops for good. B's own return search
  // closes at 1487 (inside kPmtuMaxDiffMtu of its 1500 ceiling) unless A's
  // later probes keep raising its receive bound -- which they do, but its
  // send search is its own.
  h.TickTo(2025, 70325);
  // quic-go's maxMTUDiff in action: the prober ends within kPmtuMaxDiffMtu of
  // the receiver's cap without ever crossing it, the receiver accepted
  // nothing larger than the prober's proven size, and the search stops.
  CHECK(h.a->path_mtu() <= 1500u);
  CHECK(h.a->path_mtu() >= 1500u - fcp::kPmtuMaxDiffMtu);
  CHECK_EQ(h.a->payload_max(), h.a->path_mtu() - 64u);
  // Every in-range probe A sent was answered (nothing is silently dropped
  // below B's cap), so B's receive bound matches the proven send bound's
  // geometry exactly (28-byte envelope + 6-byte FEC header).
  CHECK_EQ(h.b->recv_symbol_max(),
           fcp::pmtu_udp_payload(h.a->path_mtu(), 20) - 34u);
  CHECK(h.a->pmtu_search_done());
  CHECK(h.a->pmtu_probes_acked() > 0u);
  CHECK_EQ(h.a->pmtu_probes_lost() + h.a->pmtu_probes_acked(),
           h.a->pmtu_probes_sent());

  const uint32_t frozen = h.a->pmtu_probes_sent();
  h.TickAt(200030);
  CHECK_EQ(h.a->pmtu_probes_sent(), frozen);
}

// A ceiling at or below the configured MTU disables the ladder outright.
void TestCeilingAtConfiguredMtuIsInert() {
  Harness h;
  fcp::SessionConfig a = PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  fcp::SessionConfig b = PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S);
  a.pmtu_max_mtu = 1400;
  b.pmtu_max_mtu = 1400;
  CHECK(h.Init(a, b));
  CHECK(h.Handshake());
  h.TickAt(25);
  h.TickAt(2025);
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 0u);
}

// Full-size data dropped at a size the probes did prove -- the size-based
// path-policing case (isolated probes pass, bulk at the raised size is
// black-holed, ICMP can't-fragment suppressed). Probes proved the rung, so
// the loss ledger never sees it; the only evidence is silence: >= 256 data
// symbols over >= 6 s with zero FECSTAT. That state is unrecoverable by ARQ
// (retransmissions leave at the same dead size), so the watchdog falls back
// in-session: the send bound reverts to the configured base, the dead size
// enters the ledger, and a clamp keeps the search from re-climbing into the
// dead rung for the hold window -- probes still get acked there on a
// rate-policing path, so without the clamp the search would walk straight
// back in. Past the hold the search resumes; the path may have healed, and
// if it has not, the next watchdog episode re-clamps.
void TestFullSizeDataDropFallsBackToBase() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
  CHECK(h.Handshake());
  h.TickAt(1025);
  h.TickAt(2025);
  h.TickAt(3025);
  CHECK_EQ(h.a->path_mtu(), 1487u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 3u);

  // Data/parity datagrams above 1400 bytes now vanish; oob still flows (the
  // peer keeps proving it receives nothing new by sending no FECSTAT).
  h.data_max_wire = 1400;
  h.now = 2100;
  for (uint32_t set = 0; set < 300; ++set) {
    Bytes seg(1423, 0);
    h.a->on_kcp_output(seg.data(), seg.size(), h.now);
  }
  h.pump();

  // The fallback fires inside the watchdog window, once: the send bound is
  // back at the configured base, the payload shrank with it, and the clamp
  // keeps the search below the dead rung's neighborhood -- no probe is spent
  // on a size this session must not re-climb to yet.
  h.TickTo(2200, 6200);
  h.TickAt(8025);
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.a->payload_max(), 1336u);
  size_t warns = 0;
  for (const auto& line : h.log_a) {
    if (line.find("raised size 1487 unreachable") != std::string::npos) {
      ++warns;
    }
  }
  CHECK(warns == 1u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 3u);
  CHECK(!h.a->pmtu_search_done());

  // Hold window: no data flows, so the watchdog cannot re-fire, and the
  // clamped search spends nothing -- the bound stays at the base. The window
  // ends well inside the hold (the clamp lifts at fallback+120 s, i.e.
  // ~126 s here).
  h.TickTo(8100, 60000);
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 3u);

  // Hold over: the search resumes and, with oob always passable in this
  // harness, climbs the ladder back to just under the ceiling -- the
  // "path healed" shape. The fallback warned exactly once for the episode.
  h.TickTo(126500, 141000);
  CHECK(h.a->pmtu_search_done());
  CHECK(h.a->path_mtu() > 1400u);
  warns = 0;
  for (const auto& line : h.log_a) {
    if (line.find("unreachable") != std::string::npos) {
      ++warns;
    }
  }
  CHECK(warns == 1u);
}

// The kernel's EMSGSIZE is authoritative path evidence below the configured
// floor (an ICMP-learned path-MTU cache that outruns --mtu): a refusal at the
// bulk bound steps it down 20 bytes per refusal until sends succeed, a
// refusal above the bound is a probe-sized datagram and only feeds the
// ledger, and the descent follows the bound's own value, so queued stale
// datagrams of the pre-descent size cannot stall it.
void TestKernelSendTooBigStepsDown() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
  CHECK(h.Handshake());
  CHECK_EQ(h.a->path_mtu(), 1400u);

  // Full data datagram refused: wire 1372 -> IP 1400 == the bound, one step.
  h.a->on_kernel_send_too_big(1372, 5000);
  CHECK_EQ(h.a->path_mtu(), 1380u);
  CHECK_EQ(h.a->payload_max(), fcp::compute_mtu_limits(1380, 20).payload_max);

  // The kernel's cache is at 1352 here: every rung keeps refusing, and each
  // refusal at the CURRENT bound takes a further step.
  h.a->on_kernel_send_too_big(1352, 5025);  // IP 1380 == the bound
  CHECK_EQ(h.a->path_mtu(), 1360u);
  h.a->on_kernel_send_too_big(1332, 5050);  // IP 1360
  CHECK_EQ(h.a->path_mtu(), 1340u);
  h.a->on_kernel_send_too_big(1312, 5075);  // IP 1340
  CHECK_EQ(h.a->path_mtu(), 1320u);

  // A refusal above the bound is probe-sized: ledger only, the bulk bound
  // and the payload it arms stay put.
  const size_t payload_before = h.a->payload_max();
  h.a->on_kernel_send_too_big(1462, 5100);  // IP 1490 > 1340
  CHECK_EQ(h.a->path_mtu(), 1320u);
  CHECK_EQ(h.a->payload_max(), payload_before);
}

}  // namespace

int main() {
  TestProbeGeometry();
  TestMessageCodec();
  TestSearchRaisesBothDirections();
  TestBlockedPathConvergesDown();
  TestAllProbesLostTerminates();
  TestNoProbeWithoutPeerCapability();
  TestFullSizeSymbolAfterRaise();
  TestPeerCeilingDoesNotRaiseOurs();
  TestCeilingAtConfiguredMtuIsInert();
  TestFullSizeDataDropFallsBackToBase();
  TestKernelSendTooBigStepsDown();
  return fcp_test::finish();
}
