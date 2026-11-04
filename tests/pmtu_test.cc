// Path-MTU discovery, upward only (pmtu.h, protocol capability kCapPmtud).
//
// Three things are checked: the probe geometry is exactly the advertised IP
// size, a probe that the path drops never moves a bound, and a probe that
// arrives moves the receive bound before the ack and the send bound after it,
// so a full-size data symbol follows immediately.
//
// The harness is the one the e2e tests use, with `path_max_wire` standing in
// for a path MTU: datagrams larger than it are dropped before the peer ever
// sees them, which is exactly the failure upward PMTUD has to survive.

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

// The path carries 1500: one tick should finish the ladder in both directions.
void TestProbeRaisesBothDirections() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
  CHECK(h.Handshake());
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.b->path_mtu(), 1400u);

  h.TickAt(25);
  // Probe out, ack back, send bound raised; then the peer's own ladder.
  CHECK_EQ(h.a->path_mtu(), 1500u);
  CHECK_EQ(h.b->path_mtu(), 1500u);
  CHECK_EQ(h.a->pmtu_probes_acked(), 1u);
  CHECK_EQ(h.b->pmtu_probes_acked(), 1u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 1u);
  CHECK_EQ(h.b->pmtu_probes_sent(), 1u);
  CHECK_EQ(h.a->pmtu_probes_lost(), 0u);
  // 1500-byte IP packet, 20-byte IPv4 header: 1472 UDP, 1436 payload, 1412 mss.
  CHECK_EQ(h.a->mtu_limits().payload_max, 1436u);
  CHECK_EQ(h.a->mtu_limits().mss, 1412u);
  CHECK_EQ(h.a->payload_max(), 1436u);
  CHECK_EQ(h.b->payload_max(), 1436u);
}

// A probe the path cannot carry never gets an ack, and the session keeps the
// configured MTU after three attempts. Data at the old size keeps flowing.
void TestBlockedPathKeepsConfiguredMtu() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
  CHECK(h.Handshake());
  // 1372 UDP payload = the 1400-byte datagrams the session already sends; the
  // 1472-byte probe is the only one that no longer fits.
  h.path_max_wire = 1372;

  for (int64_t t = 25; t <= 3025; t += 1000) {
    h.TickAt(t);
  }
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.b->path_mtu(), 1400u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 3u);
  CHECK_EQ(h.a->pmtu_probes_acked(), 0u);
  CHECK_EQ(h.a->pmtu_probes_lost(), 1u);
  CHECK_EQ(h.a->payload_max(), 1336u);

  // The ladder stopped: further ticks send nothing more.
  h.TickAt(6000);
  CHECK_EQ(h.a->pmtu_probes_sent(), 3u);

  // The tunnel itself was never affected by the failed probes.
  h.Inject(0, 3, 6100);
  CHECK_EQ(h.delivered_b.size(), 3u);
  CHECK_EQ(h.corrupt_b, 0u);
}

// Without the peer's capability the flag never negotiates, so neither side
// probes and both keep the configured MTU.
void TestNoProbeWithoutPeerCapability() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, /*on=*/false)));
  CHECK(h.Handshake());
  h.TickAt(25);
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.b->path_mtu(), 1400u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 0u);
  CHECK_EQ(h.b->pmtu_probes_sent(), 0u);
  CHECK_EQ(h.a->payload_max(), 1336u);
}

// The stream may use the new size at once: a full 1436-byte symbol is
// accepted by the peer, whose receive bound moved when the probe arrived.
void TestFullSizeSymbolAfterRaise() {
  Harness h;
  CHECK(h.Init(PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
               PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
  CHECK(h.Handshake());
  h.TickAt(25);
  CHECK_EQ(h.a->payload_max(), 1436u);

  Bytes seg(1436, 0);
  for (size_t i = 0; i < seg.size(); ++i) {
    seg[i] = static_cast<uint8_t>(i * 13);
  }
  const uint64_t before = h.b->data_payload_rx();
  h.a->on_kcp_output(seg.data(), seg.size(), 50);
  h.now = 50;
  h.pump();
  CHECK_EQ(h.delivered_b.size(), 1u);
  CHECK_EQ(h.delivered_b[0].size(), 1436u);
  CHECK(h.b->data_payload_rx() > before);

  // One byte over the bound is still a mtu_drop, never a silent oversize.
  Bytes too_big(1437, 0);
  h.a->on_kcp_output(too_big.data(), too_big.size(), 60);
  h.now = 60;
  h.pump();
  CHECK_EQ(h.delivered_b.size(), 1u);
  CHECK_EQ(h.a->tx()->mtu_drops(), 1u);
}

// The ceiling is local policy. A peer whose --pmtu-max is larger keeps a
// higher ladder, but its probe must not raise the receive bound of a side
// configured lower: that bound sizes the buffers for its jumbo symbols, and
// only the local operator decides how much memory that is worth (the path may
// even be asymmetric). Both sides settle on the smaller ceiling.
void TestPeerCeilingDoesNotRaiseOurs() {
  Harness h;
  fcp::SessionConfig a = PmtuConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  fcp::SessionConfig b = PmtuConfig(fcp::Direction::kS2C, fcp::Direction::kC2S);
  a.pmtu_max_mtu = 9000;
  CHECK(h.Init(a, b));
  CHECK(h.Handshake());
  h.TickAt(25);
  // Both climb the first rung; A proves 1500, so B's receive bound is the
  // 1500 geometry (1438-byte symbol) and a full-size symbol is accepted.
  CHECK_EQ(h.a->path_mtu(), 1500u);
  CHECK_EQ(h.a->payload_max(), 1436u);
  CHECK_EQ(h.b->recv_symbol_max(), 1438u);

  // A's next rung is 9000; B ignores it and never acks, so A retries three
  // times and stops at 1500 without moving anything on B's side.
  for (int64_t t = 1025; t <= 4025; t += 1000) {
    h.TickAt(t);
  }
  CHECK_EQ(h.a->path_mtu(), 1500u);
  CHECK_EQ(h.a->payload_max(), 1436u);
  CHECK_EQ(h.b->recv_symbol_max(), 1438u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 4u);  // 1 at 1500 + 3 at 9000
  CHECK_EQ(h.a->pmtu_probes_lost(), 1u);
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
  CHECK_EQ(h.a->path_mtu(), 1400u);
  CHECK_EQ(h.a->pmtu_probes_sent(), 0u);
}

}  // namespace

int main() {
  TestProbeGeometry();
  TestMessageCodec();
  TestProbeRaisesBothDirections();
  TestBlockedPathKeepsConfiguredMtu();
  TestNoProbeWithoutPeerCapability();
  TestFullSizeSymbolAfterRaise();
  TestPeerCeilingDoesNotRaiseOurs();
  TestCeilingAtConfiguredMtuIsInert();
  return fcp_test::finish();
}
