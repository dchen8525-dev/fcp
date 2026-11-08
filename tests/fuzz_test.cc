// In-process fuzz smoke over every parser that faces the network. This is a
// tripwire, not a fuzzing campaign: a fixed-seed PRNG drives bounded
// mutations of real, valid datagrams into the real parse paths, and the test
// passes as long as nothing crashes, hangs, or throws.
//
// Surfaces, in the order the wire reaches them:
//   * Session::on_wire -- the full authenticated path (envelope -> FEC hdr ->
//     FECSTAT validation / PMTU / oob dispatch incl. the NAT keepalive).
//     A forged peer session with matching key+salt seals datagrams the target
//     decrypts, so mutations land inside the parse layers, not just in auth
//     failures.
//   * handshake-phase HELLO/HELLO_ACK into a fresh, never-established session.
//   * pure codecs: bench payload/rendezvous, PMTU frame, FECSTAT validator.
//
// Deterministic: a fixed seed and a fixed feed order reproduce any failure.
// The harness walks one pair past the 45s NAT-keepalive mark on simulated
// time, so the keepalive frame is part of the corpus it fuzzes.

#include <chrono>
#include <cstring>
#include <memory>
#include <random>
#include <vector>

#include "bench.h"
#include "fcp/fecstat.h"
#include "fcp/pmtu.h"
#include "fcp/session.h"
#include "test_util.h"

namespace {

int64_t NowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::mt19937 Rng() {
  return std::mt19937(0x5EEDu);
}

// Sessions with matching key+salt in crossed directions: whatever `forge`
// seals, `target` decrypts through the full authenticated parse path.
struct Pair {
  std::vector<std::vector<uint8_t>> forge_out;
  std::vector<std::vector<uint8_t>> target_out;
  fcp::Session* forge = nullptr;
  fcp::Session* target = nullptr;
  int64_t now = 0;
};

std::unique_ptr<fcp::Session> MakeForge(Pair& p) {
  fcp::SessionConfig cfg;
  cfg.send_direction = fcp::Direction::kC2S;
  cfg.recv_direction = fcp::Direction::kS2C;
  cfg.d = 10;
  cfg.p = 3;
  cfg.p_max = 6;
  cfg.mtu = 1400;
  cfg.ip_hdr_len = 20;
  cfg.pmtud = true;
  return std::make_unique<fcp::Session>(
      cfg,
      [&p](const uint8_t* wire, size_t len, fcp::SymbolType) {
        p.forge_out.emplace_back(wire, wire + len);
      },
      [](const uint8_t*, size_t) {}, [](const std::string&) {});
}

std::unique_ptr<fcp::Session> MakeTarget(Pair& p) {
  fcp::SessionConfig cfg;
  cfg.send_direction = fcp::Direction::kS2C;
  cfg.recv_direction = fcp::Direction::kC2S;
  cfg.d = 10;
  cfg.p = 3;
  cfg.p_max = 6;
  cfg.mtu = 1400;
  cfg.ip_hdr_len = 20;
  cfg.pmtud = true;
  return std::make_unique<fcp::Session>(
      cfg,
      [&p](const uint8_t* wire, size_t len, fcp::SymbolType) {
        p.target_out.emplace_back(wire, wire + len);
      },
      [](const uint8_t*, size_t) {}, [](const std::string&) {});
}

// Establish the pair by routing each side's sealed datagrams to the other,
// collecting everything the forge emits as seeds, then idling past the
// keepalive gate so the NAT keepalive frame joins the corpus.
void EstablishAndCollect(Pair& p, std::vector<std::vector<uint8_t>>* seeds) {
  p.forge->start(p.now);
  p.target->start(p.now);
  const uint8_t payload[fcp::bench::kDataPayloadLen] = {};
  bool established = false;
  for (; p.now < 3000; p.now += 5) {
    p.forge->on_tick(p.now);
    p.target->on_tick(p.now);
    for (const auto& d : p.forge_out) {
      (void)p.target->on_wire(d.data(), d.size(), p.now);
      if (seeds->size() < 400) {
        seeds->push_back(d);
      }
    }
    for (const auto& d : p.target_out) {
      (void)p.forge->on_wire(d.data(), d.size(), p.now);
      if (seeds->size() < 400) {
        seeds->push_back(d);
      }
    }
    p.forge_out.clear();
    p.target_out.clear();
    if (p.now % 20 == 0 && !established) {
      p.forge->on_kcp_output(payload, sizeof(payload), p.now);
    }
    if (p.forge->established() && p.target->established()) {
      established = true;
    }
  }
  CHECK(established);
  // Idle across the keepalive gate (no data pumping): both sessions emit
  // their NAT keepalives, and the harness captures them as seeds too.
  for (; p.now < 50000; p.now += 25) {
    p.forge->on_tick(p.now);
    p.target->on_tick(p.now);
    for (const auto& d : p.forge_out) {
      (void)p.target->on_wire(d.data(), d.size(), p.now);
      if (seeds->size() < 400) {
        seeds->push_back(d);
      }
    }
    for (const auto& d : p.target_out) {
      (void)p.forge->on_wire(d.data(), d.size(), p.now);
    }
    p.forge_out.clear();
    p.target_out.clear();
  }
}

std::vector<uint8_t> Mutate(const std::vector<uint8_t>& in, std::mt19937& rng) {
  std::vector<uint8_t> m = in;
  const int rounds = 1 + static_cast<int>(rng() % 4);
  for (int i = 0; i < rounds && !m.empty(); ++i) {
    switch (rng() % 5) {
      case 0: {  // bit flips
        const int flips = 1 + static_cast<int>(rng() % 8);
        for (int f = 0; f < flips; ++f) {
          m[rng() % m.size()] ^= static_cast<uint8_t>(1u << (rng() % 8));
        }
        break;
      }
      case 1: {  // truncate
        m.resize(rng() % m.size());
        break;
      }
      case 2: {  // append garbage
        const size_t extra = rng() % 64;
        for (size_t k = 0; k < extra; ++k) {
          m.push_back(static_cast<uint8_t>(rng()));
        }
        break;
      }
      case 3: {  // random overwrite span
        const size_t pos = rng() % m.size();
        const size_t span = std::min<size_t>(m.size() - pos, 1 + rng() % 32);
        for (size_t k = 0; k < span; ++k) {
          m[pos + k] = static_cast<uint8_t>(rng());
        }
        break;
      }
      default: {  // corner bytes
        m[rng() % m.size()] = static_cast<uint8_t>(rng() % 2 ? 0xFF : 0x00);
        break;
      }
    }
  }
  if (m.empty()) {
    m.push_back(0);
  }
  return m;
}

void FuzzSessionPair() {
  std::mt19937 rng = Rng();
  Pair p;
  p.forge = MakeForge(p).release();
  p.target = MakeTarget(p).release();
  std::vector<std::vector<uint8_t>> seeds;
  EstablishAndCollect(p, &seeds);
  CHECK(!seeds.empty());

  const int64_t fuzz_start = NowMs();
  int64_t now = 50000;
  for (int iter = 0; iter < 20000; ++iter) {
    const std::vector<uint8_t>& seed = seeds[rng() % seeds.size()];
    const std::vector<uint8_t> m = Mutate(seed, rng);
    // Both directions: the target eats peer-shaped traffic, the forge eats
    // what claims to come from the client.
    (void)p.target->on_wire(m.data(), m.size(), now);
    (void)p.forge->on_wire(m.data(), m.size(), now);
    ++now;
    if (iter % 256 == 0 && NowMs() - fuzz_start > 8000) {
      break;  // slow machine: the tripwire stays bounded, not the seed set
    }
  }
  delete p.forge;
  delete p.target;
  p.forge = nullptr;
  p.target = nullptr;
}

// Handshake-phase fuzz: mutated HELLO/HELLO_ACK-shaped datagrams against a
// session that has never established (the bootstrap envelope path).
void FuzzHandshakePhase() {
  std::mt19937 rng = Rng();
  Pair p;
  p.forge = MakeForge(p).release();
  std::vector<std::vector<uint8_t>> hellos;
  p.forge->start(0);
  for (int64_t t = 0; t <= 1000; t += 5) {
    p.forge->on_tick(t);
    for (const auto& d : p.forge_out) {
      hellos.push_back(d);
    }
    p.forge_out.clear();
  }
  CHECK(!hellos.empty());
  // #77: seed ext-shaped handshake messages too -- a valid TLV block, an
  // empty one, a block/length mismatch that must bounce at dispatch, and a
  // length-consistent block whose inner TLV is malformed (type 0). Mutate()
  // then twists all of them through the on_wire -> on_oob parse path.
  {
    const fcp::HandshakeCaps caps{
        1, 10, 3, static_cast<uint8_t>(fcp::kLocalFlagsM1 | fcp::kCapTlv)};
    const std::vector<fcp::HandshakeTlv> tlvs = {{0x90, {1, 2, 3}}, {0xEE, {}}};
    const uint8_t server_draw[fcp::kHandshakeNonceLen] = {9, 9, 9, 9, 9, 9, 9, 9,
                                                          9, 9, 9, 9, 9, 9, 9, 9};
    uint8_t buf[fcp::kHelloAckLen + fcp::kTlvBlockLenBytes + 64];
    size_t n = fcp::build_hello_ext(caps, p.forge->handshake_nonce(), tlvs, buf,
                                    sizeof(buf));
    CHECK(n != 0);
    hellos.emplace_back(buf, buf + n);
    n = fcp::build_hello_ack_ext(caps, p.forge->handshake_nonce(), server_draw,
                                 tlvs, buf, sizeof(buf));
    CHECK(n != 0);
    hellos.emplace_back(buf, buf + n);
    n = fcp::build_hello_ack_ext(caps, p.forge->handshake_nonce(), server_draw,
                                 {}, buf, sizeof(buf));
    CHECK(n != 0);
    hellos.emplace_back(buf, buf + n);
    std::vector<uint8_t> mismatched = hellos.front();
    mismatched[fcp::kHelloLen - 1] |= fcp::kCapTlv;  // bit5, no block follows
    hellos.push_back(mismatched);
    std::vector<uint8_t> bad_type = mismatched;
    bad_type.push_back(0x00);  // block_len = 1
    bad_type.push_back(0x01);
    bad_type.push_back(0x00);  // TLV type 0: reserved, malformed
    hellos.push_back(bad_type);
  }
  auto target = MakeTarget(p);
  target->start(0);
  const int64_t fuzz_start = NowMs();
  int64_t now = 0;
  for (int iter = 0; iter < 6000; ++iter) {
    const std::vector<uint8_t>& seed = hellos[rng() % hellos.size()];
    const std::vector<uint8_t> m = Mutate(seed, rng);
    (void)target->on_wire(m.data(), m.size(), now);
    ++now;
    if (iter % 256 == 0 && NowMs() - fuzz_start > 4000) {
      break;
    }
  }
  delete p.forge;
  p.forge = nullptr;
}

// Pure codec fuzz: no sessions, just the parse functions on mutated input.
void FuzzCodecs() {
  using namespace fcp::bench;
  std::mt19937 rng = Rng();

  std::vector<std::vector<uint8_t>> seeds;
  uint8_t buf[kReportPayloadLen] = {};
  EncodeReport(1, 123456789ull, 987654321ull, 424242ull, 555666ull, 987654u,
               true, buf, sizeof(buf));
  seeds.emplace_back(buf, buf + sizeof(buf));
  uint8_t down[kDownReportPayloadLen] = {};
  EncodeDownReport(2, 987654321ull, 123456ull, down, sizeof(down));
  seeds.emplace_back(down, down + sizeof(down));
  uint8_t ping[kPingPayloadLen] = {};
  EncodePing(3, 1234567890123ull, ping, sizeof(ping));
  seeds.emplace_back(ping, ping + sizeof(ping));
  uint8_t rendezvous[kRendezvousLen] = {};
  uint8_t salt[kSaltLen] = {1, 2, 3, 4, 5, 6, 7, 8};
  EncodeRendezvous(salt, 8, rendezvous);
  seeds.emplace_back(rendezvous, rendezvous + sizeof(rendezvous));
  // #77: handshake TLV block codec -- the parse surface the ext-shaped
  // handshake messages feed.
  {
    std::vector<fcp::HandshakeTlv> tlvs = {{1, {1}}, {0x80, {9, 9, 9}}, {0xFF, {}}};
    uint8_t tbuf[fcp::kTlvBlockLenBytes + 32];
    const size_t tn = fcp::tlv_encode(tlvs, tbuf, sizeof(tbuf));
    CHECK(tn != 0);
    seeds.emplace_back(tbuf + fcp::kTlvBlockLenBytes, tbuf + tn);
  }

  fcp::FecstatValidator validator;
  uint8_t salt8[8] = {};
  DecodedPayload decoded;
  uint16_t seconds_slot = 0;
  fcp::FecstatPacket stat{};
  const int64_t fuzz_start = NowMs();
  for (int iter = 0; iter < 12000; ++iter) {
    const std::vector<uint8_t>& seed = seeds[rng() % seeds.size()];
    const std::vector<uint8_t> m = Mutate(seed, rng);
    (void)DecodePayload(m.data(), m.size(), &decoded);
    (void)DecodeRendezvous(m.data(), m.size(), salt, &seconds_slot);
    // The FECSTAT validator shares the parse surface its real reports come
    // from; garbage must be rejected, never fatal.
    (void)validator.validate(m.data(), m.size(), salt8, &stat);
    if (iter % 256 == 0 && NowMs() - fuzz_start > 4000) {
      break;
    }
  }
}

}  // namespace

int main() {
  FuzzSessionPair();
  FuzzHandshakePhase();
  FuzzCodecs();
  return fcp_test::finish();
}
