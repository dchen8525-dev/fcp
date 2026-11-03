// Adversarial probes (对抗分析): hostile inputs at the module boundaries.
// One function per round; every CHECK failure is a finding to fix in src/.
//
// R1 envelope/AES-GCM   replay window, nonce limits, tamper, truncation
// R2 header validation  exhaustive type_k x index x geometry fuzz
// R3 RS / Cauchy        exhaustive (n, k) erasure patterns incl. ghost parity

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "fcp/aes.h"
#include "fcp/cauchy.h"
#include "fcp/envelope.h"
#include "fcp/frame_rx.h"
#include "fcp/frame_tx.h"
#include "fcp/fecstat.h"
#include "fcp/gcm.h"
#include "fcp/gf256.h"
#include "fcp/hdr.h"
#include "fcp/handshake.h"
#include "fcp/reporter.h"
#include "fcp/rs.h"
#include "fcp/settle.h"
#include "fcp/strategy.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "e2e_link.h"
#include "test_util.h"

namespace {

using Bytes = std::vector<uint8_t>;

Bytes Sealed(fcp::Envelope& env, uint64_t ctr, const Bytes& plain, bool* ok = nullptr) {
  Bytes wire;
  const bool sealed = env.seal_at(ctr, plain.data(), plain.size(), &wire);
  if (ok != nullptr) {
    *ok = sealed;
  }
  return wire;
}

// ---------------------------------------------------------------- R1 -------

void ProbeR1Envelope() {
  const uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  const uint8_t salt[8] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};

  // R1.1 empty and 1-byte plaintext roundtrip; wire == 28/29 bytes (T19).
  // The sender seals with c2s; only the peer (recv = c2s) can open it.
  {
    fcp::Envelope env(key, salt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::Envelope peer(key, salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    Bytes wire;
    CHECK(env.seal(nullptr, 0, &wire));
    CHECK_EQ(wire.size(), fcp::Envelope::kOverhead);
    Bytes plain;
    CHECK(peer.open(wire.data(), wire.size(), &plain));
    CHECK(plain.empty());

    const uint8_t one = 0x7F;
    CHECK(env.seal(&one, 1, &wire));
    CHECK_EQ(wire.size(), fcp::Envelope::kOverhead + 1);
    CHECK(peer.open(wire.data(), wire.size(), &plain));
    CHECK_EQ(plain.size(), size_t{1});
    CHECK_EQ(plain[0], one);
  }

  // R1.2 tamper every tag byte and every ciphertext byte -> open must fail.
  {
    fcp::Envelope env(key, salt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::Envelope peer(key, salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    const Bytes plain(64, 0x5A);
    const Bytes wire = Sealed(env, 1, plain);
    for (size_t i = 0; i < wire.size(); ++i) {
      Bytes bad = wire;
      bad[i] ^= 0x01;
      Bytes out;
      CHECK(!peer.open(bad.data(), bad.size(), &out));
    }
  }

  // R1.3 replay of an accepted datagram is rejected.
  {
    fcp::Envelope env(key, salt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::Envelope peer(key, salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    const Bytes wire = Sealed(env, 5, {1, 2, 3});
    Bytes out;
    CHECK(peer.open(wire.data(), wire.size(), &out));
    CHECK(!peer.open(wire.data(), wire.size(), &out));
  }

  // R1.4 reorder window boundary: delta kReplayWindow-1 accepted, delta
  // kReplayWindow rejected (#26③ widened the window from 64 to 256).
  {
    fcp::Envelope env(key, salt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::Envelope peer(key, salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    constexpr uint64_t w = fcp::Envelope::kReplayWindow;
    const Bytes wHigh = Sealed(env, w + 6, {7});
    const Bytes wEdge = Sealed(env, 6, {7});        // delta = w
    const Bytes wInner = Sealed(env, 7, {7});       // delta = w - 1
    Bytes out;
    CHECK(peer.open(wHigh.data(), wHigh.size(), &out));
    CHECK(peer.open(wInner.data(), wInner.size(), &out));  // delta w-1: last slot
    CHECK(!peer.open(wInner.data(), wInner.size(), &out)); // now a replay
    CHECK(!peer.open(wEdge.data(), wEdge.size(), &out));   // delta w: outside
  }

  // R1.5 counters at/above the 2^32 limit (#26①): seal refuses, open refuses.
  {
    fcp::Envelope env(key, salt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::Envelope peer(key, salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    const uint64_t limit = fcp::Envelope::kNonceLimit;
    Bytes wire;
    CHECK(!env.seal_at(limit, nullptr, 0, &wire));
    // A wire packet claiming a forbidden counter is a protocol violation, not a
    // replay: it must be dropped either way.
    Bytes legal;
    CHECK(env.seal_at(limit - 2, nullptr, 0, &legal));
    CHECK(peer.open(legal.data(), legal.size(), &wire));
    // forge the nonce field up to the limit
    for (int i = 0; i < 8; ++i) {
      legal[8 + i] = static_cast<uint8_t>((limit >> (8 * i)) & 0xFF);
    }
    Bytes out;
    CHECK(!peer.open(legal.data(), legal.size(), &out));
  }

  // R1.6 the last legal counter (limit-1) seals and opens; the normal send
  // path refuses afterwards and reports exhaustion. seal_at itself never
  // advances the counter (test/replay primitive).
  {
    fcp::Envelope env(key, salt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::Envelope peer(key, salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    Bytes wire;
    CHECK(env.seal_at(fcp::Envelope::kNonceLimit - 1, nullptr, 0, &wire));
    CHECK(!env.exhausted());  // seal_at does not touch send state
    CHECK(env.set_send_nonce(fcp::Envelope::kNonceLimit - 1));
    Bytes out;
    CHECK(env.seal(nullptr, 0, &out));
    CHECK(env.exhausted());
    CHECK(!env.seal(nullptr, 0, &out));  // any further seal refuses
    CHECK(peer.open(wire.data(), wire.size(), &out));
  }

  // R1.7 wrong salt / short wire / null guards.
  {
    fcp::Envelope env(key, salt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::Envelope peer(key, salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    const uint8_t other_salt[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    fcp::Envelope stranger(key, other_salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    const Bytes wire = Sealed(env, 1, {9, 9});
    Bytes out;
    CHECK(!stranger.open(wire.data(), wire.size(), &out));  // salt mismatch
    CHECK(!peer.open(wire.data(), wire.size() - 1, &out));  // truncated
    CHECK(!peer.open(nullptr, fcp::Envelope::kOverhead, &out));
    CHECK(!peer.open(wire.data(), fcp::Envelope::kOverhead - 1, &out));
  }

  // R1.8 reflection: a c2s datagram replayed back to its own sender must fail
  // (the sender's receive direction is s2c, so the IV differs); the peer still
  // accepts it. This is what kills UDP reflection attacks.
  {
    fcp::Envelope env(key, salt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::Envelope peer(key, salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    const Bytes wire = Sealed(env, 1, {1, 2, 3, 4});
    Bytes out;
    CHECK(!env.open(wire.data(), wire.size(), &out));  // reflected to sender
    CHECK(peer.open(wire.data(), wire.size(), &out));  // genuine receiver
  }

  // R1.9 envelope: sealing advances the counter by exactly 1 per packet.
  {
    fcp::Envelope env(key, salt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    Bytes wire;
    CHECK(env.seal(nullptr, 0, &wire));
    CHECK_EQ(env.send_nonce(), uint64_t{1});
    CHECK(env.seal(nullptr, 0, &wire));
    CHECK_EQ(env.send_nonce(), uint64_t{2});
    CHECK(env.set_send_nonce(100));
    CHECK_EQ(env.send_nonce(), uint64_t{100});
    CHECK(!env.set_send_nonce(fcp::Envelope::kNonceLimit));
    CHECK_EQ(env.send_nonce(), uint64_t{100});  // refused: state unchanged
    CHECK(env.seal(nullptr, 0, &wire));         // still sealable at 100
    CHECK_EQ(env.send_nonce(), uint64_t{101});
  }

  // R1.10 AES-NI and T-table paths agree on random blocks.
  {
    for (int i = 0; i < 64; ++i) {
      uint8_t key_block[16];
      uint8_t in[16];
      for (int b = 0; b < 16; ++b) {
        key_block[b] = fcp_test::random_byte();
        in[b] = fcp_test::random_byte();
      }
      fcp::Aes128Key rk;
      fcp::aes128_expand_key(key_block, &rk);
      uint8_t sw[16];
      uint8_t hw[16];
      fcp::aes128_encrypt_block_ttable(rk, in, sw);
      fcp::aes128_encrypt_block_hw(rk, in, hw);
      CHECK(std::memcmp(sw, hw, 16) == 0);
    }
  }
}

// ---------------------------------------------------------------- R2 -------

void ProbeR2Header() {
  // R2.1 pack/unpack roundtrip over every (k, j, type).
  for (uint8_t type = 0; type < 4; ++type) {
    for (uint8_t k = 0; k < 8; ++k) {
      for (uint8_t j = 0; j < 8; ++j) {
        const uint8_t tk = fcp::pack_type_k(k, j, type);
        CHECK_EQ(fcp::hdr_k(tk), k);
        CHECK_EQ(fcp::hdr_j(tk), j);
        CHECK_EQ(static_cast<uint8_t>(fcp::hdr_type(tk)), type);
      }
    }
  }

  // R2.2 exhaustive validation fuzz over data and parity geometry.
  // Spec §4.2 checks in order: index >= S; data index >= D; data index >= n
  // (when known); parity j >= k; parity n = index - j outside [1, D].
  {
    const uint8_t d = 10;
    const uint16_t s = d + 3;  // 13
    for (uint8_t type_k = 0; type_k < 255; type_k += 1) {
      const auto type = fcp::hdr_type(type_k);
      if (type != fcp::SymbolType::kData && type != fcp::SymbolType::kParity) {
        continue;
      }
      for (uint16_t index = 0; index < 256; ++index) {
        const fcp::FecHdr hdr{0, static_cast<uint8_t>(index), type_k};
        const uint8_t k = fcp::hdr_k(type_k);
        const uint8_t j = fcp::hdr_j(type_k);
        const fcp::HdrStatus st = fcp::validate_hdr(hdr, d, s, false, 0);
        if (type == fcp::SymbolType::kData) {
          const bool expect_ok = index < d;
          CHECK_EQ(st == fcp::HdrStatus::kOk, expect_ok);
        } else {
          bool expect_ok = index < s && j < k;
          const int n = static_cast<int>(index) - static_cast<int>(j);
          if (n < 1 || n > d) {
            expect_ok = false;
          }
          CHECK_EQ(st == fcp::HdrStatus::kOk, expect_ok);
          if (expect_ok) {
            // once n is known from a parity, data indices at/above it fail
            const fcp::HdrStatus st_data =
                fcp::validate_hdr(fcp::FecHdr{0, static_cast<uint8_t>(index), 0}, d, s, true,
                                  static_cast<uint8_t>(n));
            CHECK_EQ(st_data == fcp::HdrStatus::kOk, index < n);
          }
        }
      }
    }
  }

  // R2.3 parity at index 0 with j = 0 means n = 0 -> malformed (spec T16).
  CHECK(fcp::validate_hdr(fcp::FecHdr{0, 0, fcp::pack_type_k(1, 0, 1)}, 10, 13, false, 0) ==
        fcp::HdrStatus::kBadN);

  // R2.4 k = 0 parity is malformed regardless of j (j >= k when both 0).
  for (uint8_t j = 0; j < 8; ++j) {
    CHECK(fcp::validate_hdr(fcp::FecHdr{0, 5, fcp::pack_type_k(0, j, 1)}, 10, 13, false, 0) ==
          fcp::HdrStatus::kJNotBelowK);
  }

  // R2.5 oob bypasses geometry checks entirely (index 255, junk k/j); type 3 is
  // undefined since erratum #25 and rejected unconditionally.
  CHECK(fcp::validate_hdr(fcp::FecHdr{0, 255, 0xFE}, 10, 13, false, 0) ==
        fcp::HdrStatus::kOk);
  CHECK(fcp::validate_hdr(fcp::FecHdr{0, 255, 0xFF}, 10, 13, false, 0) ==
        fcp::HdrStatus::kInvalidType);

  // R2.6 parse_hdr rejects short/absent buffers.
  {
    uint8_t buf[8] = {};
    fcp::FecHdr hdr{};
    CHECK(fcp::parse_hdr(buf, 6, &hdr));
    CHECK(!fcp::parse_hdr(buf, 5, &hdr));
    CHECK(!fcp::parse_hdr(buf, 0, &hdr));
    CHECK(!fcp::parse_hdr(nullptr, 6, &hdr));
    CHECK(!fcp::parse_hdr(buf, 6, nullptr));
  }
}

// ---------------------------------------------------------------- R3 -------

void ProbeR3Rs() {
  auto run_case = [](size_t n, size_t k, size_t symbol_max, uint8_t fill,
                     const std::vector<size_t>& erased_data,
                     const std::vector<size_t>& erased_parity) {
    std::vector<std::vector<uint8_t>> data(n, std::vector<uint8_t>(symbol_max, fill));
    for (size_t i = 0; i < n; ++i) {
      data[i][0] = static_cast<uint8_t>(2 + i);  // fake len field
      for (size_t b = 2; b < symbol_max; ++b) {
        data[i][b] = static_cast<uint8_t>(fill + i * 31 + b * 7);
      }
    }
    std::vector<std::vector<uint8_t>> parity(k, std::vector<uint8_t>(symbol_max));
    std::vector<uint8_t*> parity_ptrs(k);
    for (size_t j = 0; j < k; ++j) {
      parity_ptrs[j] = parity[j].data();
    }
    std::vector<const uint8_t*> data_ptrs(n);
    for (size_t i = 0; i < n; ++i) {
      data_ptrs[i] = data[i].data();
    }
    fcp::encode(data_ptrs.data(), n, k, symbol_max, parity_ptrs.data());

    std::vector<std::vector<uint8_t>> symbols(n + k);
    std::vector<const uint8_t*> ptrs(n + k, nullptr);
    for (size_t i = 0; i < n; ++i) {
      symbols[i] = data[i];
      ptrs[i] = symbols[i].data();
    }
    for (size_t j = 0; j < k; ++j) {
      symbols[n + j] = parity[j];
      ptrs[n + j] = symbols[n + j].data();
    }
    for (size_t i : erased_data) {
      ptrs[i] = nullptr;
    }
    for (size_t j : erased_parity) {
      ptrs[n + j] = nullptr;
    }

    std::vector<std::vector<uint8_t>> recovered;
    const bool ok = fcp::decode(ptrs.data(), n, k, symbol_max, &recovered);
    if (erased_data.empty()) {
      // Nothing to erase: decode must succeed and reconstruct nothing. rs.cc
      // pre-sizes `recovered` to n slots and fills only the erased ones, so
      // "nothing reconstructed" means every slot is empty -- not that the
      // vector itself is empty. This branch used to return silently, so the
      // whole no-loss shape went unasserted.
      CHECK(ok);
      CHECK_EQ(recovered.size(), n);
      for (const std::vector<uint8_t>& r : recovered) {
        CHECK(r.empty());
      }
      return ok;
    }
    // With g ghost/lost parity rows only k-g parity rows remain, so losses
    // beyond that are physically unrecoverable (spec §4.4: ghosts shrink the
    // redundancy budget). Decode must fail exactly there.
    const size_t available = k - erased_parity.size();
    if (!ok) {
      CHECK(erased_data.size() > available);
      std::fprintf(stderr,
                   "decode refused (expected): n=%zu k=%zu lost=%zu ghost=%zu\n", n, k,
                   erased_data.size(), erased_parity.size());
      return ok;
    }
    CHECK(ok);
    for (size_t i : erased_data) {
      CHECK_EQ(recovered[i].size(), symbol_max);
      CHECK(std::memcmp(recovered[i].data(), data[i].data(), symbol_max) == 0);
    }
    for (size_t i = 0; i < n; ++i) {
      const bool erased =
          std::find(erased_data.begin(), erased_data.end(), i) != erased_data.end();
      CHECK_EQ(recovered[i].empty(), !erased);
    }
    return ok;
  };

  // R3.1 every (n, k) with a deterministic pattern of erasures: all single
  // losses, plus a couple of multi-loss patterns, plus ghost parity rows
  // (j in [k_eff, k) never arrives -> erased in decode too).
  for (size_t n = 1; n <= 10; ++n) {
    for (size_t k = 1; k <= 7; ++k) {
      for (size_t lost = 0; lost <= k && lost <= n; ++lost) {
        // erase the first `lost` data symbols and the last (k - k_eff) parity
        std::vector<size_t> erased_data;
        for (size_t i = 0; i < lost; ++i) {
          erased_data.push_back(i);
        }
        const size_t k_eff = lost == 0 ? k : std::max<size_t>(1, (k * n + 9) / 10);
        std::vector<size_t> erased_parity;
        if (k_eff < k) {
          erased_parity.push_back(k - 1);  // ghost row: not sent
        }
        run_case(n, k, 40 + n, 0xA5, erased_data, erased_parity);
      }
      // worst case: exactly k data losses and k-1 parity rows gone (ghosts)
      if (k <= n) {
        std::vector<size_t> all;
        for (size_t i = 0; i < k; ++i) {
          all.push_back(i);
        }
        std::vector<size_t> ghosts;
        for (size_t j = 1; j < k; ++j) {
          ghosts.push_back(j);
        }
        run_case(n, k, 64, 0x00, all, ghosts);  // all-zero payload
        run_case(n, k, 64, 0xFF, all, ghosts);  // all-ones payload
      }
    }
  }

  // R3.2 n = 1 recovers from a single data loss with any k.
  for (size_t k = 1; k <= 7; ++k) {
    run_case(1, k, 16, 0x33, {0}, {});
  }

  // R3.3 max geometry n + k = 256 works (index is u8).
  run_case(249, 7, 32, 0x11, {3}, {});
  run_case(255, 1, 32, 0x22, {254}, {});

  // R3.4 failure paths: more losses than k, no parity, k = 0.
  {
    std::vector<std::vector<uint8_t>> symbols(13, std::vector<uint8_t>(8, 0));
    std::vector<const uint8_t*> ptrs(13, nullptr);
    for (size_t i = 0; i < 13; ++i) {
      ptrs[i] = symbols[i].data();
    }
    ptrs[0] = nullptr;
    ptrs[1] = nullptr;          // 2 losses, k = 1 -> fail
    std::vector<std::vector<uint8_t>> rec;
    CHECK(!fcp::decode(ptrs.data(), 10, 1, 8, &rec));

    ptrs[1] = symbols[1].data();
    ptrs[10] = nullptr;         // the only parity row is lost -> fail
    CHECK(!fcp::decode(ptrs.data(), 10, 1, 8, &rec));

    CHECK(!fcp::decode(ptrs.data(), 10, 0, 8, &rec));   // k = 0
    CHECK(!fcp::decode(ptrs.data(), 0, 1, 8, &rec));    // n = 0
  }

  // R3.5 Cauchy matrix is MDS for the negotiated range: invert any t x t
  // submatrix built from distinct rows/columns.
  for (size_t n = 1; n <= 40; n += 3) {
    for (size_t k = 1; k <= 7; ++k) {
      const std::vector<uint8_t> mat = fcp::cauchy_matrix(n, k);
      const size_t t = std::min(n, k);
      // Top-left t x t block: rows 0..t-1 and columns 0..t-1 are distinct by
      // construction. The source is row-major with n columns per row, so the
      // source stride is n while the block stride is t.
      std::vector<uint8_t> block(t * t);
      for (size_t r = 0; r < t; ++r) {
        for (size_t c = 0; c < t; ++c) {
          block[r * t + c] = mat[r * n + c];
        }
      }
      // Inverting destroys the block, so keep a copy for the MDS check below.
      const std::vector<uint8_t> original = block;
      CHECK(fcp::cauchy_invert_matrix(block.data(), t));
      // MDS means the inverse restores the original block, not merely that a
      // matrix was produced: M * M^-1 must be the identity in GF(256), so
      // (M^-1)^-1 == M. Inverting the result and comparing is the cheapest way
      // to assert that without a matrix multiply here.
      std::vector<uint8_t> round_trip = block;
      CHECK(fcp::cauchy_invert_matrix(round_trip.data(), t));
      CHECK(round_trip == original);
    }
  }

  // R3.6 x_r and y_c sets are disjoint for every legal (n, k): the Cauchy
  // denominator x_r ^ (k + c) never vanishes (k + c <= 255 required).
  for (size_t k = 1; k <= 7; ++k) {
    for (size_t c = 0; k + c <= 255; ++c) {
      for (size_t r = 0; r < k; ++r) {
        // x_r and y_c are disjoint, so their XOR is non-zero and so is the
        // coefficient's inverse: a zero here would be a singular block.
        CHECK(fcp::cauchy_coeff(r, c, k) != 0);
        const uint8_t denom = static_cast<uint8_t>(r ^ (k + c));
        CHECK(denom != 0);
      }
    }
  }

  // R3.7 gf256 basics: inverse, division, pow.
  CHECK_EQ(fcp::gf256_mul(0, 0), 0);
  for (int a = 1; a < 256; ++a) {
    CHECK_EQ(fcp::gf256_mul(static_cast<uint8_t>(a), fcp::gf256_inv(static_cast<uint8_t>(a))),
             1);
  }
  CHECK_EQ(fcp::gf256_pow(0, 0), 1);
  CHECK_EQ(fcp::gf256_pow(0, 3), 0);
  CHECK_EQ(fcp::gf256_pow(2, 8), 0x1D);  // x^8 reduces to x^4+x^3+x^2+1 (0x11D)
  CHECK_EQ(fcp::gf256_exp(255), 1);
  CHECK_EQ(fcp::gf256_log(1), 0);
}

// ---------------------------------------------------------------- R4 -------

uint32_t SnAt0(const uint8_t* p, size_t len) {
  if (len < 4) {
    return 0;
  }
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

bool SnAt0Fn(const uint8_t* p, size_t len, uint32_t* sn) {
  if (len < 4) {
    return false;
  }
  *sn = SnAt0(p, len);
  return true;
}

struct RxFixture {
  uint8_t d;
  std::vector<Bytes> delivered;
  std::vector<uint32_t> delivered_sn;
  std::vector<Bytes> oobs;
  std::vector<fcp::RxEvent> events;
  fcp::FrameRx rx;

  RxFixture(uint8_t d_in = 10, uint8_t p_in = 3, bool dedup = true)
      : d(d_in),
        rx(d_in, p_in,
           [this](const uint8_t* p, size_t len) {
             delivered.emplace_back(p, p + len);
             delivered_sn.push_back(SnAt0(p, len));
           },
           [this](const uint8_t* m, size_t len, int64_t) { oobs.emplace_back(m, m + len); },
           dedup ? fcp::FrameRx::SnFn(&SnAt0Fn) : fcp::FrameRx::SnFn()) {
    rx.set_event_sink([this](fcp::RxEvent e, uint32_t) { events.push_back(e); });
  }

  void feed(uint32_t set_id, uint8_t index, uint8_t type_k, const Bytes& symbol,
            int64_t now_ms = 0) {
    uint8_t hdr[fcp::kFecHdrLen];
    fcp::pack_hdr(fcp::FecHdr{set_id, index, type_k}, hdr);
    Bytes dg(hdr, hdr + fcp::kFecHdrLen);
    dg.insert(dg.end(), symbol.begin(), symbol.end());
    rx.on_datagram(dg.data(), dg.size(), now_ms);
  }

  Bytes data_symbol(size_t payload_len, uint32_t sn) {
    Bytes sym(payload_len + 2, 0);
    sym[0] = static_cast<uint8_t>(payload_len + 2);
    sym[1] = static_cast<uint8_t>((payload_len + 2) >> 8);
    if (payload_len >= 4) {
      sym[2] = static_cast<uint8_t>(sn);
      sym[3] = static_cast<uint8_t>(sn >> 8);
      sym[4] = static_cast<uint8_t>(sn >> 16);
      sym[5] = static_cast<uint8_t>(sn >> 24);
    }
    for (size_t i = 2; i < sym.size(); ++i) {
      sym[i] = static_cast<uint8_t>(sn * 31 + i * 7);
    }
    return sym;
  }

  Bytes parity_symbol(size_t len) { return Bytes(len, 0xEE); }
};

void ProbeR4FrameRx() {
  // R4.1 duplicate data symbol: no re-delivery, no re-decode, counted as dup.
  {
    RxFixture f;
    const Bytes sym = f.data_symbol(8, 1);
    f.feed(1, 0, fcp::pack_type_k(2, 0, 0), sym);
    f.feed(1, 0, fcp::pack_type_k(2, 0, 0), sym);
    CHECK_EQ(f.delivered.size(), size_t{1});
    CHECK_EQ(f.rx.late_dup(), uint32_t{1});
  }

  // R4.2 k conflict inside one set -> struct_fail, accepted fragment untouched.
  {
    RxFixture f;
    f.feed(1, 0, fcp::pack_type_k(2, 0, 0), f.data_symbol(8, 1));
    f.feed(1, 1, fcp::pack_type_k(3, 0, 0), f.data_symbol(8, 2));
    CHECK_EQ(f.rx.struct_fail(), uint32_t{1});
    CHECK_EQ(f.delivered.size(), size_t{1});
    fcp::RxSetView v;
    CHECK(f.rx.view(1, &v));
    CHECK_EQ(v.k, uint8_t{2});
  }

  // R4.3 two parities disagreeing on n -> struct_fail (T18).
  {
    RxFixture f;
    f.feed(1, 10, fcp::pack_type_k(2, 0, 1), f.parity_symbol(12));
    f.feed(1, 11, fcp::pack_type_k(2, 1, 1), f.parity_symbol(12));
    CHECK_EQ(f.rx.struct_fail(), uint32_t{0});  // both say n = 10
    f.feed(1, 11, fcp::pack_type_k(2, 0, 1), f.parity_symbol(12));
    CHECK_EQ(f.rx.struct_fail(), uint32_t{1});  // now n = 11: conflict
  }

  // R4.4 data at index >= known n -> malformed.
  {
    RxFixture f;
    f.feed(1, 5, fcp::pack_type_k(1, 0, 1), f.parity_symbol(12));  // n = 5
    CHECK_EQ(f.rx.struct_fail(), uint32_t{0});
    f.feed(1, 5, fcp::pack_type_k(1, 0, 0), f.data_symbol(8, 5));
    CHECK_EQ(f.rx.struct_fail(), uint32_t{1});
    CHECK(f.delivered.empty());
  }

  // R4.5 a malformed far-future set_id must not move the anchor: an older
  // genuine set stays reachable (anchor check is < anchor - 256, so use a gap
  // inside the window).
  {
    RxFixture f;
    f.feed(9700, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 1));  // anchor 9700
    f.feed(60000, 200, fcp::pack_type_k(0, 0, 0),
           f.data_symbol(8, 2));  // malformed: index >= D
    CHECK_EQ(f.rx.struct_fail(), uint32_t{1});
    f.feed(9750, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 3));
    CHECK_EQ(f.delivered.size(), size_t{2});  // not stale
  }

  // R4.6 set_id wraparound: after the anchor sits near 2^32, sets that wrapped
  // to small ids are genuine new sets (spec §14.5 half-window rule) and must
  // not be treated as stale.
  {
    RxFixture f;
    const uint32_t near_top = 0xFFFFFFF0u;
    f.feed(near_top, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 1));
    CHECK_EQ(f.rx.anchor(), near_top);
    f.feed(2, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 2));  // wrapped
    CHECK_EQ(f.delivered.size(), size_t{2});
    CHECK_EQ(f.rx.anchor(), 2u);  // anchor advances across the wrap
  }

  // R4.7 short payloads (no extractable sn) must not collide in the dedup
  // table: every distinct short segment is delivered.
  {
    RxFixture f;
    f.feed(1, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(6, 1));
    f.feed(1, 1, fcp::pack_type_k(0, 0, 0), f.data_symbol(6, 2));
    f.feed(1, 2, fcp::pack_type_k(0, 0, 0), f.data_symbol(6, 3));
    CHECK_EQ(f.delivered.size(), size_t{3});
  }

  // R4.8 k = 0 sets never decode; data still delivered (spec T3).
  {
    RxFixture f;
    for (uint8_t i = 0; i < 10; ++i) {
      f.feed(1, i, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, i + 1));
    }
    CHECK_EQ(f.delivered.size(), size_t{10});
    CHECK_EQ(f.rx.decode_attempts(), uint32_t{0});
  }

  // R4.9 ghost parity: early-closed set (n=3, k=4 -> k_eff=2) recovers one
  // lost data even though parity rows 2 and 3 never existed (spec T17/T22).
  {
    RxFixture f(10, 4);
    const size_t n = 3;
    std::vector<Bytes> data;
    for (size_t i = 0; i < n; ++i) {
      data.push_back(f.data_symbol(20, static_cast<uint32_t>(100 + i)));
    }
    // encode parity over zero-extended symbols
    size_t symbol_max = 0;
    for (const auto& s : data) {
      symbol_max = std::max(symbol_max, s.size());
    }
    std::vector<std::vector<uint8_t>> padded(n, std::vector<uint8_t>(symbol_max, 0));
    std::vector<const uint8_t*> ptrs(n);
    for (size_t i = 0; i < n; ++i) {
      std::memcpy(padded[i].data(), data[i].data(), data[i].size());
      ptrs[i] = padded[i].data();
    }
    std::vector<std::vector<uint8_t>> parity(4, std::vector<uint8_t>(symbol_max));
    std::vector<uint8_t*> pptrs(4);
    for (size_t j = 0; j < 4; ++j) {
      pptrs[j] = parity[j].data();
    }
    fcp::encode(ptrs.data(), n, 4, symbol_max, pptrs.data());

    // feed data 0,1 and parity 0,1 (indices 3,4); data 2 lost
    f.feed(7, 0, fcp::pack_type_k(4, 0, 0), data[0]);
    f.feed(7, 1, fcp::pack_type_k(4, 0, 0), data[1]);
    f.feed(7, 3, fcp::pack_type_k(4, 0, 1), parity[0]);
    f.feed(7, 4, fcp::pack_type_k(4, 1, 1), parity[1]);
    CHECK_EQ(f.delivered.size(), size_t{3});  // data 2 recovered
    CHECK(f.delivered[2] == Bytes(data[2].begin() + 2, data[2].end()));
    CHECK_EQ(f.rx.recovered(), uint32_t{1});
  }

  // R4.10 capacity: 300 distinct active sets cap at 256 and tail-drop counts;
  // tombstones never let the map exceed the cap either.
  {
    RxFixture f;
    for (uint32_t id = 0; id < 300; ++id) {
      f.feed(id, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, id + 1));
    }
    CHECK(f.rx.active_sets() <= fcp::kMaxActiveSets);
    CHECK(f.rx.tail_dropped() > uint32_t{0});
  }

  // R4.11 data framing mismatch (declared len != symbol len) -> struct_fail.
  {
    RxFixture f;
    Bytes sym = f.data_symbol(8, 1);
    sym[0] = 0;  // declared 8 -> now declared 256+... mismatch
    f.feed(1, 0, fcp::pack_type_k(0, 0, 0), sym);
    CHECK_EQ(f.rx.struct_fail(), uint32_t{1});
    CHECK(f.delivered.empty());
  }

  // R4.12 duplicate parity is ignored (no re-decode, no counter churn).
  {
    RxFixture f;
    const Bytes p = f.parity_symbol(12);
    f.feed(1, 10, fcp::pack_type_k(2, 0, 1), p);
    f.feed(1, 10, fcp::pack_type_k(2, 0, 1), p);
    CHECK_EQ(f.rx.struct_fail(), uint32_t{0});
    fcp::RxSetView v;
    CHECK(f.rx.view(1, &v));
    CHECK_EQ(v.symbol_count, size_t{1});
  }
}

// ---------------------------------------------------------------- R5 -------

void ProbeR5FrameTx() {
  const Bytes g_seg8(8, 0x5C);  // an 8-byte KCP segment

  struct Out {
    std::vector<fcp::TxSymbol> symbols;
  };
  fcp::MtuLimits limits = fcp::compute_mtu_limits(1400, 20);
  auto make_tx = [&limits](Out& out, uint8_t d) {
    return fcp::FrameTx(d, limits, [&out](const fcp::TxSymbol& s) {
      out.symbols.push_back(s);
    });
  };

  // R5.1 T_flush: exact boundary closes; one tick earlier does not.
  {
    Out out;
    fcp::FrameTx tx = make_tx(out, 10);
    tx.set_srtt_ms(100);
    CHECK_EQ(tx.flush_timeout_ms(), int64_t{100});
    tx.on_kcp_output(nullptr, 0, 1000);
    CHECK(tx.has_open_set());
    tx.on_tick(1000 + 99);
    CHECK(tx.has_open_set());
    tx.on_tick(1000 + 100);
    CHECK(!tx.has_open_set());
    CHECK_EQ(tx.closed_idle(), uint32_t{1});
    CHECK_EQ(tx.parity_symbols(), uint32_t{0});  // k = 0
  }

  // R5.2 k_eff scaling table (spec T17): k=4 n=3 -> 2; k=1 n=7 -> 1; full n
  // keeps k.
  struct Case {
    uint8_t k;
    size_t n;
    uint32_t want_parity;
  };
  const Case cases[] = {
      {4, 3, 2}, {1, 7, 1}, {3, 10, 3}, {4, 10, 4}, {4, 1, 1}, {2, 5, 1},
  };
  for (const Case& c : cases) {
    Out out;
    fcp::FrameTx tx = make_tx(out, 10);
    tx.set_k(c.k);
    for (size_t i = 0; i < c.n; ++i) {
      tx.on_kcp_output(g_seg8.data(), g_seg8.size(), i * 10);
    }
    if (c.n == 10) {
      CHECK(!tx.has_open_set());
    } else {
      tx.on_tick(c.n * 10 + 500);
    }
    CHECK_EQ(tx.parity_symbols(), c.want_parity);
    if (c.want_parity > 0) {
      const fcp::TxSymbol& first = out.symbols[c.n];
      CHECK_EQ(first.index, static_cast<uint8_t>(c.n));
      CHECK_EQ(first.type_k, fcp::pack_type_k(c.k, 0, 1));
      CHECK_EQ(first.symbol.size(), size_t{8 + 2});  // symbol_max
    }
  }

  // R5.3 set_k only affects the NEXT set (locked at set start).
  {
    Out out;
    fcp::FrameTx tx = make_tx(out, 10);
    tx.set_k(1);
    tx.on_kcp_output(g_seg8.data(), g_seg8.size(), 0);
    tx.set_k(3);
    tx.on_kcp_output(g_seg8.data(), g_seg8.size(), 1);
    tx.on_tick(1000);
    CHECK_EQ(tx.parity_symbols(), uint32_t{1});  // k_eff = 1 from old k = 1
    tx.on_kcp_output(g_seg8.data(), g_seg8.size(), 2000);
    tx.on_tick(3000);
    // n = 1, k = 3 -> k_eff = 1
    CHECK_EQ(tx.parity_symbols(), uint32_t{2});
  }

  // R5.4 (erratum #25/T23) there is no content classification: a segment that
  // looks like a HELLO is ordinary data, occupies slots and is never dropped.
  {
    Out out;
    fcp::FrameTx tx = make_tx(out, 10);
    const uint8_t hello[16] = {'F', 'C', 'P', '_', 'H', 'E', 'L', 'L',
                               'O', '_', 'V', '3', 0,   0,   0,   0};
    tx.on_kcp_output(hello, 16, 0);
    tx.on_kcp_output(hello, 16, 0);
    CHECK_EQ(tx.data_symbols(), uint32_t{2});
    CHECK_EQ(tx.open_n(), uint8_t{2});
    CHECK_EQ(out.symbols[0].index, uint8_t{0});
    CHECK_EQ(out.symbols[1].index, uint8_t{1});
    for (const fcp::TxSymbol& s : out.symbols) {
      CHECK_EQ(fcp::hdr_type(s.type_k), fcp::SymbolType::kData);
      CHECK_EQ(s.symbol.size(), size_t{18});  // len(2) | payload
      CHECK(std::memcmp(s.symbol.data() + 2, hello, 16) == 0);
    }
  }

  // R5.5 oversized data segments are dropped before entering a set.
  {
    Out out;
    fcp::FrameTx tx = make_tx(out, 10);
    const Bytes big(limits.payload_max + 1, 0x11);
    tx.on_kcp_output(big.data(), big.size(), 0);
    CHECK(!tx.has_open_set());
    CHECK_EQ(tx.mtu_drops(), uint32_t{1});
    CHECK_EQ(tx.data_symbols(), uint32_t{0});
  }

  // R5.6 abort drops the open set without parity and bumps set_id.
  {
    Out out;
    fcp::FrameTx tx = make_tx(out, 10);
    tx.set_k(2);
    tx.on_kcp_output(g_seg8.data(), g_seg8.size(), 0);
    const uint32_t id = tx.set_id();
    tx.abort();
    CHECK(!tx.has_open_set());
    CHECK_EQ(tx.set_id(), id + 1);
    CHECK_EQ(tx.aborted_sets(), uint32_t{1});
    CHECK_EQ(tx.parity_symbols(), uint32_t{0});
  }

  // R5.7 zero-length payload is a legal symbol (len = 2) and a d = 1 geometry
  // closes after every segment.
  {
    Out out;
    fcp::FrameTx tx = make_tx(out, 1);
    tx.set_k(1);
    tx.on_kcp_output(nullptr, 0, 0);
    tx.on_kcp_output(nullptr, 0, 1);
    CHECK_EQ(tx.closed_full(), uint32_t{2});
    CHECK_EQ(tx.parity_symbols(), uint32_t{2});
    CHECK_EQ(out.symbols[1].symbol.size(), size_t{2});  // len=2, no payload
  }

  // R5.8 len field is little-endian 2 + payload and the symbol holds the
  // payload verbatim.
  {
    Out out;
    fcp::FrameTx tx = make_tx(out, 10);
    std::vector<uint8_t> seg(300, 0x42);
    tx.on_kcp_output(seg.data(), seg.size(), 0);
    const fcp::TxSymbol& s = out.symbols[0];
    CHECK_EQ(s.symbol.size(), size_t{302});
    CHECK_EQ(s.symbol[0], uint8_t{302 & 0xFF});
    CHECK_EQ(s.symbol[1], uint8_t{302 >> 8});
    CHECK(std::memcmp(s.symbol.data() + 2, seg.data(), seg.size()) == 0);
  }
}

// ---------------------------------------------------------------- R6 -------

struct SettleFixture {
  std::unique_ptr<fcp::FrameRx> rx;
  std::unique_ptr<fcp::FcpSettle> settle;
  std::vector<Bytes> delivered;
  std::vector<fcp::RxEvent> events;

  explicit SettleFixture(uint8_t d = 10, uint8_t p = 3) {
    rx = std::make_unique<fcp::FrameRx>(
        d, p,
        [this](const uint8_t* pl, size_t len) { delivered.emplace_back(pl, pl + len); },
        [](const uint8_t*, size_t, int64_t) {}, fcp::FrameRx::SnFn(&SnAt0Fn));
    settle = std::make_unique<fcp::FcpSettle>(d);
    settle->attach(rx.get());  // settle takes rx's single event sink...
    // ...and this probe observes the same stream through settle's forwarder.
    settle->set_observer([this](fcp::RxEvent e, uint32_t) { events.push_back(e); });
  }

  void feed(uint32_t set_id, uint8_t index, uint8_t type_k, const Bytes& symbol,
            int64_t now_ms = 0) {
    uint8_t hdr[fcp::kFecHdrLen];
    fcp::pack_hdr(fcp::FecHdr{set_id, index, type_k}, hdr);
    Bytes dg(hdr, hdr + fcp::kFecHdrLen);
    dg.insert(dg.end(), symbol.begin(), symbol.end());
    rx->on_datagram(dg.data(), dg.size(), now_ms);
  }

  Bytes data_symbol(size_t payload_len, uint32_t sn) {
    Bytes sym(payload_len + 2, 0);
    sym[0] = static_cast<uint8_t>(payload_len + 2);
    sym[1] = static_cast<uint8_t>((payload_len + 2) >> 8);
    if (payload_len >= 4) {
      sym[2] = static_cast<uint8_t>(sn);
      sym[3] = static_cast<uint8_t>(sn >> 8);
      sym[4] = static_cast<uint8_t>(sn >> 16);
      sym[5] = static_cast<uint8_t>(sn >> 24);
    }
    for (size_t i = 2; i < sym.size(); ++i) {
      sym[i] = static_cast<uint8_t>(sn * 31 + i * 7);
    }
    return sym;
  }

  // Real RS parity over a whole set of data symbols (uniform symbol length).
  // Returns parity row j; all symbols share `sym_len` bytes.
  Bytes encode_parity_row(const std::vector<Bytes>& data_syms, size_t k_rows, size_t j,
                          size_t sym_len) {
    std::vector<std::vector<uint8_t>> padded(data_syms.size(),
                                             std::vector<uint8_t>(sym_len, 0));
    std::vector<const uint8_t*> ptrs(data_syms.size());
    for (size_t i = 0; i < data_syms.size(); ++i) {
      std::memcpy(padded[i].data(), data_syms[i].data(), data_syms[i].size());
      ptrs[i] = padded[i].data();
    }
    std::vector<std::vector<uint8_t>> parity(k_rows, std::vector<uint8_t>(sym_len));
    std::vector<uint8_t*> pptrs(k_rows);
    for (size_t r = 0; r < k_rows; ++r) {
      pptrs[r] = parity[r].data();
    }
    fcp::encode(ptrs.data(), data_syms.size(), k_rows, sym_len, pptrs.data());
    return parity[j];
  }
};

void ProbeR6Settle() {
  // R6.1 full accounting with one FEC recovery: orig/recovered bitmaps stay
  // separate (erratum #2) and the identity holds.
  {
    SettleFixture f;
    std::vector<Bytes> syms;
    for (uint8_t i = 0; i < 10; ++i) {
      syms.push_back(f.data_symbol(8, 10 + i));
      if (i == 3) {
        continue;  // lost
      }
      f.feed(1, i, fcp::pack_type_k(1, 0, 0), syms.back());
    }
    f.feed(1, 10, fcp::pack_type_k(1, 0, 1), f.encode_parity_row(syms, 1, 0, 10));
    CHECK_EQ(f.delivered.size(), size_t{10});  // index 3 recovered
    CHECK_EQ(f.rx->recovered(), uint32_t{1});
    f.settle->tick(1000, 200);  // eligible + guard elapsed (t_first = 0)
    const auto& c = f.settle->counters();
    CHECK_EQ(c.sets_expected, uint32_t{1});
    CHECK_EQ(c.data_expected, uint32_t{10});
    CHECK_EQ(c.data_rx_orig, uint32_t{9});
    CHECK_EQ(c.data_recovered_dl, uint32_t{1});
    CHECK_EQ(c.sets_full, uint32_t{1});
    CHECK_EQ(c.parity_rx, uint32_t{1});
    CHECK_EQ(c.parity_expected, uint32_t{1});
    CHECK(f.settle->identity_ok());
    CHECK(f.settle->delivered_le_sum());
  }

  // R6.2 late original data inside the tombstone window: data_late_rx, no
  // double counting. Set 2 closes itself with parity so both sets are eligible
  // without a third set_id.
  {
    SettleFixture f;
    std::vector<Bytes> syms;
    for (uint8_t i = 0; i < 10; ++i) {
      syms.push_back(f.data_symbol(8, 10 + i));
      if (i == 3) {
        continue;
      }
      f.feed(1, i, fcp::pack_type_k(0, 0, 0), syms.back());
    }
    // set 2: one data + one parity -> parity makes it eligible on its own
    const Bytes s2 = f.data_symbol(8, 99);
    f.feed(2, 0, fcp::pack_type_k(1, 0, 0), s2);
    f.feed(2, 1, fcp::pack_type_k(1, 0, 1),
           f.encode_parity_row({s2}, 1, 0, s2.size()));
    f.settle->tick(1000, 200);
    const auto& c = f.settle->counters();
    CHECK_EQ(c.sets_expected, uint32_t{2});
    CHECK_EQ(c.data_expected, uint32_t{11});
    CHECK_EQ(c.data_rx_orig, uint32_t{10});
    CHECK_EQ(f.settle->data_lost(), uint32_t{1});
    // now the "lost" index 3 shows up during the tombstone
    f.feed(1, 3, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 13));
    CHECK_EQ(f.delivered.size(), size_t{11});  // 10 originals + 1 late
    CHECK_EQ(c.data_late_rx, uint32_t{1});
    CHECK_EQ(f.settle->data_lost(), uint32_t{0});
    CHECK(f.settle->identity_ok());
  }

  // R6.3 whole-set loss (placeholder): only sets_k_unknown, never expected.
  {
    SettleFixture f;
    f.feed(1, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 1));
    // set 6 observed at 500ms with its own parity so it settles at the 1000ms
    // tick; sets 2..5 exist only as placeholder graves.
    const Bytes s6 = f.data_symbol(8, 2);
    f.feed(6, 0, fcp::pack_type_k(1, 0, 0), s6, 500);
    f.feed(6, 1, fcp::pack_type_k(1, 0, 1), f.encode_parity_row({s6}, 1, 0, s6.size()),
           500);
    f.settle->tick(1000, 200);
    const auto& c = f.settle->counters();
    CHECK_EQ(c.sets_k_unknown, uint32_t{4});
    CHECK_EQ(c.sets_expected, uint32_t{2});
    CHECK_EQ(c.data_expected, uint32_t{2});
    CHECK(f.settle->untrusted());  // 4 > 0.1 * 2
  }

  // R6.4 a set that never closes (no parity, no higher set_id) is dropped as
  // tail_dropped after 1s and stays out of expected (spec T12 path 3).
  {
    SettleFixture f;
    f.feed(1, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 1));
    f.settle->tick(500, 200);
    CHECK_EQ(f.settle->counters().sets_tail_dropped, uint32_t{0});
    f.settle->tick(1100, 200);
    CHECK_EQ(f.settle->counters().sets_tail_dropped, uint32_t{1});
    CHECK_EQ(f.settle->counters().sets_expected, uint32_t{0});
  }

  // R6.5 parity alone makes a tail set eligible (spec erratum #19): no higher
  // set_id is needed once a parity fragment arrived.
  {
    SettleFixture f;
    std::vector<Bytes> syms = {f.data_symbol(8, 1), f.data_symbol(8, 77),
                               f.data_symbol(8, 78)};
    f.feed(1, 0, fcp::pack_type_k(1, 0, 0), syms[0]);
    f.feed(1, 3, fcp::pack_type_k(1, 0, 1), f.encode_parity_row(syms, 1, 0, 10));  // n = 3
    f.settle->tick(50, 200);   // guard not elapsed yet
    CHECK_EQ(f.settle->counters().sets_expected, uint32_t{0});
    f.settle->tick(200, 200);  // t_first = 0, guard = 200 -> accounted
    const auto& c = f.settle->counters();
    CHECK_EQ(c.sets_expected, uint32_t{1});
    CHECK_EQ(c.data_expected, uint32_t{3});
    CHECK_EQ(c.data_rx_orig, uint32_t{1});
    CHECK_EQ(c.sets_partial, uint32_t{1});
    CHECK(f.settle->identity_ok());
  }

  // R6.6 tombstone expiry releases the set; late recovery after accounting
  // counts data_recovered_late and never backfills recovered_dl. Two data
  // symbols are missing so parity row 0 alone cannot decode; the set only
  // repairs when the late row 1 lands inside the tombstone.
  {
    SettleFixture f;
    std::vector<Bytes> syms;
    for (uint8_t i = 0; i < 5; ++i) {
      syms.push_back(f.data_symbol(8, 10 + i));
    }
    for (uint8_t i = 0; i < 3; ++i) {
      f.feed(1, i, fcp::pack_type_k(2, 0, 0), syms[i]);
    }
    f.feed(1, 5, fcp::pack_type_k(2, 0, 1), f.encode_parity_row(syms, 2, 0, 10));  // n = 5
    f.feed(2, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 99));  // eligible
    f.settle->tick(1000, 200);  // accounted; 3/5 orig, 2 missing, 1 parity row
    const auto& c0 = f.settle->counters();
    CHECK_EQ(c0.data_recovered_dl, uint32_t{0});
    CHECK_EQ(c0.sets_full, uint32_t{0});
    f.feed(1, 6, fcp::pack_type_k(2, 1, 1), f.encode_parity_row(syms, 2, 1, 10));
    CHECK_EQ(f.delivered.size(), size_t{6});  // 3 orig + set2 data + 2 late recov
    fcp::RxSetView v;
    CHECK(f.rx->view(1, &v));
    CHECK(v.recov_mask.test(3));
    CHECK(v.recov_mask.test(4));
    CHECK_EQ(f.settle->counters().data_recovered_dl, uint32_t{0});  // no backfill
    CHECK_EQ(f.settle->counters().data_recovered_late, uint32_t{2});
    CHECK(f.settle->identity_ok());
    // tombstone ends at accounted + tomb(200ms rtt -> 400ms)
    f.settle->tick(1000 + 400, 200);
    CHECK(!f.rx->view(1, &v));
  }

  // R6.7 interval reset keeps the session-level monotonic key.
  {
    SettleFixture f;
    f.feed(1, 0, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 1));
    // set 2 self-eligible via parity, observed late enough to clear the guard
    const Bytes s2 = f.data_symbol(8, 2);
    f.feed(2, 0, fcp::pack_type_k(1, 0, 0), s2, 500);
    f.feed(2, 1, fcp::pack_type_k(1, 0, 1), f.encode_parity_row({s2}, 1, 0, s2.size()),
           500);
    f.settle->tick(1000, 200);
    CHECK_EQ(f.settle->accounted_through_set_id(), uint32_t{2});
    f.settle->reset_interval();
    CHECK_EQ(f.settle->counters().data_expected, uint32_t{0});
    CHECK_EQ(f.settle->accounted_through_set_id(), uint32_t{2});
  }
}

// ---------------------------------------------------------------- R7 -------

using fcp::FecstatPacket;
using fcp::MakeFecstatPacket;
using fcp::kFecstatLen;

void ProbeR7Fecstat() {
  const uint8_t salt[8] = {1, 2, 3, 4, 5, 6, 7, 8};

  // R7.1 golden roundtrip; every rejection reason.
  {
    FecstatPacket p = MakeFecstatPacket(salt);
    p.accounted_through_set_id = 42;
    p.sets_expected = 3;
    p.data_expected = 30;
    p.data_rx_orig = 27;
    p.interval_ms = 2000;
    uint8_t wire[fcp::kFecstatLen];
    fcp::encode_fecstat(p, wire);
    FecstatPacket q{};
    CHECK(fcp::decode_fecstat(wire, sizeof(wire), salt, &q) == fcp::FecstatStatus::kOk);
    CHECK_EQ(q.accounted_through_set_id, uint32_t{42});
    CHECK_EQ(q.data_expected, uint32_t{30});

    FecstatPacket r{};
    CHECK(fcp::decode_fecstat(wire, sizeof(wire) - 1, salt, &r) ==
          fcp::FecstatStatus::kBadLength);
    uint8_t bad[fcp::kFecstatLen];
    std::memcpy(bad, wire, sizeof(wire));
    bad[0] ^= 0x01;
    CHECK(fcp::decode_fecstat(bad, sizeof(bad), salt, &r) ==
          fcp::FecstatStatus::kBadMagic);
    std::memcpy(bad, wire, sizeof(wire));
    bad[16] ^= 0x01;  // salt byte
    CHECK(fcp::decode_fecstat(bad, sizeof(bad), salt, &r) ==
          fcp::FecstatStatus::kBadSalt);
    std::memcpy(bad, wire, sizeof(wire));
    bad[24] = 7;  // version field
    CHECK(fcp::decode_fecstat(bad, sizeof(bad), salt, &r) == fcp::FecstatStatus::kBadVer);
    const uint8_t other_salt[8] = {9, 9, 9, 9, 9, 9, 9, 9};
    CHECK(fcp::decode_fecstat(wire, sizeof(wire), other_salt, &r) ==
          fcp::FecstatStatus::kBadSalt);
  }

  // R7.2 monotonic key with wraparound (spec §14.5 half-window).
  {
    fcp::FecstatValidator v;
    FecstatPacket p = MakeFecstatPacket(salt);
    uint8_t wire[fcp::kFecstatLen];

    p.accounted_through_set_id = 100;
    fcp::encode_fecstat(p, wire);
    CHECK(fcp::FecstatValidator().validate(wire, sizeof(wire), salt, &p) ==
          fcp::FecstatStatus::kOk);

    fcp::FecstatValidator w;
    p.accounted_through_set_id = 0xFFFFFFF0u;
    fcp::encode_fecstat(p, wire);
    CHECK(w.validate(wire, sizeof(wire), salt, &p) == fcp::FecstatStatus::kOk);
    p.accounted_through_set_id = 0xFFFFFFEFu;  // 1 behind
    fcp::encode_fecstat(p, wire);
    CHECK(w.validate(wire, sizeof(wire), salt, &p) == fcp::FecstatStatus::kStale);
    p.accounted_through_set_id = 0xFFFFFFF0u;  // equal: duplicate copy (#28⑤ F3)
    fcp::encode_fecstat(p, wire);
    CHECK(w.validate(wire, sizeof(wire), salt, &p) == fcp::FecstatStatus::kDuplicate);
    p.accounted_through_set_id = 5;  // wrapped forward: genuinely newer
    fcp::encode_fecstat(p, wire);
    CHECK(w.validate(wire, sizeof(wire), salt, &p) == fcp::FecstatStatus::kOk);
    p.accounted_through_set_id = 0xFFFFFFF0u;  // now this is the ancient one
    fcp::encode_fecstat(p, wire);
    CHECK(w.validate(wire, sizeof(wire), salt, &p) == fcp::FecstatStatus::kStale);
  }

  // R7.3 reporter cadence: 2s + 256 samples gate, 60s forced report, counter
  // reset semantics, interval_ms faithful (clamped only at the field max).
  {
    SettleFixture f;

    std::vector<Bytes> syms;
    for (uint8_t i = 0; i < 10; ++i) {
      syms.push_back(f.data_symbol(8, 100 + i));
    }
    for (uint32_t sid = 0; sid < 30; ++sid) {
      for (uint8_t i = 0; i < 10; ++i) {
        f.feed(sid, i, fcp::pack_type_k(0, 0, 0), syms[i]);
      }
    }
    // 29 sets settle via the anchor; set 29 itself never becomes eligible and
    // is tail-dropped at exactly 1s.
    f.settle->tick(1000, 200);
    CHECK_EQ(f.settle->counters().data_expected, uint32_t{290});
    CHECK_EQ(f.settle->counters().sets_expected, uint32_t{29});

    uint32_t reports = 0;
    uint32_t last_expected = 0;
    uint16_t last_interval = 0;
    fcp::FcpReporter rep2(f.settle.get(),
                          [&](const uint8_t* w, size_t len) {
                            ++reports;
                            CHECK_EQ(len, fcp::kFecstatLen);
                            FecstatPacket q{};
                            CHECK(fcp::decode_fecstat(w, len, salt, &q) ==
                                  fcp::FecstatStatus::kOk);
                            last_expected = q.data_expected;
                            last_interval = q.interval_ms;
                          });
    rep2.set_salt(salt);
    rep2.on_tick(1000);          // baseline
    CHECK(!rep2.on_tick(2999));  // elapsed 1999ms: not yet
    CHECK(rep2.on_tick(3000));   // elapsed 2000ms + 290 samples -> report
    CHECK_EQ(reports, uint32_t{2});  // two copies per report (#28⑤ F3)
    CHECK_EQ(last_expected, uint32_t{290});
    CHECK_EQ(last_interval, uint16_t{2000});
    CHECK_EQ(f.settle->counters().data_expected, uint32_t{0});  // reset
    CHECK_EQ(f.settle->accounted_through_set_id(), uint32_t{28});  // kept

    // forced 60s report with only a small amount of new content
    rep2.add_auth_fail(1);
    CHECK(!rep2.on_tick(3000 + 59999));
    CHECK(rep2.on_tick(3000 + 60000));
    CHECK_EQ(reports, uint32_t{4});
    CHECK_EQ(last_interval, uint16_t{60000});  // elapsed 60s, at the field max

    // idle direction: another 60s pass with nothing at all -> no report
    CHECK(!rep2.on_tick(3000 + 120000));
    CHECK_EQ(reports, uint32_t{4});
  }
}

// ---------------------------------------------------------------- R8 -------

fcp::FecstatPacket MakeStat(uint32_t key, uint32_t expected, uint32_t rx_orig) {
  static const uint8_t kZeroSalt[8] = {};
  FecstatPacket p = MakeFecstatPacket(kZeroSalt);
  p.accounted_through_set_id = key;
  p.sets_expected = expected / 10;
  p.data_expected = expected;
  p.data_rx_orig = rx_orig;
  return p;
}

void ProbeR8Strategy() {
  // R8.1 k_for table from spec §8 (T20): 2/5/10/15/20/25% -> 1/1/2/3/4/4.
  const struct {
    double loss;
    uint8_t want;
  } table[] = {
      {0.02, 1}, {0.05, 1}, {0.10, 2}, {0.15, 3}, {0.20, 4}, {0.25, 4},
      {0.60, 4},          // no k reaches 80% -> clamp to P
  };
  for (const auto& c : table) {
    CHECK_EQ(fcp::k_for(c.loss, 10, 4), c.want);
  }
  CHECK_EQ(fcp::k_for(0.02, 10, 3), uint8_t{1});
  CHECK_EQ(fcp::k_for(0.20, 10, 3), uint8_t{3});  // p_max clamps the answer

  // R8.2 OFF -> ON thresholds: 1.5% immediate, 0.8% twice, below never.
  {
    fcp::FecStrategy s;
    CHECK_EQ(s.state(), fcp::FecState::kOff);
    s.on_report(MakeStat(1, 1000, 995), false);  // 0.5%: nothing
    CHECK_EQ(s.state(), fcp::FecState::kOff);
    s.on_report(MakeStat(2, 1000, 991), false);  // 0.9%: armed
    CHECK_EQ(s.state(), fcp::FecState::kOff);
    s.on_report(MakeStat(3, 1000, 992), false);  // 0.8% again -> ON
    CHECK_EQ(s.state(), fcp::FecState::kOn);
    CHECK_EQ(s.k(), uint8_t{1});
  }
  {
    fcp::FecStrategy s;
    s.on_report(MakeStat(1, 1000, 984), false);  // 1.6% -> immediate ON
    CHECK_EQ(s.state(), fcp::FecState::kOn);
    CHECK_EQ(s.k(), uint8_t{1});
  }

  // R8.3 ON: k moves at most one step per report; 5 clean reports -> OFF with
  // a 3-report cooldown during which only loss >= 4.5% re-opens.
  {
    fcp::FecStrategy s;
    s.on_report(MakeStat(1, 1000, 800), false);  // 20% -> ON, k = 4
    CHECK_EQ(s.k(), uint8_t{4});
    s.on_report(MakeStat(2, 1000, 850), false);  // 15% -> target 3
    CHECK_EQ(s.k(), uint8_t{3});
    s.on_report(MakeStat(3, 1000, 850), false);
    CHECK_EQ(s.k(), uint8_t{3});
    // drift to OFF: 5 consecutive reports under 0.3%
    for (uint32_t i = 0; i < 5; ++i) {
      s.on_report(MakeStat(10 + i, 1000, 1000), false);
    }
    CHECK_EQ(s.state(), fcp::FecState::kOff);
    CHECK_EQ(s.k(), uint8_t{0});
    // cooldown: 1.6% during the next 2 reports does not re-open
    s.on_report(MakeStat(20, 1000, 984), false);
    CHECK_EQ(s.state(), fcp::FecState::kOff);
    s.on_report(MakeStat(21, 1000, 984), false);
    CHECK_EQ(s.state(), fcp::FecState::kOff);
    // third cooldown report still blocks 1.6%...
    s.on_report(MakeStat(22, 1000, 984), false);
    CHECK_EQ(s.state(), fcp::FecState::kOff);
    // ...but a 4.5% burst re-opens immediately
    s.on_report(MakeStat(23, 1000, 950), false);
    CHECK_EQ(s.state(), fcp::FecState::kOn);
    CHECK_EQ(s.k(), uint8_t{1});  // enter_on: k_for(5%) = 1
  }

  // R8.4 stale / wrapped reports are ignored; the session-level key follows
  // the modular half-window.
  {
    fcp::FecStrategy s;
    s.on_report(MakeStat(0xFFFFFFF0u, 1000, 800), false);
    CHECK_EQ(s.state(), fcp::FecState::kOn);
    CHECK_EQ(s.stale_reports(), uint32_t{0});
    s.on_report(MakeStat(0xFFFFFFEFu, 1000, 800), false);  // behind -> stale
    CHECK_EQ(s.stale_reports(), uint32_t{1});
    s.on_report(MakeStat(0xFFFFFFF0u, 1000, 800), false);  // equal -> stale
    CHECK_EQ(s.stale_reports(), uint32_t{2});
    s.on_report(MakeStat(5, 1000, 800), false);  // wrapped forward -> accepted
    CHECK_EQ(s.stale_reports(), uint32_t{2});
    CHECK_EQ(s.state(), fcp::FecState::kOn);
  }

  // R8.5 sample gates: untrusted (too many whole-set losses) and too-small
  // intervals never move the state machine or consume streak counters.
  {
    fcp::FecStrategy s;
    FecstatPacket p = MakeStat(1, 1000, 995);
    p.sets_expected = 10;
    p.sets_k_unknown = 2;  // 20% > 10% -> untrusted
    s.on_report(p, false);
    CHECK_EQ(s.state(), fcp::FecState::kOff);
    CHECK_EQ(s.untrusted_reports(), uint32_t{1});
    p = MakeStat(2, 100, 99);  // < 256 -> too small
    s.on_report(p, false);
    CHECK_EQ(s.state(), fcp::FecState::kOff);
    CHECK_EQ(s.small_sample_reports(), uint32_t{1});
    // the armed streak from report 1 was consumed by nothing: still armed
    p = MakeStat(3, 1000, 991);
    s.on_report(p, false);
    CHECK_EQ(s.state(), fcp::FecState::kOff);  // 0.5%: resets the streak
  }

  // R8.6 window guard: while queued, k never grows and drops after 3 reports.
  {
    fcp::FecStrategy s;
    s.on_report(MakeStat(1, 1000, 800), false);  // ON, k = 4
    s.on_report(MakeStat(2, 1000, 800), true);   // queued: no growth
    CHECK_EQ(s.k(), uint8_t{4});
    s.on_report(MakeStat(3, 1000, 800), true);
    CHECK_EQ(s.k(), uint8_t{4});
    s.on_report(MakeStat(4, 1000, 800), true);  // third queued report: -1
    CHECK_EQ(s.k(), uint8_t{3});
    s.on_report(MakeStat(5, 1000, 850), false);  // queue clear: target 3
    CHECK_EQ(s.k(), uint8_t{3});
  }

  // R8.7 pinned k bypasses everything.
  {
    fcp::FecStrategyConfig cfg;
    cfg.pinned_k = 2;
    fcp::FecStrategy s(cfg);
    CHECK(s.pinned());
    CHECK_EQ(s.k(), uint8_t{2});
    s.on_report(MakeStat(1, 1000, 1000), false);  // 0% loss: pinned holds
    CHECK_EQ(s.k(), uint8_t{2});
    s.on_report(MakeStat(2, 1000, 500), false);  // 50% loss: pinned holds
    CHECK_EQ(s.k(), uint8_t{2});
  }
}

// ---------------------------------------------------------------- R9 -------

// R3-1: every handshake message carries a nonce now, and the ACK echoes the
// client's. The probes below pin both draws so their caps/state assertions stay
// deterministic.
const uint8_t kProbeNonce[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                                 9, 10, 11, 12, 13, 14, 15, 16};
const uint8_t kPeerNonce[16] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                                0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30};

void ProbeR9Handshake() {
  using fcp::Handshake;
  using fcp::HandshakeCaps;

  // R9.1 caps validation fuzz (§6.2: ver==1, data>=1, parity<=7,
  // u16(data)+parity<=256, reserved flag bits zero).
  auto check_caps = [](uint8_t ver, uint8_t data, uint8_t parity, uint8_t flags) {
    Handshake hs(10, 3, nullptr, fcp::HandshakeRole::kServer, kProbeNonce);
    std::vector<uint8_t> msg(fcp::kHelloLen);
    fcp::build_hello(HandshakeCaps{ver, data, parity, flags}, kProbeNonce, msg.data());
    const fcp::HandshakeStatus st = hs.on_oob(msg.data(), msg.size());
    const bool accepted = st == fcp::HandshakeStatus::kConsumed &&
                          hs.state() == fcp::HandshakeState::kEstablished;
    const bool want_ok = ver == fcp::kCapsVersion && data >= 1 && parity <= 7 &&
                         static_cast<unsigned>(data) + parity <= 256 &&
                         (flags & ~fcp::kCapKnownMask) == 0 &&
                         (flags & (fcp::kCapFraming | fcp::kCapFecstat)) ==
                             (fcp::kCapFraming | fcp::kCapFecstat);
    CHECK_EQ(accepted, want_ok);
  };
  check_caps(1, 10, 3, 0x07);   // valid
  check_caps(1, 10, 0, 0x03);   // parity 0: valid (FRAMED_STATS)
  check_caps(1, 1, 7, 0x0F);    // S = 8: valid
  check_caps(1, 249, 7, 0x03);  // S = 256: valid at the cap
  check_caps(1, 250, 7, 0x03);  // S = 257: reject (u16 compare, no wrap)
  check_caps(1, 255, 2, 0x03);  // S = 257: reject
  check_caps(0, 10, 3, 0x03);   // bad version
  check_caps(2, 10, 3, 0x03);
  check_caps(1, 0, 3, 0x03);    // data must be >= 1
  check_caps(1, 10, 8, 0x03);   // parity > 7
  check_caps(1, 10, 3, 0x10);   // reserved bit 4 set
  check_caps(1, 10, 3, 0x80);   // reserved bit 7 set
  check_caps(1, 10, 3, 0x01);   // framing without FECSTAT -> ERROR
  check_caps(1, 10, 3, 0x02);   // FECSTAT without framing -> ERROR
  check_caps(1, 10, 3, 0x00);   // neither -> ERROR

  // R9.2 bad caps after establishment must not corrupt a live session.
  {
    Handshake hs(10, 3, nullptr, fcp::HandshakeRole::kServer, kProbeNonce);
    std::vector<uint8_t> good(fcp::kHelloLen);
    fcp::build_hello(HandshakeCaps{1, 10, 3, 0x07}, kProbeNonce, good.data());
    CHECK(hs.on_oob(good.data(), good.size()) == fcp::HandshakeStatus::kConsumed);
    CHECK(hs.established());
    // a duplicate HELLO re-ACKs and keeps the session alive
    CHECK(hs.on_oob(good.data(), good.size()) == fcp::HandshakeStatus::kConsumed);
    CHECK(hs.established());
    // now a malformed HELLO: protocol failure
    std::vector<uint8_t> bad(fcp::kHelloLen);
    fcp::build_hello(HandshakeCaps{9, 10, 3, 0}, kProbeNonce, bad.data());
    CHECK(hs.on_oob(bad.data(), bad.size()) == fcp::HandshakeStatus::kProtocolFailure);
    CHECK(hs.state() == fcp::HandshakeState::kFailed);
  }

  // R9.3 ACK before any HELLO (stray) is swallowed; wrong lengths are ignored.
  {
    Handshake hs(10, 3, nullptr, fcp::HandshakeRole::kServer, kProbeNonce);
    std::vector<uint8_t> ack(fcp::kHelloAckLen);
    fcp::build_hello_ack(HandshakeCaps{1, 10, 3, 0x07}, kProbeNonce, kPeerNonce, ack.data());
    CHECK(hs.on_oob(ack.data(), ack.size()) == fcp::HandshakeStatus::kConsumed);
    CHECK(hs.state() == fcp::HandshakeState::kIdle);
    std::vector<uint8_t> short_hello(fcp::kHelloLen - 1, 'A');
    CHECK(hs.on_oob(short_hello.data(), short_hello.size()) ==
          fcp::HandshakeStatus::kNotHandshake);
    std::vector<uint8_t> hello_plus = [&] {
      std::vector<uint8_t> m(fcp::kHelloLen);
      fcp::build_hello(HandshakeCaps{}, kProbeNonce, m.data());
      m.push_back(0xAA);  // trailing junk: exact-length matching rejects it
      return m;           // requires the exact length
    }();
    CHECK(hs.on_oob(hello_plus.data(), hello_plus.size()) ==
          fcp::HandshakeStatus::kNotHandshake);
    CHECK(hs.state() == fcp::HandshakeState::kIdle);
  }

  // R9.4 retry schedule (#27①): exponential backoff 300/600/1200ms — sends at
  // 0/300/900, failure check on the tick at 2100 (no 4th HELLO).
  {
    int sent = 0;
    Handshake hs(10, 3, [&](const uint8_t*, size_t) { ++sent; },
                 fcp::HandshakeRole::kClient, kProbeNonce);
    hs.start(0);
    hs.on_tick(0);
    CHECK_EQ(sent, 1);
    hs.on_tick(299);
    CHECK_EQ(sent, 1);
    hs.on_tick(300);
    CHECK_EQ(sent, 2);
    hs.on_tick(899);
    CHECK_EQ(sent, 2);
    hs.on_tick(900);
    CHECK_EQ(sent, 3);
    hs.on_tick(2099);
    CHECK_EQ(sent, 3);
    hs.on_tick(2100);
    CHECK_EQ(sent, 3);  // 3 already sent -> fail, no 4th
    CHECK(hs.state() == fcp::HandshakeState::kFailed);
    CHECK(hs.error() == fcp::HandshakeError::kNoAck);
  }

  // R9.5 negotiation result: min on both sides; stats mode when P' = 0.
  {
    Handshake a(10, 3, nullptr, fcp::HandshakeRole::kServer, kProbeNonce);
    Handshake b(20, 0, nullptr, fcp::HandshakeRole::kClient, kPeerNonce);
    std::vector<uint8_t> hello(fcp::kHelloLen);
    fcp::build_hello(HandshakeCaps{1, 20, 0, 0x07}, kPeerNonce, hello.data());
    CHECK(a.on_oob(hello.data(), hello.size()) == fcp::HandshakeStatus::kConsumed);
    CHECK(a.established());
    CHECK_EQ(a.params().d, uint8_t{10});
    CHECK_EQ(a.params().p, uint8_t{0});
    CHECK(a.params().mode == fcp::SessionMode::kFramedStats);
    CHECK_EQ(a.params().flags, static_cast<uint8_t>(fcp::kLocalFlagsM1 & 0x07));
  }

  // R9.6 pre-negotiation cache: FIFO drain on success, hard fail on overflow
  // (segments), and the byte ceiling. Limits are explicit here to pin the
  // boundary; the default is 512 segs / 512 KiB (#28③ F2).
  {
    Handshake hs(10, 3, nullptr, fcp::HandshakeRole::kClient, kProbeNonce,
                 fcp::kLocalFlagsM1, 64, 64 * 1024);
    for (int i = 0; i < 10; ++i) {
      std::vector<uint8_t> seg(8, static_cast<uint8_t>(i));
      CHECK(hs.cache_data(std::move(seg)));
    }
    CHECK_EQ(hs.cached_segments(), size_t{10});
    std::vector<uint8_t> hello(fcp::kHelloLen);
    fcp::build_hello(HandshakeCaps{1, 10, 3, 0x07}, kProbeNonce, hello.data());
    CHECK(hs.on_oob(hello.data(), hello.size()) == fcp::HandshakeStatus::kConsumed);
    const auto drained = hs.take_cached_data();
    CHECK_EQ(drained.size(), size_t{10});
    for (size_t i = 0; i < drained.size(); ++i) {
      CHECK_EQ(drained[i][0], static_cast<uint8_t>(i));  // send order preserved
    }
  }
  {
    Handshake hs(10, 3, nullptr, fcp::HandshakeRole::kClient, kProbeNonce,
                 fcp::kLocalFlagsM1, 64, 64 * 1024);
    for (int i = 0; i < 64; ++i) {
      CHECK(hs.cache_data(std::vector<uint8_t>(8, 0)));
    }
    CHECK(!hs.cache_data(std::vector<uint8_t>(8, 0)));  // 65th -> overflow
    CHECK(hs.state() == fcp::HandshakeState::kFailed);
    CHECK(hs.error() == fcp::HandshakeError::kCacheOverflow);
  }
  {
    Handshake hs(10, 3, nullptr, fcp::HandshakeRole::kClient, kProbeNonce,
                 fcp::kLocalFlagsM1, 64, 64 * 1024);
    const size_t big = 8 * 1024;
    for (int i = 0; i < 8; ++i) {  // 8 x 8 KiB = 64 KiB exactly
      CHECK(hs.cache_data(std::vector<uint8_t>(big, 0)));
    }
    CHECK(!hs.cache_data(std::vector<uint8_t>(1, 0)));  // one byte over
    CHECK(hs.state() == fcp::HandshakeState::kFailed);
  }
}

// ---------------------------------------------------------------- R10 ------

const uint8_t kFuzzKey[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                              0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
const uint8_t kFuzzSalt[8] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};

fcp::SessionConfig FuzzConfig(fcp::Direction send, fcp::Direction recv) {
  fcp::SessionConfig cfg;
  std::memcpy(cfg.key, kFuzzKey, 16);
  std::memcpy(cfg.salt, kFuzzSalt, 8);
  cfg.send_direction = send;
  cfg.recv_direction = recv;
  return cfg;
}

void ProbeR10Session() {
  // R10.1 random garbage on the wire: nothing authenticates, no session state
  // is touched, and the session is still handshaking.
  {
    fcp::Session s(FuzzConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [](const uint8_t*, size_t, fcp::SymbolType) {},
                   [](const uint8_t*, size_t) {});
    s.start(0);
    s.on_tick(0);
    CHECK(s.state() == fcp::HandshakeState::kHelloSent);
    fcp_test::rng().seed(0xC0FFEEu);
    for (int i = 0; i < 5000; ++i) {
      const size_t len = 1 + fcp_test::rng()() % 200;
      std::vector<uint8_t> buf(len);
      for (size_t b = 0; b < len; ++b) {
        buf[b] = fcp_test::random_byte();
      }
      s.on_wire(buf.data(), len, i);
    }
    CHECK_EQ(s.auth_fail(), uint32_t{5000});
    CHECK_EQ(s.struct_fail(), uint32_t{0});
    CHECK_EQ(s.cached_segments(), size_t{0});
    CHECK(s.state() == fcp::HandshakeState::kHelloSent);
  }

  // R10.2 authenticated garbage (a rogue implementation with the right key):
  // every malformed-but-sealed frame is counted and none of it damages the
  // accounting of the good stream that flowed before. The rogue shares the
  // (key, salt, direction) triple with A - i.e. it *is* the session as far as
  // crypto goes - so its explicit counters are placed just above A's real
  // traffic (~402 packets) instead of colliding with it.
  {
    fcp_e2e::Harness h;
    CHECK(h.Init(FuzzConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                 FuzzConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
    CHECK(h.Handshake());

    // a good stream first: 40 sets of 10 segments, delivered exactly once
    for (uint32_t sn = 0; sn < 400; ++sn) {
      h.SendA(sn, sn / 10);
      h.pump();
    }
    for (uint32_t sn = 0; sn < 400; ++sn) {
      CHECK_EQ(h.hits_b.size() > sn ? h.hits_b[sn] : 0u, uint32_t{1});
    }
    CHECK_EQ(h.corrupt_b, uint32_t{0});

    // R3-1: the rogue must speak the v7 *session* key, not the bootstrap one.
    // It knows the PSK and the salt (it is a rogue implementation), and it
    // watched the handshake go by, so it holds the same session key B uses.
    fcp::Envelope rogue(kFuzzKey, kFuzzSalt, fcp::Direction::kC2S,
                        fcp::Direction::kS2C);
    {
      uint8_t session_key[16];
      fcp::derive_session_key_v7(kFuzzKey, kFuzzSalt, h.a->handshake_nonce(),
                                 h.b->handshake_nonce(), session_key);
      rogue.rekey(session_key);
    }
    uint64_t rogue_ctr = 500;  // above A's traffic, inside B's replay window
    auto sealed = [&rogue, &rogue_ctr](const Bytes& plain) {
      Bytes wire;
      CHECK(rogue.seal_at(rogue_ctr++, plain.data(), plain.size(), &wire));
      return wire;
    };
    auto feed_b = [&h](const Bytes& wire) {
      h.b->on_wire(wire.data(), wire.size(), h.now);
    };
    auto sym_data = [](uint8_t index, uint8_t k, size_t payload_len) {
      Bytes plain(fcp::kFecHdrLen + payload_len + 2);
      fcp::pack_hdr(fcp::FecHdr{50, index, fcp::pack_type_k(k, 0, 0)}, plain.data());
      plain[fcp::kFecHdrLen] = static_cast<uint8_t>(payload_len + 2);
      // Payload bytes far away from the real KCP sn range: dedup keys derived
      // from a bogus 4-byte payload must not collide with segments 0..399.
      for (size_t i = 0; i < payload_len; ++i) {
        plain[fcp::kFecHdrLen + 2 + i] = 0xFF;
      }
      return plain;
    };
    auto sym_parity = [](uint8_t index, uint8_t k, uint8_t j, size_t sym_len) {
      Bytes plain(fcp::kFecHdrLen + sym_len);
      fcp::pack_hdr(fcp::FecHdr{50, index, fcp::pack_type_k(k, j, 1)}, plain.data());
      return plain;
    };
    auto sym_oob = [](size_t len) {
      Bytes plain(fcp::kFecHdrLen + len);
      fcp::pack_hdr(fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, 2)}, plain.data());
      return plain;
    };

    const uint32_t pre = h.b->struct_fail();
    const uint32_t auth_pre = h.b->auth_fail();

    feed_b(sealed(Bytes{0x01, 0x02, 0x03}));  // shorter than a header
    feed_b(sealed(sym_data(0, 0, 4)));        // valid data, set 50
    feed_b(sealed(sym_data(1, 1, 4)));        // k conflict (0 then 1)
    Bytes bad_len = sym_data(2, 0, 4);
    bad_len[fcp::kFecHdrLen] = 9;             // declared != symbol len
    feed_b(sealed(bad_len));
    feed_b(sealed(sym_data(200, 0, 4)));      // index >= D
    feed_b(sealed(sym_parity(10, 2, 2, 12))); // j >= k
    feed_b(sealed(sym_parity(0, 1, 0, 12)));  // n = 0
    feed_b(sealed(sym_parity(255, 1, 0, 12))); // n = 255 > D
    feed_b(sealed(sym_oob(128)));             // junk oob payload
    Bytes big(fcp::kFecHdrLen + 1400, 0x20);
    big[5] = 0;                               // type data, k=0
    feed_b(sealed(big));                      // over the MTU guard

    CHECK(h.b->struct_fail() > pre);
    CHECK(h.b->auth_fail() == auth_pre);  // sealed by the real key: all open

    // the good stream's accounting is untouched
    for (uint32_t sn = 0; sn < 400; ++sn) {
      CHECK_EQ(h.hits_b.size() > sn ? h.hits_b[sn] : 0u, uint32_t{1});
    }
    CHECK_EQ(h.corrupt_b, uint32_t{1});  // exactly one bogus 4-byte delivery
  }

  // R10.3 wire fuzz on a lossy link: UDP duplicates and truncated copies fly
  // alongside honest traffic; every segment still delivers exactly once and
  // settlement accounting stays consistent.
  {
    fcp_e2e::Harness h;
    CHECK(h.Init(FuzzConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                 FuzzConfig(fcp::Direction::kS2C, fcp::Direction::kC2S)));
    CHECK(h.Handshake());

    for (uint32_t sn = 0; sn < 400; ++sn) {
      h.SendA(sn, sn / 10);
      h.pump();
      h.b->on_wire(h.last_a_wire.data(), h.last_a_wire.size(), h.now);  // UDP dup
      if (sn % 10 == 0 && h.last_a_wire.size() > 30) {
        h.b->on_wire(h.last_a_wire.data(), h.last_a_wire.size() - 5, h.now);
      }
      if (sn % 7 == 0) {
        h.b->on_tick(h.now);
      }
    }
    for (uint32_t sn = 0; sn < 400; ++sn) {
      CHECK_EQ(h.hits_b.size() > sn ? h.hits_b[sn] : 0u, uint32_t{1});
    }
    CHECK(h.corrupt_b == 0);
    CHECK(h.b->auth_fail() > 0);  // duplicates/truncations never authenticate
    CHECK_EQ(h.b->struct_fail(), uint32_t{0});

    // settlement: 40 sets of 10; set 39 has no parity (k = 0) and no higher
    // set_id, so it lands in tail_dropped instead of expected.
    h.b->on_tick(h.now + 1000);
    h.pump();
    const auto& c = h.b->settle()->counters();
    CHECK_EQ(c.sets_expected, uint32_t{39});
    CHECK_EQ(c.data_expected, uint32_t{390});
    CHECK_EQ(c.data_rx_orig, uint32_t{390});
    CHECK_EQ(c.sets_tail_dropped, uint32_t{1});
    CHECK(h.b->settle()->identity_ok());
    CHECK(h.b->settle()->delivered_le_sum());
  }
}

// ---------------------------------------------------------------- R11 ------
// KCP 段/负载层 fuzz（对抗分析第十轮补的空白）：认证面之后的下一层是
// FrameRx 的投递通道——它把每个 data symbol 的有效负载原样交给宿主
// （这里由 sn_dedup + 计数回调消费）。这里直接在 FrameRx 层批量注入
// data symbol：每一发都结构合法（declared == symbol_len、index < D），
// 但 set_id 全域随机（含绕回邻域）、k/j 结构字段随机、段体随机。边际
// 校验失败形态（index 越界、k 冲突、声明不符）由 R4 的定向用例覆盖，
// 会话层的 MTU 门由 R10.2 覆盖，不在这里重复。
void ProbeR11Stream() {
  RxFixture f;
  uint32_t rng = 0x5eed1234u;
  const size_t delivered_pre = f.delivered_sn.size();
  for (int i = 0; i < 600; ++i) {
    rng = rng * 1103515245u + 12345u;
    const uint32_t set_id = i < 8
        ? 0xFFFFFF00u + static_cast<uint32_t>(i)  // 绕回邻域开头几发
        : rng;                                    // 其余全域随机
    const uint8_t index = static_cast<uint8_t>((rng >> 20) % 10);  // 0..9 < D
    const uint8_t k_field = (rng >> 30) & 0x07;                    // 0..7，超 P' 的被钳
    const uint8_t j_field = static_cast<uint8_t>((rng >> 16) & 0x03);
    const size_t body_len = 1 + ((rng >> 24) & 0x3F);  // 1..64
    // dedup 键取段内高位 sn：远远避开其它用例的小 sn，i*31 < 2^24 内
    // 两两不同，不会让两发互相吃掉。
    f.feed(set_id, index, fcp::pack_type_k(k_field, j_field, 0),
           f.data_symbol(body_len, 0x01000000u | static_cast<uint32_t>(i) * 31u));
  }
  // 600 发里最可能的三种出路是：投递一次、同 set 同 index 的晚到重复、
  // 某 k 先到把 k 钉死后后来者走 struct_fail。共同点是"多一个字节的负
  // 效应都没有"——不发帐外投递，不把有效 set 状态写歪。
  CHECK(static_cast<uint32_t>(f.delivered_sn.size() - delivered_pre) > 0);

  // fuzz 之后同一条接收端立即消化干净流：anchor 不被一波随机 id 拖进死
  // 胡同，紧贴 anchor 之上的新 set 干净整距投递，一段不少、一段不重。
  const uint32_t anchor = f.rx.anchor();
  const size_t before = f.delivered_sn.size();
  for (uint8_t idx = 0; idx < 10; ++idx) {
    f.feed(anchor + 1, idx, fcp::pack_type_k(0, 0, 0), f.data_symbol(8, 900 + idx));
  }
  CHECK_EQ(f.delivered_sn.size(), before + 10);
}

}  // namespace

int main() {
  struct Round {
    const char* name;
    void (*fn)();
  };
  const Round rounds[] = {
      {"R1 envelope/GCM", ProbeR1Envelope},
      {"R2 header validation", ProbeR2Header},
      {"R3 RS/Cauchy", ProbeR3Rs},
      {"R4 frame_rx", ProbeR4FrameRx},
      {"R5 frame_tx", ProbeR5FrameTx},
      {"R6 settle", ProbeR6Settle},
      {"R7 fecstat/reporter", ProbeR7Fecstat},
      {"R8 strategy", ProbeR8Strategy},
      {"R9 handshake", ProbeR9Handshake},
      {"R10 session fuzz", ProbeR10Session},
      {"R11 kcp-segment fuzz", ProbeR11Stream},
  };
  const char* only = std::getenv("ADV_ONLY");
  for (const Round& r : rounds) {
    if (only != nullptr && std::strcmp(only, r.name) != 0) {
      continue;
    }
    const int before = ::fcp_test::failures();
    r.fn();
    std::fflush(stdout);
    std::fprintf(stderr, "%-24s %s\n", r.name,
                 ::fcp_test::failures() == before ? "ok" : "FAILED");
  }
  return ::fcp_test::finish();
}
