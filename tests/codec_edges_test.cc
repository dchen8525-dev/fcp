// Edge-branch coverage for the codec layer.
//
// Targets the branches ordinary traffic never reaches: envelope open/seal
// guards and epoch-key receive paths, GCM empty inputs and tamper offsets,
// frame_rx capacity eviction / placeholder / decode geometry edges, and
// frame_tx limit and state guards. Every case asserts an observable counter or
// return value; nothing depends on wall-clock time or randomness.

#include <cstdint>
#include <cstring>
#include <functional>
#include <utility>
#include <vector>

#include "fcp/envelope.h"
#include "fcp/frame_rx.h"
#include "fcp/frame_tx.h"
#include "fcp/gcm.h"
#include "fcp/hdr.h"
#include "fcp/rs.h"
#include "fcp/wire.h"
#include "test_util.h"

namespace {

using Bytes = std::vector<uint8_t>;

const uint8_t kKey[16] = {0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
                          0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0};
const uint8_t kSalt[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

fcp::Envelope MakeClient() {
  return fcp::Envelope(kKey, kSalt, fcp::Direction::kC2S, fcp::Direction::kS2C);
}
fcp::Envelope MakeServer() {
  return fcp::Envelope(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
}

// Builds a wire sealed under the epoch key the receiver would pick for the
// stated epoch. Epoch 0 uses the #26② direction key; epochs >= 1 use the
// per-epoch derivation, so this is exactly what a peer holding the session
// key would emit.
Bytes EpochWire(const uint8_t session_key[16], fcp::Direction wire_dir, uint16_t epoch,
                uint64_t counter, const uint8_t* payload, size_t len) {
  Bytes wire(fcp::Envelope::kOverhead + len);
  std::memcpy(wire.data(), kSalt, fcp::Envelope::kSaltLen);
  const uint64_t nonce =
      static_cast<uint64_t>(epoch) * fcp::Envelope::kEpochSpan + counter;
  fcp::put_le64(nonce, wire.data() + fcp::Envelope::kSaltLen);
  uint8_t key[16];
  if (epoch == 0) {
    uint8_t c2s[16];
    uint8_t s2c[16];
    fcp::derive_direction_keys(session_key, c2s, s2c);
    std::memcpy(key, wire_dir == fcp::Direction::kC2S ? c2s : s2c, 16);
  } else {
    fcp::derive_epoch_direction_key(session_key, wire_dir, epoch, key);
  }
  uint8_t iv[fcp::kGcmIvLen] = {};
  for (size_t i = 0; i < 8; ++i) {
    iv[i] = wire[fcp::Envelope::kSaltLen + i];
  }
  iv[8] = static_cast<uint8_t>(wire_dir);
  uint8_t* cipher = wire.data() + fcp::Envelope::kSaltLen + fcp::Envelope::kNonceLen;
  uint8_t* tag = cipher + len;
  CHECK(fcp::gcm_seal(key, iv, nullptr, 0, payload, len, cipher, tag));
  return wire;
}

// ---- envelope ----

void TestEnvelopeOpenGuards() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  const uint8_t payload[3] = {1, 2, 3};
  std::vector<uint8_t> wire;
  std::vector<uint8_t> plain;
  CHECK(client.seal(payload, sizeof(payload), &wire));

  // Null wire, null output, zero length and a short datagram are all refused
  // before any state moves.
  CHECK(!server.open(nullptr, wire.size(), &plain));
  CHECK(!server.open(wire.data(), wire.size(), nullptr));
  CHECK(!server.open(wire.data(), 0, &plain));
  CHECK(!server.open(wire.data(), fcp::Envelope::kOverhead - 1, &plain));

  // The intact packet is still authentic after every refused call.
  CHECK(server.open(wire.data(), wire.size(), &plain));
  CHECK_EQ(plain.size(), sizeof(payload));

  // seal() refuses a null output buffer without advancing the counter.
  fcp::Envelope fresh = MakeClient();
  CHECK(!fresh.seal(payload, sizeof(payload), nullptr));
  CHECK_EQ(fresh.send_nonce(), 0u);
}

void TestEnvelopeTagTamperEveryOffset() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  const uint8_t payload[5] = {9, 8, 7, 6, 5};
  std::vector<uint8_t> wire;
  CHECK(client.seal(payload, sizeof(payload), &wire));

  std::vector<uint8_t> plain;
  const size_t tag_start = wire.size() - fcp::Envelope::kTagLen;
  for (size_t i = 0; i < fcp::Envelope::kTagLen; ++i) {
    std::vector<uint8_t> tampered = wire;
    tampered[tag_start + i] ^= 0x01;
    CHECK(!server.open(tampered.data(), tampered.size(), &plain));
  }
  // Every tampered attempt failed before touching the replay window.
  CHECK(server.open(wire.data(), wire.size(), &plain));
  CHECK_EQ(plain.size(), sizeof(payload));
}

void TestEnvelopeReplayWindowBounds() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  const uint8_t payload[2] = {0x01, 0x02};
  std::vector<uint8_t> plain;
  auto open_at = [&](uint64_t nonce) {
    std::vector<uint8_t> wire;
    CHECK(client.seal_at(nonce, payload, sizeof(payload), &wire));
    return server.open(wire.data(), wire.size(), &plain);
  };

  CHECK(open_at(0));
  CHECK(open_at(3000));   // far forward: the window re-bases past the jump
  CHECK(open_at(1977));   // delta 1023, inside the 1024-bit window
  CHECK(!open_at(1977));  // replay inside the window
  CHECK(!open_at(1976));  // delta 1024, outside the window
  CHECK(open_at(3001));   // one past the highest
}

void TestEnvelopeBootstrapSetNonce() {
  fcp::Envelope env = MakeClient();
  CHECK(env.init_bootstrap_nonce(8));
  const uint64_t start = env.send_nonce();
  CHECK(!env.exhausted());
  CHECK(env.set_send_nonce(start));         // within the budget
  CHECK(!env.set_send_nonce(start + 9));    // == send_limit_, refused
  CHECK(!env.set_send_nonce(UINT64_MAX));   // == counter_ceiling_, refused
  CHECK(!env.exhausted());
}

void TestEnvelopeResetEdges() {
  fcp::Envelope boot = MakeClient();
  fcp::Envelope server = MakeServer();
  static const uint8_t kReset[fcp::Envelope::kResetMagicLen] = {
      'F', 'C', 'P', 'R', 'S', 'T', '1', 0};
  std::vector<uint8_t> wire;
  std::vector<uint8_t> plain;
  CHECK(boot.seal_at(0, kReset, sizeof(kReset), &wire));

  CHECK(!server.open_reset(nullptr, wire.size(), &plain));
  CHECK(!server.open_reset(wire.data(), wire.size(), nullptr));
  CHECK(!server.open_reset(wire.data(), wire.size() - 1, &plain));

  std::vector<uint8_t> tampered = wire;
  tampered.back() ^= 0x01;
  CHECK(!server.open_reset(tampered.data(), tampered.size(), &plain));

  CHECK(server.open_reset(wire.data(), wire.size(), &plain));
  CHECK_EQ(plain.size(), fcp::Envelope::kResetMagicLen);
}

// Follows a peer's rolls from the nonce alone: current epoch, the frozen
// previous epoch (including a jump re-basing its window), the next epoch's
// commit, and both "too far future" and "past the receive ceiling" refusals.
void TestEnvelopeEpochReceiveEdges() {
  uint8_t c_nonce[16];
  uint8_t s_nonce[16];
  uint8_t session_key[16];
  CHECK(fcp_test::unhex("000102030405060708090a0b0c0d0e0f", c_nonce, 16));
  CHECK(fcp_test::unhex("f0e0d0c0b0a090807060504030201000", s_nonce, 16));
  fcp::derive_session_key_v7(kKey, kSalt, c_nonce, s_nonce, session_key);

  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  client.rekey(session_key);
  server.rekey(session_key);
  client.set_key_update(true);
  server.set_key_update(true);

  const uint8_t payload[4] = {1, 2, 3, 4};
  std::vector<uint8_t> plain;
  std::vector<uint8_t> wire;
  CHECK(client.seal(payload, sizeof(payload), &wire));  // epoch 0, counter 0
  CHECK(server.open(wire.data(), wire.size(), &plain));

  // The peer's first roll: epoch 1 is derived locally and committed only on a
  // valid tag.
  Bytes roll = EpochWire(session_key, fcp::Direction::kC2S, 1, 5, payload,
                         sizeof(payload));
  CHECK(server.open(roll.data(), roll.size(), &plain));
  CHECK(!server.open(roll.data(), roll.size(), &plain));  // replay

  // Frozen epoch 0: a counter far past the old highest re-bases its window.
  Bytes old_jump = EpochWire(session_key, fcp::Direction::kC2S, 0, 5000, payload,
                             sizeof(payload));
  CHECK(server.open(old_jump.data(), old_jump.size(), &plain));
  CHECK(!server.open(old_jump.data(), old_jump.size(), &plain));

  // Outside the frozen window, then just inside it.
  Bytes old_out = EpochWire(session_key, fcp::Direction::kC2S, 0, 3000, payload,
                            sizeof(payload));
  CHECK(!server.open(old_out.data(), old_out.size(), &plain));
  Bytes old_in = EpochWire(session_key, fcp::Direction::kC2S, 0, 4999, payload,
                           sizeof(payload));
  CHECK(server.open(old_in.data(), old_in.size(), &plain));

  // Current epoch 1: another far forward jump re-bases its window.
  Bytes cur_jump = EpochWire(session_key, fcp::Direction::kC2S, 1, 2000, payload,
                             sizeof(payload));
  CHECK(server.open(cur_jump.data(), cur_jump.size(), &plain));

  // Future epoch (seen + 5) is refused outright.
  Bytes future = EpochWire(session_key, fcp::Direction::kC2S, 6, 0, payload,
                           sizeof(payload));
  CHECK(!server.open(future.data(), future.size(), &plain));

  // nonce 256 * kEpochSpan == kNonceLimit: rejected by the top-level ceiling.
  Bytes past_ceiling = EpochWire(session_key, fcp::Direction::kC2S, 256, 0, payload,
                                 sizeof(payload));
  CHECK(!server.open(past_ceiling.data(), past_ceiling.size(), &plain));

  // A receiver that never saw epoch 0 still accepts its first roll (the
  // frozen previous window is empty) and a late epoch-0 packet under it.
  fcp::Envelope server_fresh = MakeServer();
  server_fresh.rekey(session_key);
  server_fresh.set_key_update(true);
  Bytes first_roll = EpochWire(session_key, fcp::Direction::kC2S, 1, 7, payload,
                               sizeof(payload));
  CHECK(server_fresh.open(first_roll.data(), first_roll.size(), &plain));
  Bytes late_epoch0 = EpochWire(session_key, fcp::Direction::kC2S, 0, 3, payload,
                                sizeof(payload));
  CHECK(server_fresh.open(late_epoch0.data(), late_epoch0.size(), &plain));
}

// ---- gcm ----

void TestGcmEmptyInputs() {
  const uint8_t key[16] = {};
  uint8_t iv[fcp::kGcmIvLen] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  uint8_t tag[fcp::kGcmTagLen];
  uint8_t tag_keyed[fcp::kGcmTagLen];

  // Zero-length plaintext, zero-length AAD, null data pointers.
  CHECK(fcp::gcm_seal(key, iv, nullptr, 0, nullptr, 0, nullptr, tag));
  CHECK(fcp::gcm_open(key, iv, nullptr, 0, nullptr, 0, tag, nullptr));

  fcp::GcmKey expanded;
  fcp::gcm_key_init(key, &expanded);
  CHECK(fcp::gcm_seal_keyed(expanded, iv, nullptr, 0, nullptr, 0, nullptr, tag_keyed));
  CHECK(fcp::gcm_open_keyed(expanded, iv, nullptr, 0, nullptr, 0, tag, nullptr));
  CHECK_EQ(fcp_test::hex(tag, fcp::kGcmTagLen),
           fcp_test::hex(tag_keyed, fcp::kGcmTagLen));
}

void TestGcmTagMismatchEveryByte() {
  const uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  uint8_t iv[fcp::kGcmIvLen] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  Bytes plain(20);
  for (size_t i = 0; i < plain.size(); ++i) {
    plain[i] = static_cast<uint8_t>(i * 3 + 5);
  }
  Bytes cipher(plain.size());
  uint8_t tag[fcp::kGcmTagLen];
  CHECK(fcp::gcm_seal(key, iv, nullptr, 0, plain.data(), plain.size(),
                      cipher.data(), tag));

  for (size_t i = 0; i < fcp::kGcmTagLen; ++i) {
    uint8_t bad[fcp::kGcmTagLen];
    std::memcpy(bad, tag, sizeof(bad));
    bad[i] ^= 0x80;
    Bytes out(plain.size());
    CHECK(!fcp::gcm_open(key, iv, nullptr, 0, cipher.data(), cipher.size(), bad,
                         out.data()));
  }

  Bytes decoded(plain.size());
  CHECK(fcp::gcm_open(key, iv, nullptr, 0, cipher.data(), cipher.size(), tag,
                      decoded.data()));
  CHECK_EQ(fcp_test::hex(decoded.data(), decoded.size()),
           fcp_test::hex(plain.data(), plain.size()));
}

void TestGcmBlockBoundaries() {
  const uint8_t key[16] = {0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x7A, 0x79, 0x78,
                           0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70};
  uint8_t iv[fcp::kGcmIvLen] = {0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
                                0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88};
  const size_t lengths[] = {0, 1, 15, 16, 17, 31, 32, 33};
  for (size_t len : lengths) {
    Bytes plain(len);
    for (size_t i = 0; i < len; ++i) {
      plain[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    Bytes cipher(len);
    uint8_t tag[fcp::kGcmTagLen];
    CHECK(fcp::gcm_seal(key, iv, nullptr, 0, len == 0 ? nullptr : plain.data(), len,
                        len == 0 ? nullptr : cipher.data(), tag));
    Bytes decoded(len);
    CHECK(fcp::gcm_open(key, iv, nullptr, 0, len == 0 ? nullptr : cipher.data(), len,
                        tag, len == 0 ? nullptr : decoded.data()));
    CHECK_EQ(fcp_test::hex(decoded.data(), decoded.size()),
             fcp_test::hex(plain.data(), plain.size()));
  }
}

// ---- frame_rx helpers ----

void Feed(fcp::FrameRx& rx, uint32_t set_id, uint8_t index, uint8_t type_k,
          const Bytes& symbol, int64_t now_ms) {
  uint8_t hdr[fcp::kFecHdrLen];
  fcp::pack_hdr(fcp::FecHdr{set_id, index, type_k}, hdr);
  Bytes dg(hdr, hdr + fcp::kFecHdrLen);
  dg.insert(dg.end(), symbol.begin(), symbol.end());
  rx.on_datagram(dg.data(), dg.size(), now_ms);
}

struct RxHarness {
  std::vector<Bytes> delivered;
  std::vector<Bytes> oobs;
  std::vector<std::pair<fcp::RxEvent, uint32_t>> events;
  std::function<void()> on_deliver;
  fcp::FrameRx rx;

  RxHarness(uint8_t d, uint8_t p)
      : rx(d, p,
           [this](const uint8_t* payload, size_t len) {
             delivered.emplace_back(payload, payload + len);
             if (on_deliver) {
               on_deliver();
             }
           },
           [this](const uint8_t* msg, size_t len, int64_t) {
             oobs.emplace_back(msg, msg + len);
           }) {
    rx.set_event_sink(
        [this](fcp::RxEvent event, uint32_t value) { events.emplace_back(event, value); });
  }

  void feed(uint32_t set_id, uint8_t index, uint8_t type_k, const Bytes& symbol,
            int64_t now_ms = 0) {
    Feed(rx, set_id, index, type_k, symbol, now_ms);
  }

  size_t count_event(fcp::RxEvent event) const {
    size_t n = 0;
    for (const auto& e : events) {
      if (e.first == event) {
        ++n;
      }
    }
    return n;
  }

  uint32_t event_value(fcp::RxEvent event) const {
    for (const auto& e : events) {
      if (e.first == event) {
        return e.second;
      }
    }
    return 0;
  }
};

// ---- frame_rx ----

void TestRxNullCallbacksAndView() {
  // Every callback left empty: no delivery, no oob dispatch, no event sink.
  fcp::FrameRx rx(10, 3, fcp::FrameRx::DeliverFn{}, fcp::FrameRx::OobFn{});
  Feed(rx, 0, 0, fcp::pack_type_k(2, 0, 0), Bytes{4, 0, 1, 2}, 0);
  CHECK_EQ(rx.data_delivered(), 1u);
  // A duplicate emits an event through a null sink without crashing.
  Feed(rx, 0, 0, fcp::pack_type_k(2, 0, 0), Bytes{4, 0, 1, 2}, 0);
  CHECK_EQ(rx.late_dup(), 1u);
  // oob with a null handler is simply consumed.
  Feed(rx, 0, 0, fcp::pack_type_k(0, 0, 2), Bytes{1, 2, 3}, 0);

  fcp::RxSetView view;
  CHECK(!rx.view(0, nullptr));
  CHECK(!rx.view(99, &view));
  CHECK(!rx.mark_eligible(99));
  CHECK(!rx.mark_accounted(99, 0));
  CHECK(!rx.release_set(99));

  std::vector<uint32_t> ids;
  ids.push_back(77);
  rx.active_set_ids(&ids);
  CHECK_EQ(ids.size(), 1u);
  CHECK_EQ(ids[0], 0u);
}

void TestRxUnaccountedEvictionEvent() {
  RxHarness h(10, 3);
  for (uint32_t sid = 0; sid < fcp::kMaxActiveSets; ++sid) {
    h.feed(sid, 0, fcp::pack_type_k(2, 0, 0), Bytes{4, 0, 1, 2});
  }
  CHECK_EQ(h.rx.active_sets(), fcp::kMaxActiveSets);
  CHECK_EQ(h.count_event(fcp::RxEvent::kSetTailDropped), 0u);

  const uint32_t next_id = static_cast<uint32_t>(fcp::kMaxActiveSets);
  h.feed(next_id, 0, fcp::pack_type_k(2, 0, 0), Bytes{4, 0, 1, 2});
  CHECK_EQ(h.rx.active_sets(), fcp::kMaxActiveSets);
  CHECK_EQ(h.rx.tail_dropped(), 1u);

  fcp::RxSetView view;
  CHECK(!h.rx.view(0, &view));
  CHECK(h.rx.view(next_id, &view));

  // The unaccounted victim is announced with the number of symbols it had
  // delivered (one).
  CHECK_EQ(h.count_event(fcp::RxEvent::kSetTailDropped), 1u);
  CHECK_EQ(h.event_value(fcp::RxEvent::kSetTailDropped), 1u);
}

void TestRxAccountedEviction() {
  RxHarness h(10, 3);
  for (uint32_t sid = 0; sid < fcp::kMaxActiveSets; ++sid) {
    h.feed(sid, 0, fcp::pack_type_k(2, 0, 0), Bytes{4, 0, 1, 2});
  }
  for (uint32_t sid = 0; sid < fcp::kMaxActiveSets; ++sid) {
    CHECK(h.rx.mark_accounted(sid, 0));
  }

  fcp::RxSetView view;
  CHECK(h.rx.view(0, &view));
  CHECK(view.phase == fcp::SetPhase::kAccounted);
  // An accounted set does not move to Eligible.
  CHECK(h.rx.mark_eligible(0));
  CHECK(h.rx.view(0, &view));
  CHECK(view.phase == fcp::SetPhase::kAccounted);

  // Tombstones outrank capacity pressure: the oldest accounted set is evicted
  // without a tail-drop event, and its id is retired.
  const uint32_t next_id = static_cast<uint32_t>(fcp::kMaxActiveSets);
  h.feed(next_id, 0, fcp::pack_type_k(2, 0, 0), Bytes{4, 0, 1, 2});
  CHECK_EQ(h.rx.active_sets(), fcp::kMaxActiveSets);
  CHECK(!h.rx.view(0, &view));
  CHECK(h.rx.view(next_id, &view));
  CHECK_EQ(h.rx.tail_dropped(), 1u);
  CHECK_EQ(h.count_event(fcp::RxEvent::kSetTailDropped), 0u);

  // The evicted id is retired: a late fragment is dropped, not re-created.
  h.feed(0, 0, fcp::pack_type_k(2, 0, 0), Bytes{4, 0, 1, 2});
  CHECK_EQ(h.rx.retired_dropped(), 1u);
  CHECK(!h.rx.view(0, &view));
}

void TestRxPlaceholders() {
  RxHarness h(10, 3);
  h.feed(0, 0, fcp::pack_type_k(1, 0, 0), Bytes{2, 0}, 100);
  h.feed(8, 0, fcp::pack_type_k(1, 0, 0), Bytes{2, 0}, 200);
  CHECK_EQ(h.rx.anchor(), 8u);
  // Sets 0 and 8 plus the gap placeholders 1..7.
  CHECK_EQ(h.rx.active_sets(), 9u);

  fcp::RxSetView view;
  CHECK(h.rx.view(3, &view));
  CHECK_EQ(view.t_first_ms, 200);

  // A placeholder has no symbols: accounting it records a zero boundary, so
  // every later original is "late unexpected".
  CHECK(h.rx.mark_accounted(3, 0));
  CHECK(h.rx.view(3, &view));
  CHECK(view.phase == fcp::SetPhase::kAccounted);
  h.feed(3, 0, fcp::pack_type_k(1, 0, 0), Bytes{2, 0}, 300);
  CHECK_EQ(h.count_event(fcp::RxEvent::kDataLateUnexpected), 1u);
}

void TestRxPlaceholderCapacityLimit() {
  RxHarness h(10, 3);
  for (uint32_t sid = 0; sid < 200; ++sid) {
    h.feed(sid, 0, fcp::pack_type_k(1, 0, 0), Bytes{2, 0});
  }
  CHECK_EQ(h.rx.anchor(), 199u);
  CHECK_EQ(h.rx.active_sets(), 200u);

  // A 60-id gap would overflow the table, so no placeholders are materialised
  // and only the new set is created.
  h.feed(260, 0, fcp::pack_type_k(1, 0, 0), Bytes{2, 0}, 1000);
  CHECK_EQ(h.rx.anchor(), 260u);
  CHECK_EQ(h.rx.active_sets(), 201u);
  fcp::RxSetView view;
  CHECK(!h.rx.view(200, &view));
  CHECK(h.rx.view(260, &view));
}

void TestRxRetiredAndPrune() {
  RxHarness h(10, 3);
  h.feed(0, 0, fcp::pack_type_k(1, 0, 0), Bytes{4, 0, 1, 2});
  CHECK(h.rx.mark_accounted(0, 0));
  CHECK(h.rx.release_set(0));  // retired, still inside the staleness window

  // A far-forward id is dropped once, then confirmed by the same id (A8).
  h.feed(200, 0, fcp::pack_type_k(1, 0, 0), Bytes{4, 0, 1, 2}, 0);
  CHECK_EQ(h.rx.ahead_dropped(), 1u);
  CHECK_EQ(h.rx.anchor(), 0u);
  h.feed(200, 0, fcp::pack_type_k(1, 0, 0), Bytes{4, 0, 1, 2}, 0);
  CHECK_EQ(h.rx.anchor(), 200u);
  CHECK(h.rx.mark_accounted(200, 0));
  CHECK(h.rx.release_set(200));

  h.feed(250, 0, fcp::pack_type_k(1, 0, 0), Bytes{4, 0, 1, 2}, 0);
  CHECK_EQ(h.rx.anchor(), 250u);

  // Id 0 is still within 256 of the anchor, so the retired check catches it.
  h.feed(0, 0, fcp::pack_type_k(1, 0, 0), Bytes{4, 0, 1, 2}, 0);
  CHECK_EQ(h.rx.retired_dropped(), 1u);

  // A confirmed jump past 256 prunes those tombstones; the same id is now
  // stale at ingress instead.
  h.feed(600, 0, fcp::pack_type_k(1, 0, 0), Bytes{4, 0, 1, 2}, 0);
  CHECK_EQ(h.rx.ahead_dropped(), 2u);
  h.feed(600, 0, fcp::pack_type_k(1, 0, 0), Bytes{4, 0, 1, 2}, 0);
  CHECK_EQ(h.rx.anchor(), 600u);
  h.feed(0, 0, fcp::pack_type_k(1, 0, 0), Bytes{4, 0, 1, 2}, 0);
  CHECK_EQ(h.rx.stale(), 1u);
}

void TestRxLateBoundaries() {
  RxHarness h(10, 3);

  // Set 0: n never learned, so the accounting boundary is max_data_index + 1.
  h.feed(0, 0, fcp::pack_type_k(2, 0, 0), Bytes{3, 0, 1});
  h.feed(0, 1, fcp::pack_type_k(2, 0, 0), Bytes{3, 0, 2});
  h.feed(0, 2, fcp::pack_type_k(2, 0, 0), Bytes{3, 0, 3});
  CHECK(h.rx.mark_accounted(0, 5000));
  h.feed(0, 5, fcp::pack_type_k(2, 0, 0), Bytes{3, 0, 4});
  CHECK_EQ(h.count_event(fcp::RxEvent::kDataLateUnexpected), 1u);

  // Set 1: n is known, so an index below n is a plain late original.
  h.feed(1, 0, fcp::pack_type_k(2, 0, 0), Bytes{3, 0, 5});
  h.feed(1, 1, fcp::pack_type_k(2, 0, 0), Bytes{3, 0, 6});
  h.feed(1, 5, fcp::pack_type_k(2, 0, 1), Bytes{2, 0, 7});
  CHECK(h.rx.mark_accounted(1, 6000));
  h.feed(1, 3, fcp::pack_type_k(2, 0, 0), Bytes{3, 0, 8});
  CHECK_EQ(h.count_event(fcp::RxEvent::kDataLate), 1u);
  CHECK_EQ(h.count_event(fcp::RxEvent::kDataLateUnexpected), 1u);
}

void TestRxPinnedRelease() {
  RxHarness h(10, 3);
  bool released_inside = true;
  h.on_deliver = [&]() { released_inside = h.rx.release_set(0); };
  h.feed(0, 0, fcp::pack_type_k(0, 0, 0), Bytes{4, 0, 1, 2}, 0);
  // The set was pinned while its symbol was on the stack, so the reentrant
  // release was refused; after the call it succeeds.
  CHECK(!released_inside);
  CHECK_EQ(h.rx.active_sets(), 1u);
  CHECK(h.rx.release_set(0));
  CHECK_EQ(h.rx.active_sets(), 0u);
}

void TestRxStaleAndWrapPlaceholders() {
  RxHarness h(10, 3);
  h.feed(0xFFFFFFF0u, 0, fcp::pack_type_k(1, 0, 0), Bytes{2, 0}, 0);
  CHECK_EQ(h.rx.anchor(), 0xFFFFFFF0u);

  // 292 behind the anchor: stale, no state created.
  h.feed(0xFFFFFECCu, 0, fcp::pack_type_k(1, 0, 0), Bytes{2, 0}, 0);
  CHECK_EQ(h.rx.stale(), 1u);
  CHECK_EQ(h.rx.active_sets(), 1u);

  // A wrapped forward jump across the u32 boundary materialises placeholders.
  h.feed(0x00000010u, 0, fcp::pack_type_k(1, 0, 0), Bytes{2, 0}, 500);
  CHECK_EQ(h.rx.anchor(), 0x00000010u);
  CHECK_EQ(h.rx.active_sets(), 33u);  // F0 + 31 placeholders + 0x10
  fcp::RxSetView view;
  CHECK(h.rx.view(0xFFFFFFF0u, &view));
  CHECK(h.rx.view(0xFFFFFFFFu, &view));  // placeholder
  CHECK(h.rx.view(0x00000000u, &view));  // placeholder
  CHECK(h.rx.view(0x00000010u, &view));
}

// n + k above kRsMaxShards cannot be decoded (rs.cc rejects it), so 251 + 6
// must be refused before the padded buffers are allocated.
void TestRxDecodeGeometryLimit() {
  RxHarness h(251, 7);
  const Bytes symbol{2, 0};
  for (size_t i = 0; i < 250; ++i) {
    h.feed(0, static_cast<uint8_t>(i), fcp::pack_type_k(6, 0, 0), symbol);
  }
  h.feed(0, 251, fcp::pack_type_k(6, 0, 1), symbol);  // n = 251
  fcp::RxSetView view;
  CHECK(h.rx.view(0, &view));
  CHECK(view.n_known);
  CHECK_EQ(view.n, 251u);
  CHECK_EQ(h.rx.decode_attempts(), 0u);
  CHECK_EQ(h.rx.recovered(), 0u);
}

// A synchronous host can re-enter from the delivery of a recovered symbol; the
// nested decode must use its own scratch buffers instead of clobbering the
// outer attempt's rows.
void TestRxDecodeNested() {
  RxHarness h(10, 3);
  const size_t sym_max = 8;
  auto make_symbol = [&](uint8_t tag) {
    Bytes s(sym_max, 0);
    s[0] = static_cast<uint8_t>(sym_max);
    s[1] = 0;
    s[2] = tag;
    for (size_t i = 3; i < s.size(); ++i) {
      s[i] = static_cast<uint8_t>(tag + i);
    }
    return s;
  };

  const Bytes d0 = make_symbol(0x10);
  const Bytes d1 = make_symbol(0x20);
  const Bytes d2 = make_symbol(0x30);
  std::vector<Bytes> rows(3, Bytes(sym_max, 0));
  std::memcpy(rows[0].data(), d0.data(), d0.size());
  std::memcpy(rows[1].data(), d1.data(), d1.size());
  std::memcpy(rows[2].data(), d2.data(), d2.size());
  std::vector<const uint8_t*> data_ptrs = {rows[0].data(), rows[1].data(), rows[2].data()};
  Bytes p0(sym_max, 0);
  Bytes p1(sym_max, 0);
  std::vector<uint8_t*> parity_ptrs = {p0.data(), p1.data()};
  fcp::encode(data_ptrs.data(), 3, 2, sym_max, parity_ptrs.data());

  // Prime set 5 so the callback's parity completes it and starts a decode.
  h.feed(5, 0, fcp::pack_type_k(1, 0, 0), Bytes{2, 0});
  bool armed = false;
  bool nested_feed = false;
  h.on_deliver = [&]() {
    if (!armed) {
      return;
    }
    armed = false;
    nested_feed = true;
    h.feed(5, 2, fcp::pack_type_k(1, 0, 1), Bytes{2, 0});
  };

  h.feed(0, 0, fcp::pack_type_k(2, 0, 0), d0);
  h.feed(0, 1, fcp::pack_type_k(2, 0, 0), d1);
  armed = true;
  h.feed(0, 3, fcp::pack_type_k(2, 0, 1), p0);  // completes set 0, recovers idx 2
  h.feed(0, 4, fcp::pack_type_k(2, 1, 1), p1);

  CHECK(nested_feed);
  CHECK_EQ(h.rx.decode_attempts(), 2u);
  CHECK(h.rx.recovered() >= 1u);
  fcp::RxSetView outer;
  fcp::RxSetView inner;
  CHECK(h.rx.view(0, &outer));
  CHECK(outer.recov_mask.test(2));
  CHECK(h.rx.view(5, &inner));
}

// ---- frame_tx ----

void TestTxLimitsAndNullPaths() {
  fcp::MtuLimits limits = fcp::compute_mtu_limits(1400, 20);
  std::vector<fcp::TxSymbol> out;
  fcp::FrameTx tx(10, limits, [&out](const fcp::TxSymbol& s) { out.push_back(s); });

  fcp::MtuLimits invalid{};
  tx.raise_limits(invalid);                              // invalid: ignored
  tx.raise_limits(fcp::compute_mtu_limits(900, 20));     // smaller: ignored
  tx.raise_limits(fcp::compute_mtu_limits(1500, 20));    // larger: applied
  tx.raise_limits(fcp::compute_mtu_limits(1500, 20));    // unchanged: ignored

  const Bytes big(1400, 0x5A);
  tx.on_kcp_output(big.data(), big.size(), 0);
  CHECK_EQ(tx.mtu_drops(), 0u);
  CHECK_EQ(tx.data_symbols(), 1u);

  tx.lower_limits(invalid);                              // invalid: ignored
  tx.lower_limits(fcp::compute_mtu_limits(1500, 20));    // larger: ignored
  tx.lower_limits(fcp::compute_mtu_limits(900, 20));     // smaller: applied
  tx.on_kcp_output(big.data(), big.size(), 1);
  CHECK_EQ(tx.mtu_drops(), 1u);
  CHECK_EQ(tx.data_symbols(), 1u);
}

void TestTxNullSegment() {
  fcp::MtuLimits limits = fcp::compute_mtu_limits(1400, 20);
  std::vector<fcp::TxSymbol> out;
  fcp::FrameTx tx(10, limits, [&out](const fcp::TxSymbol& s) { out.push_back(s); });

  // A null segment with a non-zero length is a host bug and is refused.
  tx.on_kcp_output(nullptr, 4, 0);
  CHECK_EQ(tx.open_n(), 0u);
  CHECK_EQ(tx.data_symbols(), 0u);

  // A null segment with length 0 is a legal empty symbol: len(2) | nothing.
  tx.on_kcp_output(nullptr, 0, 0);
  CHECK_EQ(tx.open_n(), 1u);
  CHECK_EQ(out.size(), 1u);
  CHECK_EQ(out[0].symbol.size(), 2u);
  CHECK_EQ(out[0].symbol[0], 2);
  CHECK_EQ(out[0].symbol[1], 0);
}

void TestTxZeroD() {
  // D' == 0 is unreachable through Session, but close_set() must drop the set
  // instead of dividing by zero.
  fcp::MtuLimits limits = fcp::compute_mtu_limits(1400, 20);
  std::vector<fcp::TxSymbol> out;
  fcp::FrameTx tx(0, limits, [&out](const fcp::TxSymbol& s) { out.push_back(s); });
  tx.set_k(3);
  const Bytes seg(4, 0x11);
  tx.on_kcp_output(seg.data(), seg.size(), 0);
  CHECK(tx.has_open_set());
  CHECK_EQ(out.size(), 1u);  // the data symbol is still emitted

  tx.on_tick(300);  // T_flush expired: the zero-D set aborts, no parity
  CHECK_EQ(tx.aborted_sets(), 1u);
  CHECK_EQ(tx.closed_idle(), 0u);
  CHECK_EQ(tx.closed_full(), 0u);
  CHECK_EQ(tx.parity_symbols(), 0u);
  CHECK_EQ(tx.set_id(), 1u);
  CHECK(!tx.has_open_set());
}

void TestTxNullEmitAndKClamp() {
  fcp::MtuLimits limits = fcp::compute_mtu_limits(1400, 20);
  const Bytes seg(4, 0x22);

  // No emit callback at all: data and parity are both dropped silently.
  fcp::FrameTx silent(10, limits, fcp::FrameTx::EmitFn{});
  silent.set_k(1);
  for (int i = 0; i < 10; ++i) {
    silent.on_kcp_output(seg.data(), seg.size(), i);
  }
  CHECK_EQ(silent.closed_full(), 1u);
  CHECK_EQ(silent.parity_symbols(), 1u);

  // set_k clamps to the 3-bit parity field limit.
  std::vector<fcp::TxSymbol> out;
  fcp::FrameTx clamped(10, limits, [&out](const fcp::TxSymbol& s) { out.push_back(s); });
  clamped.set_k(200);
  for (int i = 0; i < 10; ++i) {
    clamped.on_kcp_output(seg.data(), seg.size(), i);
  }
  CHECK_EQ(clamped.parity_symbols(), 7u);
  CHECK_EQ(clamped.closed_full(), 1u);
}

}  // namespace

int main() {
  TestEnvelopeOpenGuards();
  TestEnvelopeTagTamperEveryOffset();
  TestEnvelopeReplayWindowBounds();
  TestEnvelopeBootstrapSetNonce();
  TestEnvelopeResetEdges();
  TestEnvelopeEpochReceiveEdges();
  TestGcmEmptyInputs();
  TestGcmTagMismatchEveryByte();
  TestGcmBlockBoundaries();
  TestRxNullCallbacksAndView();
  TestRxUnaccountedEvictionEvent();
  TestRxAccountedEviction();
  TestRxPlaceholders();
  TestRxPlaceholderCapacityLimit();
  TestRxRetiredAndPrune();
  TestRxLateBoundaries();
  TestRxPinnedRelease();
  TestRxStaleAndWrapPlaceholders();
  TestRxDecodeGeometryLimit();
  TestRxDecodeNested();
  TestTxLimitsAndNullPaths();
  TestTxNullSegment();
  TestTxZeroD();
  TestTxNullEmitAndKClamp();
  return fcp_test::finish();
}
