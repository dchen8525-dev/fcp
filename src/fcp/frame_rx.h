// Receiving path: framed FEC symbol -> KCP payload (design doc §6).
//
// The session AEAD-verifies the datagram first and passes the plaintext
// `fec_hdr | symbol` here; authentication failures never reach this module.
//
// Three bitmaps per set keep original arrivals, reconstructions and parity
// strictly separate (erratum #2): data_rx_orig counts only orig_mask,
// data_recovered_dl only recov_mask. `n` is learned exclusively from parity
// (n = index - j); data-only sets are never decoded.
//
// Delivery is deduplicated by KCP sn (4096-entry sliding window), so a late
// retransmission and a reconstruction of the same segment deliver once.

#ifndef FCP_FRAME_RX_H_
#define FCP_FRAME_RX_H_

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <vector>

namespace fcp {

constexpr size_t kMaxS = 256;           // index is u8; D + P <= 256
constexpr size_t kMaxActiveSets = 256;
constexpr size_t kSnWindow = 4096;
// Forward jumps larger than this are treated as a session discontinuity: no
// placeholder sets are created for the skipped ids.
constexpr uint32_t kMaxGapPlaceholders = 64;

// KCP sn sliding window: the slot is sn mod kSnWindow, so a value is only
// "recently seen" while it stays inside the window. The 64 KiB slot table
// lives on the heap so FrameRx stays a stack-friendly object.
class SnDedup {
 public:
  SnDedup();
  // Returns true when sn is new (and records it), false when it is a duplicate.
  bool accept(uint32_t sn, int64_t now_ms);
  bool seen(uint32_t sn) const;
  void reset();

 private:
  struct Slot {
    uint32_t sn = 0;
    int64_t ts_ms = 0;
    bool used = false;
  };
  std::unique_ptr<std::array<Slot, kSnWindow>> slots_;
};

enum class SetPhase : uint8_t {
  kActive = 0,
  kEligible,
  kAccounted,
};

// Delivery classifications routed to the settle module (interval counters).
enum class RxEvent : uint8_t {
  kDataDelivered,   // unique original delivery before settlement
  kDataLate,        // unique original delivery during the tombstone window
  kDataDuplicate,   // duplicate sn or duplicate symbol of an active set
  kRecovered,       // unique delivery of a reconstruction before settlement
  kRecoveredLate,   // unique delivery of a reconstruction after settlement
  // Capacity eviction dropped a set that was never accounted (design #9:
  // tombstones outrank capacity pressure). The event value carries how many
  // symbols it had already delivered, so settle can close the delivered-vs-
  // accounted invariant like its own 1s tail drop does.
  kSetTailDropped,
};

struct RxSetView {
  uint32_t set_id = 0;
  SetPhase phase = SetPhase::kActive;
  uint8_t k = 0;
  bool k_known = false;
  uint8_t n = 0;
  bool n_known = false;
  uint8_t max_data_index = 0;
  bool saw_parity = false;
  bool has_any_symbol = false;
  size_t symbol_count = 0;
  size_t symbol_max = 0;
  int64_t t_first_ms = 0;
  int64_t tombstone_until_ms = 0;
  uint32_t decode_attempts = 0;
  std::bitset<kMaxS> orig_mask;
  std::bitset<kMaxS> recov_mask;
  std::bitset<kMaxS> parity_mask;
  std::bitset<kMaxS> decoded_once;
};

class FrameRx {
 public:
  using DeliverFn = std::function<void(const uint8_t* payload, size_t len)>;
  // now_ms rides along: the trace recorder (SessionConfig::trace) stamps
  // report arrival time, which the pre-#28 dispatch dropped on the floor.
  using OobFn = std::function<void(const uint8_t* payload, size_t len, int64_t now_ms)>;
  // Extracts the KCP sn from a delivered payload into *sn; returns false when
  // the payload is too short to carry one (dedup is skipped for those). An
  // empty fn disables dedup entirely.
  using SnFn = std::function<bool(const uint8_t* payload, size_t len, uint32_t* sn)>;
  // Repair events carry now - set.t_first_ms; other events pass 0.
  using EventFn = std::function<void(RxEvent, uint32_t)>;

  FrameRx(uint8_t d, uint8_t p, DeliverFn deliver, OobFn oob, SnFn sn_of = SnFn());

  // `plaintext` is fec_hdr(6) | symbol, already authenticated by the envelope.
  void on_datagram(const uint8_t* plaintext, size_t len, int64_t now_ms);

  std::vector<uint32_t> active_set_ids() const;
  size_t active_sets() const { return sets_.size(); }
  bool view(uint32_t set_id, RxSetView* out) const;

  // Settlement primitives driven by FcpSettle.
  void set_event_sink(EventFn fn);
  bool mark_eligible(uint32_t set_id);
  bool mark_accounted(uint32_t set_id, int64_t tombstone_until_ms);
  bool release_set(uint32_t set_id);

  uint32_t anchor() const { return anchor_; }
  uint32_t struct_fail() const { return struct_fail_; }
  uint32_t stale() const { return stale_; }
  uint32_t late_dup() const { return late_dup_; }
  uint32_t late_data() const { return late_data_; }
  uint32_t late_recovered() const { return late_recovered_; }
  uint32_t data_delivered() const { return data_delivered_; }
  uint32_t recovered() const { return recovered_; }
  uint32_t decode_attempts() const { return decode_attempts_; }
  // #31 (M4 trigger metric): data symbols for a slot FEC had already
  // recovered — the sender's retransmission raced the parity and lost. Pure
  // FEC/ARQ waste; the M4 evaluation doc uses it to decide whether a delayed
  // retransmission is worth building.
  uint32_t dup_after_recovered() const { return dup_after_recovered_; }
  uint32_t tail_dropped() const { return tail_dropped_; }
  // Fragments for an already-accounted, released set id (§5.3: settlement is
  // final; a late fragment must not open a second accounting unit).
  uint32_t retired_dropped() const { return retired_dropped_; }

 private:
  struct RxSet {
    uint32_t set_id = 0;
    SetPhase phase = SetPhase::kActive;
    uint8_t k = 0;
    bool k_known = false;
    uint8_t n = 0;
    bool n_known = false;
    uint8_t max_data_index = 0;
    bool saw_parity = false;
    bool has_any_symbol = false;
    size_t symbol_count = 0;
    size_t symbol_max = 0;
    int64_t t_first_ms = 0;
    int64_t tombstone_until_ms = 0;
    uint32_t decode_attempts = 0;
    std::bitset<kMaxS> orig_mask;
    std::bitset<kMaxS> recov_mask;
    std::bitset<kMaxS> parity_mask;
    std::bitset<kMaxS> decoded_once;
    std::array<std::vector<uint8_t>, kMaxS> symbols;
  };

  RxSet& get_or_create(uint32_t set_id, int64_t now_ms);
  bool note_k(RxSet* set, uint8_t k);
  void prune_retired();
  void store_symbol(RxSet* set, uint8_t index, const uint8_t* symbol, size_t len);
  void create_placeholders(uint32_t first, uint32_t last, int64_t now_ms);
  void deliver_payload(const uint8_t* payload, size_t len, bool recovered, bool late,
                       int64_t now_ms, uint32_t repair_ms);
  void try_decode(RxSet* set, int64_t now_ms);
  void emit_event(RxEvent event, uint32_t value);

  uint8_t d_;
  uint8_t p_;
  DeliverFn deliver_;
  OobFn oob_;
  SnFn sn_of_;
  EventFn event_;
  SnDedup sn_dedup_;

  std::map<uint32_t, RxSet> sets_;
  // Set ids whose accounting is final (tombstone expired, or a tombstone was
  // capacity-evicted). Re-creating their state would let one late fragment
  // account the same set twice. Entries are pruned once they fall out of the
  // 256-id staleness window, so the set stays O(kMaxActiveSets).
  std::set<uint32_t> retired_;
  uint32_t anchor_ = 0;
  bool anchor_valid_ = false;

  uint32_t struct_fail_ = 0;
  uint32_t stale_ = 0;
  uint32_t late_dup_ = 0;
  uint64_t dup_after_recovered_ = 0;  // #31: retransmission lost the race to parity
  uint32_t late_data_ = 0;
  uint32_t late_recovered_ = 0;
  uint32_t data_delivered_ = 0;
  uint32_t recovered_ = 0;
  uint32_t decode_attempts_ = 0;
  uint32_t tail_dropped_ = 0;
  uint32_t retired_dropped_ = 0;
};

}  // namespace fcp

#endif  // FCP_FRAME_RX_H_
