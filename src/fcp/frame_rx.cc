#include "fcp/frame_rx.h"

#include <algorithm>
#include <utility>

#include "fcp/hdr.h"

namespace fcp {
namespace {

bool IsPinned(const std::vector<uint32_t>& ids, uint32_t id) {
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}

// Pins the set for the duration of on_datagram. A synchronous host may deliver
// a whole window from inside deliver_ (in-process loopback), which re-enters
// on_datagram and can hit the capacity eviction path; the set being decoded
// must not be the victim.
class SetPin {
 public:
  SetPin(std::vector<uint32_t>* ids, uint32_t id) : ids_(ids) { ids_->push_back(id); }
  ~SetPin() { ids_->pop_back(); }
  SetPin(const SetPin&) = delete;
  SetPin& operator=(const SetPin&) = delete;

 private:
  std::vector<uint32_t>* ids_;
};

}  // namespace

SnDedup::SnDedup() : slots_(std::make_unique<std::array<Slot, kSnWindow>>()) {
  slots_->fill(Slot{});
}

bool SnDedup::accept(uint32_t sn, int64_t now_ms) {
  Slot& slot = (*slots_)[sn % kSnWindow];
  if (slot.used && slot.sn == sn) {
    return false;
  }
  slot.used = true;
  slot.sn = sn;
  slot.ts_ms = now_ms;
  return true;
}

bool SnDedup::seen(uint32_t sn) const {
  const Slot& slot = (*slots_)[sn % kSnWindow];
  return slot.used && slot.sn == sn;
}

void SnDedup::reset() { slots_->fill(Slot{}); }

FrameRx::FrameRx(uint8_t d, uint8_t p, DeliverFn deliver, OobFn oob, SnFn sn_of)
    : d_(d),
      p_(p),
      deliver_(std::move(deliver)),
      oob_(std::move(oob)),
      sn_of_(std::move(sn_of)) {}

void FrameRx::on_datagram(const uint8_t* plaintext, size_t len, int64_t now_ms) {
  FecHdr hdr{};
  if (!parse_hdr(plaintext, len, &hdr)) {
    ++struct_fail_;
    return;
  }
  const uint8_t* symbol = plaintext + kFecHdrLen;
  const size_t symbol_len = len - kFecHdrLen;

  const SymbolType type = hdr_type(hdr.type_k);
  if (type == SymbolType::kOob) {
    if (oob_) {
      oob_(symbol, symbol_len, now_ms);
    }
    return;
  }
  if (!valid_symbol_type(type)) {
    // The 2-bit type field can encode 3; erratum #25 retired it, so it has no
    // meaning and must never create set state.
    ++struct_fail_;
    return;
  }

  // Window anchor = highest *structurally valid* set_id seen so far. A malformed
  // header must not advance it, or one forged far-future set_id would make every
  // subsequent genuine set look stale. Staleness is a modular half-window test
  // (§14.5): a set_id more than kMaxActiveSets behind the anchor is stale.
  if (anchor_valid_ &&
      static_cast<uint32_t>(anchor_ - hdr.set_id) > kMaxActiveSets &&
      static_cast<uint32_t>(anchor_ - hdr.set_id) < 0x80000000u) {
    ++stale_;
    return;
  }

  const uint16_t s = static_cast<uint16_t>(d_) + p_;
  const auto existing = sets_.find(hdr.set_id);
  const bool n_known = existing != sets_.end() && existing->second.n_known;
  const uint8_t n = existing != sets_.end() ? existing->second.n : 0;
  if (validate_hdr(hdr, d_, s, n_known, n) != HdrStatus::kOk) {
    ++struct_fail_;
    return;
  }
  if (symbol_len < 2) {
    ++struct_fail_;
    return;
  }
  const uint8_t k_field = hdr_k(hdr.type_k);
  const uint8_t j_field = hdr_j(hdr.type_k);
  uint8_t n_new = 0;
  if (type == SymbolType::kData) {
    const size_t declared =
        static_cast<size_t>(symbol[0]) | (static_cast<size_t>(symbol[1]) << 8);
    if (declared != symbol_len) {
      ++struct_fail_;
      return;
    }
  } else {
    n_new = static_cast<uint8_t>(hdr.index - j_field);
    if (n_known && n != n_new) {
      ++struct_fail_;
      return;
    }
  }

  // Accounting for this set is already final (§5.3: the tombstone was
  // released). Re-creating the state would let one late fragment settle the
  // same set a second time, inflating expected/rx and the peer's loss sample.
  if (retired_.find(hdr.set_id) != retired_.end()) {
    ++retired_dropped_;
    return;
  }

  // The symbol is well formed: only now may it create set state and move the
  // window (plus materialise gap placeholders).
  //
  // A8: the anchor is the staleness baseline for every later set, so one
  // symbol far ahead of it must not move the anchor by itself -- a single
  // far-future set_id would make all genuine traffic look stale for as long as
  // the jump. A real discontinuity (long outage) arrives as a whole set whose
  // symbols share one id, so a second symbol of the SAME set is as good a
  // confirmation as the next consecutive id. A sparse source that emits one
  // symbol per set would never produce either signal; the 2s timeout keeps it
  // from blackholing forever (a peer that holds the PSK can already re-anchor
  // with two consecutive ids, so the timeout adds no new capability).
  if (anchor_valid_ && set_id_after(anchor_, hdr.set_id) &&
      static_cast<uint32_t>(hdr.set_id - anchor_) > kMaxGapPlaceholders) {
    const bool same_pending = pending_ahead_valid_ && hdr.set_id == pending_ahead_;
    const bool consecutive =
        pending_ahead_valid_ && set_id_after(pending_ahead_, hdr.set_id) &&
        static_cast<uint32_t>(hdr.set_id - pending_ahead_) <= kMaxGapPlaceholders;
    const bool expired =
        pending_ahead_valid_ && now_ms - pending_ahead_ms_ >= kAheadConfirmTimeoutMs;
    if (same_pending || consecutive || expired) {
      anchor_ = hdr.set_id;
      pending_ahead_valid_ = false;
      prune_retired();
    } else {
      pending_ahead_ = hdr.set_id;
      pending_ahead_valid_ = true;
      pending_ahead_ms_ = now_ms;
      ++ahead_dropped_;
      return;
    }
  } else {
    pending_ahead_valid_ = false;  // traffic near the anchor cancels the jump
  }
  const bool had_anchor = anchor_valid_;
  const uint32_t prev_anchor = anchor_;
  if (!anchor_valid_ || set_id_after(anchor_, hdr.set_id)) {
    anchor_ = hdr.set_id;
    anchor_valid_ = true;
    prune_retired();
  }
  if (had_anchor && set_id_after(prev_anchor + 1, hdr.set_id)) {
    create_placeholders(prev_anchor + 1, hdr.set_id, now_ms);
  }

  RxSet* created = get_or_create(hdr.set_id, now_ms);
  if (created == nullptr) {
    ++struct_fail_;
    return;
  }
  RxSet& set = *created;
  const SetPin pin(&pinned_ids_, hdr.set_id);
  // A9: k is the sender's parity count for this set, but the peer may only
  // choose it within the negotiated P'. Clamping keeps a lying k from poisoning
  // the set against the honest k (note_k is first-wins) and from inflating the
  // RS geometry past what the session agreed to.
  if (!note_k(&set, std::min<uint8_t>(k_field, p_))) {
    ++struct_fail_;
    return;
  }

  if (type == SymbolType::kData) {
    const uint8_t index = hdr.index;
    if (set.orig_mask.test(index)) {
      ++late_dup_;
      emit_event(RxEvent::kDataDuplicate, 0);
      return;
    }
    if (set.recov_mask.test(index)) {
      // Already credited as recovered; masks must stay disjoint or settlement
      // would double count this index. #31: this is also the FEC/ARQ waste
      // signal — the sender's retransmission raced the parity and lost.
      ++late_dup_;
      ++dup_after_recovered_;
      emit_event(RxEvent::kDataDuplicate, 0);
      return;
    }
    set.orig_mask.set(index);
    set.max_data_index = std::max(set.max_data_index, index);
    store_symbol(&set, index, symbol, symbol_len);
    const bool late = set.phase == SetPhase::kAccounted;
    const auto boundary = account_boundary_.find(hdr.set_id);
    const bool late_unexpected =
        late && (boundary == account_boundary_.end() || index >= boundary->second);
    deliver_payload(symbol + 2, symbol_len - 2, false, late, late_unexpected, now_ms, 0);
    try_decode(&set, now_ms);
    return;
  }

  // Parity: n = index - j, and this is the only source of n.
  if (set.parity_mask.test(hdr.index)) {
    return;  // duplicate fragment: no store, no re-decode
  }
  // n must cover every data index already accepted. hdr.cc only checks the
  // other direction (a data index past a known n), so parity arriving after
  // out-of-order data could otherwise lock n below max_data_index. Settlement
  // would then count fewer expected bytes than were delivered and break the
  // delivered <= expected invariant. Reject this parity and wait for one whose
  // geometry covers what we already have.
  if (!set.n_known && set.max_data_index >= n_new) {
    ++struct_fail_;
    return;
  }
  set.n = n_new;
  set.n_known = true;
  set.saw_parity = true;
  set.parity_mask.set(hdr.index);
  store_symbol(&set, hdr.index, symbol, symbol_len);
  try_decode(&set, now_ms);
}

std::vector<uint32_t> FrameRx::active_set_ids() const {
  std::vector<uint32_t> ids;
  active_set_ids(&ids);
  return ids;
}

void FrameRx::active_set_ids(std::vector<uint32_t>* out) const {
  if (out == nullptr) {
    return;
  }
  // Clear, not assign: the storage is kept so a per-tick caller (FcpSettle)
  // does not allocate once every 25ms.
  out->clear();
  out->reserve(sets_.size());
  for (const auto& kv : sets_) {
    out->push_back(kv.first);
  }
}

void FrameRx::set_event_sink(EventFn fn) { event_ = std::move(fn); }

bool FrameRx::mark_eligible(uint32_t set_id) {
  const auto it = sets_.find(set_id);
  if (it == sets_.end()) {
    return false;
  }
  if (it->second.phase == SetPhase::kActive) {
    it->second.phase = SetPhase::kEligible;
  }
  return true;
}

bool FrameRx::mark_accounted(uint32_t set_id, int64_t tombstone_until_ms) {
  const auto it = sets_.find(set_id);
  if (it == sets_.end()) {
    return false;
  }
  it->second.phase = SetPhase::kAccounted;
  it->second.tombstone_until_ms = tombstone_until_ms;
  // Mirror FcpSettle::account()'s boundary. A k-unknown set contributed 0;
  // otherwise the code length is n when known, else highest index + 1. Late
  // originals outside this range were never part of data_expected.
  account_boundary_[set_id] =
      it->second.has_any_symbol
          ? (it->second.n_known ? it->second.n
                                : static_cast<uint32_t>(it->second.max_data_index) + 1)
          : 0;
  return true;
}

bool FrameRx::release_set(uint32_t set_id) {
  // A reentrant settle (host callback) must not free the set whose symbol is
  // still being decoded; the next tick releases it instead.
  if (IsPinned(pinned_ids_, set_id)) {
    return false;
  }
  const auto it = sets_.find(set_id);
  if (it == sets_.end()) {
    return false;
  }
  account_boundary_.erase(set_id);
  // Only an accounted set is final (§5.3). A tail-dropped set is a heuristic
  // verdict (1s without parity); a late parity may legitimately rebuild it and
  // settle it once, which is what TestNoReaccountAfterRelease's tail half and
  // the M2 recovery path expect. Capacity eviction of an accounted set is
  // handled in get_or_create, where the same rule applies.
  if (it->second.phase == SetPhase::kAccounted) {
    retired_.insert(set_id);
    prune_retired();
  }
  symbol_bytes_ -= symbols_bytes_of(it->second);
  sets_.erase(it);
  return true;
}

void FrameRx::prune_retired() {
  // Only ids inside the staleness window can still reach the retired check;
  // anything further behind is already dropped as stale at ingress.
  for (auto it = retired_.begin(); it != retired_.end();) {
    const uint32_t behind = static_cast<uint32_t>(anchor_ - *it);
    if (behind > kMaxActiveSets && behind < 0x80000000u) {
      it = retired_.erase(it);
    } else {
      ++it;
    }
  }
}

void FrameRx::create_placeholders(uint32_t first, uint32_t last, int64_t now_ms) {
  // last is strictly after first in the modular half-window sense; the gap may
  // span the u32 wrap (e.g. first = 0xFFFFFFFE, last = 2).
  const uint32_t gap = static_cast<uint32_t>(last - first);
  if (gap == 0 || gap > kMaxGapPlaceholders || sets_.size() + gap >= kMaxActiveSets) {
    return;
  }
  for (uint32_t id = first; id != last; ++id) {
    const auto inserted = sets_.emplace(id, RxSet{});
    RxSet& set = inserted.first->second;
    set.set_id = id;
    // Only a new placeholder starts the tail-drop clock. Rewriting it on an
    // existing set pushed its settlement/tail-drop deadline forward every time
    // a later gap created placeholders (B-14).
    if (inserted.second) {
      set.t_first_ms = now_ms;
    }
  }
}

void FrameRx::emit_event(RxEvent event, uint32_t value) {
  if (event_) {
    event_(event, value);
  }
}

bool FrameRx::view(uint32_t set_id, RxSetView* out) const {
  if (out == nullptr) {
    return false;
  }
  const auto it = sets_.find(set_id);
  if (it == sets_.end()) {
    return false;
  }
  // Slicing copy: RxSet derives from RxSetView, so this carries exactly the
  // published fields and nothing else.
  *out = it->second;
  return true;
}

FrameRx::RxSet* FrameRx::get_or_create(uint32_t set_id, int64_t now_ms) {
  const auto it = sets_.find(set_id);
  if (it != sets_.end()) {
    return &it->second;
  }
  if (sets_.size() >= kMaxActiveSets) {
    // Tombstones outrank capacity pressure: evict the oldest unaccounted set.
    // Pinned sets (currently being processed further up the stack) are never
    // victims: erasing one frees an RxSet that a reentrant caller still holds.
    auto victim = sets_.end();
    for (auto sit = sets_.begin(); sit != sets_.end(); ++sit) {
      if (sit->second.phase != SetPhase::kAccounted &&
          !IsPinned(pinned_ids_, sit->first)) {
        victim = sit;
        break;
      }
    }
    if (victim == sets_.end()) {
      // Everything is a tombstone: still bound the map by evicting the oldest
      // grave instead of growing past the cap (an authenticated peer flooding
      // fresh set ids between settle ticks must not balloon memory).
      for (auto sit = sets_.begin(); sit != sets_.end(); ++sit) {
        if (!IsPinned(pinned_ids_, sit->first)) {
          victim = sit;
          break;
        }
      }
    }
    if (victim == sets_.end()) {
      // Every set is pinned: only reachable if the host re-enters one
      // on_datagram per set (depth kMaxActiveSets). Drop this datagram; the
      // peer retransmits, and growing past the cap is the worse failure.
      return nullptr;
    }
    const uint32_t victim_id = victim->first;
    const bool victim_accounted = victim->second.phase == SetPhase::kAccounted;
    // Capture the delivered count before the erase, but emit only after it: the
    // event sink is a synchronous host callback that may re-enter this module,
    // and it must not see (or free) the victim through a stale iterator.
    const uint32_t victim_delivered = static_cast<uint32_t>(
        (victim->second.orig_mask | victim->second.recov_mask).count());
    account_boundary_.erase(victim_id);
    if (victim_accounted) {
      // Evicted after accounting: never let the id be settled again.
      retired_.insert(victim_id);
      prune_retired();
    }
    symbol_bytes_ -= symbols_bytes_of(victim->second);
    sets_.erase(victim);
    ++tail_dropped_;
    if (!victim_accounted) {
      // Unaccounted set dropped under capacity pressure: same bookkeeping as
      // the settle module's 1s tail drop, so delivered stays bounded by
      // expected + tail_delivered.
      emit_event(RxEvent::kSetTailDropped, victim_delivered);
    }
  }
  RxSet& set = sets_.emplace(set_id, RxSet{}).first->second;
  set.set_id = set_id;
  set.t_first_ms = now_ms;
  return &set;
}

bool FrameRx::note_k(RxSet* set, uint8_t k) {
  if (set->k_known) {
    return set->k == k;
  }
  set->k = k;
  set->k_known = true;
  return true;
}

size_t FrameRx::symbols_bytes_of(const RxSet& set) const {
  size_t bytes = 0;
  for (const std::vector<uint8_t>& slot : set.symbols) {
    bytes += slot.size();
  }
  return bytes;
}

void FrameRx::store_symbol(RxSet* set, uint8_t index, const uint8_t* symbol, size_t len) {
  std::vector<uint8_t>& slot = set->symbols[index];
  const size_t old = slot.size();
  if (symbol_bytes_ - old + len > kMaxRxSymbolBytes) {
    // The session's symbol budget is full. Dropping is the right failure: the
    // peer's ARQ retransmits, and evicting a set here could free state that a
    // reentrant host callback is still walking. Counting it keeps the loss
    // visible instead of turning it into a silent FEC-only slowdown.
    ++symbol_budget_drops_;
    return;
  }
  symbol_bytes_ = symbol_bytes_ - old + len;
  slot.assign(symbol, symbol + len);
  ++set->symbol_count;
  set->has_any_symbol = true;
  set->symbol_max = std::max(set->symbol_max, len);
}

void FrameRx::deliver_payload(const uint8_t* payload, size_t len, bool recovered, bool late,
                              bool late_unexpected, int64_t now_ms, uint32_t repair_ms) {
  if (sn_of_) {
    uint32_t sn = 0;
    // Payloads too short to carry a KCP sn (control/keepalive-sized segments)
    // bypass the dedup window: they share no key, and collapsing them onto one
    // slot would silently swallow every short segment after the first.
    if (sn_of_(payload, len, &sn) && !sn_dedup_.accept(sn, now_ms)) {
      ++late_dup_;
      emit_event(RxEvent::kDataDuplicate, 0);
      return;
    }
  }
  ++data_delivered_;
  if (deliver_) {
    deliver_(payload, len);
  }
  if (recovered) {
    if (late) {
      emit_event(RxEvent::kRecoveredLate, repair_ms);
    } else {
      emit_event(RxEvent::kRecovered, repair_ms);
    }
  } else if (late_unexpected) {
    emit_event(RxEvent::kDataLateUnexpected, 0);
  } else if (late) {
    emit_event(RxEvent::kDataLate, 0);
  } else {
    emit_event(RxEvent::kDataDelivered, 0);
  }
}

}  // namespace fcp
