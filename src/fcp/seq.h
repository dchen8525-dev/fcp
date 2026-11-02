// Wrap-safe comparison of u32 counters (spec §14.5).
//
// Two kinds of counter ride the wire and both wrap: set_id (set counter) and
// the stream's byte offsets (4 GiB is ~27 minutes at 20 Mbps). Everything that
// orders them must use the same modular half-window rule, so the rule lives
// here once instead of in an anonymous namespace per translation unit.
//
// seq_after(a, b) is true when a is strictly after b, i.e. a - b mod 2^32 lies
// in [1, 2^31). seq_at_or_after is exactly !seq_after(b, a), including a == b;
// the static_asserts below pin that equivalence rather than leaving it to
// reasoning.

#ifndef FCP_SEQ_H_
#define FCP_SEQ_H_

#include <cstdint>

namespace fcp {

constexpr bool seq_after(uint32_t a, uint32_t b) {
  return static_cast<int32_t>(a - b) > 0;
}

constexpr bool seq_at_or_after(uint32_t a, uint32_t b) {
  return !seq_after(b, a);
}

constexpr int64_t seq_dist(uint32_t a, uint32_t b) {
  return static_cast<int32_t>(a - b);
}

namespace seq_detail {

// Same shape as the historical hdr.h implementation, computed on the unsigned
// delta. Kept as a static_assert operand so "the two spellings agree" stays a
// compile-time fact.
constexpr bool half_window_after(uint32_t a, uint32_t b) {
  const uint32_t delta = static_cast<uint32_t>(b - a);
  return delta != 0 && delta < 0x80000000u;
}

}  // namespace seq_detail

// Forward: a is behind b by a small amount.
static_assert(seq_after(11u, 10u) && !seq_after(10u, 11u) && !seq_after(10u, 10u));
// Backward: the other side of the half window.
static_assert(seq_after(0u, 0xFFFFFFFFu) && !seq_after(0xFFFFFFFFu, 0u));
// Wrap: 0 comes right after 0xFFFFFFFF.
static_assert(!seq_after(0xFFFFFFF0u, 0x00000002u));
static_assert(seq_after(0x00000002u, 0xFFFFFFF0u));
// Equal: not after, but at-or-after.
static_assert(!seq_after(7u, 7u) && seq_at_or_after(7u, 7u));
// The merge 1.1 relies on: at_or_after is the negation of the reverse test.
static_assert(seq_at_or_after(5u, 5u) == !seq_after(5u, 5u));
static_assert(seq_at_or_after(6u, 5u) == !seq_after(5u, 6u));
static_assert(seq_at_or_after(5u, 6u) == !seq_after(6u, 5u));
static_assert(seq_at_or_after(0x00000001u, 0xFFFFFFFFu) ==
              !seq_after(0xFFFFFFFFu, 0x00000001u));
// Distance is the signed modular delta.
static_assert(seq_dist(11u, 10u) == 1 && seq_dist(10u, 11u) == -1);
static_assert(seq_dist(0u, 0xFFFFFFFFu) == 1 &&
              seq_dist(0xFFFFFFFFu, 0u) == -1);
static_assert(seq_dist(42u, 42u) == 0);
// And the unsigned half-window form used by set_id_after says the same thing.
static_assert(seq_detail::half_window_after(10u, 11u) == seq_after(11u, 10u));
static_assert(seq_detail::half_window_after(11u, 10u) == seq_after(10u, 11u));
static_assert(seq_detail::half_window_after(0xFFFFFFFFu, 0u) ==
              seq_after(0u, 0xFFFFFFFFu));
static_assert(seq_detail::half_window_after(0x7FFFFFFFu, 0xFFFFFFFFu) ==
              seq_after(0xFFFFFFFFu, 0x7FFFFFFFu));
static_assert(seq_detail::half_window_after(7u, 7u) == seq_after(7u, 7u));

}  // namespace fcp

#endif  // FCP_SEQ_H_
