// FECSTAT v6: 128-byte oob report (协议规格.md §7.1).
//
// All counters are per-interval; only accounted_through_set_id is session-level
// and serves as the monotonic key.

#ifndef FCP_FECSTAT_H_
#define FCP_FECSTAT_H_

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace fcp {

constexpr size_t kFecstatLen = 128;
constexpr uint8_t kFecstatVersion = 1;
// A report's key may lead the last accepted one by at most this many sets.
// One interval cannot settle more groups than the active-set window even at
// line rate; anything larger is a stale/forged neighbour, not progress.
constexpr uint32_t kFecstatMaxForwardSets = 1u << 20;
// §8 "样本": a report with fewer accounted data packets than this may refresh
// the log but must not move k. The reporter's 2s cadence and the strategy's
// decision gate are the same threshold — one constant so they cannot drift
// into "reports on a sample the controller refuses to act on".
constexpr uint32_t kMinSamplePackets = 256;
constexpr char kFecstatMagic[16] = "FCP_FECSTAT_V1";

// flg bit3: the M3 ledger fields (ledger_groups/fail_ppm/meta) are valid.
// Sender sets it only when the interval accounted at least one full-size
// group; receivers additionally gate on ledger_groups, so a bit without
// backing counts is still ignored.
constexpr uint8_t kFlgLedger = 0x08;
// All four bits of FecstatPacket::flg live next to the field description
// above; the writers are reporter.cc (direction/tail/late) and strategy (via
// ledger_groups), the readers are the receiving strategy.
constexpr uint8_t kFlgDirection = 0x01;
constexpr uint8_t kFlgTailDropped = 0x02;
constexpr uint8_t kFlgLateRecovery = 0x04;

struct FecstatPacket {
  char magic[16];              // "FCP_FECSTAT_V1" + 2 x NUL, fixed width
  uint8_t session_salt[8];
  uint8_t ver;                 // 1
  uint8_t flg;                 // bit0 direction(1 = you->me), bit1 tail drop, bit2 late recovery
  uint16_t interval_ms;        // <= 60000
  uint32_t accounted_through_set_id;
  uint32_t sets_expected;
  uint32_t data_expected;      // sum of n_used
  uint32_t data_rx_orig;
  uint32_t data_recovered_dl;
  uint32_t data_recovered_late;
  uint32_t data_delivered;
  uint32_t parity_rx;
  uint32_t parity_expected;    // sum of planned k (upper bound)
  uint32_t sets_k_unknown;
  uint32_t sets_full;
  uint32_t auth_fail;
  uint32_t late_dup;
  uint32_t struct_fail;
  uint16_t repair_lat_p50_ms;
  uint16_t repair_lat_p95_ms;
  uint32_t data_bytes_rx;
  uint32_t parity_bytes_rx;
  uint32_t sets_tail_dropped;
  uint32_t data_late_rx;
  uint32_t sets_partial;
  // M3 R(k) ledger (M3控制设计.md §1.2), carved out of the frozen
  // reserved[5]. bit3 marks the fields present; a report without it carries
  // no ledger, and ledger_groups == 0 means the interval accounted no
  // full-size group. The gate is one condition, worth no negotiation.
  uint32_t ledger_groups;      // settled sets with n_used == D, k known, k >= 1
  uint32_t ledger_fail_ppm;    // of those, >= 1 data unrecovered at settlement
  uint32_t ledger_meta;        // byte0 = dominant k; byte1 = 0;
                               // bytes2-3 = burst KL, 0.01 nat (#26 fills it)
  uint32_t reserved[2];
};

// ledger_meta unpacking (see field comment): dominant k in byte0, burst KL
// quantized to 0.01 nat in bytes2-3.
inline uint8_t ledger_k(const FecstatPacket& p) {
  return static_cast<uint8_t>(p.ledger_meta & 0xFFu);
}

inline uint16_t ledger_burst_kl(const FecstatPacket& p) {
  return static_cast<uint16_t>(p.ledger_meta >> 16);
}

static_assert(std::is_standard_layout_v<FecstatPacket>);
static_assert(sizeof(FecstatPacket) == 128);
static_assert(alignof(FecstatPacket) == 4);
static_assert(offsetof(FecstatPacket, magic) == 0);
static_assert(offsetof(FecstatPacket, session_salt) == 16);
static_assert(offsetof(FecstatPacket, ver) == 24);
static_assert(offsetof(FecstatPacket, flg) == 25);
static_assert(offsetof(FecstatPacket, interval_ms) == 26);
static_assert(offsetof(FecstatPacket, accounted_through_set_id) == 28);
static_assert(offsetof(FecstatPacket, sets_expected) == 32);
static_assert(offsetof(FecstatPacket, data_expected) == 36);
static_assert(offsetof(FecstatPacket, data_rx_orig) == 40);
static_assert(offsetof(FecstatPacket, data_recovered_dl) == 44);
static_assert(offsetof(FecstatPacket, data_recovered_late) == 48);
static_assert(offsetof(FecstatPacket, data_delivered) == 52);
static_assert(offsetof(FecstatPacket, parity_rx) == 56);
static_assert(offsetof(FecstatPacket, parity_expected) == 60);
static_assert(offsetof(FecstatPacket, sets_k_unknown) == 64);
static_assert(offsetof(FecstatPacket, sets_full) == 68);
static_assert(offsetof(FecstatPacket, auth_fail) == 72);
static_assert(offsetof(FecstatPacket, late_dup) == 76);
static_assert(offsetof(FecstatPacket, struct_fail) == 80);
static_assert(offsetof(FecstatPacket, repair_lat_p50_ms) == 84);
static_assert(offsetof(FecstatPacket, repair_lat_p95_ms) == 86);
static_assert(offsetof(FecstatPacket, data_bytes_rx) == 88);
static_assert(offsetof(FecstatPacket, parity_bytes_rx) == 92);
static_assert(offsetof(FecstatPacket, sets_tail_dropped) == 96);
static_assert(offsetof(FecstatPacket, data_late_rx) == 100);
static_assert(offsetof(FecstatPacket, sets_partial) == 104);
static_assert(offsetof(FecstatPacket, ledger_groups) == 108);
static_assert(offsetof(FecstatPacket, ledger_fail_ppm) == 112);
static_assert(offsetof(FecstatPacket, ledger_meta) == 116);
static_assert(offsetof(FecstatPacket, reserved) == 120);

enum class FecstatStatus : uint8_t {
  kOk = 0,
  kBadLength,
  kBadMagic,
  kBadSalt,
  kBadVer,
  kStale,
  kDuplicate,  // #28⑤ (F3): exact repeat of the last accepted report — the
               // second copy of a double-sent FECSTAT; ignored, not stale.
};

// Returns a zeroed packet with magic/salt/ver filled in.
FecstatPacket MakeFecstatPacket(const uint8_t salt[8]);

void encode_fecstat(const FecstatPacket& packet, uint8_t out[kFecstatLen]);

// Validates length, magic, salt and version, then decodes all fields.
FecstatStatus decode_fecstat(const uint8_t* in, size_t len, const uint8_t salt[8],
                             FecstatPacket* out);

// Decodes and enforces the monotonic key: reports with
// accounted_through_set_id <= the last accepted value are kStale.
class FecstatValidator {
 public:
  FecstatStatus validate(const uint8_t* in, size_t len, const uint8_t salt[8],
                         FecstatPacket* out);

  // Reports rejected for jumping implausibly far ahead (kept apart from the
  // stale counter so "behind" and "from the future" stay distinguishable).
  // Not read by any host yet: it exists so a session that starved its peer's
  // controller with a forged forward jump can be diagnosed without a rebuild.
  uint32_t future_rejects() const { return future_rejects_; }

 private:
  bool have_last_ = false;
  uint32_t last_set_id_ = 0;
  uint32_t future_rejects_ = 0;
};

}  // namespace fcp

#endif  // FCP_FECSTAT_H_
