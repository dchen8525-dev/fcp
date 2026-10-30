// FECSTAT v6: 128-byte oob report (FCP_PROTOCOL_V6.md §7.1).
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
constexpr uint8_t kFecstatVersion = 6;
constexpr char kFecstatMagic[16] = "FCP_FECSTAT_V6";

struct FecstatPacket {
  char magic[16];              // "FCP_FECSTAT_V6" + 2 x NUL, fixed width
  uint8_t session_salt[8];
  uint8_t ver;                 // 6
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
  uint32_t reserved[5];
};

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
static_assert(offsetof(FecstatPacket, reserved) == 108);

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

 private:
  bool have_last_ = false;
  uint32_t last_set_id_ = 0;
};

}  // namespace fcp

#endif  // FCP_FECSTAT_H_
