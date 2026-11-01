// FCP 6-byte FEC header (协议规格.md §4.2).
//
//   offset 0  set_id  u32 little-endian
//   offset 4  index   u8
//   offset 5  type_k  (k << 5) | (j << 2) | type
//
// type: 0 data, 1 parity, 2 oob (FECSTAT/KEEPALIVE/HELLO/HELLO_ACK). The field
// is 2 bits, so the value 3 exists on the wire but is undefined since erratum
// #25 retired the old inline control type; RX counts it as struct_fail.

#ifndef FCP_HDR_H_
#define FCP_HDR_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

constexpr size_t kFecHdrLen = 6;

enum class SymbolType : uint8_t {
  kData = 0,
  kParity = 1,
  kOob = 2,
  // No enumerator for 3: erratum #25 retired the inline control type, so any
  // value outside these three is undefined and must be rejected.
};

struct FecHdr {
  uint32_t set_id;
  uint8_t index;
  uint8_t type_k;
};

constexpr uint8_t pack_type_k(uint8_t k, uint8_t j, uint8_t type) {
  return static_cast<uint8_t>(((k & 0x07) << 5) | ((j & 0x07) << 2) | (type & 0x03));
}

constexpr void unpack_type_k(uint8_t type_k, uint8_t* k, uint8_t* j, uint8_t* type) {
  *k = static_cast<uint8_t>(type_k >> 5);
  *j = static_cast<uint8_t>((type_k >> 2) & 0x07);
  *type = static_cast<uint8_t>(type_k & 0x03);
}

constexpr SymbolType hdr_type(uint8_t type_k) {
  return static_cast<SymbolType>(type_k & 0x03);
}

// True only for data/parity/oob. The 2-bit type field can encode 3, which has
// no meaning since erratum #25; RX treats every other value as structurally
// invalid (struct_fail) and never lets it create set state.
constexpr bool valid_symbol_type(SymbolType type) {
  return type == SymbolType::kData || type == SymbolType::kParity ||
         type == SymbolType::kOob;
}

constexpr uint8_t hdr_k(uint8_t type_k) { return static_cast<uint8_t>(type_k >> 5); }

constexpr uint8_t hdr_j(uint8_t type_k) {
  return static_cast<uint8_t>((type_k >> 2) & 0x07);
}

// Spec §14.5: set_id ordering is a modular half-window test so every u32
// comparison keeps working across the wrap. True when b is strictly after a
// (b - a mod 2^32 is in [1, 2^31)).
constexpr bool set_id_after(uint32_t a, uint32_t b) {
  const uint32_t delta = static_cast<uint32_t>(b - a);
  return delta != 0 && delta < 0x80000000u;
}

void pack_hdr(const FecHdr& hdr, uint8_t out[kFecHdrLen]);

// Parses the 6-byte header; returns false when fewer than 6 bytes are available.
bool parse_hdr(const uint8_t* in, size_t len, FecHdr* out);

enum class HdrStatus : uint8_t {
  kOk = 0,
  kIndexPastS,
  kDataIndexPastD,
  kJNotBelowK,
  kBadN,
  kDataPastKnownN,
  kInvalidType,  // type outside data/parity/oob (3 is undefined since #25)
};

// Validation order matches §4.2 (1..5). oob bypasses the collection checks.
// s is D + P; it is a u16 because the negotiated sum may be exactly 256.
HdrStatus validate_hdr(const FecHdr& hdr, uint8_t d, uint16_t s, bool n_known, uint8_t n);

}  // namespace fcp

#endif  // FCP_HDR_H_
