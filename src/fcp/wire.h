// Little/big-endian integer access for byte buffers.
//
// One implementation for every wire field in the protocol: the FEC header and
// set ids, the envelope counter, the FECSTAT body and the KCP sn inside a
// stream segment are little endian, while the proxy codecs are network order.
// They used to be spelled out at each site (get_u32 here, read32 there, an
// inline shift chain in parse_hdr), which is how two of them once drifted.
//
// Everything is constexpr and compiles to the same loads/stores the inline
// shift chains did -- parsers are fed by untrusted peers and run per symbol, so
// there is no extra call on the hot path. The API is shift-based, not
// memcpy+bit_cast: -Wpedantic rejects bit_cast on platforms where it is not
// constexpr, and a memcpy would force a stack copy for a two-byte read.
//
// None of these check the buffer length; callers validate it first (every
// parser here takes an explicit len).

#ifndef FCP_WIRE_H_
#define FCP_WIRE_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

constexpr uint16_t get_le16(const uint8_t* p) {
  return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                               (static_cast<uint16_t>(p[1]) << 8));
}

constexpr size_t kLe64Len = 8;

constexpr uint32_t get_le32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

constexpr uint64_t get_le64(const uint8_t* p) {
  uint64_t v = 0;
  for (size_t i = 0; i < kLe64Len; ++i) {
    v |= static_cast<uint64_t>(p[i]) << (8 * i);
  }
  return v;
}

constexpr void put_le16(uint32_t v, uint8_t* p) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
}

constexpr void put_le32(uint32_t v, uint8_t* p) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

constexpr void put_le64(uint64_t v, uint8_t* p) {
  for (size_t i = 0; i < kLe64Len; ++i) {
    p[i] = static_cast<uint8_t>(v >> (8 * i));
  }
}

// LEB128 unsigned varint (#78): 7 bits per byte, high bit = continuation,
// little-endian byte order. Used by the FCP-STREAM ACK v2 range fields, whose
// magnitudes (byte gaps between hole blocks) span 1..4 GiB -- fixed-width
// fields would tax the common small-gap case. `put_uvarint` returns the byte
// count (<= 5 for u32); `get_uvarint` consumes at most 5 bytes from
// [p, p + cap), advancing *off -- false on truncation or a 5-byte continuation
// run (not a u32).
constexpr size_t put_uvarint(uint32_t v, uint8_t* p) {
  size_t n = 0;
  while (v >= 0x80) {
    p[n++] = static_cast<uint8_t>(v) | 0x80;
    v >>= 7;
  }
  p[n++] = static_cast<uint8_t>(v);
  return n;
}

constexpr bool get_uvarint(const uint8_t* p, size_t cap, size_t* off, uint32_t* out) {
  uint32_t v = 0;
  int shift = 0;
  for (int i = 0; i < 5; ++i) {
    if (*off >= cap) {
      return false;
    }
    const uint8_t b = p[(*off)++];
    v |= static_cast<uint32_t>(b & 0x7F) << shift;
    if ((b & 0x80) == 0) {
      *out = v;
      return true;
    }
    shift += 7;
  }
  return false;
}

// Network order (RFC 1928 and every proxy message; proxy_proto.h §"字节序").
constexpr uint16_t get_be16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

constexpr void put_be16(uint16_t v, uint8_t* p) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v);
}

}  // namespace fcp

#endif  // FCP_WIRE_H_
