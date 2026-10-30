#include "fcp/fecstat.h"

#include <cstring>

#include "test_util.h"

namespace {

const uint8_t kSalt[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};

void put16(uint8_t* out, size_t offset, uint16_t value) {
  out[offset] = static_cast<uint8_t>(value);
  out[offset + 1] = static_cast<uint8_t>(value >> 8);
}

void put32(uint8_t* out, size_t offset, uint32_t value) {
  out[offset] = static_cast<uint8_t>(value);
  out[offset + 1] = static_cast<uint8_t>(value >> 8);
  out[offset + 2] = static_cast<uint8_t>(value >> 16);
  out[offset + 3] = static_cast<uint8_t>(value >> 24);
}

fcp::FecstatPacket SamplePacket() {
  fcp::FecstatPacket packet = fcp::MakeFecstatPacket(kSalt);
  packet.flg = 0x05;
  packet.interval_ms = 2000;
  packet.accounted_through_set_id = 0x11223344u;
  packet.sets_expected = 0x01020304u;
  packet.data_expected = 0x11121314u;
  packet.data_rx_orig = 0x21222324u;
  packet.data_recovered_dl = 0x31323334u;
  packet.data_recovered_late = 0x41424344u;
  packet.data_delivered = 0x51525354u;
  packet.parity_rx = 0x61626364u;
  packet.parity_expected = 0x71727374u;
  packet.sets_k_unknown = 0x81828384u;
  packet.sets_full = 0x91929394u;
  packet.auth_fail = 0xA1A2A3A4u;
  packet.late_dup = 0xB1B2B3B4u;
  packet.struct_fail = 0xC1C2C3C4u;
  packet.repair_lat_p50_ms = 0xD1D2;
  packet.repair_lat_p95_ms = 0xE1E2;
  packet.data_bytes_rx = 0xF1F2F3F4u;
  packet.parity_bytes_rx = 0x01020305u;
  packet.sets_tail_dropped = 0x11121315u;
  packet.data_late_rx = 0x21222325u;
  packet.sets_partial = 0x31323335u;
  for (int i = 0; i < 5; ++i) {
    packet.reserved[i] = 0x41424345u + static_cast<uint32_t>(i);
  }
  return packet;
}

void TestGoldenLayout() {
  const fcp::FecstatPacket packet = SamplePacket();
  CHECK_EQ(sizeof(fcp::FecstatPacket), static_cast<size_t>(128));
  CHECK_EQ(alignof(fcp::FecstatPacket), static_cast<size_t>(4));

  // Build the wire image with literal offsets from FCP_PROTOCOL_V6.md §7.1.
  uint8_t expected[128] = {};
  std::memcpy(expected + 0, "FCP_FECSTAT_V6", 15);  // 14 chars + NUL; rest zero
  std::memcpy(expected + 16, kSalt, 8);
  expected[24] = 6;
  expected[25] = 0x05;
  put16(expected, 26, 2000);
  put32(expected, 28, 0x11223344u);
  put32(expected, 32, 0x01020304u);
  put32(expected, 36, 0x11121314u);
  put32(expected, 40, 0x21222324u);
  put32(expected, 44, 0x31323334u);
  put32(expected, 48, 0x41424344u);
  put32(expected, 52, 0x51525354u);
  put32(expected, 56, 0x61626364u);
  put32(expected, 60, 0x71727374u);
  put32(expected, 64, 0x81828384u);
  put32(expected, 68, 0x91929394u);
  put32(expected, 72, 0xA1A2A3A4u);
  put32(expected, 76, 0xB1B2B3B4u);
  put32(expected, 80, 0xC1C2C3C4u);
  put16(expected, 84, 0xD1D2);
  put16(expected, 86, 0xE1E2);
  put32(expected, 88, 0xF1F2F3F4u);
  put32(expected, 92, 0x01020305u);
  put32(expected, 96, 0x11121315u);
  put32(expected, 100, 0x21222325u);
  put32(expected, 104, 0x31323335u);
  for (int i = 0; i < 5; ++i) {
    put32(expected, 108 + 4 * static_cast<size_t>(i),
          0x41424345u + static_cast<uint32_t>(i));
  }

  uint8_t encoded[128];
  fcp::encode_fecstat(packet, encoded);
  CHECK_EQ(fcp_test::hex(encoded, 128), fcp_test::hex(expected, 128));

  fcp::FecstatPacket decoded{};
  CHECK(fcp::decode_fecstat(encoded, sizeof(encoded), kSalt, &decoded) ==
        fcp::FecstatStatus::kOk);
  uint8_t reencoded[128];
  fcp::encode_fecstat(decoded, reencoded);
  CHECK_EQ(fcp_test::hex(reencoded, 128), fcp_test::hex(expected, 128));
  CHECK_EQ(decoded.interval_ms, 2000);
  CHECK_EQ(decoded.sets_partial, 0x31323335u);
  CHECK_EQ(decoded.reserved[4], 0x41424349u);
}

void TestValidation() {
  uint8_t wire[128];
  fcp::encode_fecstat(SamplePacket(), wire);
  fcp::FecstatPacket out{};

  CHECK(fcp::decode_fecstat(wire, 127, kSalt, &out) == fcp::FecstatStatus::kBadLength);
  CHECK(fcp::decode_fecstat(wire, 129, kSalt, &out) == fcp::FecstatStatus::kBadLength);

  uint8_t bad_magic[128];
  std::memcpy(bad_magic, wire, 128);
  bad_magic[0] ^= 0x01;
  CHECK(fcp::decode_fecstat(bad_magic, 128, kSalt, &out) == fcp::FecstatStatus::kBadMagic);

  const uint8_t other_salt[8] = {9, 9, 9, 9, 9, 9, 9, 9};
  CHECK(fcp::decode_fecstat(wire, 128, other_salt, &out) == fcp::FecstatStatus::kBadSalt);

  uint8_t bad_ver[128];
  std::memcpy(bad_ver, wire, 128);
  bad_ver[24] = 5;
  CHECK(fcp::decode_fecstat(bad_ver, 128, kSalt, &out) == fcp::FecstatStatus::kBadVer);

  // The magic occupies exactly 16 bytes with two NULs.
  CHECK_EQ(std::memcmp(wire, "FCP_FECSTAT_V6", 14), 0);
  CHECK_EQ(wire[14], 0);
  CHECK_EQ(wire[15], 0);
}

void TestMonotonicKey() {
  fcp::FecstatValidator validator;
  fcp::FecstatPacket packet = fcp::MakeFecstatPacket(kSalt);
  uint8_t wire[128];
  fcp::FecstatPacket out{};

  packet.accounted_through_set_id = 100;
  fcp::encode_fecstat(packet, wire);
  CHECK(validator.validate(wire, 128, kSalt, &out) == fcp::FecstatStatus::kOk);

  packet.accounted_through_set_id = 101;
  fcp::encode_fecstat(packet, wire);
  CHECK(validator.validate(wire, 128, kSalt, &out) == fcp::FecstatStatus::kOk);

  CHECK(validator.validate(wire, 128, kSalt, &out) == fcp::FecstatStatus::kDuplicate);
  packet.accounted_through_set_id = 100;
  fcp::encode_fecstat(packet, wire);
  CHECK(validator.validate(wire, 128, kSalt, &out) == fcp::FecstatStatus::kStale);

  // A bad packet does not advance the monotonic key.
  packet.accounted_through_set_id = 200;
  fcp::encode_fecstat(packet, wire);
  wire[24] = 5;
  CHECK(validator.validate(wire, 128, kSalt, &out) == fcp::FecstatStatus::kBadVer);
  fcp::encode_fecstat(packet, wire);
  CHECK(validator.validate(wire, 128, kSalt, &out) == fcp::FecstatStatus::kOk);
}

}  // namespace

int main() {
  TestGoldenLayout();
  TestValidation();
  TestMonotonicKey();
  return fcp_test::finish();
}
