// fcp/wire.h: the one implementation of byte-order access for the wire.
//
// Every field here is spelled out as its literal byte sequence rather than as
// a round trip, because a round trip only proves get/put agree with each other
// -- a byte order both of them share would still pass. The literals come from
// 协议规格.md: §4.2 (FEC header, set_id little endian), §4.1 (envelope counter,
// little endian), §6 (FECSTAT body) and proxy_proto.h (network order).

#include <cstdint>

#include "fcp/hdr.h"
#include "fcp/wire.h"
#include "test_util.h"

namespace {

void TestLittleEndianLayout() {
  uint8_t buf[8] = {};

  fcp::put_le16(0x1234, buf);
  CHECK_EQ(buf[0], 0x34);
  CHECK_EQ(buf[1], 0x12);
  CHECK_EQ(fcp::get_le16(buf), 0x1234);

  fcp::put_le32(0xDEADBEEF, buf);
  CHECK_EQ(buf[0], 0xEF);
  CHECK_EQ(buf[1], 0xBE);
  CHECK_EQ(buf[2], 0xAD);
  CHECK_EQ(buf[3], 0xDE);
  CHECK_EQ(fcp::get_le32(buf), 0xDEADBEEFu);

  fcp::put_le64(0x1122334455667788ull, buf);
  CHECK_EQ(buf[0], 0x88);
  CHECK_EQ(buf[7], 0x11);
  CHECK_EQ(fcp::get_le64(buf), 0x1122334455667788ull);
}

void TestBigEndianLayout() {
  uint8_t buf[2] = {};
  fcp::put_be16(0x1F90, buf);  // port 8080
  CHECK_EQ(buf[0], 0x1F);
  CHECK_EQ(buf[1], 0x90);
  CHECK_EQ(fcp::get_be16(buf), 0x1F90);
}

// Full-width values: a shift that forgets to widen to uint64_t loses the top
// byte, which a small constant would never catch.
void TestWidths() {
  uint8_t buf[8] = {};
  fcp::put_le64(UINT64_MAX, buf);
  CHECK_EQ(fcp::get_le64(buf), UINT64_MAX);
  fcp::put_le32(UINT32_MAX, buf);
  CHECK_EQ(fcp::get_le32(buf), UINT32_MAX);
  fcp::put_le16(0xFFFF, buf);
  CHECK_EQ(fcp::get_le16(buf), 0xFFFFu);
  fcp::put_le64(0x80, buf);
  CHECK_EQ(buf[1], 0x00);
  CHECK_EQ(buf[7], 0x00);
}

// constexpr is part of the contract (no runtime call on the per-symbol path).
constexpr uint8_t kConstBuf[4] = {0x01, 0x02, 0x03, 0x04};
static_assert(fcp::get_le32(kConstBuf) == 0x04030201u, "get_le32 is constexpr");
static_assert(fcp::get_be16(kConstBuf) == 0x0102u, "get_be16 is constexpr");

// The KCP sn offset lives in one place now; the FEC header golden below pins
// the other reader that used to be an inline shift chain (hdr.cc).
void TestHdrGoldenUsesWire() {
  fcp::FecHdr hdr;
  hdr.set_id = 0x01020304;
  hdr.index = 7;
  hdr.type_k = 0xA5;
  uint8_t out[fcp::kFecHdrLen] = {};
  fcp::pack_hdr(hdr, out);
  CHECK_EQ(fcp_test::hex(out, 4), std::string("04030201"));
  fcp::FecHdr back{};
  CHECK(fcp::parse_hdr(out, sizeof(out), &back));
  CHECK_EQ(back.set_id, 0x01020304u);
}

}  // namespace

int main() {
  TestLittleEndianLayout();
  TestBigEndianLayout();
  TestWidths();
  TestHdrGoldenUsesWire();
  return fcp_test::finish();
}
