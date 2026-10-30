#include "fcp/hdr.h"

#include "test_util.h"

namespace {

void TestPackGolden() {
  CHECK_EQ(fcp::pack_type_k(1, 0, 0), 0x20);
  CHECK_EQ(fcp::pack_type_k(1, 0, 1), 0x21);
  CHECK_EQ(fcp::pack_type_k(1, 1, 1), 0x25);
  CHECK_EQ(fcp::pack_type_k(4, 2, 1), 0x89);
  CHECK_EQ(fcp::pack_type_k(7, 7, 1), 0xFD);
  CHECK_EQ(fcp::pack_type_k(0, 0, 2), 0x02);
  CHECK_EQ(fcp::pack_type_k(0, 0, 3), 0x03);

  fcp::FecHdr hdr{0x04030201u, 5, fcp::pack_type_k(1, 0, 0)};
  uint8_t bytes[fcp::kFecHdrLen];
  fcp::pack_hdr(hdr, bytes);
  static const uint8_t kExpected[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x20};
  CHECK_EQ(fcp_test::hex(bytes, 6), fcp_test::hex(kExpected, 6));

  fcp::FecHdr parsed{};
  CHECK(fcp::parse_hdr(bytes, sizeof(bytes), &parsed));
  CHECK_EQ(parsed.set_id, 0x04030201u);
  CHECK_EQ(parsed.index, 5);
  CHECK_EQ(parsed.type_k, 0x20);
  CHECK(fcp::hdr_type(parsed.type_k) == fcp::SymbolType::kData);
  CHECK_EQ(fcp::hdr_k(parsed.type_k), 1);
  CHECK_EQ(fcp::hdr_j(parsed.type_k), 0);

  CHECK(!fcp::parse_hdr(bytes, 5, &parsed));
}

void TestRoundTripAllFields() {
  for (uint8_t type = 0; type < 4; ++type) {
    for (uint8_t k = 0; k < 8; ++k) {
      for (uint8_t j = 0; j < 8; ++j) {
        const uint8_t packed = fcp::pack_type_k(k, j, type);
        uint8_t out_k = 0;
        uint8_t out_j = 0;
        uint8_t out_type = 0;
        fcp::unpack_type_k(packed, &out_k, &out_j, &out_type);
        CHECK_EQ(out_k, k);
        CHECK_EQ(out_j, j);
        CHECK_EQ(out_type, type);
        CHECK_EQ(fcp::hdr_k(packed), k);
        CHECK_EQ(fcp::hdr_j(packed), j);
      }
    }
  }
}

void TestValidationOrder() {
  const uint8_t d = 10;
  const uint8_t s = 13;

  auto make = [](uint8_t index, uint8_t k, uint8_t j, uint8_t type) {
    return fcp::FecHdr{1, index, fcp::pack_type_k(k, j, type)};
  };

  CHECK(fcp::validate_hdr(make(0, 2, 0, 0), d, s, false, 0) == fcp::HdrStatus::kOk);
  CHECK(fcp::validate_hdr(make(9, 2, 0, 0), d, s, false, 0) == fcp::HdrStatus::kOk);
  CHECK(fcp::validate_hdr(make(10, 2, 0, 0), d, s, false, 0) ==
        fcp::HdrStatus::kDataIndexPastD);
  CHECK(fcp::validate_hdr(make(12, 2, 0, 0), d, s, false, 0) ==
        fcp::HdrStatus::kDataIndexPastD);
  CHECK(fcp::validate_hdr(make(13, 2, 0, 0), d, s, false, 0) ==
        fcp::HdrStatus::kIndexPastS);

  CHECK(fcp::validate_hdr(make(12, 3, 2, 1), d, s, false, 0) == fcp::HdrStatus::kOk);
  CHECK(fcp::validate_hdr(make(10, 3, 0, 1), d, s, false, 0) == fcp::HdrStatus::kOk);
  CHECK(fcp::validate_hdr(make(0, 3, 0, 1), d, s, false, 0) == fcp::HdrStatus::kBadN);
  CHECK(fcp::validate_hdr(make(11, 3, 0, 1), d, s, false, 0) == fcp::HdrStatus::kBadN);
  CHECK(fcp::validate_hdr(make(6, 3, 3, 1), d, s, false, 0) ==
        fcp::HdrStatus::kJNotBelowK);
  CHECK(fcp::validate_hdr(make(0, 0, 0, 1), d, s, false, 0) ==
        fcp::HdrStatus::kJNotBelowK);
  CHECK(fcp::validate_hdr(make(12, 4, 2, 1), d, s, false, 0) == fcp::HdrStatus::kOk);

  CHECK(fcp::validate_hdr(make(5, 2, 0, 0), d, s, true, 5) ==
        fcp::HdrStatus::kDataPastKnownN);
  CHECK(fcp::validate_hdr(make(5, 2, 0, 0), d, s, true, 6) == fcp::HdrStatus::kOk);

  // oob bypasses collection validation entirely; type 3 is undefined since
  // erratum #25 and rejected unconditionally.
  CHECK(fcp::validate_hdr(make(200, 0, 0, 2), d, s, true, 1) == fcp::HdrStatus::kOk);
  CHECK(fcp::validate_hdr(make(200, 0, 0, 3), d, s, true, 1) ==
        fcp::HdrStatus::kInvalidType);
}

}  // namespace

int main() {
  TestPackGolden();
  TestRoundTripAllFields();
  TestValidationOrder();
  return fcp_test::finish();
}
