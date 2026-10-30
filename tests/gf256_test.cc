#include "fcp/gf256.h"

#include "test_util.h"

namespace {

void TestTableProperties() {
  CHECK_EQ(fcp::gf256_exp(0), 1);
  CHECK_EQ(fcp::gf256_exp(255), 1);
  for (int i = 0; i < 255; ++i) {
    CHECK_EQ(fcp::gf256_exp(i + 255), fcp::gf256_exp(i));
  }
  const uint8_t* exp = fcp::gf256_exp_table();
  const uint8_t* log = fcp::gf256_log_table();
  for (int a = 1; a < 256; ++a) {
    CHECK_EQ(exp[log[a]], a);
    CHECK_EQ(fcp::gf256_mul(static_cast<uint8_t>(a),
                            fcp::gf256_inv(static_cast<uint8_t>(a))),
             1);
    CHECK_EQ(fcp::gf256_div(static_cast<uint8_t>(a),
                            static_cast<uint8_t>(a)),
             1);
  }
  CHECK_EQ(fcp::gf256_mul(0, 3), 0);
  CHECK_EQ(fcp::gf256_inv(0), 0);
  CHECK_EQ(fcp::gf256_div(0, 3), 0);
}

void TestArithmetic() {
  // Independent reference value under 0x11D (not the AES 0x11B polynomial).
  CHECK_EQ(fcp::gf256_mul(0x57, 0x83), 0x31);
  CHECK_EQ(fcp::gf256_inv(3), 0xF4);
  CHECK_EQ(fcp::gf256_pow(2, 8), 0x1D);
  CHECK_EQ(fcp::gf256_pow(5, 0), 1);
  CHECK_EQ(fcp::gf256_pow(0, 0), 1);
  CHECK_EQ(fcp::gf256_pow(0, 2), 0);

  const uint8_t (*table)[256] = fcp::gf256_mul_table();
  for (int i = 0; i < 2000; ++i) {
    const uint8_t a = fcp_test::random_byte();
    const uint8_t b = fcp_test::random_byte();
    const uint8_t c = fcp_test::random_byte();
    CHECK_EQ(fcp::gf256_mul(a, b), fcp::gf256_mul(b, a));
    CHECK_EQ(fcp::gf256_mul(a, b), table[a][b]);
    CHECK_EQ(fcp::gf256_mul(a, static_cast<uint8_t>(b ^ c)),
             static_cast<uint8_t>(fcp::gf256_mul(a, b) ^ fcp::gf256_mul(a, c)));
    CHECK_EQ(fcp::gf256_mul(fcp::gf256_mul(a, b), c),
             fcp::gf256_mul(a, fcp::gf256_mul(b, c)));
    if (b != 0) {
      CHECK_EQ(fcp::gf256_div(fcp::gf256_mul(a, b), b), a);
    }
  }
}

}  // namespace

int main() {
  TestTableProperties();
  TestArithmetic();
  return fcp_test::finish();
}
