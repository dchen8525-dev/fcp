#include "fcp/aes.h"

#include "test_util.h"

namespace {

void TestFips197AppendixC1() {
  const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  const uint8_t plain[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  const uint8_t expected[16] = {0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
                                0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A};

  fcp::Aes128Key round_keys;
  fcp::aes128_expand_key(key, &round_keys);

  uint8_t out[16];
  fcp::aes128_encrypt_block_ttable(round_keys, plain, out);
  CHECK_EQ(fcp_test::hex(out, 16), fcp_test::hex(expected, 16));

  fcp::aes128_encrypt_block_hw(round_keys, plain, out);
  CHECK_EQ(fcp_test::hex(out, 16), fcp_test::hex(expected, 16));

  std::printf("AES-NI available: %s\n", fcp::aesni_available() ? "yes" : "no");
}

void TestDualPathAgreement() {
  for (int trial = 0; trial < 200; ++trial) {
    uint8_t key[16];
    uint8_t plain[16];
    for (int i = 0; i < 16; ++i) {
      key[i] = fcp_test::random_byte();
      plain[i] = fcp_test::random_byte();
    }
    fcp::Aes128Key round_keys;
    fcp::aes128_expand_key(key, &round_keys);

    uint8_t soft[16];
    uint8_t hard[16];
    uint8_t picked[16];
    fcp::aes128_encrypt_block_ttable(round_keys, plain, soft);
    fcp::aes128_encrypt_block_hw(round_keys, plain, hard);
    fcp::aes128_encrypt_block(round_keys, plain, picked);
    CHECK_EQ(fcp_test::hex(soft, 16), fcp_test::hex(hard, 16));
    CHECK_EQ(fcp_test::hex(soft, 16), fcp_test::hex(picked, 16));
  }
}

}  // namespace

int main() {
  TestFips197AppendixC1();
  TestDualPathAgreement();
  return fcp_test::finish();
}
