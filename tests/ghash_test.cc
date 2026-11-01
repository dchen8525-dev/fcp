#include "fcp/ghash.h"

#include <cstdio>
#include <cstring>

#include "test_util.h"

namespace {

void TestFieldProperties() {
  uint8_t one[16] = {0x80};
  uint8_t zero[16] = {};
  for (int trial = 0; trial < 100; ++trial) {
    uint8_t a[16];
    uint8_t b[16];
    uint8_t c[16];
    for (int i = 0; i < 16; ++i) {
      a[i] = fcp_test::random_byte();
      b[i] = fcp_test::random_byte();
      c[i] = fcp_test::random_byte();
    }
    uint8_t out[16];
    uint8_t other[16];

    std::memcpy(out, a, 16);
    fcp::gf128_mul(a, one, out);
    CHECK_EQ(fcp_test::hex(out, 16), fcp_test::hex(a, 16));

    fcp::gf128_mul(a, zero, out);
    CHECK_EQ(fcp_test::hex(out, 16), fcp_test::hex(zero, 16));

    fcp::gf128_mul(a, b, out);
    fcp::gf128_mul(b, a, other);
    CHECK_EQ(fcp_test::hex(out, 16), fcp_test::hex(other, 16));

    fcp::gf128_mul(a, b, out);
    fcp::gf128_mul(out, c, out);
    uint8_t bc[16];
    fcp::gf128_mul(b, c, bc);
    fcp::gf128_mul(a, bc, other);
    CHECK_EQ(fcp_test::hex(out, 16), fcp_test::hex(other, 16));
  }
}

// The table path must agree, block for block, with the bit-serial definition of
// the field: same H, same input, same accumulator after every update. This is
// the gate that lets gcm.cc use the table.
void TestTableMatchesReference() {
  uint8_t h[16];
  for (int i = 0; i < 16; ++i) {
    h[i] = fcp_test::random_byte();
  }
  fcp::GhashTable table;
  fcp::ghash_init_table(h, &table);

  uint8_t state_ref[16] = {};
  fcp::Ghash ghash(table);
  for (int block = 0; block < 200; ++block) {
    uint8_t in[16];
    for (int i = 0; i < 16; ++i) {
      in[i] = fcp_test::random_byte();
    }
    // y = (y ^ block) * H, by definition.
    for (int i = 0; i < 16; ++i) {
      state_ref[i] ^= in[i];
    }
    fcp::gf128_mul(state_ref, h, state_ref);

    ghash.update_block(in);
    uint8_t got[16];
    ghash.finalize(got);
    CHECK_EQ(fcp_test::hex(got, 16), fcp_test::hex(state_ref, 16));
  }
}

// The table is built from H, and one mul-by-x step; check its entries are the
// field products they claim to be: T[p][n] == n_weighted * H for every nibble.
void TestTableEntries() {
  uint8_t h[16];
  for (int i = 0; i < 16; ++i) {
    h[i] = fcp_test::random_byte();
  }
  fcp::GhashTable table;
  fcp::ghash_init_table(h, &table);
  // Position 0 is the high nibble of block byte 0: its bits are the polynomial
  // terms x^127, x^126, x^125, x^124.
  for (int n = 0; n < 16; ++n) {
    uint8_t operand[16] = {};
    operand[0] = static_cast<uint8_t>(n << 4);
    uint8_t expected[16];
    fcp::gf128_mul(operand, h, expected);
    CHECK_EQ(fcp_test::hex(table.t[0][n], 16), fcp_test::hex(expected, 16));
  }
}

void TestGhashGolden() {
  // H = AES_0(0^128); aad = "abcdefgh", cipher = 0x00..0x13.
  static const uint8_t kH[16] = {0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B,
                                 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E};
  static const uint8_t kAad[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
  uint8_t cipher[20];
  for (int i = 0; i < 20; ++i) {
    cipher[i] = static_cast<uint8_t>(i);
  }
  static const uint8_t kExpected[16] = {0x85, 0x08, 0xEB, 0x9A, 0x75, 0x3C, 0x4A, 0x6E,
                                        0x51, 0x84, 0x32, 0x0E, 0x35, 0xCB, 0xCB, 0xC6};

  fcp::GhashTable table;
  fcp::ghash_init_table(kH, &table);
  fcp::Ghash ghash(table);
  ghash.update_padded(kAad, sizeof(kAad));
  ghash.update_padded(cipher, sizeof(cipher));
  ghash.update_lengths(sizeof(kAad), sizeof(cipher));
  uint8_t out[16];
  ghash.finalize(out);
  CHECK_EQ(fcp_test::hex(out, 16), fcp_test::hex(kExpected, 16));

  // Empty input (all-zero blocks and zero lengths) leaves the accumulator at zero.
  fcp::Ghash empty(table);
  empty.update_padded(nullptr, 0);
  empty.update_lengths(0, 0);
  empty.finalize(out);
  for (int i = 0; i < 16; ++i) {
    CHECK_EQ(out[i], 0);
  }
}

}  // namespace

int main() {
  TestFieldProperties();
  TestTableEntries();
  TestTableMatchesReference();
  TestGhashGolden();
  return fcp_test::finish();
}
