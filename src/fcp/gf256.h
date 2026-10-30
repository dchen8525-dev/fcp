// GF(2^8) arithmetic for the Reed-Solomon codec (FCP_PROTOCOL_V6.md §4.4).
//
// Reduction polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D), generator 2. Both are
// wire-visible through the parity bytes, so they are fixed by the spec.

#ifndef FCP_GF256_H_
#define FCP_GF256_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

constexpr uint16_t kGf256Poly = 0x11D;

// a * b in GF(2^8).
uint8_t gf256_mul(uint8_t a, uint8_t b);

// a / b. Returns 0 when a == 0; b must be non-zero.
uint8_t gf256_div(uint8_t a, uint8_t b);

// Multiplicative inverse; 0 maps to 0 so singular matrices surface as failures.
uint8_t gf256_inv(uint8_t a);

// a^e. e == 0 yields 1 even for a == 0.
uint8_t gf256_pow(uint8_t a, unsigned e);

// 2^i (i is reduced modulo 255).
uint8_t gf256_exp(unsigned i);

// Discrete log base 2; 0 maps to 0.
uint8_t gf256_log(uint8_t a);

// 256x256 product table: table[a][b] == a * b. Built once at startup.
const uint8_t (*gf256_mul_table())[256];

// 512-entry exp table; exp[i] == 2^(i mod 255).
const uint8_t* gf256_exp_table();

// 256-entry log table.
const uint8_t* gf256_log_table();

}  // namespace fcp

#endif  // FCP_GF256_H_
