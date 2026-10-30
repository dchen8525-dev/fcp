#include "fcp/gf256.h"

namespace fcp {
namespace {

struct Gf256Tables {
  uint8_t exp[512]{};
  uint8_t log[256]{};
  uint8_t mul[256][256]{};

  Gf256Tables() {
    uint16_t x = 1;
    for (int i = 0; i < 255; ++i) {
      exp[i] = static_cast<uint8_t>(x);
      log[x] = static_cast<uint8_t>(i);
      x = static_cast<uint16_t>(x << 1);
      if (x & 0x100) {
        x ^= kGf256Poly;
      }
    }
    for (int i = 255; i < 512; ++i) {
      exp[i] = exp[i - 255];
    }
    for (int a = 0; a < 256; ++a) {
      for (int b = 0; b < 256; ++b) {
        mul[a][b] = (a == 0 || b == 0)
                        ? 0
                        : exp[static_cast<int>(log[a]) + static_cast<int>(log[b])];
      }
    }
  }
};

const Gf256Tables& tables() {
  static const Gf256Tables kTables;
  return kTables;
}

}  // namespace

uint8_t gf256_mul(uint8_t a, uint8_t b) { return tables().mul[a][b]; }

uint8_t gf256_div(uint8_t a, uint8_t b) {
  return a == 0 ? 0 : tables().mul[a][gf256_inv(b)];
}

uint8_t gf256_inv(uint8_t a) {
  return a == 0 ? 0 : tables().exp[255 - tables().log[a]];
}

uint8_t gf256_pow(uint8_t a, unsigned e) {
  if (e == 0) {
    return 1;
  }
  if (a == 0) {
    return 0;
  }
  const unsigned exponent = (static_cast<unsigned>(tables().log[a]) * (e % 255)) % 255;
  return tables().exp[exponent];
}

uint8_t gf256_exp(unsigned i) { return tables().exp[i % 255]; }

uint8_t gf256_log(uint8_t a) { return tables().log[a]; }

const uint8_t (*gf256_mul_table())[256] { return tables().mul; }

const uint8_t* gf256_exp_table() { return tables().exp; }

const uint8_t* gf256_log_table() { return tables().log; }

}  // namespace fcp
