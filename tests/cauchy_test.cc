#include "fcp/cauchy.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "fcp/gf256.h"
#include "test_util.h"

namespace {

void TestGoldenMatrix() {
  // Frozen reference: C[r][c] = 1 / (r ^ (k + c)), n = 10, k = 3.
  static const uint8_t kGolden[3][10] = {
      {0xF4, 0x47, 0xA7, 0x7A, 0xBA, 0xAD, 0x9D, 0xDD, 0x98, 0x3D},
      {0x8E, 0xA7, 0x47, 0xBA, 0x7A, 0x9D, 0xAD, 0x98, 0xDD, 0xAA},
      {0x01, 0x7A, 0xBA, 0x47, 0xA7, 0xDD, 0x98, 0xAD, 0x9D, 0x5D},
  };
  const std::vector<uint8_t> matrix = fcp::cauchy_matrix(10, 3);
  CHECK_EQ(matrix.size(), 30u);
  for (size_t r = 0; r < 3; ++r) {
    for (size_t c = 0; c < 10; ++c) {
      CHECK_EQ(matrix[r * 10 + c], kGolden[r][c]);
      CHECK_EQ(fcp::cauchy_coeff(r, c, 3), kGolden[r][c]);
      CHECK_EQ(fcp::gf256_mul(fcp::cauchy_coeff(r, c, 3),
                              static_cast<uint8_t>(r ^ (3 + c))),
               1);
    }
  }
}

void TestSubmatrixInvertibility() {
  for (size_t n = 1; n <= 20; n += 3) {
    for (size_t k = 1; k <= 7; ++k) {
      const size_t max_dim = n < k ? n : k;
      for (size_t dim = 1; dim <= max_dim; ++dim) {
        for (int trial = 0; trial < 40; ++trial) {
          std::vector<size_t> rows(k);
          std::vector<size_t> cols(n);
          for (size_t i = 0; i < k; ++i) {
            rows[i] = i;
          }
          for (size_t i = 0; i < n; ++i) {
            cols[i] = i;
          }
          std::shuffle(rows.begin(), rows.end(), fcp_test::rng());
          std::shuffle(cols.begin(), cols.end(), fcp_test::rng());
          rows.resize(dim);
          cols.resize(dim);

          std::vector<uint8_t> sub(dim * dim);
          for (size_t i = 0; i < dim; ++i) {
            for (size_t j = 0; j < dim; ++j) {
              sub[i * dim + j] = fcp::cauchy_coeff(rows[i], cols[j], k);
            }
          }
          const std::vector<uint8_t> original = sub;
          CHECK(fcp::cauchy_invert_matrix(sub.data(), dim));

          // sub is now the inverse: original * inverse must be the identity.
          for (size_t i = 0; i < dim; ++i) {
            for (size_t j = 0; j < dim; ++j) {
              uint8_t acc = 0;
              for (size_t t = 0; t < dim; ++t) {
                acc ^= fcp::gf256_mul(original[i * dim + t], sub[t * dim + j]);
              }
              CHECK_EQ(acc, i == j ? 1 : 0);
            }
          }
        }
      }
    }
  }

  // A singular matrix must be rejected.
  std::vector<uint8_t> singular = {1, 2, 2, 4};
  CHECK(!fcp::cauchy_invert_matrix(singular.data(), 2));
}

}  // namespace

int main() {
  TestGoldenMatrix();
  TestSubmatrixInvertibility();
  return fcp_test::finish();
}
