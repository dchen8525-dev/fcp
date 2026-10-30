#include "fcp/cauchy.h"

#include <algorithm>

#include "fcp/gf256.h"

namespace fcp {

uint8_t cauchy_coeff(size_t r, size_t c, size_t k) {
  return gf256_inv(static_cast<uint8_t>(r ^ (k + c)));
}

std::vector<uint8_t> cauchy_matrix(size_t n, size_t k) {
  std::vector<uint8_t> matrix(n * k);
  for (size_t r = 0; r < k; ++r) {
    for (size_t c = 0; c < n; ++c) {
      matrix[r * n + c] = cauchy_coeff(r, c, k);
    }
  }
  return matrix;
}

bool cauchy_invert_matrix(uint8_t* matrix, size_t dim) {
  std::vector<uint8_t> inverse(dim * dim, 0);
  for (size_t i = 0; i < dim; ++i) {
    inverse[i * dim + i] = 1;
  }

  for (size_t col = 0; col < dim; ++col) {
    size_t pivot = col;
    while (pivot < dim && matrix[pivot * dim + col] == 0) {
      ++pivot;
    }
    if (pivot == dim) {
      return false;
    }
    if (pivot != col) {
      std::swap_ranges(matrix + pivot * dim, matrix + (pivot + 1) * dim,
                       matrix + col * dim);
      std::swap_ranges(inverse.begin() + static_cast<std::ptrdiff_t>(pivot * dim),
                       inverse.begin() + static_cast<std::ptrdiff_t>((pivot + 1) * dim),
                       inverse.begin() + static_cast<std::ptrdiff_t>(col * dim));
    }

    const uint8_t pivot_inv = gf256_inv(matrix[col * dim + col]);
    for (size_t j = 0; j < dim; ++j) {
      matrix[col * dim + j] = gf256_mul(matrix[col * dim + j], pivot_inv);
      inverse[col * dim + j] = gf256_mul(inverse[col * dim + j], pivot_inv);
    }

    for (size_t row = 0; row < dim; ++row) {
      if (row == col) {
        continue;
      }
      const uint8_t factor = matrix[row * dim + col];
      if (factor == 0) {
        continue;
      }
      for (size_t j = 0; j < dim; ++j) {
        matrix[row * dim + j] ^= gf256_mul(factor, matrix[col * dim + j]);
        inverse[row * dim + j] ^= gf256_mul(factor, inverse[col * dim + j]);
      }
    }
  }

  std::copy(inverse.begin(), inverse.end(), matrix);
  return true;
}

}  // namespace fcp
