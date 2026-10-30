#include "fcp/rs.h"

#include <cstring>

#include "fcp/cauchy.h"
#include "fcp/gf256.h"

namespace fcp {
namespace {

void xor_scaled(uint8_t* dst, const uint8_t* src, size_t len, uint8_t coeff) {
  if (coeff == 0) {
    return;
  }
  const uint8_t* row = gf256_mul_table()[coeff];
  for (size_t i = 0; i < len; ++i) {
    dst[i] ^= row[src[i]];
  }
}

}  // namespace

void encode(const uint8_t* const* data, size_t n, size_t k, size_t symbol_max,
            uint8_t** parity_out) {
  if (k == 0 || n == 0) {
    return;
  }
  for (size_t r = 0; r < k; ++r) {
    std::memset(parity_out[r], 0, symbol_max);
  }
  for (size_t c = 0; c < n; ++c) {
    for (size_t r = 0; r < k; ++r) {
      xor_scaled(parity_out[r], data[c], symbol_max, cauchy_coeff(r, c, k));
    }
  }
}

bool decode(const uint8_t* const* symbols, size_t n, size_t k, size_t symbol_max,
            std::vector<std::vector<uint8_t>>* recovered) {
  if (recovered == nullptr || n == 0 || n + k > kRsMaxShards) {
    return false;
  }
  recovered->assign(n, std::vector<uint8_t>());

  std::vector<size_t> missing;
  for (size_t i = 0; i < n; ++i) {
    if (symbols[i] == nullptr) {
      missing.push_back(i);
    }
  }
  if (missing.empty()) {
    return true;
  }
  if (k == 0 || missing.size() > k) {
    return false;
  }

  std::vector<size_t> rows;
  rows.reserve(k);
  for (size_t r = 0; r < k && rows.size() < missing.size(); ++r) {
    if (symbols[n + r] != nullptr) {
      rows.push_back(r);
    }
  }
  if (rows.size() < missing.size()) {
    return false;
  }

  const size_t t = missing.size();
  std::vector<uint8_t> matrix(t * t);
  for (size_t i = 0; i < t; ++i) {
    for (size_t j = 0; j < t; ++j) {
      matrix[i * t + j] = cauchy_coeff(rows[i], missing[j], k);
    }
  }
  if (!cauchy_invert_matrix(matrix.data(), t)) {
    return false;
  }

  // RHS for each chosen parity row: parity ^ sum(known data contributions).
  std::vector<std::vector<uint8_t>> rhs(t, std::vector<uint8_t>(symbol_max));
  for (size_t i = 0; i < t; ++i) {
    std::memcpy(rhs[i].data(), symbols[n + rows[i]], symbol_max);
    for (size_t c = 0; c < n; ++c) {
      if (symbols[c] == nullptr) {
        continue;
      }
      xor_scaled(rhs[i].data(), symbols[c], symbol_max, cauchy_coeff(rows[i], c, k));
    }
  }

  for (size_t j = 0; j < t; ++j) {
    std::vector<uint8_t> out(symbol_max, 0);
    for (size_t i = 0; i < t; ++i) {
      xor_scaled(out.data(), rhs[i].data(), symbol_max, matrix[j * t + i]);
    }
    (*recovered)[missing[j]] = std::move(out);
  }
  return true;
}

}  // namespace fcp
