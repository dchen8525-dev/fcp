// Cauchy matrix used by the systematic Reed-Solomon codec.
//
// The parity coefficient matrix C is k rows (parity) by n columns (data):
//   C[r][c] = 1 / (x_r ^ y_c),  x_r = r,  y_c = k + c
//
// The two index sets must be disjoint; with x_r = r the data set is offset by k.
// (FCP_V6_DETAILED_DESIGN.md §5.4 writes "y_c = 256 + c"; over GF(2^8) that is
// c modulo 256 and collides with x_r = r, so the offset is k. Any Cauchy matrix
// is MDS, i.e. every square submatrix is invertible, which is what the codec
// relies on.)

#ifndef FCP_CAUCHY_H_
#define FCP_CAUCHY_H_

#include <cstddef>
#include <cstdint>
#include <vector>

namespace fcp {

// C[r][c] with r < k, c arbitrary. Requires k + c <= 255.
uint8_t cauchy_coeff(size_t r, size_t c, size_t k);

// Row-major k x n coefficient matrix.
std::vector<uint8_t> cauchy_matrix(size_t n, size_t k);

// Inverts a dim x dim matrix in place. Returns false (matrix untouched) when singular.
bool cauchy_invert_matrix(uint8_t* matrix, size_t dim);

}  // namespace fcp

#endif  // FCP_CAUCHY_H_
