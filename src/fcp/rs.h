// Systematic Cauchy Reed-Solomon codec over GF(2^8) (协议规格.md §4.4).
//
// Code length is always n + k (planned values): indices [0, n) are data,
// [n, n + k) are parity. Early-closed sets simply send fewer parity symbols
// (k_eff); that never changes the matrix.

#ifndef FCP_RS_H_
#define FCP_RS_H_

#include <cstddef>
#include <cstdint>
#include <vector>

namespace fcp {

constexpr size_t kRsMaxShards = 256;  // n + k, limited by the u8 index
constexpr size_t kRsMaxParity = 7;    // k occupies 3 header bits

// Computes all k parity symbols. Every data symbol points to exactly
// `symbol_max` bytes (callers zero-extend shorter payloads); parity_out[j]
// points to `symbol_max` writable bytes.
void encode(const uint8_t* const* data, size_t n, size_t k, size_t symbol_max,
            uint8_t** parity_out);

// Reconstructs erased data symbols. `symbols` has n + k entries; nullptr marks
// an erasure (lost or never-sent parity). Every non-null entry points to
// `symbol_max` bytes. On success `recovered` is resized to n: for each erased
// data index i < n, recovered[i] holds the reconstructed symbol; entries for
// symbols that were already present stay empty.
bool decode(const uint8_t* const* symbols, size_t n, size_t k, size_t symbol_max,
            std::vector<std::vector<uint8_t>>* recovered);

}  // namespace fcp

#endif  // FCP_RS_H_
