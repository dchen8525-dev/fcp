#include "fcp/hdr.h"

#include "fcp/wire.h"

namespace fcp {

void pack_hdr(const FecHdr& hdr, uint8_t out[kFecHdrLen]) {
  put_le32(hdr.set_id, out);
  out[4] = hdr.index;
  out[5] = hdr.type_k;
}

bool parse_hdr(const uint8_t* in, size_t len, FecHdr* out) {
  if (in == nullptr || out == nullptr || len < kFecHdrLen) {
    return false;
  }
  out->set_id = get_le32(in);
  out->index = in[4];
  out->type_k = in[5];
  return true;
}

HdrStatus validate_hdr(const FecHdr& hdr, uint8_t d, uint16_t s, bool n_known, uint8_t n) {
  const SymbolType type = hdr_type(hdr.type_k);
  if (type == SymbolType::kOob) {
    return HdrStatus::kOk;
  }
  if (!valid_symbol_type(type)) {
    return HdrStatus::kInvalidType;
  }
  if (hdr.index >= s) {
    return HdrStatus::kIndexPastS;
  }
  if (type == SymbolType::kData) {
    if (hdr.index >= d) {
      return HdrStatus::kDataIndexPastD;
    }
    if (n_known && hdr.index >= n) {
      return HdrStatus::kDataPastKnownN;
    }
    return HdrStatus::kOk;
  }

  const uint8_t k = hdr_k(hdr.type_k);
  const uint8_t j = hdr_j(hdr.type_k);
  if (j >= k) {
    return HdrStatus::kJNotBelowK;
  }
  const int parity_n = static_cast<int>(hdr.index) - static_cast<int>(j);
  if (parity_n < 1 || parity_n > d) {
    return HdrStatus::kBadN;
  }
  return HdrStatus::kOk;
}

}  // namespace fcp
