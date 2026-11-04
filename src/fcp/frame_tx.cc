#include "fcp/frame_tx.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "fcp/rs.h"

namespace fcp {
namespace {

constexpr int64_t kMinFlushMs = 25;
constexpr int64_t kMaxFlushMs = 200;

}  // namespace

FrameTx::FrameTx(uint8_t d, const MtuLimits& limits, EmitFn emit)
    : d_(d), limits_(limits), emit_(std::move(emit)) {}

void FrameTx::set_k(uint8_t k) {
  next_k_ = std::min(k, static_cast<uint8_t>(kRsMaxParity));
}

void FrameTx::raise_limits(const MtuLimits& limits) {
  if (!limits.valid || limits.payload_max <= limits_.payload_max) {
    return;
  }
  limits_ = limits;
}

void FrameTx::set_srtt_ms(int64_t srtt_ms) {
  flush_ms_ = std::clamp<int64_t>(srtt_ms, kMinFlushMs, kMaxFlushMs);
}

void FrameTx::on_kcp_output(const uint8_t* seg, size_t len, int64_t now_ms) {
  if (seg == nullptr && len != 0) {
    return;
  }
  if (len > limits_.payload_max) {
    ++mtu_drops_;
    return;
  }

  maybe_flush(now_ms);
  if (n_ == 0) {
    k_ = next_k_;
    symbol_max_ = 0;
    symbols_.clear();
  }

  const size_t sym_len = len + 2;
  TxSymbol out;
  out.set_id = set_id_;
  out.index = n_;
  out.type_k = pack_type_k(k_, 0, 0);
  out.symbol.resize(sym_len);
  out.symbol[0] = static_cast<uint8_t>(sym_len & 0xFF);
  out.symbol[1] = static_cast<uint8_t>((sym_len >> 8) & 0xFF);
  if (len != 0) {
    std::memcpy(out.symbol.data() + 2, seg, len);
  }
  symbol_max_ = std::max(symbol_max_, sym_len);
  symbols_.push_back(out.symbol);

  ++data_symbols_;
  ++n_;
  t_last_ms_ = now_ms;
  emit(out);

  if (n_ == d_) {
    close_set(CloseReason::kFull);
  }
}

void FrameTx::on_tick(int64_t now_ms) { maybe_flush(now_ms); }

void FrameTx::abort() {
  if (n_ == 0) {
    return;
  }
  ++aborted_sets_;
  set_id_ += 1;
  n_ = 0;
  k_ = 0;
  symbol_max_ = 0;
  symbols_.clear();
}

void FrameTx::maybe_flush(int64_t now_ms) {
  if (n_ >= 1 && now_ms - t_last_ms_ >= flush_ms_) {
    close_set(CloseReason::kIdle);
  }
}

void FrameTx::emit(const TxSymbol& symbol) {
  if (emit_) {
    emit_(symbol);
  }
}

void FrameTx::close_set(CloseReason reason) {
  if (n_ == 0) {
    return;
  }
  if (d_ == 0) {
    // Unreachable through Session (D' >= 1): drop the set instead of dividing
    // by zero in the k_eff scaling below.
    ++aborted_sets_;
    set_id_ += 1;
    n_ = 0;
    k_ = 0;
    symbol_max_ = 0;
    symbols_.clear();
    return;
  }

  uint8_t k_eff = 0;
  if (k_ >= 1) {
    size_t scaled = (static_cast<size_t>(k_) * n_ + d_ - 1) / d_;
    scaled = std::max<size_t>(scaled, 1);
    k_eff = static_cast<uint8_t>(std::min<size_t>(k_, scaled));
  }

  if (k_eff >= 1) {
    // RS works on fixed-size symbols: zero-extend every data symbol.
    std::vector<std::vector<uint8_t>> padded(n_, std::vector<uint8_t>(symbol_max_, 0));
    std::vector<const uint8_t*> data_ptrs(n_);
    for (size_t i = 0; i < n_; ++i) {
      std::memcpy(padded[i].data(), symbols_[i].data(), symbols_[i].size());
      data_ptrs[i] = padded[i].data();
    }
    std::vector<std::vector<uint8_t>> parities(k_, std::vector<uint8_t>(symbol_max_));
    std::vector<uint8_t*> parity_ptrs(k_);
    for (size_t j = 0; j < k_; ++j) {
      parity_ptrs[j] = parities[j].data();
    }
    encode(data_ptrs.data(), n_, k_, symbol_max_, parity_ptrs.data());

    for (uint8_t j = 0; j < k_eff; ++j) {
      TxSymbol out;
      out.set_id = set_id_;
      out.index = static_cast<uint8_t>(n_ + j);
      out.type_k = pack_type_k(k_, j, static_cast<uint8_t>(SymbolType::kParity));
      out.symbol = std::move(parities[j]);
      ++parity_symbols_;
      emit(out);
    }
  }

  if (reason == CloseReason::kFull) {
    ++closed_full_;
  } else {
    ++closed_idle_;
  }
  set_id_ += 1;
  n_ = 0;
  k_ = 0;
  symbol_max_ = 0;
  symbols_.clear();
}

}  // namespace fcp
