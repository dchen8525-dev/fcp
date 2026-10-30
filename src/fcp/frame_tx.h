// Sending path: KCP segment -> framed FEC symbol (design doc §5).
//
// Each KCP output segment becomes exactly one FEC symbol. There is no content
// classification on this path: handshake messages travel as oob frames sent by
// the handshake module directly (erratum #25). Everything arriving here is
// appended to the open set; the set closes when n == D or after T_flush of
// inactivity, at which point k_eff parity symbols are emitted.
//
// The emit callback receives the unencrypted header fields plus the symbol; the
// session wraps it in the envelope and sends it over UDP.

#ifndef FCP_FRAME_TX_H_
#define FCP_FRAME_TX_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "fcp/hdr.h"

namespace fcp {

constexpr size_t kFrameEnvelopeOverhead = 28;  // salt 8 + nonce 8 + tag 12
// data wire = ip + udp + 28 + hdr(6) + len(2) + payload
constexpr size_t kDataWireOverhead = kFrameEnvelopeOverhead + kFecHdrLen + 2;  // 36
// parity wire = ip + udp + 28 + hdr(6) + symbol_max
constexpr size_t kParityWireOverhead = kFrameEnvelopeOverhead + kFecHdrLen;  // 34
constexpr size_t kKcpHeaderReserve = 24;  // mss = payload_max - 24

struct MtuLimits {
  size_t mtu = 0;
  size_t ip_hdr_len = 0;
  size_t payload_max = 0;  // largest KCP payload carried by one data symbol
  size_t symbol_max = 0;   // largest RS symbol, i.e. payload_max + len(2)
  size_t mss = 0;          // value handed to KCP after negotiation
  bool valid = false;
};

// ip_hdr_len is 20 for IPv4 and 40 for IPv6. The UDP header (8 bytes) is
// included here; the envelope overhead is not part of mtu.
constexpr MtuLimits compute_mtu_limits(size_t mtu, size_t ip_hdr_len) {
  MtuLimits limits{};
  limits.mtu = mtu;
  limits.ip_hdr_len = ip_hdr_len;
  const size_t base = mtu > ip_hdr_len + 8 ? mtu - ip_hdr_len - 8 : 0;
  if (base < kDataWireOverhead + kKcpHeaderReserve + 1) {
    return limits;
  }
  limits.payload_max = base - kDataWireOverhead;
  limits.symbol_max = base - kParityWireOverhead;
  limits.mss = limits.payload_max - kKcpHeaderReserve;
  limits.valid = true;
  return limits;
}

static_assert(compute_mtu_limits(1400, 20).payload_max == 1336);
static_assert(compute_mtu_limits(1400, 20).symbol_max == 1338);
static_assert(compute_mtu_limits(1400, 20).mss == 1312);
static_assert(compute_mtu_limits(1400, 40).payload_max == 1316);
static_assert(compute_mtu_limits(1400, 40).symbol_max == 1318);
static_assert(compute_mtu_limits(1400, 40).mss == 1292);
static_assert(!compute_mtu_limits(80, 20).valid);

struct TxSymbol {
  uint32_t set_id = 0;
  uint8_t index = 0;
  uint8_t type_k = 0;
  std::vector<uint8_t> symbol;
};

class FrameTx {
 public:
  using EmitFn = std::function<void(const TxSymbol&)>;

  FrameTx(uint8_t d, const MtuLimits& limits, EmitFn emit);

  // Planned k for the next set that starts; a set locks the value at n == 0.
  void set_k(uint8_t k);
  // T_flush = clamp(srtt, 25ms, 200ms); default srtt is 200ms.
  void set_srtt_ms(int64_t srtt_ms);

  void on_kcp_output(const uint8_t* seg, size_t len, int64_t now_ms);
  void on_tick(int64_t now_ms);

  // Abnormal termination: the open set is dropped without parity, exactly as
  // the peer will see it (never closed -> tail_dropped, not in expected).
  void abort();

  bool has_open_set() const { return n_ > 0; }
  uint8_t open_n() const { return n_; }
  uint8_t open_k() const { return n_ > 0 ? k_ : 0; }
  uint32_t set_id() const { return set_id_; }
  int64_t flush_timeout_ms() const { return flush_ms_; }

  uint32_t closed_full() const { return closed_full_; }
  uint32_t closed_idle() const { return closed_idle_; }
  uint32_t aborted_sets() const { return aborted_sets_; }
  uint32_t data_symbols() const { return data_symbols_; }
  uint32_t parity_symbols() const { return parity_symbols_; }
  uint32_t mtu_drops() const { return mtu_drops_; }

 private:
  enum class CloseReason : uint8_t { kFull, kIdle };

  void close_set(CloseReason reason);
  void maybe_flush(int64_t now_ms);
  void emit(const TxSymbol& symbol);

  uint8_t d_;
  MtuLimits limits_;
  EmitFn emit_;

  uint32_t set_id_ = 0;
  uint8_t n_ = 0;
  uint8_t k_ = 0;
  uint8_t next_k_ = 0;
  size_t symbol_max_ = 0;
  int64_t t_last_ms_ = 0;
  int64_t flush_ms_ = 200;
  std::vector<std::vector<uint8_t>> symbols_;

  uint32_t closed_full_ = 0;
  uint32_t closed_idle_ = 0;
  uint32_t aborted_sets_ = 0;
  uint32_t data_symbols_ = 0;
  uint32_t parity_symbols_ = 0;
  uint32_t mtu_drops_ = 0;
};

}  // namespace fcp

#endif  // FCP_FRAME_TX_H_
