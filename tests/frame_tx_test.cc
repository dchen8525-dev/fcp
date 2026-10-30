#include "fcp/frame_tx.h"

#include <cstring>

#include "fcp/handshake.h"
#include "fcp/hdr.h"
#include "fcp/rs.h"
#include "test_util.h"

namespace {

std::vector<uint8_t> Pattern(size_t len, uint8_t seed = 0) {
  std::vector<uint8_t> out(len);
  for (size_t i = 0; i < len; ++i) {
    out[i] = static_cast<uint8_t>(seed + 7 * i);
  }
  return out;
}

struct Fixture {
  fcp::MtuLimits limits;
  std::vector<fcp::TxSymbol> out;
  fcp::FrameTx tx;

  explicit Fixture(uint8_t d = 10, size_t mtu = 1400, size_t ip_hdr = 20)
      : limits(fcp::compute_mtu_limits(mtu, ip_hdr)),
        tx(d, limits, [this](const fcp::TxSymbol& s) { out.push_back(s); }) {}

  void send(size_t len, int64_t now_ms, uint8_t seed = 0) {
    const std::vector<uint8_t> seg = Pattern(len, seed);
    tx.on_kcp_output(seg.data(), seg.size(), now_ms);
  }

  void send_bytes(const std::vector<uint8_t>& bytes, int64_t now_ms) {
    tx.on_kcp_output(bytes.data(), bytes.size(), now_ms);
  }

  size_t count_type(fcp::SymbolType type) const {
    size_t n = 0;
    for (const auto& s : out) {
      if (fcp::hdr_type(s.type_k) == type) {
        ++n;
      }
    }
    return n;
  }
};

void TestMtuLimits() {
  using fcp::compute_mtu_limits;

  const auto v4 = compute_mtu_limits(1400, 20);
  CHECK(v4.valid);
  CHECK_EQ(v4.payload_max, 1336u);
  CHECK_EQ(v4.symbol_max, 1338u);
  CHECK_EQ(v4.mss, 1312u);

  const auto v6 = compute_mtu_limits(1400, 40);
  CHECK(v6.valid);
  CHECK_EQ(v6.payload_max, 1316u);
  CHECK_EQ(v6.symbol_max, 1318u);
  CHECK_EQ(v6.mss, 1292u);

  // Minimum-ish MTUs.
  const auto v4_min = compute_mtu_limits(576, 20);
  CHECK(v4_min.valid);
  CHECK_EQ(v4_min.payload_max, 512u);
  CHECK_EQ(v4_min.symbol_max, 514u);
  CHECK_EQ(v4_min.mss, 488u);

  const auto v6_min = compute_mtu_limits(1280, 40);
  CHECK(v6_min.valid);
  CHECK_EQ(v6_min.payload_max, 1196u);
  CHECK_EQ(v6_min.symbol_max, 1198u);
  CHECK_EQ(v6_min.mss, 1172u);

  // The validity edge: mss must be at least 1.
  CHECK(!compute_mtu_limits(88, 20).valid);
  const auto edge = compute_mtu_limits(89, 20);
  CHECK(edge.valid);
  CHECK_EQ(edge.payload_max, 25u);
  CHECK_EQ(edge.mss, 1u);
  CHECK(!compute_mtu_limits(0, 20).valid);
}

void TestFullClose() {
  Fixture f(10, 1400, 20);
  f.tx.set_k(2);
  for (int i = 0; i < 10; ++i) {
    f.send(100, i, static_cast<uint8_t>(i));
  }
  CHECK_EQ(f.out.size(), 12u);
  CHECK_EQ(f.tx.data_symbols(), 10u);
  CHECK_EQ(f.tx.parity_symbols(), 2u);
  CHECK_EQ(f.tx.closed_full(), 1u);
  CHECK_EQ(f.tx.closed_idle(), 0u);
  CHECK_EQ(f.tx.set_id(), 1u);
  CHECK(!f.tx.has_open_set());

  for (uint8_t i = 0; i < 10; ++i) {
    const fcp::TxSymbol& s = f.out[i];
    CHECK_EQ(s.set_id, 0u);
    CHECK_EQ(s.index, i);
    CHECK_EQ(s.type_k, fcp::pack_type_k(2, 0, 0));
    CHECK_EQ(s.symbol.size(), 102u);
    CHECK_EQ(s.symbol[0], 102);
    CHECK_EQ(s.symbol[1], 0);
    const auto payload = Pattern(100, i);
    CHECK(std::memcmp(s.symbol.data() + 2, payload.data(), payload.size()) == 0);
  }

  // k_eff == k for a full set, indices run from n, j counts 0..k-1.
  for (uint8_t j = 0; j < 2; ++j) {
    const fcp::TxSymbol& s = f.out[10 + j];
    CHECK_EQ(s.set_id, 0u);
    CHECK_EQ(s.index, static_cast<uint8_t>(10 + j));
    CHECK_EQ(s.type_k, fcp::pack_type_k(2, j, 1));
    CHECK_EQ(s.symbol.size(), 102u);
  }

  // Parity must match an independent encode of the zero-extended data.
  std::vector<std::vector<uint8_t>> padded(10, std::vector<uint8_t>(102));
  std::vector<const uint8_t*> data_ptrs(10);
  for (size_t i = 0; i < 10; ++i) {
    std::memcpy(padded[i].data(), f.out[i].symbol.data(), f.out[i].symbol.size());
    data_ptrs[i] = padded[i].data();
  }
  std::vector<std::vector<uint8_t>> parity(2, std::vector<uint8_t>(102));
  std::vector<uint8_t*> parity_ptrs = {parity[0].data(), parity[1].data()};
  fcp::encode(data_ptrs.data(), 10, 2, 102, parity_ptrs.data());
  CHECK(f.out[10].symbol == parity[0]);
  CHECK(f.out[11].symbol == parity[1]);

  // The next segment opens set 1 at index 0.
  f.send(50, 100);
  CHECK_EQ(f.out.back().set_id, 1u);
  CHECK_EQ(f.out.back().index, 0);
}

void TestIdleCloseAndDecode() {
  Fixture f(10, 1400, 20);
  f.tx.set_k(4);
  f.send(120, 0, 1);
  f.send(120, 10, 2);
  f.send(120, 20, 3);
  CHECK(f.tx.has_open_set());
  CHECK_EQ(f.tx.open_n(), 3);
  CHECK_EQ(f.tx.open_k(), 4);
  CHECK_EQ(f.tx.flush_timeout_ms(), 200);

  f.tx.on_tick(219);
  CHECK(f.tx.has_open_set());  // 199ms < T_flush
  f.tx.on_tick(220);
  CHECK(!f.tx.has_open_set());
  CHECK_EQ(f.tx.closed_idle(), 1u);
  CHECK_EQ(f.tx.closed_full(), 0u);

  CHECK_EQ(f.count_type(fcp::SymbolType::kData), 3u);
  CHECK_EQ(f.count_type(fcp::SymbolType::kParity), 2u);  // k_eff = ceil(4*3/10) = 2

  const fcp::TxSymbol& p0 = f.out[3];
  const fcp::TxSymbol& p1 = f.out[4];
  CHECK_EQ(p0.index, 3);
  CHECK_EQ(p1.index, 4);
  CHECK_EQ(p0.type_k, fcp::pack_type_k(4, 0, 1));
  CHECK_EQ(p1.type_k, fcp::pack_type_k(4, 1, 1));
  CHECK_EQ(p0.symbol.size(), 122u);  // symbol_max = 120 + len(2)

  // T17/T22: code length stays n + k = 7. Parity 2..3 were never sent
  // (ghost erasures); dropping two data symbols is still recoverable.
  const size_t symbol_max = 122;
  std::vector<std::vector<uint8_t>> padded(5, std::vector<uint8_t>(symbol_max, 0));
  for (size_t i = 0; i < 3; ++i) {
    std::memcpy(padded[i].data(), f.out[i].symbol.data(), f.out[i].symbol.size());
  }
  std::memcpy(padded[3].data(), p0.symbol.data(), p0.symbol.size());
  std::memcpy(padded[4].data(), p1.symbol.data(), p1.symbol.size());

  const uint8_t* symbols[7] = {padded[0].data(), nullptr, nullptr,
                               padded[3].data(), padded[4].data(), nullptr, nullptr};
  std::vector<std::vector<uint8_t>> recovered;
  CHECK(fcp::decode(symbols, 3, 4, symbol_max, &recovered));
  CHECK_EQ(recovered.size(), 3u);

  // Recovered data must match the original symbols (len prefix + payload).
  for (size_t i = 1; i < 3; ++i) {
    std::vector<uint8_t> expected(symbol_max, 0);
    expected[0] = 122;
    expected[1] = 0;
    const auto payload = Pattern(120, static_cast<uint8_t>(i + 1));
    std::memcpy(expected.data() + 2, payload.data(), payload.size());
    CHECK(recovered[i] == expected);
  }

  // Full groups keep k_eff == k.
  Fixture g(10, 1400, 20);
  g.tx.set_k(4);
  for (int i = 0; i < 10; ++i) {
    g.send(10, i);
  }
  CHECK_EQ(g.count_type(fcp::SymbolType::kParity), 4u);
}

void TestKEffScaling() {
  struct Case {
    uint8_t k;
    int n;
    uint8_t expected;
  };
  static const Case kCases[] = {
      {4, 1, 1}, {4, 2, 1}, {4, 3, 2}, {4, 7, 3}, {4, 10, 4},
      {3, 1, 1}, {3, 5, 2}, {3, 9, 3}, {3, 10, 3},
      {1, 1, 1},
  };
  for (const Case& c : kCases) {
    Fixture f(10, 1400, 20);
    f.tx.set_k(c.k);
    for (int i = 0; i < c.n; ++i) {
      f.send(40, i);
    }
    if (c.n < 10) {
      f.tx.on_tick(1000);
      CHECK_EQ(f.tx.closed_idle(), 1u);
    } else {
      CHECK_EQ(f.tx.closed_full(), 1u);
    }
    CHECK_EQ(f.count_type(fcp::SymbolType::kParity), c.expected);
  }
}

void TestZeroK() {
  Fixture f(10, 1400, 20);  // default k = 0
  for (int i = 0; i < 10; ++i) {
    f.send(30, i);
  }
  CHECK_EQ(f.out.size(), 10u);
  CHECK_EQ(f.count_type(fcp::SymbolType::kParity), 0u);
  CHECK_EQ(f.tx.closed_full(), 1u);

  Fixture g(10, 1400, 20);
  g.send(30, 0);
  g.send(30, 1);
  g.tx.on_tick(201);
  CHECK_EQ(g.out.size(), 2u);
  CHECK_EQ(g.count_type(fcp::SymbolType::kParity), 0u);
  CHECK_EQ(g.tx.closed_idle(), 1u);
}

void TestKcpOutputIsAlwaysData() {
  // Erratum #25: the KCP output path has no content classification. A segment
  // that happens to start with the HELLO magic is ordinary data (T23).
  Fixture f(10, 1400, 20);
  f.tx.set_k(2);

  uint8_t hello[fcp::kHelloLen];
  fcp::build_hello(fcp::HandshakeCaps{1, 10, 3, fcp::kLocalFlagsM1}, hello);
  const std::vector<uint8_t> hello_bytes(hello, hello + sizeof(hello));

  f.send_bytes(hello_bytes, 0);
  f.send_bytes(hello_bytes, 1);
  CHECK_EQ(f.out.size(), 2u);
  CHECK_EQ(f.tx.data_symbols(), 2u);
  CHECK(f.tx.has_open_set());
  CHECK_EQ(f.tx.set_id(), 0u);
  for (const auto& s : f.out) {
    CHECK_EQ(fcp::hdr_type(s.type_k), fcp::SymbolType::kData);
    CHECK_EQ(s.symbol.size(), hello_bytes.size() + 2);  // len(2) | payload
    CHECK_EQ(s.symbol[0], static_cast<uint8_t>((hello_bytes.size() + 2) & 0xFF));
    CHECK(std::memcmp(s.symbol.data() + 2, hello_bytes.data(), hello_bytes.size()) == 0);
  }

  // T14 (updated): oob never appears here; the set keeps filling at index 2.
  f.send(20, 2);
  const fcp::TxSymbol& data = f.out.back();
  CHECK_EQ(fcp::hdr_type(data.type_k), fcp::SymbolType::kData);
  CHECK_EQ(data.index, 2);
  CHECK_EQ(f.tx.open_n(), 3);
}

void TestFlushClock() {
  Fixture f(10, 1400, 20);
  f.tx.set_srtt_ms(10);
  CHECK_EQ(f.tx.flush_timeout_ms(), 25);
  f.tx.set_srtt_ms(100);
  CHECK_EQ(f.tx.flush_timeout_ms(), 100);
  f.tx.set_srtt_ms(5000);
  CHECK_EQ(f.tx.flush_timeout_ms(), 200);
  f.tx.set_srtt_ms(-5);
  CHECK_EQ(f.tx.flush_timeout_ms(), 25);

  // The clock restarts with every data segment.
  f.tx.set_srtt_ms(100);
  f.send(10, 0);
  f.send(10, 50);
  f.tx.on_tick(140);
  CHECK(f.tx.has_open_set());
  f.tx.on_tick(150);
  CHECK(!f.tx.has_open_set());
  CHECK_EQ(f.tx.closed_idle(), 1u);

  // A new segment arriving after a long gap flushes the stale set first.
  Fixture g(10, 1400, 20);
  g.tx.set_k(1);
  g.tx.set_srtt_ms(100);
  g.send(10, 0);
  g.send(10, 500);
  CHECK_EQ(g.out.size(), 3u);  // 1 data + 1 parity (idle) + 1 data
  CHECK_EQ(g.tx.closed_idle(), 1u);
  CHECK_EQ(g.out[1].set_id, 0u);
  CHECK_EQ(fcp::hdr_type(g.out[1].type_k), fcp::SymbolType::kParity);
  CHECK_EQ(g.out[2].set_id, 1u);
  CHECK_EQ(g.out[2].index, 0);
}

void TestAbort() {
  Fixture f(10, 1400, 20);
  f.tx.set_k(3);
  f.send(10, 0);
  f.send(10, 1);
  f.tx.abort();
  CHECK_EQ(f.tx.aborted_sets(), 1u);
  CHECK_EQ(f.tx.closed_full(), 0u);
  CHECK_EQ(f.tx.closed_idle(), 0u);
  CHECK_EQ(f.out.size(), 2u);  // no parity emitted
  CHECK(!f.tx.has_open_set());
  CHECK_EQ(f.tx.set_id(), 1u);

  f.tx.abort();  // nothing open
  CHECK_EQ(f.tx.aborted_sets(), 1u);

  f.send(10, 2);
  CHECK_EQ(f.out.back().set_id, 1u);
}

void TestMtuDrop() {
  Fixture f(10, 1400, 20);
  f.tx.set_k(1);
  f.send(f.limits.payload_max, 0);
  CHECK_EQ(f.tx.data_symbols(), 1u);
  CHECK_EQ(f.out.back().symbol.size(), f.limits.payload_max + 2);

  f.send(f.limits.payload_max + 1, 1);
  CHECK_EQ(f.tx.mtu_drops(), 1u);
  CHECK_EQ(f.tx.data_symbols(), 1u);
  CHECK_EQ(f.tx.open_n(), 1);

  // An empty payload is legal (symbol length 2).
  f.send(0, 2);
  CHECK_EQ(f.out.back().symbol.size(), 2u);
  CHECK_EQ(f.out.back().symbol[0], 2);
  CHECK_EQ(f.out.back().symbol[1], 0);
}

void TestHeaderPackRoundTrip() {
  Fixture f(10, 1400, 20);
  f.tx.set_k(4);
  f.send(50, 0);
  f.send(60, 1);
  f.tx.on_tick(201);

  for (const fcp::TxSymbol& s : f.out) {
    uint8_t raw[fcp::kFecHdrLen];
    fcp::pack_hdr(fcp::FecHdr{s.set_id, s.index, s.type_k}, raw);
    fcp::FecHdr parsed{};
    CHECK(fcp::parse_hdr(raw, sizeof(raw), &parsed));
    CHECK_EQ(parsed.set_id, s.set_id);
    CHECK_EQ(parsed.index, s.index);
    CHECK_EQ(parsed.type_k, s.type_k);
    CHECK_EQ(fcp::hdr_k(parsed.type_k), 4);
  }
}

}  // namespace

int main() {
  TestMtuLimits();
  TestFullClose();
  TestIdleCloseAndDecode();
  TestKEffScaling();
  TestZeroK();
  TestKcpOutputIsAlwaysData();
  TestFlushClock();
  TestAbort();
  TestMtuDrop();
  TestHeaderPackRoundTrip();
  return fcp_test::finish();
}
