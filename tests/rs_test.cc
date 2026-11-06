#include "fcp/rs.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "test_util.h"

namespace {

using Symbols = std::vector<std::vector<uint8_t>>;

std::vector<const uint8_t*> ConstPointers(const Symbols& symbols,
                                          const std::vector<bool>& present) {
  std::vector<const uint8_t*> pointers(symbols.size(), nullptr);
  for (size_t i = 0; i < symbols.size(); ++i) {
    pointers[i] = present[i] ? symbols[i].data() : nullptr;
  }
  return pointers;
}

void TestGoldenParity() {
  const size_t n = 4;
  const size_t k = 2;
  const size_t symbol_max = 6;
  Symbols data = {
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
      {0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
      {0x20, 0x21, 0x22, 0x23, 0x24, 0x25},
      {0x30, 0x31, 0x32, 0x33, 0x34, 0x35},
  };
  Symbols parity(k, std::vector<uint8_t>(symbol_max));
  std::vector<const uint8_t*> data_ptr;
  for (const auto& symbol : data) {
    data_ptr.push_back(symbol.data());
  }
  std::vector<uint8_t*> parity_ptr;
  for (auto& symbol : parity) {
    parity_ptr.push_back(symbol.data());
  }
  fcp::encode(data_ptr.data(), n, k, symbol_max, parity_ptr.data());

  static const uint8_t kGolden[2][6] = {
      {0x08, 0x92, 0x21, 0xBB, 0x5A, 0xC0},
      {0x5D, 0xC7, 0x74, 0xEE, 0x0F, 0x95},
  };
  CHECK_EQ(fcp_test::hex(parity[0].data(), symbol_max),
           fcp_test::hex(kGolden[0], symbol_max));
  CHECK_EQ(fcp_test::hex(parity[1].data(), symbol_max),
           fcp_test::hex(kGolden[1], symbol_max));
}

void TestFuzzRecovery() {
  for (int iter = 0; iter < 300; ++iter) {
    const size_t n = 1 + fcp_test::rng()() % 10;
    const size_t k = 1 + fcp_test::rng()() % 5;  // k == 0 has no code to decode
    const size_t symbol_max = 1 + fcp_test::rng()() % 1400;

    Symbols data(n, std::vector<uint8_t>(symbol_max));
    for (auto& symbol : data) {
      for (auto& byte : symbol) {
        byte = fcp_test::random_byte();
      }
    }
    Symbols parity(k, std::vector<uint8_t>(symbol_max));
    std::vector<const uint8_t*> data_ptr;
    for (const auto& symbol : data) {
      data_ptr.push_back(symbol.data());
    }
    std::vector<uint8_t*> parity_ptr;
    for (auto& symbol : parity) {
      parity_ptr.push_back(symbol.data());
    }
    fcp::encode(data_ptr.data(), n, k, symbol_max, parity_ptr.data());

    Symbols all(data);
    all.insert(all.end(), parity.begin(), parity.end());
    std::vector<bool> present(n + k, true);

    std::vector<size_t> order(n + k);
    for (size_t i = 0; i < order.size(); ++i) {
      order[i] = i;
    }
    std::shuffle(order.begin(), order.end(), fcp_test::rng());
    const size_t drop = k == 0 ? 0 : fcp_test::rng()() % (k + 1);
    for (size_t i = 0; i < drop; ++i) {
      present[order[i]] = false;
    }

    const std::vector<const uint8_t*> pointers = ConstPointers(all, present);
    std::vector<std::vector<uint8_t>> recovered;
    const bool ok = fcp::decode(pointers.data(), n, k, symbol_max, &recovered);
    CHECK_EQ(ok, true);
    CHECK_EQ(recovered.size(), n);
    for (size_t i = 0; i < n; ++i) {
      if (present[i]) {
        CHECK(recovered[i].empty());
      } else {
        CHECK_EQ(recovered[i].size(), symbol_max);
        CHECK_EQ(fcp_test::hex(recovered[i].data(), symbol_max),
                 fcp_test::hex(data[i].data(), symbol_max));
      }
    }
  }
}

void TestGhostParity() {
  const size_t n = 3;
  const size_t k = 4;
  const size_t symbol_max = 8;
  Symbols data(n, std::vector<uint8_t>(symbol_max));
  for (auto& symbol : data) {
    for (auto& byte : symbol) {
      byte = fcp_test::random_byte();
    }
  }
  Symbols parity(k, std::vector<uint8_t>(symbol_max));
  std::vector<const uint8_t*> data_ptr;
  for (const auto& symbol : data) {
    data_ptr.push_back(symbol.data());
  }
  std::vector<uint8_t*> parity_ptr;
  for (auto& symbol : parity) {
    parity_ptr.push_back(symbol.data());
  }
  fcp::encode(data_ptr.data(), n, k, symbol_max, parity_ptr.data());

  // k_eff = 2: parity 2 and 3 were never sent (ghost erasures), and data 0/2 are lost.
  Symbols all(data);
  all.insert(all.end(), parity.begin(), parity.end());
  std::vector<bool> present(n + k, true);
  present[0] = false;
  present[2] = false;
  present[n + 2] = false;
  present[n + 3] = false;

  const std::vector<const uint8_t*> pointers = ConstPointers(all, present);
  std::vector<std::vector<uint8_t>> recovered;
  CHECK(fcp::decode(pointers.data(), n, k, symbol_max, &recovered));
  CHECK_EQ(fcp_test::hex(recovered[0].data(), symbol_max),
           fcp_test::hex(data[0].data(), symbol_max));
  CHECK_EQ(fcp_test::hex(recovered[2].data(), symbol_max),
           fcp_test::hex(data[2].data(), symbol_max));
}

void TestTooManyErasures() {
  const size_t n = 4;
  const size_t k = 2;
  const size_t symbol_max = 4;
  Symbols all(n + k, std::vector<uint8_t>(symbol_max, 0x5A));
  std::vector<bool> present(n + k, true);
  present[0] = false;
  present[1] = false;
  present[2] = false;
  const std::vector<const uint8_t*> pointers = ConstPointers(all, present);
  std::vector<std::vector<uint8_t>> recovered;
  CHECK(!fcp::decode(pointers.data(), n, k, symbol_max, &recovered));

  present[0] = false;
  present[1] = false;
  present[n] = false;
  present[n + 1] = false;
  const std::vector<const uint8_t*> no_parity = ConstPointers(all, present);
  CHECK(!fcp::decode(no_parity.data(), n, k, symbol_max, &recovered));

  // k == 0 is not a code, so the call fails instead of leaving the caller to
  // deal with a success whose output (resized to n) cannot be honoured.
  present.assign(all.size(), true);
  const std::vector<const uint8_t*> no_code = ConstPointers(all, present);
  std::vector<std::vector<uint8_t>> untouched(3);
  CHECK(!fcp::decode(no_code.data(), n, 0, symbol_max, &untouched));
  CHECK_EQ(untouched.size(), 3);
}

}  // namespace

int main() {
  TestGoldenParity();
  TestFuzzRecovery();
  TestGhostParity();
  TestTooManyErasures();
  return fcp_test::finish();
}
