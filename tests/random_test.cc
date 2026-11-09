// random.cc: the OS CSPRNG wrapper every nonce/salt/seed draw goes through.
//
// envelope_test covers the session-facing use (nonces are fresh and non-zero);
// this pins the API-level contract: length handling, buffer bounds, the null
// destination rejection, and that bulk draws are real draws rather than a
// constant.

#include "fcp/random.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "test_util.h"

namespace {

// random_bytes writes exactly len bytes: a buffer bracketed by sentinels must
// keep both bytes, and the filled range must not be an untouched zero block.
void TestWritesExactlyLen() {
  const size_t lens[] = {1, 4, 16, 64};
  for (size_t len : lens) {
    std::vector<uint8_t> buf(len + 2, 0xEE);
    // A CSPRNG may legitimately return an all-zero block on a single draw:
    // for len == 1 that happens with probability 1/256. Asserting "acc != 0"
    // on one draw is therefore a flaky gate (it red-blocked the v0.0.19
    // release coverage job). Accumulate over 8 fresh draws instead: a false
    // failure now needs 64+ consecutive zero bytes, i.e. 2^-64 for len == 1
    // and far less for the longer lengths. Every round re-checks both
    // sentinels so "writes exactly len bytes without overrun" stays pinned.
    uint8_t acc = 0;
    for (int round = 0; round < 8; ++round) {
      CHECK(fcp::random_bytes(buf.data() + 1, len));
      CHECK_EQ(buf.front(), static_cast<uint8_t>(0xEE));
      CHECK_EQ(buf.back(), static_cast<uint8_t>(0xEE));
      for (size_t i = 1; i <= len; ++i) {
        acc = static_cast<uint8_t>(acc | buf[i]);
      }
    }
    CHECK(acc != 0);
  }
}

void TestEmptyAndNull() {
  // len == 0 is a no-op success, even with a null pointer (nothing to write).
  CHECK(fcp::random_bytes(nullptr, 0));
  uint8_t byte = 0;
  CHECK(fcp::random_bytes(&byte, 0));
  // A null destination with a non-zero length is an argument error, not a
  // silent no-op.
  CHECK(!fcp::random_bytes(nullptr, 1));
  CHECK(!fcp::random_bytes(nullptr, 4096));
}

// Two draws of the same size must differ; a CSPRNG that repeated itself would
// make every nonce and salt in the protocol predictable.
void TestFreshDraws() {
  uint8_t a[64];
  uint8_t b[64];
  CHECK(fcp::random_bytes(a, sizeof(a)));
  CHECK(fcp::random_bytes(b, sizeof(b)));
  CHECK(std::memcmp(a, b, sizeof(a)) != 0);
}

// Bulk draws must not collapse onto one value; >= 900 distinct 32-bit values in
// 1000 keeps it deterministic while a broken generator (constant or 16-bit)
// fails hard. This used to go through a random_u32() wrapper that returned 0 on
// CSPRNG failure; that wrapper is gone (F-1) — the only contract is
// random_bytes, which fails loudly.
void TestBulkDraws() {
  std::vector<uint32_t> draws(1000);
  for (auto& v : draws) {
    CHECK(fcp::random_bytes(&v, sizeof(v)));
  }
  size_t distinct = 0;
  for (size_t i = 0; i < draws.size(); ++i) {
    bool seen = false;
    for (size_t j = 0; j < i; ++j) {
      if (draws[j] == draws[i]) {
        seen = true;
        break;
      }
    }
    if (!seen) {
      ++distinct;
    }
  }
  CHECK(distinct >= 900);
}

}  // namespace

int main() {
  TestWritesExactlyLen();
  TestEmptyAndNull();
  TestFreshDraws();
  TestBulkDraws();
  return fcp_test::finish();
}
