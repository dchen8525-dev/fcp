// Minimal hand-written test harness (same style as kcp-cpp: no third-party deps).

#ifndef FCP_TESTS_TEST_UTIL_H_
#define FCP_TESTS_TEST_UTIL_H_

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>

namespace fcp_test {

inline int& failures() {
  static int count = 0;
  return count;
}

inline void report_failure(const char* file, int line, const char* expr) {
  std::fprintf(stderr, "%s:%d CHECK failed: %s\n", file, line, expr);
  ++failures();
}

inline int finish() {
  if (failures() == 0) {
    std::printf("PASS\n");
    return 0;
  }
  std::fprintf(stderr, "FAILED: %d check(s)\n", failures());
  return 1;
}

inline std::string hex(const uint8_t* data, size_t len) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0x0F]);
  }
  return out;
}

inline std::mt19937& rng() {
  static std::mt19937 engine(0x5EED1234u);
  return engine;
}

inline uint8_t random_byte() {
  return static_cast<uint8_t>(rng()() & 0xFF);
}

}  // namespace fcp_test

#define CHECK(cond)                                            \
  do {                                                         \
    if (!(cond)) {                                             \
      ::fcp_test::report_failure(__FILE__, __LINE__, #cond);   \
    }                                                          \
  } while (0)

#define CHECK_EQ(actual, expected)                                   \
  do {                                                               \
    if (!((actual) == (expected))) {                                 \
      ::fcp_test::report_failure(__FILE__, __LINE__,                 \
                                 #actual " == " #expected);          \
    }                                                                \
  } while (0)

#define TEST_MAIN()          \
  int main() {               \
    return ::fcp_test::finish(); \
  }

#endif  // FCP_TESTS_TEST_UTIL_H_
