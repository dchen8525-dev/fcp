// Minimal hand-written test harness (same style as kcp-cpp: no third-party deps).

#ifndef FCP_TESTS_TEST_UTIL_H_
#define FCP_TESTS_TEST_UTIL_H_

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ostream>
#include <random>
#include <sstream>
#include <string>
#include <type_traits>

namespace fcp_test {

inline int& failures() {
  static int count = 0;
  return count;
}

inline void report_failure(const char* file, int line, const char* expr) {
  std::fprintf(stderr, "%s:%d CHECK failed: %s\n", file, line, expr);
  ++failures();
}

// CHECK_EQ reports what it compared, not just the expression: on a threshold
// assertion ("expected >= 256 packets") the bare text "#actual == #expected"
// cannot tell a CI reader whether the run missed by one or by a factor of a
// hundred. Everything that prints is streamed generically, so any type with an
// operator<< works, and an enum without one falls back to its integer value.
// Narrow integer types are widened first: printing uint8_t through the generic
// path would emit a character, not a number.
template <typename T>
struct Fmt {
  const T& v;
};

template <typename T>
Fmt<T> fmt(const T& v) {
  return Fmt<T>{v};
}

template <typename T>
std::ostream& operator<<(std::ostream& os, const Fmt<T>& f) {
  if constexpr (std::is_enum_v<T>) {
    os << +static_cast<std::underlying_type_t<T>>(f.v);
  } else if constexpr (std::is_integral_v<T> && sizeof(T) == 1) {
    os << +f.v;
  } else {
    os << f.v;
  }
  return os;
}

inline void report_failure_values(const char* file, int line, const char* expr,
                                  const std::string& actual, const std::string& expected) {
  std::fprintf(stderr, "%s:%d CHECK failed: %s\n    actual:   %s\n    expected: %s\n", file,
               line, expr, actual.c_str(), expected.c_str());
  ++failures();
}

template <typename A, typename E>
void check_eq(const char* file, int line, const char* expr, const A& actual, const E& expected) {
  if (actual == expected) {
    return;
  }
  std::ostringstream a;
  std::ostringstream e;
  a << fmt(actual);
  e << fmt(expected);
  report_failure_values(file, line, expr, a.str(), e.str());
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

// Parses 2*len hex digits into out. Returns false on a short string or a
// non-hex digit, so a mistyped vector fails the test instead of silently
// comparing against half a buffer.
inline bool unhex(const char* text, uint8_t* out, size_t len) {
  if (text == nullptr || out == nullptr) {
    return false;
  }
  auto nibble = [](char c, uint8_t* v) {
    if (c >= '0' && c <= '9') {
      *v = static_cast<uint8_t>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      *v = static_cast<uint8_t>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      *v = static_cast<uint8_t>(c - 'A' + 10);
    } else {
      return false;
    }
    return true;
  };
  for (size_t i = 0; i < len; ++i) {
    uint8_t hi = 0;
    uint8_t lo = 0;
    if (!nibble(text[2 * i], &hi) || !nibble(text[2 * i + 1], &lo)) {
      return false;
    }
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
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

// 两侧都按值保存：`std::min/max` 返回的是实参的**引用**，而 `w0 + w0 / 4`
// 这类实参是临时量。先前的 `const auto&` 绑定只把临时量活到本语句结束，
// 下一句比较读到的是已析构的栈槽（Linux 上实测把 40960 读成 106，Windows
// 恰好还是旧值，所以只在 CI 红）。测试里拷贝几个 size_t/枚举可以忽略。
#define CHECK_EQ(actual, expected)                                                 \
  do {                                                                             \
    const auto check_eq_a = (actual);                                              \
    const auto check_eq_e = (expected);                                            \
    ::fcp_test::check_eq(__FILE__, __LINE__, #actual " == " #expected, check_eq_a, \
                         check_eq_e);                                              \
  } while (0)

#define TEST_MAIN()          \
  int main() {               \
    return ::fcp_test::finish(); \
  }

#endif  // FCP_TESTS_TEST_UTIL_H_
