#include "fcp/random.h"

#include <cstdio>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <bcrypt.h>
#else
#include <cerrno>
#endif

namespace fcp {

namespace {
// Test-only failure injection (see random.h). A plain bool: tests are
// single-threaded and the flag must not cost the real path anything.
bool g_inject_failure = false;
}  // namespace

void set_random_failure_injection(bool enabled) { g_inject_failure = enabled; }

bool random_bytes(void* out, size_t len) {
  if (g_inject_failure) {
    return false;
  }
  if (len == 0) {
    return true;
  }
  if (out == nullptr) {
    return false;
  }
#if defined(_WIN32)
  // BCRYPT_USE_SYSTEM_PREFERRED_RNG: no provider handle to open or close, and
  // the call is the same one the OS uses for its own keys. NTSTATUS 0 == OK.
  return BCryptGenRandom(nullptr, static_cast<PUCHAR>(out),
                         static_cast<ULONG>(len),
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
  // Portable POSIX source. Opening per call costs one fd for a handful of
  // calls per session (salt + nonce + counter seed), which is cheaper than
  // keeping a long-lived fd alive across a proxy restart.
  FILE* f = std::fopen("/dev/urandom", "rb");
  if (f == nullptr) {
    return false;
  }
  const size_t got = std::fread(out, 1, len, f);
  const bool closed = std::fclose(f) == 0;
  return got == len && closed;
#endif
}

void secure_zero(void* p, size_t len) {
  if (p == nullptr || len == 0) {
    return;
  }
#if defined(_WIN32)
  // Intrinsic-style inline in the SDK and documented as non-optimizable-away.
  SecureZeroMemory(p, len);
#else
  // Volatile byte stores: the compiler must keep them because the value can
  // be observed. Not formally guaranteed by the standard, but no mainstream
  // optimizer drops a volatile store through this shape, and this is the
  // spelling every non-Windows C library (BoringSSL's OPENSSL_cleanse and
  // friends) ships.
  volatile uint8_t* vp = static_cast<volatile uint8_t*>(p);
  while (len-- != 0) {
    *vp++ = 0;
  }
#endif
}

}  // namespace fcp
