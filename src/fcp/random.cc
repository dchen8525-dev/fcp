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

bool random_bytes(void* out, size_t len) {
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

uint32_t random_u32() {
  uint32_t value = 0;
  if (!random_bytes(&value, sizeof(value))) {
    return 0;
  }
  return value;
}

}  // namespace fcp
