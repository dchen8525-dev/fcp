// Operating-system CSPRNG access.
//
// Handshake nonces and the handshake envelope's starting counter are
// security-relevant: a predictable value there reintroduces exactly the
// cross-session (key, IV) reuse that #28① and R3-1 exist to prevent. The core
// library must therefore own the source instead of trusting the host's idea of
// "random"; this is that one implementation.
//
// Hosts not yet routed through it (left as-is, both are still OS-backed):
//   src/proxy/proxy_engine.cc random_salt()          std::random_device
//   tools/fcp-bench.cc        meet-greeting salt     std::random_device

#ifndef FCP_RANDOM_H_
#define FCP_RANDOM_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

// Fills out[0..len) from the OS CSPRNG. Returns false when the source is
// unavailable; callers must treat that as fatal rather than fall back to a
// weaker generator (a session with a guessable nonce is worse than no session).
//
// There is deliberately no "give me a uint32/uint64" convenience wrapper: the
// only sensible failure convention for a security-relevant draw is "stop", and
// a helper returning 0 would silently hand the caller exactly the predictable
// value the CSPRNG exists to avoid (F-1, 对抗分析报告-第四轮).
bool random_bytes(void* out, size_t len);

// Test-only: forces random_bytes to report the source as unavailable, so tests
// can prove callers fail loudly instead of degrading (第四轮 F-6：熵源失败时的
// 握手起点)。Not thread-safe, not part of the library contract, and never set
// by production code.
void set_random_failure_injection(bool enabled);

// Wipes len bytes at p in a way the compiler may not optimize away
// (SecureZeroMemory on Windows, a volatile byte store otherwise). Use it on
// key material leaving scope: expanded key schedules, derived direction keys,
// handshake nonces. It is deliberately one implementation here so the crypto
// paths cannot pick a weaker spelling (plain memset is dead-store-eliminable
// at scope exit, and a plaintext key in freed heap outlives the session).
void secure_zero(void* p, size_t len);

}  // namespace fcp

#endif  // FCP_RANDOM_H_
