// Operating-system CSPRNG access.
//
// Handshake nonces and the handshake envelope's starting counter are
// security-relevant: a predictable value there reintroduces exactly the
// cross-session (key, IV) reuse that #28① and R3-1 exist to prevent. The core
// library must therefore own the source instead of trusting the host's idea of
// "random"; this is that one implementation.
//
// Hosts not yet routed through it (left as-is, both are still OS-backed):
//   apps/fcp-proxy/engine.cc  random_salt()          std::random_device
//   tools/fcp_bench.cc        meet-greeting salt     std::random_device
//   apps/fcp-client/*         session salt / PSK      QRandomGenerator::system()
// Note `QRandomGenerator::system()` is a CSPRNG (unlike `global()`, which is a
// deterministic PRNG and must never be used for a nonce or a key).

#ifndef FCP_RANDOM_H_
#define FCP_RANDOM_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

// Fills out[0..len) from the OS CSPRNG. Returns false when the source is
// unavailable; callers must treat that as fatal rather than fall back to a
// weaker generator (a session with a guessable nonce is worse than no session).
bool random_bytes(void* out, size_t len);

// Convenience wrapper for a 32-bit draw. Returns 0 if the CSPRNG failed, so
// callers that need a non-zero value must check `random_bytes` themselves.
uint32_t random_u32();

}  // namespace fcp

#endif  // FCP_RANDOM_H_
