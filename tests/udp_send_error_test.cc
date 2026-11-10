// #90: the UDP send-error classification is the only piece of socket recovery
// that is pure and platform-neutral, so it is also the only piece that can be
// unit-tested on both Windows and Linux CI. The descriptor swap itself lives
// in reactor.cc and is Windows-client only.
//
// Pin the contract: transient errors must stay invisible to the recovery
// state machine, EMSGSIZE must stay on the PMTUD path, and the "close the
// socket" class must be exactly the set that arms a rebuild. A code that
// drifts between classes either rebuilds on a normal full queue or silently
// drops keepalives again -- the latter is the bug this change fixes.

#include "udp_send_error.h"

#ifdef _WIN32
#include <string>
#include "udp_rebind.h"
#endif

#include "test_util.h"

namespace {

#ifdef _WIN32
constexpr int kTransientCodes[] = {WSAEWOULDBLOCK, WSAEINTR};
constexpr int kDeadCodes[] = {WSAEINVAL, WSAECONNRESET, WSAENETRESET,
                              WSAENOTSOCK, WSAESHUTDOWN, WSAENETDOWN,
                              WSAENOTCONN};
constexpr int kTooBigCode = WSAEMSGSIZE;
#else
constexpr int kTransientCodes[] = {EAGAIN, EINTR};
constexpr int kDeadCodes[] = {EINVAL, ECONNRESET, ENETRESET, ENOTSOCK,
                              EPIPE, ENETDOWN, ENOTCONN};
constexpr int kTooBigCode = EMSGSIZE;
#endif

using fcp::ClassifyUdpSendError;
using fcp::UdpSendVerdict;

void TestTransientIsNotAnErrorToRecover() {
  for (int err : kTransientCodes) {
    CHECK(ClassifyUdpSendError(err) == UdpSendVerdict::kTransient);
    CHECK(!(ClassifyUdpSendError(err) == UdpSendVerdict::kSocketDead));
  }
}

void TestPathTooBigKeepsPmtudPath() {
  CHECK(ClassifyUdpSendError(kTooBigCode) == UdpSendVerdict::kPathTooBig);
  CHECK(!(ClassifyUdpSendError(kTooBigCode) == UdpSendVerdict::kSocketDead));
}

void TestSocketDeadArmsRebuild() {
  for (int err : kDeadCodes) {
    CHECK(ClassifyUdpSendError(err) == UdpSendVerdict::kSocketDead);
  }
}

void TestUnknownStaysOnLegacyPath() {
  CHECK(ClassifyUdpSendError(0) == UdpSendVerdict::kOther);
  CHECK(ClassifyUdpSendError(999999) == UdpSendVerdict::kOther);
  CHECK(ClassifyUdpSendError(-1) == UdpSendVerdict::kOther);
}

// The four verdicts are a partition: every code above must land in exactly
// one class, and the classes must be distinguishable by value (the reactor
// switches on them, so a duplicated enumerator would silently merge paths).
void TestVerdictsAreDistinct() {
  CHECK(!(UdpSendVerdict::kTransient == UdpSendVerdict::kPathTooBig));
  CHECK(!(UdpSendVerdict::kTransient == UdpSendVerdict::kSocketDead));
  CHECK(!(UdpSendVerdict::kTransient == UdpSendVerdict::kOther));
  CHECK(!(UdpSendVerdict::kPathTooBig == UdpSendVerdict::kSocketDead));
  CHECK(!(UdpSendVerdict::kPathTooBig == UdpSendVerdict::kOther));
  CHECK(!(UdpSendVerdict::kSocketDead == UdpSendVerdict::kOther));
}

#ifdef _WIN32
// The server keys peers by IP:port, so a changed local port silently turns a
// recovering client into a brand-new peer and loses every session. This test
// runs the exact function Reactor::rebuild_udp_socket() calls, and is
// deliberately timing-free: UDP connect() needs no live peer and getsockname()
// is synchronous, so there is no recv/sleep to go flaky. Data delivery after
// the rebind is covered by build/wsa_port_reuse_probe.py (cases Y/Z).
void TestRebindPreservesLocalPort() {
  WSADATA wsa{};
  CHECK(::WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
  sockaddr_in remote{};
  remote.sin_family = AF_INET;
  remote.sin_port = htons(9);  // discard; UDP connect() needs no listener
  remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  CHECK(s != INVALID_SOCKET);
  CHECK(::connect(s, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) == 0);

  sockaddr_in before{};
  int len = sizeof(before);
  CHECK(::getsockname(s, reinterpret_cast<sockaddr*>(&before), &len) == 0);
  CHECK(before.sin_port != 0);

  std::string error;
  bool df_ok = false;
  CHECK(fcp::RebuildConnectedUdp(&s, remote, /*tune_buffers=*/false,
                                 /*dont_fragment=*/false, &df_ok, &error));
  CHECK(s != INVALID_SOCKET);
  sockaddr_in after{};
  len = sizeof(after);
  CHECK(::getsockname(s, reinterpret_cast<sockaddr*>(&after), &len) == 0);
  CHECK(after.sin_port == before.sin_port);
  CHECK(after.sin_family == AF_INET);
  ::closesocket(s);

  // A bad input must fail loudly without touching the caller's descriptor.
  SOCKET bad = INVALID_SOCKET;
  std::string bad_error;
  CHECK(!fcp::RebuildConnectedUdp(&bad, remote, false, false, nullptr, &bad_error));
  CHECK(!bad_error.empty());
  CHECK(bad == INVALID_SOCKET);
  ::WSACleanup();
}
#endif

}  // namespace

int main() {
  TestTransientIsNotAnErrorToRecover();
  TestPathTooBigKeepsPmtudPath();
  TestSocketDeadArmsRebuild();
  TestUnknownStaysOnLegacyPath();
  TestVerdictsAreDistinct();
#ifdef _WIN32
  TestRebindPreservesLocalPort();
#endif
  return fcp_test::finish();
}
