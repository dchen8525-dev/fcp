// #90: rebuild a connected IPv4 UDP socket without changing its local port.
//
// The server keys peers by IP:port (Reactor::addr_key), so a client that
// simply creates a fresh socket gets a new ephemeral port, looks like a new
// peer, and loses every in-flight session. The sequence below was verified on
// Winsock by build/wsa_port_reuse_probe.py (cases Y/Z): getsockname -> close
// -> socket -> bind(original address:port) -> connect -> send, with the peer
// observing the same source port. SO_REUSEADDR is not needed (UDP has no
// TIME_WAIT).
//
// Header-only and Windows-only on purpose: the reactor is not part of any
// library, so this is the only way to test the port-preserving invariant
// directly on the exact code the reactor calls. Linux keeps its original
// startup path untouched.

#ifndef FCP_PROXY_UDP_REBIND_H_
#define FCP_PROXY_UDP_REBIND_H_

#ifdef _WIN32

#include <string>
#include <winsock2.h>

namespace fcp {

// On success: the old socket is closed and *inout holds the replacement.
// On failure: *inout is left untouched and the candidate socket is closed, so
// the caller can retry from a consistent state. dont_fragment_ok reports
// whether IP_DONTFRAGMENT could be set (a fresh failure must not silently
// change the engine's one-shot PMTUD decision).
inline bool RebuildConnectedUdp(SOCKET* inout, const sockaddr_in& remote,
                                bool tune_buffers, bool dont_fragment,
                                bool* dont_fragment_ok, std::string* error) {
  if (dont_fragment_ok != nullptr) {
    *dont_fragment_ok = false;
  }
  if (inout == nullptr || *inout == INVALID_SOCKET) {
    *error = "udp socket already closed";
    return false;
  }
  sockaddr_in local{};
  int local_len = sizeof(local);
  if (::getsockname(*inout, reinterpret_cast<sockaddr*>(&local), &local_len) != 0) {
    *error = "getsockname: winsock error " + std::to_string(::WSAGetLastError());
    return false;
  }
  const SOCKET fresh = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fresh == INVALID_SOCKET) {
    *error = "socket: winsock error " + std::to_string(::WSAGetLastError());
    return false;
  }
  auto fail = [fresh, error](const char* what) {
    const int err = ::WSAGetLastError();
    *error = std::string(what) + ": winsock error " + std::to_string(err);
    ::closesocket(fresh);
    return false;
  };
  if (tune_buffers) {
    const int size = 7 * 1024 * 1024;
    ::setsockopt(fresh, SOL_SOCKET, SO_RCVBUF,
                 reinterpret_cast<const char*>(&size), sizeof(size));
    ::setsockopt(fresh, SOL_SOCKET, SO_SNDBUF,
                 reinterpret_cast<const char*>(&size), sizeof(size));
  }
  if (dont_fragment) {
#ifdef IP_DONTFRAGMENT
    const int on = 1;
    const bool ok = ::setsockopt(fresh, IPPROTO_IP, IP_DONTFRAGMENT,
                                 reinterpret_cast<const char*>(&on),
                                 sizeof(on)) == 0;
    if (dont_fragment_ok != nullptr) {
      *dont_fragment_ok = ok;
    }
#endif
  }
  // Preferred: the exact original local address. Fallback: the same port on
  // INADDR_ANY, for when a VPN/interface change made the old source IP vanish.
  // Both keep the port, which is the only part the server's peer key uses.
  if (::bind(fresh, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
    sockaddr_in any = local;
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    if (::bind(fresh, reinterpret_cast<sockaddr*>(&any), sizeof(any)) != 0) {
      return fail("bind original port");
    }
  }
  if (::connect(fresh, reinterpret_cast<const sockaddr*>(&remote),
                sizeof(sockaddr_in)) != 0) {
    return fail("connect");
  }
  u_long mode = 1;
  if (::ioctlsocket(fresh, FIONBIO, &mode) != 0) {
    return fail("nonblocking");
  }
  ::closesocket(*inout);
  *inout = fresh;
  return true;
}

}  // namespace fcp

#endif  // _WIN32
#endif  // FCP_PROXY_UDP_REBIND_H_
