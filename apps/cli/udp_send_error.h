// Classification of a failed send()/sendto() on the FCP UDP tunnel socket.
//
// Before #90 every non-EMSGSIZE error was handled identically by
// note_udp_send_error(): count it, log once per second, drop the datagram. That
// is safe for a transient kernel refusal, but a descriptor that Winsock has
// put into an unusable state never recovers -- every later send() fails too,
// including the NAT keepalive / liveness probe that shares this very path. The
// server then sees 135 s of silence and tears down every session at once.
//
// This header is deliberately platform-neutral and header-only: the reactor is
// not part of any library, so a free function here is the only piece of the
// recovery decision that tests on both Windows and Linux CI can link directly.
// The descriptor swap itself stays in reactor.cc and is Windows-client only.

#ifndef FCP_PROXY_UDP_SEND_ERROR_H_
#define FCP_PROXY_UDP_SEND_ERROR_H_

#ifdef _WIN32
#include <winsock2.h>
#else
#include <cerrno>
#endif

namespace fcp {

enum class UdpSendVerdict {
  kTransient,   // kernel queue full / interrupted; engine retries next tick
  kPathTooBig,  // EMSGSIZE: authoritative path-MTU evidence
  kSocketDead,  // descriptor no longer usable; rebuild it
  kOther,       // counted and logged, datagram dropped (legacy behaviour)
};

inline UdpSendVerdict ClassifyUdpSendError(int err) {
#ifdef _WIN32
  switch (err) {
    case WSAEWOULDBLOCK:
    case WSAEINTR:
      return UdpSendVerdict::kTransient;
    case WSAEMSGSIZE:
      return UdpSendVerdict::kPathTooBig;
    // WSAEINVAL (10022) is the code seen in the production GUI logs
    // (fcp-client-11576 / 18896 / 22632). MSDN lists "socket not bound /
    // unknown flag / MSG_OOB with SO_OOBINLINE" for send(), none of which this
    // reactor ever does -- so on a connected UDP socket it means the handle is
    // no longer usable. The rest are the other documented "close the socket"
    // class errors; WSAECONNRESET on UDP is an ICMP port-unreachable reply.
    case WSAEINVAL:
    case WSAECONNRESET:
    case WSAENETRESET:
    case WSAENOTSOCK:
    case WSAESHUTDOWN:
    case WSAENETDOWN:
    case WSAENOTCONN:
      return UdpSendVerdict::kSocketDead;
    default:
      return UdpSendVerdict::kOther;
  }
#else
  switch (err) {
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case EINTR:
      return UdpSendVerdict::kTransient;
    case EMSGSIZE:
      return UdpSendVerdict::kPathTooBig;
    case EINVAL:
    case ECONNRESET:
    case ENETRESET:
    case ENOTSOCK:
    case EPIPE:
    case ENETDOWN:
    case ENOTCONN:
      return UdpSendVerdict::kSocketDead;
    default:
      return UdpSendVerdict::kOther;
  }
#endif
}

}  // namespace fcp

#endif  // FCP_PROXY_UDP_SEND_ERROR_H_
