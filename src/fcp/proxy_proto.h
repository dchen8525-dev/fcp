// Proxy entry codecs (docs/FCP_M2_PROXY.md §4).
//
// Pure functions over byte ranges: no sockets, no clocks, no buffers owned by
// this layer. The host (the CLI select reactor or the Qt adapter) accumulates
// what its local socket has handed it and calls the parse function again as
// more arrives, so every parser has to answer "need more" without consuming
// anything, and on success report the exact length of the message so the bytes
// that follow -- which already belong to the tunneled connection -- can be
// forwarded untouched.
//
// Everything parsed here comes from a local application or through the tunnel.
// Both are treated as hostile: no branch may read past the caller's buffer, and
// every rejected shape has to be expressible as one of the defined error
// replies.
//
// Byte order: multi-byte fields are network order (big endian), like RFC 1928.
// FCP-STREAM's own header is little endian; these are proxy-facing messages,
// and their ports have to stay comparable with what a SOCKS5 client puts on the
// wire.

#ifndef FCP_PROXY_PROTO_H_
#define FCP_PROXY_PROTO_H_

#include <cstddef>
#include <cstdint>
#include <string>

namespace fcp {

// Address types, shared by SOCKS5 and the tunnel OPEN frame. These are the wire
// values, which is what lets the client forward the application's choice without
// re-encoding it.
constexpr uint8_t kAtypIpv4 = 0x01;
constexpr uint8_t kAtypDomain = 0x03;
constexpr uint8_t kAtypIpv6 = 0x04;

// The target of a CONNECT, however it arrived.
struct ProxyTarget {
  uint8_t atyp = kAtypIpv4;
  // Raw address as the wire carries it: 4 bytes for kAtypIpv4, 16 for
  // kAtypIpv6, textual for kAtypDomain. std::string because the wire form is not
  // NUL-terminated, not because it is text.
  std::string addr;
  uint16_t port = 0;
};

bool atyp_valid(uint8_t atyp);

// Required address length for a numeric atyp; 0 for kAtypDomain, whose length is
// the explicit 1..255 field. Callers check atyp_valid() first.
size_t atyp_addr_len(uint8_t atyp);

// Log/connection-table form of a target. IPv6 gets eight colon-separated groups
// with no zero compression: valid text, just not the shortest, and it keeps this
// layer free of inet_ntop (and therefore of Winsock).
std::string target_text(const ProxyTarget& target);

// ---- SOCKS5, CONNECT only (RFC 1928) ----

constexpr uint8_t kSocks5Version = 0x05;
constexpr uint8_t kSocks5MethodNoAuth = 0x00;
constexpr uint8_t kSocks5MethodNone = 0xFF;  // greeting reply: nothing acceptable
constexpr uint8_t kSocks5CmdConnect = 0x01;
constexpr size_t kSocks5GreetingReplyLen = 2;
constexpr size_t kSocks5ReplyLen = 10;
// Both messages carry a one-byte domain length, so 255 is the ceiling for the
// address in either; the request adds the port. A host that has read past these
// and still has no complete message is talking to something that is not SOCKS5.
constexpr size_t kSocks5MaxDomainLen = 255;
constexpr size_t kSocks5MaxGreetingBytes = 2 + kSocks5MaxDomainLen;
constexpr size_t kSocks5MaxRequestBytes = 5 + kSocks5MaxDomainLen + 2;

// Reply field of the CONNECT response, RFC 1928 §6 verbatim.
enum class Socks5Rep : uint8_t {
  kSucceeded = 0x00,
  kGeneralFailure = 0x01,
  kNotAllowed = 0x02,
  kNetworkUnreachable = 0x03,
  kHostUnreachable = 0x04,
  kConnectionRefused = 0x05,
  kTtlExpired = 0x06,
  kCommandNotSupported = 0x07,
  kAtypNotSupported = 0x08,
};

enum class Socks5Parse {
  kOk = 0,
  kNeedMore,
  // Not a SOCKS5 client, or a field this subset does not allow (wrong version,
  // NMETHODS == 0, non-zero RSV, zero-length DOMAIN, port 0). The host replies
  // nothing and closes.
  kMalformed,
  kCommandNotSupported,
  kAtypNotSupported,
};

struct Socks5Greeting {
  bool no_auth = false;  // the client offered NO AUTH
};

// greeting: ver(1)=5 | nmeth(1) | methods(nmeth)
// `len` may be longer than the greeting (a client may cork it together with the
// request); only the message itself is examined.
Socks5Parse socks5_parse_greeting(const uint8_t* buf, size_t len, size_t* consumed,
                                 Socks5Greeting* out);

// reply: ver(1)=5 | method(1). Pass false to answer 0xFF (no acceptable method),
// after which the host closes.
size_t socks5_write_greeting_reply(uint8_t* out, size_t cap, bool accept_no_auth);

// request: ver(1)=5 | cmd(1) | rsv(1)=0 | atyp(1) | addr | port(2)
// On kOk, `*consumed` is the whole request; everything after it is the tunnel.
// `len` may already run past the request -- a client can write the first payload
// bytes immediately after it -- so only the first kSocks5MaxRequestBytes are
// examined, and a message longer than that cannot exist.
Socks5Parse socks5_parse_request(const uint8_t* buf, size_t len, size_t* consumed,
                                 ProxyTarget* out);

// response: ver | rep | rsv(0) | atyp=IPv4 | 0.0.0.0 | port 0. The bound address
// is a formality: this proxy never promises a real egress endpoint (§4.1).
size_t socks5_write_reply(uint8_t* out, size_t cap, Socks5Rep rep);

// ---- HTTP CONNECT ----

// Total head budget (request line plus headers), §4.2. A cap against a client
// that never sends the blank line, not a format limit -- real browsers send a
// few hundred bytes. Also the reason a host name longer than 255 is refused here
// rather than truncated: OPEN cannot carry it.
constexpr size_t kHttpHeadMaxBytes = 8192;
constexpr size_t kHttpMaxHostLen = 255;

enum class HttpParse {
  kOk = 0,
  kNeedMore,  // no CRLFCRLF yet, still under the cap
  kBadRequest,
  kMethodNotAllowed,
  kHeadTooLarge,
};

// The four bodies this proxy ever sends back on the HTTP listener. Nothing in
// them is built from peer input, so a reply cannot become a header-injection
// vector.
enum class HttpReply : uint16_t {
  kEstablished = 200,           // "HTTP/1.1 200 Connection Established"
  kBadRequest = 400,
  kMethodNotAllowed = 405,
  kRequestHeaderTooLarge = 431,
};

// Parses `CONNECT host:port HTTP/1.x` plus headers up to CRLFCRLF. The target is
// always kAtypDomain, including for an IP literal: resolution happens remotely
// (§4.3), and getaddrinfo() short-circuits on literals, so tunneling the text
// costs nothing and keeps this layer free of a hand-rolled inet_pton.
// Brackets around an IPv6 literal are stripped; the bare address is what the
// resolver needs.
HttpParse http_parse_connect(const uint8_t* buf, size_t len, size_t* consumed,
                             ProxyTarget* target);

size_t http_write_response(uint8_t* out, size_t cap, HttpReply reply);

// ---- FCP OPEN: the first bytes of the tunneled stream (not a framed message) ----

// OPEN     : "FCPO"(4) | ver(1)=1 | atyp(1) | len(1) | addr(len) | port(2)
// OPEN_OK  : "FCPO"(4) | ver(1)=1 | 0x01     | reserved(2)=0
// OPEN_ERR : "FCPO"(4) | ver(1)=1 | 0xFF     | code(1)
constexpr uint8_t kOpenVersion = 1;
constexpr uint8_t kOpenKindOk = 0x01;
constexpr uint8_t kOpenKindErr = 0xFF;
constexpr size_t kOpenMaxAddrLen = 255;
// OPEN_OK is magic | ver | kind | reserved(2) and OPEN_ERR is magic | ver | kind
// | code(1), so the two replies are 8 and 7 bytes -- asymmetric, but that is
// what §4.3 puts on the wire. The request's fixed part is 9 (magic | ver | atyp
// | len | port), plus the address, so 9 + 255 is the longest legal OPEN: the
// host stops accumulating past that if it still has no complete message.
constexpr size_t kOpenOkLen = 8;
constexpr size_t kOpenErrLen = 7;
constexpr size_t kOpenMaxBytes = 9 + kOpenMaxAddrLen;

enum class OpenError : uint8_t {
  kRefused = 1,        // policy
  kDns = 2,            // remote resolution failed
  kTargetTimeout = 3,  // dial or resolve timed out
  kNotSupported = 4,   // unknown atyp
  kTooManySessions = 5,
};

enum class OpenParse {
  kOk = 0,
  kNeedMore,
  kBadMagic,    // not FCP-OPEN at all
  kBadVersion,
  kBadAtyp,     // answer OPEN_ERR{kNotSupported}
  kBadAddress,  // len disagrees with atyp, is 0, or the port is 0
  kBadKind,     // reply byte is neither 0x01 nor 0xFF, or an unknown error code
  kBadReserved,  // OPEN_OK with non-zero reserved: defined as zero on the wire
};

// `len` may run past the message (the client can send payload bytes behind its
// OPEN); at most kOpenMaxBytes are examined. A buffer that starts with a byte
// other than 'F' is reported kBadMagic at once rather than waiting for four.
OpenParse open_parse_request(const uint8_t* buf, size_t len, size_t* consumed,
                             ProxyTarget* out);
// Returns the bytes written, or 0 when the target is not encodable (unknown atyp,
// wrong address length, empty or overlong domain, port 0) or cap is too small.
size_t open_write_request(uint8_t* out, size_t cap, const ProxyTarget& target);

// Reply direction. `*ok` is true for OPEN_OK; `err` only means something when it
// is false.
OpenParse open_parse_reply(const uint8_t* buf, size_t len, size_t* consumed, bool* ok,
                           OpenError* err);
size_t open_write_ok(uint8_t* out, size_t cap);
size_t open_write_err(uint8_t* out, size_t cap, OpenError err);

// How the client should answer its local socket when the server refused a
// tunnel. Kept here so the mapping is written once and tested.
Socks5Rep socks5_rep_for_open_error(OpenError err);

}  // namespace fcp

#endif  // FCP_PROXY_PROTO_H_
