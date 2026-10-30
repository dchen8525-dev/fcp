#include "fcp/proxy_proto.h"

#include <cstdio>
#include <cstring>

namespace fcp {
namespace {

constexpr size_t kMaxMessage = 1u << 20;

bool host_char_ok(uint8_t c) {
  if (c >= 'a' && c <= 'z') {
    return true;
  }
  if (c >= 'A' && c <= 'Z') {
    return true;
  }
  if (c >= '0' && c <= '9') {
    return true;
  }
  return c == '.' || c == '-' || c == '_';
}

// 1-65535 from ASCII digits; 0 on anything else, including an empty or
// overlong run and leading zeros are accepted (curl sends "0080" nowhere,
// but it is syntactically a digit run and means the same number).
bool parse_port(const uint8_t* p, size_t n, uint16_t* port) {
  if (n == 0 || n > 5) {
    return false;
  }
  unsigned value = 0;
  for (size_t i = 0; i < n; ++i) {
    if (p[i] < '0' || p[i] > '9') {
      return false;
    }
    value = value * 10u + (p[i] - '0');
  }
  if (value == 0u || value > 65535u) {
    return false;
  }
  *port = static_cast<uint16_t>(value);
  return true;
}

constexpr char kHttpOk[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
constexpr char kHttpBadRequest[] =
    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
constexpr char kHttpMethodNotAllowed[] =
    "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\n\r\n";
constexpr char kHttpHeadTooLarge[] =
    "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n";

bool write_bytes(uint8_t* out, size_t cap, const char* text) {
  const size_t n = std::strlen(text);
  if (n > cap) {
    return false;
  }
  std::memcpy(out, text, n);
  return true;
}

}  // namespace

bool atyp_valid(uint8_t atyp) {
  return atyp == kAtypIpv4 || atyp == kAtypDomain || atyp == kAtypIpv6;
}

size_t atyp_addr_len(uint8_t atyp) {
  if (atyp == kAtypIpv4) {
    return 4;
  }
  if (atyp == kAtypIpv6) {
    return 16;
  }
  return 0;  // kAtypDomain: the explicit length byte decides
}

std::string target_text(const ProxyTarget& target) {
  std::string out;
  char num[40];
  if (target.atyp == kAtypIpv4 && target.addr.size() == 4) {
    const uint8_t* b = reinterpret_cast<const uint8_t*>(target.addr.data());
    std::snprintf(num, sizeof(num), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    out = num;
  } else if (target.atyp == kAtypIpv6 && target.addr.size() == 16) {
    const uint8_t* b = reinterpret_cast<const uint8_t*>(target.addr.data());
    for (size_t i = 0; i < 16; i += 2) {
      if (i != 0) {
        out.push_back(':');
      }
      std::snprintf(num, sizeof(num), "%x", (b[i] << 8) | b[i + 1]);
      out += num;
    }
  } else if (target.atyp == kAtypDomain) {
    out = target.addr;
  } else {
    out = "?";
  }
  std::snprintf(num, sizeof(num), ":%u", target.port);
  out += num;
  return out;
}

Socks5Parse socks5_parse_greeting(const uint8_t* buf, size_t len, size_t* consumed,
                                  Socks5Greeting* out) {
  if (consumed != nullptr) {
    *consumed = 0;
  }
  if (buf == nullptr || len < 2 || len > kMaxMessage) {
    return Socks5Parse::kMalformed;
  }
  if (buf[0] != kSocks5Version) {
    return Socks5Parse::kMalformed;
  }
  const size_t nmethods = buf[1];
  if (nmethods == 0) {
    return Socks5Parse::kMalformed;
  }
  const size_t need = 2 + nmethods;
  if (len < need) {
    return Socks5Parse::kNeedMore;
  }
  bool no_auth = false;
  for (size_t i = 0; i < nmethods; ++i) {
    if (buf[2 + i] == kSocks5MethodNoAuth) {
      no_auth = true;
      break;
    }
  }
  if (consumed != nullptr) {
    *consumed = need;
  }
  if (out != nullptr) {
    out->no_auth = no_auth;
  }
  return Socks5Parse::kOk;
}

size_t socks5_write_greeting_reply(uint8_t* out, size_t cap, bool accept_no_auth) {
  if (out == nullptr || cap < kSocks5GreetingReplyLen) {
    return 0;
  }
  out[0] = kSocks5Version;
  out[1] = accept_no_auth ? kSocks5MethodNoAuth : kSocks5MethodNone;
  return kSocks5GreetingReplyLen;
}

Socks5Parse socks5_parse_request(const uint8_t* buf, size_t len, size_t* consumed,
                                 ProxyTarget* out) {
  if (consumed != nullptr) {
    *consumed = 0;
  }
  if (buf == nullptr || len < 4 || len > kMaxMessage) {
    return Socks5Parse::kMalformed;
  }
  if (buf[0] != kSocks5Version) {
    return Socks5Parse::kMalformed;
  }
  // Command and address type are answered with a reply instead of a close, so
  // they are checked before framing: an unknown ATYP has no address length and
  // cannot be framed at all.
  if (buf[1] != kSocks5CmdConnect) {
    return Socks5Parse::kCommandNotSupported;
  }
  const uint8_t atyp = buf[3];
  if (!atyp_valid(atyp)) {
    return Socks5Parse::kAtypNotSupported;
  }
  const size_t fixed = atyp_addr_len(atyp);
  size_t addr_len = fixed;
  size_t header = 4;  // ver | cmd | rsv | atyp, then the address
  if (atyp == kAtypDomain) {
    if (len < 5) {
      return Socks5Parse::kNeedMore;
    }
    addr_len = buf[4];
    header = 5;  // the length byte precedes the address
  }
  const size_t total = header + addr_len + 2;  // + port
  if (addr_len == 0 || len < total) {
    return Socks5Parse::kNeedMore;
  }
  size_t off = header;
  if (atyp == kAtypDomain) {
    // The domain itself has to be a host name. Checked after framing because the
    // framing only needs its length: an invalid byte is a protocol error, not a
    // short read.
    for (size_t i = 0; i < addr_len; ++i) {
      if (!host_char_ok(buf[off + i])) {
        return Socks5Parse::kMalformed;
      }
    }
  }
  const uint16_t port = static_cast<uint16_t>((buf[off + addr_len] << 8) |
                                              buf[off + addr_len + 1]);
  if (consumed != nullptr) {
    *consumed = total;
  }
  if (out != nullptr) {
    out->atyp = atyp;
    out->addr.assign(reinterpret_cast<const char*>(buf + off), addr_len);
    out->port = port;
  }
  return Socks5Parse::kOk;
}

size_t socks5_write_reply(uint8_t* out, size_t cap, Socks5Rep rep) {
  if (out == nullptr || cap < kSocks5ReplyLen) {
    return 0;
  }
  std::memset(out, 0, kSocks5ReplyLen);
  out[0] = kSocks5Version;
  out[1] = static_cast<uint8_t>(rep);
  out[3] = kAtypIpv4;  // BNDADDR is 0.0.0.0:0, which is an IPv4 literal
  return kSocks5ReplyLen;
}

HttpParse http_parse_connect(const uint8_t* buf, size_t len, size_t* consumed,
                             ProxyTarget* target) {
  if (consumed != nullptr) {
    *consumed = 0;
  }
  if (buf == nullptr) {
    return HttpParse::kBadRequest;
  }
  // Everything below 8 KiB is answered; a head that never ends is 431 once the
  // budget is spent. The buffer is still bounded by the caller, so the scan
  // itself cannot be made expensive by a peer.
  const bool capped = len >= kHttpHeadMaxBytes;
  const size_t win = capped ? kHttpHeadMaxBytes : len;
  const uint8_t* end = nullptr;
  const uint8_t found_crlfcrlf = find_head_end(buf, win, &end);
  if (!found_crlfcrlf) {
    return capped ? HttpParse::kHeadTooLarge : HttpParse::kNeedMore;
  }
  const size_t head_len = static_cast<size_t>(end - buf) + 4;
  const uint8_t* line_end = nullptr;
  if (!find_line_end(buf, head_len, &line_end)) {
    // CRLFCRLF exists, so the request line cannot be unterminated unless it is
    // empty; that is a bad request.
    return HttpParse::kBadRequest;
  }
  const size_t line_len = static_cast<size_t>(line_end - buf);
  const uint8_t* tok[4] = {nullptr, nullptr, nullptr, nullptr};
  size_t tok_len[4] = {0, 0, 0, 0};
  size_t nt = 0;
  size_t i = 0;
  while (i < line_len && nt < 4) {
    while (i < line_len && buf[i] == ' ') {
      ++i;
    }
    const size_t start = i;
    while (i < line_len && buf[i] != ' ') {
      ++i;
    }
    if (i == start) {
      break;
    }
    tok[nt] = buf + start;
    tok_len[nt] = i - start;
    ++nt;
  }
  if (nt != 3) {
    return HttpParse::kBadRequest;
  }
  if (tok_len[0] != 7 || std::memcmp(tok[0], "CONNECT", 7) != 0) {
    return HttpParse::kMethodNotAllowed;
  }
  if (tok_len[2] != 8 || std::memcmp(tok[2], "HTTP/1.0", 8) != 0) {
    return HttpParse::kBadRequest;
  }

  const uint8_t* auth = tok[1];
  size_t auth_len = tok_len[1];
  if (auth_len == 0 || auth_len > kHttpMaxHostLen + 6) {
    return HttpParse::kBadRequest;
  }
  std::string host;
  uint16_t port = 0;
  if (auth[0] == '[') {
    // Bracketed IPv6 literal: the colons inside are not the host/port split.
    const uint8_t* close = nullptr;
    for (size_t k = 0; k < auth_len; ++k) {
      if (auth[k] == ']') {
        close = auth + k;
        break;
      }
    }
    if (close == nullptr || close < auth + 2) {
      return HttpParse::kBadRequest;
    }
    host.assign(reinterpret_cast<const char*>(auth + 1),
                static_cast<size_t>(close - auth - 1));
    const uint8_t* sep = close + 1;
    const size_t rest = auth_len - static_cast<size_t>(sep - auth);
    if (rest != 0) {
      return HttpParse::kBadRequest;  // junk after the closing bracket
    }
    // An IPv6 literal without a port cannot be dialled: CONNECT has no default
    // port of its own (the scheme-less authority carries it).
    return HttpParse::kBadRequest;
  }
  const uint8_t* colon = nullptr;
  for (size_t k = 1; k + 1 < auth_len; ++k) {
    if (auth[k] == ':') {
      colon = auth + k;
      break;
    }
  }
  if (colon == nullptr) {
    return HttpParse::kBadRequest;  // CONNECT requires an explicit port
  }
  host.assign(reinterpret_cast<const char*>(auth), static_cast<size_t>(colon - auth));
  if (!parse_port(colon + 1, auth_len - static_cast<size_t>(colon - auth) - 1, &port)) {
    return HttpParse::kBadRequest;
  }
  if (host.empty() || host.size() > kHttpMaxHostLen) {
    return HttpParse::kBadRequest;
  }
  // A colon outside the bracketed form means an IPv6 literal that was not
  // bracketed; the tunnel could carry it as a domain and the resolver would
  // reject it, but refusing here keeps the log honest.
  for (size_t k = 0; k < host.size(); ++k) {
    if (!host_char_ok(static_cast<uint8_t>(host[k]))) {
      return HttpParse::kBadRequest;
    }
  }

  if (consumed != nullptr) {
    *consumed = head_len;
  }
  if (target != nullptr) {
    target->atyp = kAtypDomain;
    target->addr = host;
    target->port = port;
  }
  return HttpParse::kOk;
}

size_t http_write_response(uint8_t* out, size_t cap, HttpReply reply) {
  if (out == nullptr) {
    return 0;
  }
  switch (reply) {
    case HttpReply::kEstablished:
      return write_bytes(out, cap, kHttpOk) ? sizeof(kHttpOk) - 1 : 0;
    case HttpReply::kBadRequest:
      return write_bytes(out, cap, kHttpBadRequest) ? sizeof(kHttpBadRequest) - 1 : 0;
    case HttpReply::kMethodNotAllowed:
      return write_bytes(out, cap, kHttpMethodNotAllowed)
                 ? sizeof(kHttpMethodNotAllowed) - 1
                 : 0;
    case HttpReply::kRequestHeaderTooLarge:
      return write_bytes(out, cap, kHttpHeadTooLarge) ? sizeof(kHttpHeadTooLarge) - 1 : 0;
  }
  return 0;
}

OpenParse open_parse_request(const uint8_t* buf, size_t len, size_t* consumed,
                             ProxyTarget* out) {
  if (consumed != nullptr) {
    *consumed = 0;
  }
  if (buf == nullptr || len > kOpenMaxBytes) {
    return OpenParse::kBadMagic;
  }
  if (len < 4) {
    return OpenParse::kNeedMore;
  }
  if (std::memcmp(buf, "FCPO", 4) != 0) {
    return OpenParse::kBadMagic;
  }
  if (len < 7) {  // magic | ver | atyp | len
    return OpenParse::kNeedMore;
  }
  if (buf[4] != kOpenVersion) {
    return OpenParse::kBadVersion;
  }
  const uint8_t atyp = buf[5];
  if (!atyp_valid(atyp)) {
    return OpenParse::kBadAtyp;
  }
  const size_t addr_len = buf[6];
  if (addr_len == 0) {
    return OpenParse::kBadAddress;
  }
  const size_t fixed = atyp_addr_len(atyp);
  if (fixed != 0 && addr_len != fixed) {
    return OpenParse::kBadAddress;
  }
  const size_t total = 7 + addr_len + 2;
  if (len < total) {
    return OpenParse::kNeedMore;
  }
  if (consumed != nullptr) {
    *consumed = total;
  }
  if (out != nullptr) {
    out->atyp = atyp;
    out->addr.assign(reinterpret_cast<const char*>(buf + 7), addr_len);
    out->port = static_cast<uint16_t>((buf[7 + addr_len] << 8) | buf[8 + addr_len]);
  }
  return OpenParse::kOk;
}

size_t open_write_request(uint8_t* out, size_t cap, const ProxyTarget& target) {
  if (out == nullptr || !atyp_valid(target.atyp)) {
    return 0;
  }
  const size_t addr_len = target.addr.size();
  const size_t fixed = atyp_addr_len(target.atyp);
  if (addr_len == 0 || addr_len > kOpenMaxAddrLen) {
    return 0;
  }
  if (fixed != 0 && addr_len != fixed) {
    return 0;
  }
  const size_t total = 7 + addr_len + 2;
  if (cap < total) {
    return 0;
  }
  std::memcpy(out, "FCPO", 4);
  out[4] = kOpenVersion;
  out[5] = target.atyp;
  out[6] = static_cast<uint8_t>(addr_len);
  std::memcpy(out + 7, target.addr.data(), addr_len);
  out[7 + addr_len] = static_cast<uint8_t>(target.port >> 8);
  out[8 + addr_len] = static_cast<uint8_t>(target.port & 0xFFu);
  return total;
}

OpenParse open_parse_reply(const uint8_t* buf, size_t len, size_t* consumed, bool* ok,
                           OpenError* err) {
  if (consumed != nullptr) {
    *consumed = 0;
  }
  if (buf == nullptr) {
    return OpenParse::kBadMagic;
  }
  if (len < 7) {
    return OpenParse::kNeedMore;
  }
  if (std::memcmp(buf, "FCPO", 4) != 0) {
    return OpenParse::kBadMagic;
  }
  if (buf[4] != kOpenVersion) {
    return OpenParse::kBadVersion;
  }
  const uint8_t kind = buf[5];
  if (kind == kOpenKindOk) {
    if (len < kOpenOkLen) {
      return OpenParse::kNeedMore;
    }
    if (buf[7] != 0 || buf[8] != 0) {
      return OpenParse::kBadAddress;  // reserved must be zero, same rejection rule
    }
    if (consumed != nullptr) {
      *consumed = kOpenOkLen;
    }
    if (ok != nullptr) {
      *ok = true;
    }
    return OpenParse::kOk;
  }
  if (kind != kOpenKindErr) {
    return OpenParse::kBadKind;
  }
  if (len < kOpenErrLen) {
    return OpenParse::kNeedMore;
  }
  OpenError code = OpenError::kRefused;
  switch (buf[7]) {
    case 1:
      code = OpenError::kRefused;
      break;
    case 2:
      code = OpenError::kDns;
      break;
    case 3:
      code = OpenError::kTargetTimeout;
      break;
    case 4:
      code = OpenError::kNotSupported;
      break;
    case 5:
      code = OpenError::kTooManySessions;
      break;
    default:
      return OpenParse::kBadKind;
  }
  if (consumed != nullptr) {
    *consumed = kOpenErrLen;
  }
  if (ok != nullptr) {
    *ok = false;
  }
  if (err != nullptr) {
    *err = code;
  }
  return OpenParse::kOk;
}

size_t open_write_ok(uint8_t* out, size_t cap) {
  if (out == nullptr || cap < kOpenOkLen) {
    return 0;
  }
  std::memcpy(out, "FCPO", 4);
  out[4] = kOpenVersion;
  out[5] = kOpenKindOk;
  out[6] = 0;
  out[7] = 0;
  out[8] = 0;
  return kOpenOkLen;
}

size_t open_write_err(uint8_t* out, size_t cap, OpenError err) {
  if (out == nullptr || cap < kOpenErrLen) {
    return 0;
  }
  std::memcpy(out, "FCPO", 4);
  out[4] = kOpenVersion;
  out[5] = kOpenKindErr;
  out[6] = static_cast<uint8_t>(err);
  return kOpenErrLen;
}

Socks5Rep socks5_rep_for_open_error(OpenError err) {
  switch (err) {
    case OpenError::kRefused:
      return Socks5Rep::kConnectionRefused;
    case OpenError::kDns:
      return Socks5Rep::kHostUnreachable;
    case OpenError::kTargetTimeout:
      return Socks5Rep::kTtlExpired;
    case OpenError::kNotSupported:
      return Socks5Rep::kAtypNotSupported;
    case OpenError::kTooManySessions:
      return Socks5Rep::kNotAllowed;
  }
  return Socks5Rep::kGeneralFailure;
}

}  // namespace fcp
