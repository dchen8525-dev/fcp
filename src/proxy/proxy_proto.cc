#include "proxy/proxy_proto.h"

#include <cstdio>
#include <cstring>

#include "fcp/wire.h"

namespace fcp {
namespace {

// The OPEN magic. It is compared against a partial window on purpose: a short
// read must be able to say "not FCPO yet", so the parsers pass a length of
// their own and the writers copy the whole thing.
constexpr char kOpenMagic[4] = {'F', 'C', 'P', 'O'};
constexpr size_t kOpenMagicLen = sizeof(kOpenMagic);

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

// Accepted inside brackets, where the text is an address rather than a name:
// hex digits and colons, plus dots for an IPv4-mapped literal. Nothing else
// parses as an address, and this layer never resolves -- it only refuses
// obviously bogus text so the log and the tunnel carry something dialable.
bool ipv6_char_ok(uint8_t c) {
  if (c >= '0' && c <= '9') {
    return true;
  }
  if (c >= 'a' && c <= 'f') {
    return true;
  }
  if (c >= 'A' && c <= 'F') {
    return true;
  }
  return c == ':' || c == '.';
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
    value = value * 10u + static_cast<unsigned>(p[i] - '0');
  }
  if (value == 0u || value > 65535u) {
    return false;
  }
  *port = static_cast<uint16_t>(value);
  return true;
}

// Position of the blank line that ends an HTTP head. `*end` is the offset of the
// first CR of the CRLFCRLF, so the head is `*end + 4` bytes long.
bool find_head_end(const uint8_t* buf, size_t win, size_t* end) {
  if (win < 4) {
    return false;
  }
  for (size_t i = 0; i + 4 <= win; ++i) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
      *end = i;
      return true;
    }
  }
  return false;
}

// Position of the CRLF that ends the request line, i.e. the offset of its CR.
// Only CRLF counts: a bare LF is not a line ending here, and the head has to
// have a request line before the blank line that was already found.
bool find_line_end(const uint8_t* buf, size_t win, size_t* line_end) {
  if (win < 2) {
    return false;
  }
  for (size_t i = 0; i + 2 <= win; ++i) {
    if (buf[i] == '\r' && buf[i + 1] == '\n') {
      *line_end = i;
      return true;
    }
  }
  return false;
}

constexpr char kHttpOk[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
constexpr char kHttpBadRequest[] =
    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
constexpr char kHttpMethodNotAllowed[] =
    "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\n\r\n";
constexpr char kHttpHeadTooLarge[] =
    "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n";
constexpr char kHttpBadGateway[] =
    "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
// The forward listener relays methods as well as CONNECT, so its 405 lists the
// methods it would have accepted instead of claiming CONNECT-only.
constexpr char kHttpForwardMethodNotAllowed[] =
    "HTTP/1.1 405 Method Not Allowed\r\n"
    "Allow: CONNECT, GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH\r\n"
    "Connection: close\r\n\r\n";

bool write_bytes(uint8_t* out, size_t cap, const char* text) {
  const size_t n = std::strlen(text);
  if (n > cap) {
    return false;
  }
  std::memcpy(out, text, n);
  return true;
}

// RFC 7230 token characters for header names. A name that is not a token is
// refused instead of being copied into the rewritten head.
bool tchar_ok(uint8_t c) {
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
    return true;
  }
  switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
    case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
      return true;
    default:
      return false;
  }
}

std::string lower_copy(const uint8_t* p, size_t n) {
  std::string s(reinterpret_cast<const char*>(p), n);
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] >= 'A' && s[i] <= 'Z') {
      s[i] = static_cast<char>(s[i] - 'A' + 'a');
    }
  }
  return s;
}

bool ascii_ieq(const uint8_t* p, size_t n, const char* lit, size_t lit_len) {
  if (n != lit_len) {
    return false;
  }
  for (size_t i = 0; i < n; ++i) {
    uint8_t c = p[i];
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<uint8_t>(c - 'A' + 'a');
    }
    const uint8_t l = static_cast<uint8_t>(lit[i]);
    if (c != l) {
      return false;
    }
  }
  return true;
}

// Splits a request line into at most four space-separated tokens. Leading
// spaces are noise, and >3 tokens is a bad request -- the same rule the CONNECT
// parser has always applied, now shared with the forward parser.
void split_request_line(const uint8_t* buf, size_t line_len, const uint8_t* tok[4],
                        size_t tok_len[4], size_t* nt) {
  size_t i = 0;
  size_t n = 0;
  while (i < line_len && n < 4) {
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
    tok[n] = buf + start;
    tok_len[n] = i - start;
    ++n;
  }
  *nt = n;
}

bool http_version_ok(const uint8_t* p, size_t n) {
  return n == 8 && std::memcmp(p, "HTTP/1.", 7) == 0 && (p[7] == '0' || p[7] == '1');
}

bool forward_method_ok(const uint8_t* p, size_t n) {
  static const char* const kMethods[] = {"GET",     "HEAD",  "POST",   "PUT",
                                         "DELETE",  "OPTIONS", "PATCH"};
  for (const char* m : kMethods) {
    const size_t len = std::strlen(m);
    if (n == len && std::memcmp(p, m, len) == 0) {
      return true;
    }
  }
  return false;
}

// Parses an authority (`host`, `host:port`, `[v6]` or `[v6]:port`) into the
// text the remote resolver needs and the effective port. Used for the URL's
// authority and for the Host header, so the two can be compared in the same
// shape instead of as raw strings. Userinfo, control bytes and non-ASCII are
// refused: this text ends up in a DNS lookup and in a request head.
bool parse_authority(const uint8_t* p, size_t n, uint16_t default_port,
                     std::string* host, uint16_t* port) {
  if (n == 0) {
    return false;
  }
  for (size_t i = 0; i < n; ++i) {
    if (p[i] == '@' || p[i] < 0x21 || p[i] > 0x7e) {
      return false;
    }
  }
  const bool bracketed = p[0] == '[';
  size_t host_begin = 0;
  size_t host_end = n;
  if (bracketed) {
    size_t close = 0;
    for (size_t k = 1; k < n; ++k) {
      if (p[k] == ']') {
        close = k;
        break;
      }
    }
    if (close < 2) {
      return false;  // no "]", or an empty address
    }
    host_begin = 1;
    host_end = close;
    if (close + 1 < n) {
      if (p[close + 1] != ':') {
        return false;
      }
      if (!parse_port(p + close + 2, n - close - 2, port)) {
        return false;
      }
    } else {
      *port = default_port;
    }
  } else {
    size_t colon = n;
    for (size_t k = 0; k < n; ++k) {
      if (p[k] == ':') {
        if (colon != n) {
          return false;  // bare IPv6 literal, bracket it
        }
        colon = k;
      }
    }
    if (colon != n) {
      host_end = colon;
      if (!parse_port(p + colon + 1, n - colon - 1, port)) {
        return false;
      }
    } else {
      *port = default_port;
    }
  }
  if (host_end <= host_begin || host_end - host_begin > kHttpMaxHostLen) {
    return false;
  }
  for (size_t i = host_begin; i < host_end; ++i) {
    const uint8_t c = p[i];
    if (bracketed ? !ipv6_char_ok(c) : !host_char_ok(c)) {
      return false;
    }
  }
  host->assign(reinterpret_cast<const char*>(p + host_begin), host_end - host_begin);
  return true;
}

// Header lines collected before the rewrite. The Connection header can appear
// anywhere, so the hop-by-hop drop list is only complete after every line has
// been read; filtering therefore happens in a second pass.
struct HeaderLine {
  const uint8_t* begin = nullptr;
  size_t len = 0;
  std::string name;  // lower-case
};

bool header_value_ok(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if ((p[i] < 0x20 && p[i] != '\t') || p[i] == 0x7f) {
      return false;
    }
  }
  return true;
}

void collect_hops(const uint8_t* p, size_t n, std::vector<std::string>* hops) {
  size_t i = 0;
  while (i < n) {
    while (i < n && (p[i] == ' ' || p[i] == '\t' || p[i] == ',')) {
      ++i;
    }
    const size_t start = i;
    while (i < n && p[i] != ',') {
      ++i;
    }
    size_t end = i;
    while (end > start && (p[end - 1] == ' ' || p[end - 1] == '\t')) {
      --end;
    }
    if (end > start) {
      hops->push_back(lower_copy(p + start, end - start));
    }
  }
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
    std::snprintf(num, sizeof(num), "%u.%u.%u.%u", static_cast<unsigned>(b[0]),
                  static_cast<unsigned>(b[1]), static_cast<unsigned>(b[2]),
                  static_cast<unsigned>(b[3]));
    out = num;
  } else if (target.atyp == kAtypIpv6 && target.addr.size() == 16) {
    const uint8_t* b = reinterpret_cast<const uint8_t*>(target.addr.data());
    for (size_t i = 0; i < 16; i += 2) {
      if (i != 0) {
        out.push_back(':');
      }
      std::snprintf(num, sizeof(num), "%x",
                    static_cast<unsigned>((b[i] << 8) | b[i + 1]));
      out += num;
    }
  } else if (target.atyp == kAtypDomain) {
    out = target.addr;
  } else {
    out = "?";
  }
  std::snprintf(num, sizeof(num), ":%u", static_cast<unsigned>(target.port));
  out += num;
  return out;
}

Socks5Parse socks5_parse_greeting(const uint8_t* buf, size_t len, size_t* consumed,
                                  Socks5Greeting* out) {
  if (consumed != nullptr) {
    *consumed = 0;
  }
  if (buf == nullptr || len == 0) {
    return Socks5Parse::kNeedMore;
  }
  if (buf[0] != kSocks5Version) {
    return Socks5Parse::kMalformed;
  }
  if (len < 2) {
    return Socks5Parse::kNeedMore;
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
  if (buf == nullptr || len == 0) {
    return Socks5Parse::kNeedMore;
  }
  // A complete request is at most this long, so bytes past it are already the
  // tunnel and must not make a valid message look malformed.
  const size_t win = len > kSocks5MaxRequestBytes ? kSocks5MaxRequestBytes : len;
  if (buf[0] != kSocks5Version) {
    return Socks5Parse::kMalformed;
  }
  if (win < 4) {
    return Socks5Parse::kNeedMore;
  }
  // Command and address type are answered with a reply instead of a close, so
  // they are checked before framing: an unknown ATYP has no address length and
  // cannot be framed at all.
  if (buf[1] != kSocks5CmdConnect) {
    return Socks5Parse::kCommandNotSupported;
  }
  if (buf[2] != 0) {
    return Socks5Parse::kMalformed;  // RSV is defined as X'00'
  }
  const uint8_t atyp = buf[3];
  if (!atyp_valid(atyp)) {
    return Socks5Parse::kAtypNotSupported;
  }
  const size_t fixed = atyp_addr_len(atyp);
  size_t addr_len = fixed;
  size_t header = 4;  // ver | cmd | rsv | atyp, then the address
  if (atyp == kAtypDomain) {
    if (win < 5) {
      return Socks5Parse::kNeedMore;
    }
    addr_len = buf[4];
    header = 5;  // the length byte precedes the address
    if (addr_len == 0) {
      return Socks5Parse::kMalformed;  // an empty domain is not short, it is wrong
    }
  }
  const size_t total = header + addr_len + 2;  // + port
  if (win < total) {
    return Socks5Parse::kNeedMore;
  }
  const size_t off = header;
  if (atyp == kAtypDomain) {
    // The domain itself has to be a host name. Checked after framing because the
    // framing only needs its length: an invalid byte is a protocol error, not a
    // short read. A numeric address gets no such check -- the tunnel carries the
    // raw 4 or 16 bytes and the far end dials it without parsing.
    for (size_t i = 0; i < addr_len; ++i) {
      if (!host_char_ok(buf[off + i])) {
        return Socks5Parse::kMalformed;
      }
    }
  }
  const uint16_t port = get_be16(buf + off + addr_len);
  if (port == 0) {
    return Socks5Parse::kMalformed;  // CONNECT to port 0 cannot be dialled
  }
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
  // budget is spent. The scan window is the budget even when the caller has read
  // more, because a head longer than the budget is a rejection either way.
  const bool capped = len >= kHttpHeadMaxBytes;
  const size_t win = capped ? kHttpHeadMaxBytes : len;
  size_t blank = 0;
  if (!find_head_end(buf, win, &blank)) {
    return capped ? HttpParse::kHeadTooLarge : HttpParse::kNeedMore;
  }
  const size_t head_len = blank + 4;
  size_t line_len = 0;
  // The window is the whole head, not up to the blank line: a request with no
  // headers ends at the very CRLF that starts that blank line.
  if (!find_line_end(buf, head_len, &line_len) || line_len > blank) {
    return HttpParse::kBadRequest;
  }
  const uint8_t* tok[4] = {nullptr, nullptr, nullptr, nullptr};
  size_t tok_len[4] = {0, 0, 0, 0};
  size_t nt = 0;
  split_request_line(buf, line_len, tok, tok_len, &nt);
  if (nt != 3) {
    return HttpParse::kBadRequest;
  }
  if (tok_len[0] != 7 || std::memcmp(tok[0], "CONNECT", 7) != 0) {
    return HttpParse::kMethodNotAllowed;
  }
  if (!http_version_ok(tok[2], tok_len[2])) {
    return HttpParse::kBadRequest;
  }

  const uint8_t* auth = tok[1];
  const size_t auth_len = tok_len[1];
  // Host plus ":port": the length byte in OPEN caps the host at 255 and the port
  // is five digits and a colon. Refusing here beats truncating later.
  if (auth_len == 0 || auth_len > kHttpMaxHostLen + 6) {
    return HttpParse::kBadRequest;
  }
  std::string host;
  uint16_t port = 0;
  const uint8_t* sep = nullptr;  // the colon that starts the port
  bool bracketed = false;
  if (auth[0] == '[') {
    // Bracketed IPv6 literal: every colon before the closing bracket belongs to
    // the address, so the split is the colon that follows it.
    const uint8_t* close = nullptr;
    for (size_t k = 1; k < auth_len; ++k) {
      if (auth[k] == ']') {
        close = auth + k;
        break;
      }
    }
    if (close == nullptr || close == auth + 1 || close + 2 >= auth + auth_len ||
        close[1] != ':') {
      return HttpParse::kBadRequest;  // no "]", empty address, or no "]:"
    }
    sep = close + 1;
    host.assign(reinterpret_cast<const char*>(auth + 1),
                static_cast<size_t>(close - auth - 1));
    bracketed = true;
  } else {
    for (size_t k = 1; k + 1 < auth_len; ++k) {
      if (auth[k] == ':') {
        sep = auth + k;
        break;
      }
    }
    if (sep == nullptr) {
      return HttpParse::kBadRequest;  // CONNECT requires an explicit port
    }
    host.assign(reinterpret_cast<const char*>(auth), static_cast<size_t>(sep - auth));
  }
  if (!parse_port(sep + 1, auth_len - static_cast<size_t>(sep - auth) - 1, &port)) {
    return HttpParse::kBadRequest;
  }
  if (host.empty() || host.size() > kHttpMaxHostLen) {
    return HttpParse::kBadRequest;
  }
  // A colon outside the bracketed form means an IPv6 literal that was not
  // bracketed; the tunnel could carry it as a domain and the resolver would
  // reject it, but refusing here keeps the log honest.
  for (size_t k = 0; k < host.size(); ++k) {
    const uint8_t c = static_cast<uint8_t>(host[k]);
    if (bracketed ? !ipv6_char_ok(c) : !host_char_ok(c)) {
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

HttpParse http_parse_forward(const uint8_t* buf, size_t len, size_t* consumed,
                             HttpForward* out) {
  if (consumed != nullptr) {
    *consumed = 0;
  }
  if (buf == nullptr) {
    return HttpParse::kBadRequest;
  }
  // The same head budget and short-read rules as CONNECT. The host only calls
  // this after http_parse_connect() reported a non-CONNECT method, but the
  // parser still answers for itself so it stays testable in isolation.
  const bool capped = len >= kHttpHeadMaxBytes;
  const size_t win = capped ? kHttpHeadMaxBytes : len;
  size_t blank = 0;
  if (!find_head_end(buf, win, &blank)) {
    return capped ? HttpParse::kHeadTooLarge : HttpParse::kNeedMore;
  }
  const size_t head_len = blank + 4;
  size_t line_len = 0;
  if (!find_line_end(buf, head_len, &line_len) || line_len > blank) {
    return HttpParse::kBadRequest;
  }
  const uint8_t* tok[4] = {nullptr, nullptr, nullptr, nullptr};
  size_t tok_len[4] = {0, 0, 0, 0};
  size_t nt = 0;
  split_request_line(buf, line_len, tok, tok_len, &nt);
  if (nt != 3) {
    return HttpParse::kBadRequest;
  }
  if (!forward_method_ok(tok[0], tok_len[0])) {
    return HttpParse::kMethodNotAllowed;
  }
  if (!http_version_ok(tok[2], tok_len[2])) {
    return HttpParse::kBadRequest;
  }

  // The request-target has to be absolute-form http://authority/path. An
  // `https://` URL deliberately falls out as kBadRequest: this proxy never
  // originates TLS, and that shape is what CONNECT exists for.
  const uint8_t* uri = tok[1];
  const size_t uri_len = tok_len[1];
  if (uri_len < 7 || !ascii_ieq(uri, 7, "http://", 7)) {
    return HttpParse::kBadRequest;
  }
  size_t auth_end = 7;
  while (auth_end < uri_len && uri[auth_end] != '/' && uri[auth_end] != '?' &&
         uri[auth_end] != '#') {
    ++auth_end;
  }
  const uint8_t* authority = uri + 7;
  const size_t authority_len = auth_end - 7;
  std::string host;
  uint16_t port = 0;
  if (!parse_authority(authority, authority_len, kHttpForwardDefaultPort, &host, &port)) {
    return HttpParse::kBadRequest;
  }
  size_t path_end = uri_len;
  for (size_t i = auth_end; i < uri_len; ++i) {
    if (uri[i] == '#') {  // a fragment is never sent to a server
      path_end = i;
      break;
    }
  }
  const uint8_t* path = uri + auth_end;
  const size_t path_len = path_end - auth_end;
  std::string origin_target;
  if (path_len == 0) {
    origin_target = "/";
  } else if (path[0] == '/') {
    origin_target.assign(reinterpret_cast<const char*>(path), path_len);
  } else if (path[0] == '?') {
    origin_target = "/";
    origin_target.append(reinterpret_cast<const char*>(path), path_len);
  } else {
    return HttpParse::kBadRequest;
  }
  for (size_t i = 0; i < origin_target.size(); ++i) {
    const uint8_t c = static_cast<uint8_t>(origin_target[i]);
    if (c < 0x21 || c > 0x7e) {
      return HttpParse::kBadRequest;  // no control bytes, no raw non-ASCII
    }
  }

  // First pass: collect every header line, the Host value and the hop-by-hop
  // names listed in Connection. The Connection header may appear anywhere, so
  // the drop list is only complete once every line has been seen.
  std::vector<HeaderLine> lines;
  std::vector<std::string> hops;
  std::string host_value;
  bool have_host = false;
  size_t pos = line_len + 2;
  while (pos < blank) {
    // The last header line's CRLF is the first half of the CRLFCRLF that ends
    // the head, so it sits at `blank`, outside this window. A line that runs to
    // `blank` without a CRLF is that last line, not a malformed one.
    size_t cr = pos;
    while (cr + 1 < blank && !(buf[cr] == '\r' && buf[cr + 1] == '\n')) {
      ++cr;
    }
    const bool has_crlf = cr + 1 < blank && buf[cr] == '\r' && buf[cr + 1] == '\n';
    const size_t line_size = has_crlf ? cr - pos : blank - pos;
    const uint8_t* line = buf + pos;
    pos = has_crlf ? cr + 2 : blank;
    if (line_size == 0 || line[0] == ' ' || line[0] == '\t') {
      return HttpParse::kBadRequest;  // empty line or obs-fold
    }
    size_t colon = 0;
    while (colon < line_size && line[colon] != ':') {
      ++colon;
    }
    if (colon == 0 || colon == line_size) {
      return HttpParse::kBadRequest;
    }
    for (size_t i = 0; i < colon; ++i) {
      if (!tchar_ok(line[i])) {
        return HttpParse::kBadRequest;
      }
    }
    size_t vbegin = colon + 1;
    size_t vend = line_size;
    while (vbegin < vend && (line[vbegin] == ' ' || line[vbegin] == '\t')) {
      ++vbegin;
    }
    while (vend > vbegin && (line[vend - 1] == ' ' || line[vend - 1] == '\t')) {
      --vend;
    }
    const uint8_t* value = line + vbegin;
    const size_t value_len = vend - vbegin;
    if (!header_value_ok(value, value_len)) {
      return HttpParse::kBadRequest;
    }
    const std::string name = lower_copy(line, colon);
    if (name == "host") {
      if (have_host) {
        return HttpParse::kBadRequest;  // ambiguous Host
      }
      have_host = true;
      host_value.assign(reinterpret_cast<const char*>(value), value_len);
    } else if (name == "connection") {
      collect_hops(value, value_len, &hops);
    }
    lines.push_back(HeaderLine{line, line_size, name});
  }

  // Host must name exactly the URL's authority. Silently rewriting a
  // disagreeing Host would let a local application address one server through
  // another one's connection (request smuggling), so refusing is the only safe
  // answer. A missing Host (HTTP/1.0) is filled from the URL.
  if (have_host) {
    std::string hh;
    uint16_t hp = 0;
    if (!parse_authority(reinterpret_cast<const uint8_t*>(host_value.data()),
                         host_value.size(), kHttpForwardDefaultPort, &hh, &hp) ||
        lower_copy(reinterpret_cast<const uint8_t*>(hh.data()), hh.size()) !=
            lower_copy(reinterpret_cast<const uint8_t*>(host.data()), host.size()) ||
        hp != port) {
      return HttpParse::kBadRequest;
    }
  } else {
    host_value.assign(reinterpret_cast<const char*>(authority), authority_len);
  }

  // Second pass: rewrite. Drop hop-by-hop and proxy-specific headers, keep
  // everything else byte-for-byte. Transfer-Encoding and Content-Length are
  // deliberately kept even if a Connection token names them: this proxy never
  // decodes a body, so dropping either would corrupt a chunked upload.
  std::string head;
  head.append(reinterpret_cast<const char*>(tok[0]), tok_len[0]);
  head += ' ';
  head += origin_target;
  head += ' ';
  head.append(reinterpret_cast<const char*>(tok[2]), tok_len[2]);
  head += "\r\n";
  for (const HeaderLine& l : lines) {
    bool drop = l.name == "connection" || l.name == "host" ||
               l.name == "upgrade" || l.name == "keep-alive" || l.name == "te" ||
               l.name == "trailer" || l.name.compare(0, 6, "proxy-") == 0;
    if (!drop && l.name != "transfer-encoding" && l.name != "content-length") {
      for (const std::string& h : hops) {
        if (h == l.name) {
          drop = true;
          break;
        }
      }
    }
    if (drop) {
      continue;
    }
    head.append(reinterpret_cast<const char*>(l.begin), l.len);
    head += "\r\n";
  }
  head += "Host: ";
  head += host_value;
  // One local connection carries exactly one request: force the target to close
  // when it is done, so its FIN is what ends the exchange (§3, §4.2).
  head += "\r\nConnection: close\r\n\r\n";

  if (consumed != nullptr) {
    *consumed = head_len;
  }
  if (out != nullptr) {
    out->target.atyp = kAtypDomain;
    out->target.addr = host;
    out->target.port = port;
    out->head.assign(head.begin(), head.end());
  }
  return HttpParse::kOk;
}

size_t http_write_response(uint8_t* out, size_t cap, HttpReply reply) {
  if (out == nullptr) {
    return 0;
  }
  // Explicit chain: the two 405 replies are distinct tags, and keeping the
  // mapping here (rather than in each caller) is what makes the Allow header
  // match the listener that produced the refusal.
  if (reply == HttpReply::kEstablished) {
    return write_bytes(out, cap, kHttpOk) ? sizeof(kHttpOk) - 1 : 0;
  }
  if (reply == HttpReply::kBadRequest) {
    return write_bytes(out, cap, kHttpBadRequest) ? sizeof(kHttpBadRequest) - 1 : 0;
  }
  if (reply == HttpReply::kMethodNotAllowed) {
    return write_bytes(out, cap, kHttpMethodNotAllowed)
               ? sizeof(kHttpMethodNotAllowed) - 1
               : 0;
  }
  if (reply == HttpReply::kForwardMethodNotAllowed) {
    return write_bytes(out, cap, kHttpForwardMethodNotAllowed)
               ? sizeof(kHttpForwardMethodNotAllowed) - 1
               : 0;
  }
  if (reply == HttpReply::kRequestHeaderTooLarge) {
    return write_bytes(out, cap, kHttpHeadTooLarge) ? sizeof(kHttpHeadTooLarge) - 1 : 0;
  }
  if (reply == HttpReply::kBadGateway) {
    return write_bytes(out, cap, kHttpBadGateway) ? sizeof(kHttpBadGateway) - 1 : 0;
  }
  return 0;
}

OpenParse open_parse_request(const uint8_t* buf, size_t len, size_t* consumed,
                             ProxyTarget* out) {
  if (consumed != nullptr) {
    *consumed = 0;
  }
  if (buf == nullptr || len == 0) {
    return OpenParse::kNeedMore;
  }
  // Past the longest possible OPEN the extra bytes are payload, so the message
  // is looked for in the first kOpenMaxBytes only.
  const size_t win = len > kOpenMaxBytes ? kOpenMaxBytes : len;
  // Fail fast: one byte that is not 'F' can never become the magic.
  const size_t magic_len = win < 4 ? win : 4;
  if (std::memcmp(buf, kOpenMagic, magic_len) != 0) {
    return OpenParse::kBadMagic;
  }
  if (win < 7) {  // magic | ver | atyp | len
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
  if (win < total) {
    return OpenParse::kNeedMore;
  }
  if (atyp == kAtypDomain) {
    // Same rule as the SOCKS5 entry: a domain the far end will hand to
    // getaddrinfo has to be a host name. Without it a peer could smuggle CR/LF
    // or ANSI escapes into audit logs and drive pointless DNS lookups (B-13).
    for (size_t i = 0; i < addr_len; ++i) {
      if (!host_char_ok(buf[7 + i])) {
        return OpenParse::kBadAddress;
      }
    }
  }
  const uint16_t port = get_be16(buf + 7 + addr_len);
  if (port == 0) {
    return OpenParse::kBadAddress;  // nothing to dial
  }
  if (consumed != nullptr) {
    *consumed = total;
  }
  if (out != nullptr) {
    out->atyp = atyp;
    out->addr.assign(reinterpret_cast<const char*>(buf + 7), addr_len);
    out->port = port;
  }
  return OpenParse::kOk;
}

size_t open_write_request(uint8_t* out, size_t cap, const ProxyTarget& target) {
  if (out == nullptr || !atyp_valid(target.atyp) || target.port == 0) {
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
  std::memcpy(out, kOpenMagic, kOpenMagicLen);
  out[4] = kOpenVersion;
  out[5] = target.atyp;
  out[6] = static_cast<uint8_t>(addr_len);
  std::memcpy(out + 7, target.addr.data(), addr_len);
  put_be16(target.port, out + 7 + addr_len);
  return total;
}

OpenParse open_parse_reply(const uint8_t* buf, size_t len, size_t* consumed, bool* ok,
                           OpenError* err) {
  if (consumed != nullptr) {
    *consumed = 0;
  }
  if (buf == nullptr || len == 0) {
    return OpenParse::kNeedMore;
  }
  const size_t magic_len = len < 4 ? len : 4;
  if (std::memcmp(buf, kOpenMagic, magic_len) != 0) {
    return OpenParse::kBadMagic;
  }
  if (len < 6) {  // magic | ver | kind
    return OpenParse::kNeedMore;
  }
  if (buf[4] != kOpenVersion) {
    return OpenParse::kBadVersion;
  }
  const uint8_t kind = buf[5];
  if (kind == kOpenKindOk) {
    if (len < kOpenOkLen) {
      return OpenParse::kNeedMore;
    }
    if (buf[6] != 0 || buf[7] != 0) {
      return OpenParse::kBadReserved;
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
  switch (buf[6]) {
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
      return OpenParse::kBadKind;  // 0 and 6+ are not defined codes
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
  std::memcpy(out, kOpenMagic, kOpenMagicLen);
  out[4] = kOpenVersion;
  out[5] = kOpenKindOk;
  out[6] = 0;
  out[7] = 0;
  return kOpenOkLen;
}

size_t open_write_err(uint8_t* out, size_t cap, OpenError err) {
  if (out == nullptr || cap < kOpenErrLen) {
    return 0;
  }
  std::memcpy(out, kOpenMagic, kOpenMagicLen);
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
