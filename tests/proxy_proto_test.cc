// Proxy entry codec tests (M2代理设计.md §4, task #20 / line T31).
//
// Nothing here touches a socket: each case hands the codec a byte range and
// checks the verdict, the exact consumed length, and the wire bytes written.
// The consumed length matters as much as the parse itself -- a proxy that eats
// one byte of the tunneled stream corrupts the connection it just opened. Every
// message is also fed back one byte at a time, so no branch can mistake a short
// read for a protocol error or read past the buffer.

#include "proxy/proxy_proto.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "test_util.h"

namespace {

using fcp::HttpParse;
using fcp::HttpReply;
using fcp::OpenError;
using fcp::OpenParse;
using fcp::ProxyTarget;
using fcp::Socks5Greeting;
using fcp::Socks5Parse;
using fcp::Socks5Rep;

std::vector<uint8_t> raw(const std::string& s) {
  std::vector<uint8_t> out;
  out.reserve(s.size());
  for (char c : s) {
    out.push_back(static_cast<uint8_t>(c));
  }
  return out;
}

std::string text(const std::vector<uint8_t>& v) { return std::string(v.begin(), v.end()); }

const uint8_t* ptr(const std::vector<uint8_t>& v) { return v.data(); }

std::vector<uint8_t> v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return std::vector<uint8_t>{a, b, c, d};
}

std::vector<uint8_t> v6loopback() {
  std::vector<uint8_t> b(16, 0);
  b[15] = 1;
  return b;
}

// ver | cmd | rsv | atyp [| domlen] | addr | port(be16)
std::vector<uint8_t> socks5_request(uint8_t cmd, uint8_t rsv, uint8_t atyp,
                                    const std::vector<uint8_t>& addr, uint16_t port) {
  std::vector<uint8_t> b;
  b.push_back(0x05);
  b.push_back(cmd);
  b.push_back(rsv);
  b.push_back(atyp);
  if (atyp == fcp::kAtypDomain) {
    b.push_back(static_cast<uint8_t>(addr.size()));
  }
  b.insert(b.end(), addr.begin(), addr.end());
  b.push_back(static_cast<uint8_t>(port >> 8));
  b.push_back(static_cast<uint8_t>(port & 0xFFu));
  return b;
}

std::vector<uint8_t> open_request_bytes(const ProxyTarget& t) {
  uint8_t buf[fcp::kOpenMaxBytes];
  const size_t n = fcp::open_write_request(buf, sizeof(buf), t);
  return std::vector<uint8_t>(buf, buf + n);
}

ProxyTarget domain_target(const std::string& addr, uint16_t port) {
  ProxyTarget t;
  t.atyp = fcp::kAtypDomain;
  t.addr = addr;
  t.port = port;
  return t;
}

// ---- SOCKS5 ----

void TestAtypHelpers() {
  CHECK(fcp::atyp_valid(fcp::kAtypIpv4));
  CHECK(fcp::atyp_valid(fcp::kAtypDomain));
  CHECK(fcp::atyp_valid(fcp::kAtypIpv6));
  CHECK(!fcp::atyp_valid(0x00));
  CHECK(!fcp::atyp_valid(0x02));  // the address type RFC 1928 withdrew
  CHECK(!fcp::atyp_valid(0x05));
  CHECK(!fcp::atyp_valid(0xFF));
  CHECK_EQ(fcp::atyp_addr_len(fcp::kAtypIpv4), 4u);
  CHECK_EQ(fcp::atyp_addr_len(fcp::kAtypIpv6), 16u);
  CHECK_EQ(fcp::atyp_addr_len(fcp::kAtypDomain), 0u);  // the length byte decides
}

void TestSocks5Greeting() {
  size_t consumed = 12345;
  Socks5Greeting g;
  std::vector<uint8_t> nothing;
  CHECK(fcp::socks5_parse_greeting(nullptr, 0, &consumed, &g) == Socks5Parse::kNeedMore);
  CHECK_EQ(consumed, 0u);
  std::vector<uint8_t> one_byte{0x05};
  // One byte is a short read, not a wrong protocol: the host keeps accumulating.
  CHECK(fcp::socks5_parse_greeting(ptr(one_byte), one_byte.size(), &consumed, &g) ==
        Socks5Parse::kNeedMore);

  std::vector<uint8_t> offers{0x05, 0x02, 0x02, 0x00};
  CHECK(fcp::socks5_parse_greeting(ptr(offers), offers.size(), &consumed, &g) == Socks5Parse::kOk);
  CHECK_EQ(consumed, offers.size());
  CHECK(g.no_auth);  // GSS-API first, NO AUTH second: still accepted

  std::vector<uint8_t> no_auth{0x05, 0x01, 0x02};
  CHECK(fcp::socks5_parse_greeting(ptr(no_auth), no_auth.size(), &consumed, &g) ==
        Socks5Parse::kOk);
  CHECK(!g.no_auth);
  CHECK_EQ(consumed, 3u);

  // Truncated method list: the count outruns the buffer.
  std::vector<uint8_t> short_list{0x05, 0x03, 0x00};
  CHECK(fcp::socks5_parse_greeting(ptr(short_list), short_list.size(), &consumed, &g) ==
        Socks5Parse::kNeedMore);
  CHECK_EQ(consumed, 0u);

  // The longest list the count byte can carry.
  std::vector<uint8_t> big(257, 0x0A);
  big[0] = 0x05;
  big[1] = 0xFF;
  big[256] = 0x00;
  CHECK(fcp::socks5_parse_greeting(ptr(big), big.size(), &consumed, &g) == Socks5Parse::kOk);
  CHECK_EQ(consumed, 257u);
  CHECK(g.no_auth);

  // A client may cork the greeting and the request into one write; the greeting
  // parse must claim only its three bytes.
  std::vector<uint8_t> corked{0x05, 0x01, 0x00};
  const std::vector<uint8_t> req = socks5_request(0x01, 0x00, fcp::kAtypIpv4, v4(1, 2, 3, 4), 80);
  corked.insert(corked.end(), req.begin(), req.end());
  CHECK(fcp::socks5_parse_greeting(ptr(corked), corked.size(), &consumed, &g) == Socks5Parse::kOk);
  CHECK_EQ(consumed, 3u);

  std::vector<uint8_t> socks4{0x04, 0x01, 0x00};
  CHECK(fcp::socks5_parse_greeting(ptr(socks4), socks4.size(), &consumed, &g) ==
        Socks5Parse::kMalformed);
  std::vector<uint8_t> zero_methods{0x05, 0x00};
  CHECK(fcp::socks5_parse_greeting(ptr(zero_methods), zero_methods.size(), &consumed, &g) ==
        Socks5Parse::kMalformed);
  std::vector<uint8_t> http = raw("GET / HTTP/1.1\r\n");
  CHECK(fcp::socks5_parse_greeting(ptr(http), http.size(), &consumed, &g) ==
        Socks5Parse::kMalformed);

  uint8_t out[8] = {0};
  CHECK_EQ(fcp::socks5_write_greeting_reply(out, sizeof(out), true), fcp::kSocks5GreetingReplyLen);
  CHECK_EQ(out[0], 0x05);
  CHECK_EQ(out[1], 0x00);
  CHECK_EQ(fcp::socks5_write_greeting_reply(out, sizeof(out), false), fcp::kSocks5GreetingReplyLen);
  CHECK_EQ(out[1], 0xFF);
  CHECK_EQ(fcp::socks5_write_greeting_reply(out, 1, true), 0u);
  CHECK_EQ(fcp::socks5_write_greeting_reply(nullptr, 8, true), 0u);
}

void TestSocks5RequestIpv4() {
  const std::vector<uint8_t> msg =
      socks5_request(0x01, 0x00, fcp::kAtypIpv4, v4(93, 184, 216, 34), 8080);
  CHECK_EQ(msg.size(), 10u);
  size_t consumed = 0;
  ProxyTarget t;
  CHECK(fcp::socks5_parse_request(ptr(msg), msg.size(), &consumed, &t) == Socks5Parse::kOk);
  CHECK_EQ(consumed, msg.size());
  CHECK_EQ(t.atyp, fcp::kAtypIpv4);
  CHECK_EQ(t.addr.size(), 4u);
  CHECK_EQ(static_cast<uint8_t>(t.addr[0]), 93);
  CHECK_EQ(static_cast<uint8_t>(t.addr[3]), 34);
  CHECK_EQ(t.port, 8080);  // network order on the wire

  // Payload that follows belongs to the tunnel, not to the request.
  std::vector<uint8_t> corked = msg;
  const std::vector<uint8_t> payload = raw("hello");
  corked.insert(corked.end(), payload.begin(), payload.end());
  CHECK(fcp::socks5_parse_request(ptr(corked), corked.size(), &consumed, &t) == Socks5Parse::kOk);
  CHECK_EQ(consumed, msg.size());

  for (size_t n = 0; n < msg.size(); ++n) {
    consumed = 99;
    CHECK(fcp::socks5_parse_request(ptr(msg), n, &consumed, &t) == Socks5Parse::kNeedMore);
    CHECK_EQ(consumed, 0u);
  }
}

void TestSocks5RequestDomain() {
  const std::vector<uint8_t> name = raw("example.com");
  const std::vector<uint8_t> msg = socks5_request(0x01, 0x00, fcp::kAtypDomain, name, 443);
  size_t consumed = 0;
  ProxyTarget t;
  CHECK(fcp::socks5_parse_request(ptr(msg), msg.size(), &consumed, &t) == Socks5Parse::kOk);
  CHECK_EQ(consumed, msg.size());
  CHECK_EQ(t.atyp, fcp::kAtypDomain);
  CHECK_EQ(t.addr, std::string("example.com"));
  CHECK_EQ(t.port, 443);

  // The longest domain the length byte can carry, in a buffer that runs past it.
  const std::vector<uint8_t> max_name(255, 'a');
  const std::vector<uint8_t> max_msg = socks5_request(0x01, 0x00, fcp::kAtypDomain, max_name, 22);
  CHECK_EQ(max_msg.size(), fcp::kSocks5MaxRequestBytes);
  std::vector<uint8_t> padded = max_msg;
  padded.resize(max_msg.size() + 4096, 'Z');
  CHECK(fcp::socks5_parse_request(ptr(padded), padded.size(), &consumed, &t) == Socks5Parse::kOk);
  CHECK_EQ(consumed, max_msg.size());
  CHECK_EQ(t.addr.size(), 255u);
  CHECK_EQ(t.port, 22);

  // Labels the far end could not resolve, and the two ways the framing can lie.
  for (const std::string& bad : {std::string("exa mple.com"), std::string("ex\rample.com"),
                                 std::string("user@host"), std::string("host/1"),
                                 std::string("a:b")}) {
    const std::vector<uint8_t> m =
        socks5_request(0x01, 0x00, fcp::kAtypDomain, raw(bad), 80);
    CHECK(fcp::socks5_parse_request(ptr(m), m.size(), &consumed, &t) == Socks5Parse::kMalformed);
    CHECK_EQ(consumed, 0u);
  }
  std::vector<uint8_t> empty_domain{0x05, 0x01, 0x00, fcp::kAtypDomain, 0x00, 0x00, 0x50};
  CHECK(fcp::socks5_parse_request(ptr(empty_domain), empty_domain.size(), &consumed, &t) ==
        Socks5Parse::kMalformed);
  const std::vector<uint8_t> zero_port = socks5_request(0x01, 0x00, fcp::kAtypIpv4,
                                                         v4(1, 1, 1, 1), 0);
  CHECK(fcp::socks5_parse_request(ptr(zero_port), zero_port.size(), &consumed, &t) ==
        Socks5Parse::kMalformed);
}

void TestSocks5RequestIpv6() {
  const std::vector<uint8_t> msg = socks5_request(0x01, 0x00, fcp::kAtypIpv6, v6loopback(), 8443);
  CHECK_EQ(msg.size(), 22u);
  size_t consumed = 0;
  ProxyTarget t;
  CHECK(fcp::socks5_parse_request(ptr(msg), msg.size(), &consumed, &t) == Socks5Parse::kOk);
  CHECK_EQ(consumed, msg.size());
  CHECK_EQ(t.addr.size(), 16u);
  CHECK_EQ(t.port, 8443);
  // The raw bytes go through untouched: no re-encoding means no chance to
  // corrupt a scope id or a multicast group on the way.
  CHECK_EQ(t.addr, text(v6loopback()));
}

void TestSocks5RejectsUnsupported() {
  size_t consumed = 0;
  ProxyTarget t;
  // CMD other than CONNECT is answered, not closed (§4.1).
  const uint8_t cmds[] = {0x02, 0x03};
  for (const uint8_t cmd : cmds) {
    const std::vector<uint8_t> m = socks5_request(cmd, 0x00, fcp::kAtypIpv4, v4(1, 2, 3, 4), 80);
    CHECK(fcp::socks5_parse_request(ptr(m), m.size(), &consumed, &t) ==
          Socks5Parse::kCommandNotSupported);
  }
  const uint8_t atyps[] = {0x00, 0x02, 0x05, 0xFF};
  for (const uint8_t atyp : atyps) {
    const std::vector<uint8_t> m = socks5_request(0x01, 0x00, atyp, v4(1, 2, 3, 4), 80);
    CHECK(fcp::socks5_parse_request(ptr(m), m.size(), &consumed, &t) ==
          Socks5Parse::kAtypNotSupported);
  }
  // RSV must be zero and the version must be five; both close the connection.
  const std::vector<uint8_t> rsv = socks5_request(0x01, 0x01, fcp::kAtypIpv4, v4(1, 2, 3, 4), 80);
  CHECK(fcp::socks5_parse_request(ptr(rsv), rsv.size(), &consumed, &t) == Socks5Parse::kMalformed);
  std::vector<uint8_t> bad_ver = rsv;
  bad_ver[0] = 0x04;
  CHECK(fcp::socks5_parse_request(ptr(bad_ver), bad_ver.size(), &consumed, &t) ==
        Socks5Parse::kMalformed);
  CHECK_EQ(consumed, 0u);
}

void TestSocks5ReplyBytes() {
  std::vector<uint8_t> out(16, 0xAA);
  CHECK_EQ(fcp::socks5_write_reply(out.data(), out.size(), Socks5Rep::kSucceeded),
           fcp::kSocks5ReplyLen);
  CHECK_EQ(out[0], 0x05);
  CHECK_EQ(out[1], 0x00);
  CHECK_EQ(out[2], 0x00);  // RSV
  CHECK_EQ(out[3], fcp::kAtypIpv4);
  for (size_t i = 4; i < fcp::kSocks5ReplyLen; ++i) {
    CHECK_EQ(out[i], 0x00);  // BNDADDR 0.0.0.0, BNDPORT 0: no egress promise
  }
  CHECK_EQ(out[10], 0xAA);  // nothing written past the reply

  CHECK_EQ(fcp::socks5_write_reply(out.data(), out.size(), Socks5Rep::kCommandNotSupported),
           fcp::kSocks5ReplyLen);
  CHECK_EQ(out[1], 0x07);
  CHECK_EQ(fcp::socks5_write_reply(out.data(), out.size(), Socks5Rep::kAtypNotSupported),
           fcp::kSocks5ReplyLen);
  CHECK_EQ(out[1], 0x08);
  CHECK_EQ(fcp::socks5_write_reply(out.data(), 9, Socks5Rep::kSucceeded), 0u);
  CHECK_EQ(fcp::socks5_write_reply(nullptr, out.size(), Socks5Rep::kSucceeded), 0u);
}

// ---- HTTP CONNECT ----

void TestHttpConnect() {
  const std::string head = "CONNECT example.com:8443 HTTP/1.1\r\n"
                           "Host: example.com:8443\r\n"
                           "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n"
                           "\r\n";
  const std::vector<uint8_t> buf = raw(head);
  size_t consumed = 0;
  ProxyTarget t;
  CHECK(fcp::http_parse_connect(ptr(buf), buf.size(), &consumed, &t) == HttpParse::kOk);
  CHECK_EQ(consumed, buf.size());
  CHECK_EQ(t.atyp, fcp::kAtypDomain);  // always a name: resolution happens remotely
  CHECK_EQ(t.addr, std::string("example.com"));
  CHECK_EQ(t.port, 8443);

  // HTTP/1.0 is as good as 1.1, and the header block is otherwise ignored.
  const std::vector<uint8_t> v10 = raw("CONNECT a.b:80 HTTP/1.0\r\n\r\n");
  CHECK(fcp::http_parse_connect(ptr(v10), v10.size(), &consumed, &t) == HttpParse::kOk);
  CHECK_EQ(consumed, v10.size());
  CHECK_EQ(t.addr, std::string("a.b"));
  CHECK_EQ(t.port, 80);

  // Payload behind the head belongs to the tunnel, not to the parser.
  const std::vector<uint8_t> base = raw("CONNECT a.b:80 HTTP/1.1\r\n\r\n");
  std::vector<uint8_t> corked = base;
  const std::vector<uint8_t> payload = raw("GET / HTTP/1.1\r\n\r\n");
  corked.insert(corked.end(), payload.begin(), payload.end());
  CHECK(fcp::http_parse_connect(ptr(corked), corked.size(), &consumed, &t) == HttpParse::kOk);
  CHECK_EQ(consumed, base.size());

  // Every prefix is a short read, including the one that stops mid blank line.
  for (size_t n = 0; n < buf.size(); ++n) {
    CHECK(fcp::http_parse_connect(ptr(buf), n, &consumed, &t) == HttpParse::kNeedMore);
    CHECK_EQ(consumed, 0u);
  }
}

void TestHttpAuthorityForms() {
  size_t consumed = 0;
  ProxyTarget t;
  struct Case {
    const char* authority;
    const char* host;
    uint16_t port;
  };
  const Case ok[] = {
      {"example.com:80", "example.com", 80},
      {"127.0.0.1:1080", "127.0.0.1", 1080},
      {"[::1]:8443", "::1", 8443},
      {"[fe80::1ff:fe23:4567:890a]:22", "fe80::1ff:fe23:4567:890a", 22},
      {"[::ffff:1.2.3.4]:443", "::ffff:1.2.3.4", 443},
      {"sub.domain.example.co.uk:65535", "sub.domain.example.co.uk", 65535},
      {"0080.example.com:8080", "0080.example.com", 8080},
      {"trailing0:1", "trailing0", 1},
  };
  for (const Case& c : ok) {
    const std::vector<uint8_t> buf =
        raw(std::string("CONNECT ") + c.authority + " HTTP/1.1\r\n\r\n");
    CHECK(fcp::http_parse_connect(ptr(buf), buf.size(), &consumed, &t) == HttpParse::kOk);
    CHECK_EQ(consumed, buf.size());
    CHECK_EQ(t.addr, std::string(c.host));  // brackets stripped, address verbatim
    CHECK_EQ(t.port, c.port);
    CHECK_EQ(t.atyp, fcp::kAtypDomain);
  }

  // Refused before the tunnel would carry something undialable.
  const char* bad[] = {
      "example.com",      // CONNECT has no default port
      "example.com:0",    // nothing to dial
      "example.com:65536",
      "example.com:99999",
      "example.com:http",  // no service names here
      "example.com:",
      ":80",        // empty host
      "[]:80",      // empty IPv6 literal
      "[::1]",      // bracketed, no port
      "[::1]80",    // junk after the bracket
      "[::1]]:80",
      "::1:80",     // unbracketed IPv6: the split would be inside the address
      "a<b.example.com:80",
      "under_score.example.com:80_ok",
  };
  for (const char* a : bad) {
    const std::vector<uint8_t> buf = raw(std::string("CONNECT ") + a + " HTTP/1.1\r\n\r\n");
    CHECK(fcp::http_parse_connect(ptr(buf), buf.size(), &consumed, &t) == HttpParse::kBadRequest);
    CHECK_EQ(consumed, 0u);
  }

  // A host longer than the OPEN length byte can carry is refused, not truncated.
  const std::vector<uint8_t> too_long = raw("CONNECT " + std::string(256, 'a') +
                                            ":80 HTTP/1.1\r\n\r\n");
  CHECK(fcp::http_parse_connect(ptr(too_long), too_long.size(), &consumed, &t) ==
        HttpParse::kBadRequest);
  const std::vector<uint8_t> max_host = raw("CONNECT " + std::string(255, 'a') +
                                            ":80 HTTP/1.1\r\n\r\n");
  CHECK(fcp::http_parse_connect(ptr(max_host), max_host.size(), &consumed, &t) == HttpParse::kOk);
  CHECK_EQ(t.addr.size(), 255u);
}

void TestHttpMalformedRequests() {
  struct Case {
    const char* head;
    HttpParse want;
  };
  const Case cases[] = {
      {"CONNECT a.b:80\r\n\r\n", HttpParse::kBadRequest},           // no version
      {"CONNECT a.b:80 HTTP/2.0\r\n\r\n", HttpParse::kBadRequest},  // not a version we speak
      {"CONNECT a.b:80 HTTP/1.2\r\n\r\n", HttpParse::kBadRequest},
      {"CONNECT a.b:80 HTTP/1\r\n\r\n", HttpParse::kBadRequest},
      {"CONNECT a.b:80 x HTTP/1.1\r\n\r\n", HttpParse::kBadRequest},  // four tokens
      {"CONNECT\r\n\r\n", HttpParse::kBadRequest},
      {"\r\n\r\n", HttpParse::kBadRequest},  // empty request line
      {"  CONNECT a.b:80 HTTP/1.1\r\n\r\n", HttpParse::kOk},          // leading blanks are noise
      {"CONNECT a.b:80 HTTP/1.1\r\n", HttpParse::kNeedMore},          // head not finished
      {"CONNECT a.b:80 HTTP/1.1\n\n", HttpParse::kNeedMore},  // bare LF is not a line ending
      {"GET a.b:80 HTTP/1.1\r\nX: 1", HttpParse::kNeedMore},  // method waits for the head
      {"PUT a.b:80 HTTP/1.1\r\n\r\n", HttpParse::kMethodNotAllowed},
      {"GET / HTTP/1.1\r\n\r\n", HttpParse::kMethodNotAllowed},
  };
  size_t consumed = 0;
  ProxyTarget t;
  for (const Case& c : cases) {
    const std::vector<uint8_t> buf = raw(c.head);
    CHECK(fcp::http_parse_connect(ptr(buf), buf.size(), &consumed, &t) == c.want);
    if (c.want != HttpParse::kOk) {
      CHECK_EQ(consumed, 0u);
    }
  }
}

void TestHttpHeadCap() {
  size_t consumed = 0;
  ProxyTarget t;
  // Exactly on budget: an 8192-byte head that ends with the blank line parses.
  const size_t pad = fcp::kHttpHeadMaxBytes - 40;
  std::vector<uint8_t> on_cap = raw("CONNECT example.com:80 HTTP/1.1\r\nX: ");
  on_cap.insert(on_cap.end(), pad, 'a');
  on_cap.insert(on_cap.end(), {'\r', '\n', '\r', '\n'});
  CHECK_EQ(on_cap.size(), fcp::kHttpHeadMaxBytes);
  CHECK(fcp::http_parse_connect(ptr(on_cap), on_cap.size(), &consumed, &t) == HttpParse::kOk);
  CHECK_EQ(consumed, fcp::kHttpHeadMaxBytes);
  CHECK_EQ(t.addr, std::string("example.com"));

  // An unterminated head: 431 once the budget is spent, and the same answer no
  // matter how much more the caller has read.
  std::vector<uint8_t> unterminated = on_cap;
  unterminated.resize(on_cap.size() - 2);  // the blank line's CRLF is gone
  unterminated.insert(unterminated.end(), 16, 'b');
  CHECK(fcp::http_parse_connect(ptr(unterminated), unterminated.size(), &consumed, &t) ==
        HttpParse::kHeadTooLarge);
  const std::vector<uint8_t> way_over(64 * 1024, 'c');
  CHECK(fcp::http_parse_connect(ptr(way_over), way_over.size(), &consumed, &t) ==
        HttpParse::kHeadTooLarge);

  // The blank line only after the cap: still 431, because the budget bounds both
  // the peer's memory and the scan, not just the peer's promise.
  std::vector<uint8_t> late = unterminated;
  late.insert(late.end(), {'\r', '\n', '\r', '\n'});
  CHECK(fcp::http_parse_connect(ptr(late), late.size(), &consumed, &t) ==
        HttpParse::kHeadTooLarge);

  // A complete head with bytes behind it is not a 431: those bytes are the
  // tunnel and the parse stops at the budget.
  std::vector<uint8_t> behind = on_cap;
  behind.insert(behind.end(), 4096, 'd');
  CHECK(fcp::http_parse_connect(ptr(behind), behind.size(), &consumed, &t) == HttpParse::kOk);
  CHECK_EQ(consumed, fcp::kHttpHeadMaxBytes);

  CHECK(fcp::http_parse_connect(nullptr, 100, &consumed, &t) == HttpParse::kBadRequest);
  std::vector<uint8_t> one{0x00};
  CHECK(fcp::http_parse_connect(ptr(one), 0, &consumed, &t) == HttpParse::kNeedMore);
}

void TestHttpResponseBytes() {
  uint8_t out[256] = {0};
  struct Case {
    HttpReply reply;
    const char* body;
  };
  const Case cases[] = {
      {HttpReply::kEstablished, "HTTP/1.1 200 Connection Established\r\n\r\n"},
      {HttpReply::kBadRequest, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"},
      {HttpReply::kMethodNotAllowed,
       "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\n\r\n"},
      {HttpReply::kForwardMethodNotAllowed,
       "HTTP/1.1 405 Method Not Allowed\r\n"
       "Allow: CONNECT, GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH\r\n"
       "Connection: close\r\n\r\n"},
      {HttpReply::kRequestHeaderTooLarge,
       "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"},
      // 502 is the answer to a tunnel the server refused, so it is the only
      // status a correctly parsed CONNECT can be followed by.
      {HttpReply::kBadGateway, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"},
  };
  for (const Case& c : cases) {
    const size_t n = fcp::http_write_response(out, sizeof(out), c.reply);
    CHECK_EQ(n, std::strlen(c.body));
    CHECK_EQ(text(std::vector<uint8_t>(out, out + n)), std::string(c.body));
    CHECK_EQ(fcp::http_write_response(out, n - 1, c.reply), 0u);  // one byte short
    CHECK_EQ(fcp::http_write_response(out, 0, c.reply), 0u);
    CHECK_EQ(fcp::http_write_response(nullptr, sizeof(out), c.reply), 0u);
  }
}

// ---- tunnel OPEN ----

void TestOpenRoundTrip() {
  const ProxyTarget cases[] = {
      {fcp::kAtypIpv4, text(v4(1, 2, 3, 4)), 443},
      domain_target("example.com", 8443),
      domain_target(std::string(255, 'z'), 65535),
      {fcp::kAtypIpv6, text(v6loopback()), 22},
  };
  uint8_t buf[fcp::kOpenMaxBytes + 16];
  for (const ProxyTarget& in : cases) {
    const size_t n = fcp::open_write_request(buf, sizeof(buf), in);
    CHECK_EQ(n, 9u + in.addr.size());
    // Ports are network order here too, so a capture of the tunnel shows the
    // number the application asked for.
    CHECK_EQ(buf[n - 2], static_cast<uint8_t>(in.port >> 8));
    CHECK_EQ(buf[n - 1], static_cast<uint8_t>(in.port & 0xFFu));
    CHECK_EQ(buf[0], 'F');
    CHECK_EQ(buf[4], fcp::kOpenVersion);
    CHECK_EQ(buf[5], in.atyp);
    CHECK_EQ(buf[6], static_cast<uint8_t>(in.addr.size()));

    size_t consumed = 0;
    ProxyTarget out;
    CHECK(fcp::open_parse_request(buf, n, &consumed, &out) == OpenParse::kOk);
    CHECK_EQ(consumed, n);
    CHECK_EQ(out.atyp, in.atyp);
    CHECK_EQ(out.addr, in.addr);
    CHECK_EQ(out.port, in.port);

    // Bytes behind the message stay for the stream.
    std::memcpy(buf + n, "\xAA\xAA\xAA\xAA", 4);
    CHECK(fcp::open_parse_request(buf, n + 4, &consumed, &out) == OpenParse::kOk);
    CHECK_EQ(consumed, n);

    // Every prefix is a short read (or, before the magic completes, still a
    // short read) and never claims to have consumed anything.
    for (size_t k = 1; k < n; ++k) {
      consumed = 7;
      const OpenParse r = fcp::open_parse_request(buf, k, &consumed, &out);
      CHECK(r == OpenParse::kNeedMore || r == OpenParse::kBadMagic);
      CHECK(r != OpenParse::kOk);
      CHECK_EQ(consumed, 0u);
    }
  }
}

void TestOpenWriteRejectsUnencodable() {
  uint8_t buf[fcp::kOpenMaxBytes + 16];
  ProxyTarget t = domain_target("x", 80);
  t.atyp = 0x02;  // retired
  CHECK_EQ(fcp::open_write_request(buf, sizeof(buf), t), 0u);
  t.atyp = fcp::kAtypIpv4;
  t.addr = "1.2.3.4";  // textual, not the four raw bytes
  CHECK_EQ(fcp::open_write_request(buf, sizeof(buf), t), 0u);
  t.addr = std::string(4, '\x01');
  CHECK(fcp::open_write_request(buf, sizeof(buf), t) > 0);
  t.port = 0;
  CHECK_EQ(fcp::open_write_request(buf, sizeof(buf), t), 0u);
  t.port = 80;
  t.atyp = fcp::kAtypDomain;
  t.addr = std::string();
  CHECK_EQ(fcp::open_write_request(buf, sizeof(buf), t), 0u);
  t.addr = std::string(256, 'a');
  CHECK_EQ(fcp::open_write_request(buf, sizeof(buf), t), 0u);

  const ProxyTarget max_domain = domain_target(std::string(255, 'a'), 80);
  CHECK_EQ(fcp::open_write_request(buf, 9 + 255 - 1, max_domain), 0u);  // cap one short
  CHECK_EQ(fcp::open_write_request(buf, 9 + 255, max_domain), fcp::kOpenMaxBytes);
  CHECK_EQ(fcp::open_write_request(nullptr, sizeof(buf), max_domain), 0u);
}

void TestOpenRequestRejects() {
  size_t consumed = 0;
  ProxyTarget t;
  const std::vector<uint8_t> good = open_request_bytes(domain_target("example.com", 443));

  std::vector<uint8_t> bad_magic = good;
  bad_magic[0] = 'X';
  CHECK(fcp::open_parse_request(ptr(bad_magic), bad_magic.size(), &consumed, &t) ==
        OpenParse::kBadMagic);
  // One byte that cannot become the magic is rejected at once, so the host does
  // not have to wait for four.
  CHECK(fcp::open_parse_request(ptr(bad_magic), 1, &consumed, &t) == OpenParse::kBadMagic);
  // Bytes that could still become the magic are a short read.
  std::vector<uint8_t> fc = raw("FC");
  CHECK(fcp::open_parse_request(ptr(fc), fc.size(), &consumed, &t) == OpenParse::kNeedMore);

  std::vector<uint8_t> bad_ver = good;
  bad_ver[4] = 2;
  CHECK(fcp::open_parse_request(ptr(bad_ver), bad_ver.size(), &consumed, &t) ==
        OpenParse::kBadVersion);
  const uint8_t bad_atyps[] = {0x00, 0x02, 0x77};
  for (const uint8_t atyp : bad_atyps) {
    std::vector<uint8_t> m = good;
    m[5] = atyp;
    CHECK(fcp::open_parse_request(ptr(m), m.size(), &consumed, &t) == OpenParse::kBadAtyp);
  }
  std::vector<uint8_t> zero_len = good;
  zero_len[6] = 0;
  CHECK(fcp::open_parse_request(ptr(zero_len), zero_len.size(), &consumed, &t) ==
        OpenParse::kBadAddress);
  std::vector<uint8_t> wrong_len = good;
  wrong_len[5] = fcp::kAtypIpv4;  // a 4-byte address, but the length byte says 11
  CHECK(fcp::open_parse_request(ptr(wrong_len), wrong_len.size(), &consumed, &t) ==
        OpenParse::kBadAddress);
  // A port-0 request, built by hand because the writer refuses to encode one.
  const std::vector<uint8_t> zero_port{0x46, 0x43, 0x50, 0x4F, 0x01, 0x01, 0x04,
                                       0x01, 0x02, 0x03, 0x04, 0x00, 0x00};
  CHECK(fcp::open_parse_request(ptr(zero_port), zero_port.size(), &consumed, &t) ==
        OpenParse::kBadAddress);
  CHECK_EQ(consumed, 0u);
  CHECK(fcp::open_parse_request(nullptr, 8, &consumed, &t) == OpenParse::kNeedMore);
}

void TestOpenReplyCodecs() {
  uint8_t buf[16] = {0};
  CHECK_EQ(fcp::open_write_ok(buf, sizeof(buf)), fcp::kOpenOkLen);
  CHECK_EQ(std::memcmp(buf, "FCPO", 4), 0);
  CHECK_EQ(buf[4], fcp::kOpenVersion);
  CHECK_EQ(buf[5], fcp::kOpenKindOk);
  CHECK_EQ(buf[6], 0x00);
  CHECK_EQ(buf[7], 0x00);

  size_t consumed = 0;
  bool ok = false;
  OpenError err = OpenError::kRefused;
  CHECK(fcp::open_parse_reply(buf, fcp::kOpenOkLen, &consumed, &ok, &err) == OpenParse::kOk);
  CHECK_EQ(consumed, fcp::kOpenOkLen);
  CHECK(ok);
  // A long buffer is fine: the reply is 8 bytes, the rest is the tunnel.
  ok = false;
  CHECK(fcp::open_parse_reply(buf, 16, &consumed, &ok, &err) == OpenParse::kOk);
  CHECK(ok);
  CHECK_EQ(consumed, fcp::kOpenOkLen);

  // A reserved byte that is not zero is a disagreement about the format, not a
  // refused target: the host closes instead of tunnelling.
  std::vector<uint8_t> dirty(buf, buf + fcp::kOpenOkLen);
  dirty[7] = 0x01;
  CHECK(fcp::open_parse_reply(ptr(dirty), dirty.size(), &consumed, &ok, &err) ==
        OpenParse::kBadReserved);
  CHECK_EQ(consumed, 0u);
  CHECK_EQ(fcp::open_write_ok(buf, fcp::kOpenOkLen - 1), 0u);
  CHECK_EQ(fcp::open_write_ok(nullptr, sizeof(buf)), 0u);

  for (size_t n = 0; n < dirty.size(); ++n) {
    dirty[7] = 0;
    consumed = 3;
    const OpenParse r = fcp::open_parse_reply(dirty.data(), n, &consumed, &ok, &err);
    CHECK(r == OpenParse::kNeedMore || r == OpenParse::kBadMagic);
    CHECK(r != OpenParse::kOk);
    CHECK_EQ(consumed, 0u);
  }

  const OpenError codes[] = {OpenError::kRefused, OpenError::kDns, OpenError::kTargetTimeout,
                             OpenError::kNotSupported, OpenError::kTooManySessions};
  for (const OpenError c : codes) {
    const size_t n = fcp::open_write_err(buf, sizeof(buf), c);
    CHECK_EQ(n, fcp::kOpenErrLen);
    CHECK_EQ(buf[4], fcp::kOpenVersion);
    CHECK_EQ(buf[5], fcp::kOpenKindErr);
    CHECK_EQ(buf[6], static_cast<uint8_t>(c));
    consumed = 0;
    ok = true;
    err = c == OpenError::kRefused ? OpenError::kDns : OpenError::kRefused;
    CHECK(fcp::open_parse_reply(buf, n, &consumed, &ok, &err) == OpenParse::kOk);
    CHECK_EQ(consumed, n);
    CHECK(!ok);
    CHECK_EQ(static_cast<uint8_t>(err), static_cast<uint8_t>(c));
    for (size_t k = 1; k < n; ++k) {
      CHECK(fcp::open_parse_reply(buf, k, &consumed, &ok, &err) != OpenParse::kOk);
    }
  }
  CHECK_EQ(fcp::open_write_err(buf, fcp::kOpenErrLen - 1, OpenError::kDns), 0u);

  // Undefined kind and undefined code are both broken replies, and a longer
  // buffer than the message is not a problem.
  uint8_t junk[16] = {0x46, 0x43, 0x50, 0x4F, 0x01, 0x02, 0x00, 0x00};
  CHECK(fcp::open_parse_reply(junk, sizeof(junk), &consumed, &ok, &err) == OpenParse::kBadKind);
  junk[5] = fcp::kOpenKindErr;
  junk[6] = 0;  // 0 is not a code
  CHECK(fcp::open_parse_reply(junk, 7, &consumed, &ok, &err) == OpenParse::kBadKind);
  junk[6] = 6;  // above the defined range
  CHECK(fcp::open_parse_reply(junk, 7, &consumed, &ok, &err) == OpenParse::kBadKind);
  junk[6] = 2;
  junk[4] = 9;
  CHECK(fcp::open_parse_reply(junk, 7, &consumed, &ok, &err) == OpenParse::kBadVersion);
  junk[0] = 'Q';
  CHECK(fcp::open_parse_reply(junk, 7, &consumed, &ok, &err) == OpenParse::kBadMagic);
  CHECK(fcp::open_parse_reply(nullptr, 8, &consumed, &ok, &err) == OpenParse::kNeedMore);
}

void TestOpenErrorToSocks5Rep() {
  CHECK_EQ(static_cast<uint8_t>(fcp::socks5_rep_for_open_error(OpenError::kRefused)),
           static_cast<uint8_t>(Socks5Rep::kConnectionRefused));
  CHECK_EQ(static_cast<uint8_t>(fcp::socks5_rep_for_open_error(OpenError::kDns)),
           static_cast<uint8_t>(Socks5Rep::kHostUnreachable));
  CHECK_EQ(static_cast<uint8_t>(fcp::socks5_rep_for_open_error(OpenError::kTargetTimeout)),
           static_cast<uint8_t>(Socks5Rep::kTtlExpired));
  CHECK_EQ(static_cast<uint8_t>(fcp::socks5_rep_for_open_error(OpenError::kNotSupported)),
           static_cast<uint8_t>(Socks5Rep::kAtypNotSupported));
  CHECK_EQ(static_cast<uint8_t>(fcp::socks5_rep_for_open_error(OpenError::kTooManySessions)),
           static_cast<uint8_t>(Socks5Rep::kNotAllowed));
}

void TestTargetText() {
  ProxyTarget t;
  t.atyp = fcp::kAtypIpv4;
  t.addr = text(v4(99, 0, 0, 1));
  t.port = 443;
  CHECK_EQ(fcp::target_text(t), std::string("99.0.0.1:443"));

  t.atyp = fcp::kAtypIpv6;
  t.addr = std::string(16, '\0');
  t.port = 80;
  // Eight groups with no zero compression: valid text, and free of inet_ntop.
  CHECK_EQ(fcp::target_text(t), std::string("0:0:0:0:0:0:0:0:80"));
  std::string full(16, '\0');
  full[0] = 0x20;
  full[1] = 0x01;
  full[15] = 0x01;
  t.addr = full;
  t.port = 65535;
  CHECK_EQ(fcp::target_text(t), std::string("2001:0:0:0:0:0:0:1:65535"));

  t.atyp = fcp::kAtypDomain;
  t.addr = "Example.COM";
  t.port = 22;
  CHECK_EQ(fcp::target_text(t), std::string("Example.COM:22"));

  // Logging must survive a target no parser produced.
  t.atyp = 0x7F;
  t.addr = "junk";
  CHECK_EQ(fcp::target_text(t), std::string("?:22"));
  ProxyTarget half;
  half.atyp = fcp::kAtypIpv4;  // three bytes is not an IPv4 address
  half.addr = std::string(3, 'a');
  half.port = 0;
  CHECK_EQ(fcp::target_text(half), std::string("?:0"));
}

// ---- HTTP absolute-form forward requests ----

void TestHttpForward() {
  size_t consumed = 0;
  fcp::HttpForward f;
  const std::string head =
      "GET http://example.com/index.html?q=1 HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "User-Agent: fcp-test\r\n"
      "\r\n";
  const std::vector<uint8_t> buf = raw(head);
  CHECK(fcp::http_parse_forward(ptr(buf), buf.size(), &consumed, &f) == HttpParse::kOk);
  CHECK_EQ(consumed, buf.size());
  CHECK_EQ(f.target.atyp, fcp::kAtypDomain);
  CHECK_EQ(f.target.addr, std::string("example.com"));
  CHECK_EQ(f.target.port, 80);
  // The URL becomes origin-form, Host is rewritten last, and the forced close
  // is what makes the origin's FIN end this one-request connection.
  CHECK_EQ(text(f.head),
           std::string("GET /index.html?q=1 HTTP/1.1\r\n"
                       "User-Agent: fcp-test\r\n"
                       "Host: example.com\r\n"
                       "Connection: close\r\n\r\n"));

  // The CONNECT parser still refuses that head; the host tries forward next.
  ProxyTarget t;
  CHECK(fcp::http_parse_connect(ptr(buf), buf.size(), &consumed, &t) ==
        HttpParse::kMethodNotAllowed);
  CHECK_EQ(consumed, 0u);

  // A short read never consumes, and bytes behind the head are the body.
  for (size_t n = 0; n < buf.size(); ++n) {
    CHECK(fcp::http_parse_forward(ptr(buf), n, &consumed, &f) == HttpParse::kNeedMore);
    CHECK_EQ(consumed, 0u);
  }
  const std::vector<uint8_t> corked = raw(head + "BODY");
  CHECK(fcp::http_parse_forward(ptr(corked), corked.size(), &consumed, &f) ==
        HttpParse::kOk);
  CHECK_EQ(consumed, buf.size());

  // Authorities: explicit port, :80 on a default-port URL, case-insensitive
  // Host, a query with no slash, and a bracketed IPv6 literal.
  struct OkCase {
    const char* uri;
    const char* host_header;
    const char* host;
    uint16_t port;
    const char* origin;
  };
  const OkCase ok[] = {
      {"http://example.com:8080/", "example.com:8080", "example.com", 8080, "/"},
      {"http://example.com/", "example.com:80", "example.com", 80, "/"},
      {"http://EXAMPLE.com/", "example.com", "EXAMPLE.com", 80, "/"},
      {"http://a.b?x=1", "a.b", "a.b", 80, "/?x=1"},
      {"http://[::1]:8443/a", "[::1]:8443", "::1", 8443, "/a"},
      {"HTTP://example.com/", "example.com", "example.com", 80, "/"},
  };
  for (const OkCase& c : ok) {
    const std::vector<uint8_t> b = raw(std::string("GET ") + c.uri +
                                       " HTTP/1.1\r\nHost: " + c.host_header + "\r\n\r\n");
    CHECK(fcp::http_parse_forward(ptr(b), b.size(), &consumed, &f) == HttpParse::kOk);
    CHECK_EQ(consumed, b.size());
    CHECK_EQ(f.target.addr, std::string(c.host));
    CHECK_EQ(f.target.port, c.port);
    CHECK(text(f.head).find(std::string("GET ") + c.origin + " HTTP/1.1\r\n") == 0);
    CHECK(text(f.head).find(std::string("Host: ") + c.host_header + "\r\n") !=
          std::string::npos);
    CHECK(text(f.head).find("Connection: close\r\n\r\n") != std::string::npos);
    CHECK(!f.head.empty());
  }

  // A missing Host (HTTP/1.0 shaped request) is filled from the URL.
  const std::vector<uint8_t> no_host =
      raw("GET http://example.com/x HTTP/1.0\r\n\r\n");
  CHECK(fcp::http_parse_forward(ptr(no_host), no_host.size(), &consumed, &f) ==
        HttpParse::kOk);
  CHECK_EQ(text(f.head),
           std::string("GET /x HTTP/1.0\r\nHost: example.com\r\n"
                       "Connection: close\r\n\r\n"));

  // Fragment is stripped, never sent to the origin server.
  const std::vector<uint8_t> frag =
      raw("GET http://example.com/a/b#frag HTTP/1.1\r\nHost: example.com\r\n\r\n");
  CHECK(fcp::http_parse_forward(ptr(frag), frag.size(), &consumed, &f) == HttpParse::kOk);
  CHECK_EQ(text(f.head),
           std::string("GET /a/b HTTP/1.1\r\nHost: example.com\r\n"
                       "Connection: close\r\n\r\n"));

  // Hop-by-hop and proxy headers are dropped; body framing headers survive
  // even when the Connection header names them (this proxy never decodes a body).
  const std::vector<uint8_t> hops = raw(
      "POST http://api.example.com/upload HTTP/1.1\r\n"
      "Host: api.example.com\r\n"
      "Proxy-Authorization: Basic secret\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "Connection: keep-alive, X-Custom, Transfer-Encoding\r\n"
      "X-Custom: drop-me\r\n"
      "Upgrade: h2c\r\n"
      "Keep-Alive: timeout=5\r\n"
      "TE: trailers\r\n"
      "X-Keep: yes\r\n"
      "Content-Length: 5\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n");
  CHECK(fcp::http_parse_forward(ptr(hops), hops.size(), &consumed, &f) == HttpParse::kOk);
  CHECK_EQ(text(f.head),
           std::string("POST /upload HTTP/1.1\r\n"
                       "X-Keep: yes\r\n"
                       "Content-Length: 5\r\n"
                       "Transfer-Encoding: chunked\r\n"
                       "Host: api.example.com\r\n"
                       "Connection: close\r\n\r\n"));

  struct BadCase {
    const char* head_text;
    HttpParse want;
  };
  const BadCase bad[] = {
      // TLS is CONNECT's job, never an absolute-form forward request.
      {"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", HttpParse::kBadRequest},
      {"GET ftp://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET http://u:p@example.com/ HTTP/1.1\r\nHost: u:p@example.com\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET http://example.com/ HTTP/2.0\r\nHost: example.com\r\n\r\n",
       HttpParse::kBadRequest},
      {"TRACE http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
       HttpParse::kMethodNotAllowed},
      // A disagreeing or duplicated Host is refused, never rewritten.
      {"GET http://example.com/ HTTP/1.1\r\nHost: other.com\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET http://example.com:8080/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
       "Host: example.com\r\n\r\n",
       HttpParse::kBadRequest},
      // obs-fold, control bytes in a value, a bad header name and no colon.
      {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n X-Fold: 1\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX: \x01\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nBad Header: x\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET http://example.com/ HTTP/1.1\r\nNoColon\r\n\r\n", HttpParse::kBadRequest},
      {"GET http://example.com:0/ HTTP/1.1\r\nHost: example.com:0\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET http://example.com:65536/ HTTP/1.1\r\nHost: example.com:65536\r\n\r\n",
       HttpParse::kBadRequest},
      {"GET http://[::1/ HTTP/1.1\r\nHost: [::1\r\n\r\n", HttpParse::kBadRequest},
  };
  for (const BadCase& c : bad) {
    const std::vector<uint8_t> b = raw(c.head_text);
    CHECK(fcp::http_parse_forward(ptr(b), b.size(), &consumed, &f) == c.want);
    CHECK_EQ(consumed, 0u);
  }

  // Same 8 KiB head budget as CONNECT, and the same null/short-read contract.
  std::vector<uint8_t> huge =
      raw("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX: ");
  huge.insert(huge.end(), fcp::kHttpHeadMaxBytes, 'a');
  CHECK(fcp::http_parse_forward(ptr(huge), huge.size(), &consumed, &f) ==
        HttpParse::kHeadTooLarge);
  CHECK_EQ(consumed, 0u);
  CHECK(fcp::http_parse_forward(nullptr, 100, &consumed, &f) == HttpParse::kBadRequest);
  CHECK_EQ(consumed, 0u);
  CHECK(fcp::http_parse_forward(ptr(buf), 0, &consumed, &f) == HttpParse::kNeedMore);
  CHECK_EQ(consumed, 0u);
}

}  // namespace

int main() {
  TestAtypHelpers();
  TestSocks5Greeting();
  TestSocks5RequestIpv4();
  TestSocks5RequestDomain();
  TestSocks5RequestIpv6();
  TestSocks5RejectsUnsupported();
  TestSocks5ReplyBytes();
  TestHttpConnect();
  TestHttpAuthorityForms();
  TestHttpMalformedRequests();
  TestHttpHeadCap();
  TestHttpResponseBytes();
  TestHttpForward();
  TestOpenRoundTrip();
  TestOpenWriteRejectsUnencodable();
  TestOpenRequestRejects();
  TestOpenReplyCodecs();
  TestOpenErrorToSocks5Rep();
  TestTargetText();
  return fcp_test::finish();
}
