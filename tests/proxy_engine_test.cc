// T31 (docs/FCP_M2_PROXY.md §6): ProxyEngine driven without a single socket.
//
// The engine is the part of the proxy that decides things -- connection table,
// salt routing, entry parsing, OPEN exchange, backpressure, teardown, prewarm --
// and it decides all of it from callbacks. So the test provides the other half:
// two engines wired to each other through in-memory datagram queues, a fake
// application socket with a switchable acceptance limit, and a fake dial that
// answers whenever the test says. Everything runs on one virtual clock, so a
// whole proxy session costs microseconds and every deadline is exact.
//
// What this cannot prove is the socket half (that is #22, the loopback and WAN
// runs): nothing here exercises select(), DNS or MTU behaviour on a real path.
//
// One rule the harness keeps, because the real hosts keep it: a host callback
// never calls back into the engine. Dial answers are recorded by dial() and
// applied at the top of the next step, which is also how a connect completion
// reaches the reactor.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "engine.h"
#include "fcp/proxy_proto.h"
#include "test_util.h"

namespace {

using namespace fcp;

constexpr int64_t kTickMs = 25;
constexpr uint64_t kServerPeer = 2;  // the client's id for the server's address
constexpr uint64_t kClientPeer = 3;  // the server's id for the client's address
constexpr uint64_t kOtherPeer = 9;   // a fourth-party source address
constexpr uint64_t kLocalConn = 101;  // the first id the client host allocates
constexpr size_t kNoLimit = static_cast<size_t>(-1);

struct Options {
  size_t client_max_sessions = 256;
  size_t server_max_sessions = 256;
  int64_t flush_grace_ms = 2000;
  int64_t dial_timeout_ms = 5000;
  size_t send_window_bytes = 64 * 1024;
  size_t rcv_buf_bytes = 32 * 1024;
  bool prewarm = true;
  std::string trace_prefix;  // #29a: per-session controller trace when set
};

struct DialRequest {
  uint64_t conn = 0;
  ProxyTarget target;
};

class Harness {
 public:
  explicit Harness(const Options& opt) {
    EngineConfig base;
    std::memset(base.key, 0x2A, sizeof(base.key));
    base.mtu = 1400;
    base.flush_grace_ms = opt.flush_grace_ms;
    base.dial_timeout_ms = opt.dial_timeout_ms;
    base.prewarm = opt.prewarm;
    base.send_window_bytes = opt.send_window_bytes;
    base.rcv_buf_bytes = opt.rcv_buf_bytes;

    EngineConfig cc = base;
    cc.role = EngineRole::kClient;
    cc.max_sessions = opt.client_max_sessions;
    cc.trace_prefix = opt.trace_prefix;
    EngineConfig sc = base;
    sc.role = EngineRole::kServer;
    sc.max_sessions = opt.server_max_sessions;
    client = std::make_unique<ProxyEngine>(cc, make_host(true));
    server = std::make_unique<ProxyEngine>(sc, make_host(false));
  }

  // ---- the virtual clock ----

  void step() {
    now_ms += kTickMs;
    if (auto_answer) {
      answer_pending(true, OpenError::kRefused);
    }
    // One pass of deliver-and-tick moves a datagram one hop; a second is needed
    // because the reply to it is produced during the first, and a third because
    // the engine's own follow-up (OPEN, OPEN_OK) rides that reply. Eight is room
    // for a cascade without ever letting the virtual clock stall.
    for (int round = 0; round < 8; ++round) {
      deliver();
      client->on_tick(now_ms);
      server->on_tick(now_ms);
      if (to_client.empty() && to_server.empty()) {
        break;
      }
    }
  }

  bool run_until(const std::function<bool()>& pred, int max_steps) {
    for (int i = 0; i < max_steps; ++i) {
      step();
      if (pred()) {
        return true;
      }
    }
    return false;
  }

  // ---- client side: the local application socket ----

  void local_open(uint64_t conn) { client->on_local_open(conn, kServerPeer, now_ms); }
  void local_send(uint64_t conn, const std::vector<uint8_t>& bytes) {
    client->on_local_bytes(conn, bytes.data(), bytes.size(), now_ms);
  }
  void local_send(uint64_t conn, const std::string& text) {
    local_send(conn, std::vector<uint8_t>(text.begin(), text.end()));
  }
  void local_close(uint64_t conn) { client->on_local_closed(conn, now_ms); }

  // ---- server side: the dialed target socket ----

  // Mirrors the reactor: bytes go to the engine only while it wants them, so a
  // stalled tunnel cannot make to_stream grow behind the engine's back.
  size_t target_send(uint64_t conn, const std::vector<uint8_t>& bytes) {
    if (!server->wants_target_read(conn)) {
      return 0;
    }
    server->on_target_bytes(conn, bytes.data(), bytes.size(), now_ms);
    return bytes.size();
  }
  void target_close(uint64_t conn) { server->on_target_closed(conn, now_ms); }

  // ---- dialling ----

  // Applies every dial the test has not answered yet. Called from step() in
  // auto-answer mode and directly otherwise, always between engine calls -- a
  // host callback that re-entered the engine would not be a real connect.
  void answer_dial(bool ok, OpenError err) { answer_pending(ok, err); }

  // ---- observation ----

  std::vector<uint8_t> app_bytes(uint64_t conn) const {
    const auto it = client_side.written.find(conn);
    return it == client_side.written.end() ? std::vector<uint8_t>() : it->second;
  }
  std::vector<uint8_t> target_bytes(uint64_t conn) const {
    const auto it = server_side.written.find(conn);
    return it == server_side.written.end() ? std::vector<uint8_t>() : it->second;
  }
  bool app_closed(uint64_t conn) const { return client_side.closed.count(conn) != 0; }
  bool target_closed(uint64_t conn) const { return server_side.closed.count(conn) != 0; }

  std::unique_ptr<ProxyEngine> client, server;
  // Every dial request the server asked for, kept for inspection; `dials` is a
  // log, not a queue, so a scenario can read the target after it was answered.
  std::vector<DialRequest> dials;
  std::vector<std::string> client_log, server_log;
  std::vector<uint8_t> last_from_client;  // for the salt replay case
  uint64_t datagrams = 0;
  bool auto_answer = true;
  size_t client_accept_limit = kNoLimit;  // 0 = the socket will not take anything
  size_t server_accept_limit = kNoLimit;
  bool mute_server = false;  // the peer vanished: client datagrams go nowhere
  int64_t now_ms = 1000;

  uint64_t first_dial_conn() const { return dials.empty() ? 0 : dials.front().conn; }
  uint64_t last_dial_conn() const { return dials.empty() ? 0 : dials.back().conn; }

 private:
  struct Side {
    std::map<uint64_t, std::vector<uint8_t>> written;
    std::set<uint64_t> closed;
  };

  EngineHost make_host(bool is_client) {
    EngineHost h;
    h.app_send = [this, is_client](uint64_t conn, const uint8_t* data, size_t len) {
      return app_send(is_client, conn, data, len);
    };
    h.app_close = [this, is_client](uint64_t conn) {
      (is_client ? client_side : server_side).closed.insert(conn);
    };
    h.wire_send = [this, is_client](uint64_t peer, const uint8_t* wire, size_t len) {
      std::vector<uint8_t> d(wire, wire + len);
      if (is_client) {
        last_from_client = d;
        to_server.push_back(std::move(d));
      } else {
        to_client.push_back(std::move(d));
      }
      ++datagrams;
      (void)peer;
    };
    h.dial = [this](uint64_t conn, const ProxyTarget& target) {
      dials.push_back(DialRequest{conn, target});
    };
    h.peer_key = [is_client](uint64_t peer) {
      return std::string(is_client ? "server:peer" : "client:peer") + std::to_string(peer);
    };
    h.new_salt = [this](uint8_t salt[Envelope::kSaltLen]) {
      std::memset(salt, 0, Envelope::kSaltLen);
      salt[Envelope::kSaltLen - 1] = static_cast<uint8_t>(salt_counter++);
    };
    h.log = [this, is_client](const std::string& line) {
      (is_client ? client_log : server_log).push_back(line);
    };
    return h;
  }

  size_t app_send(bool is_client, uint64_t conn, const uint8_t* data, size_t len) {
    const size_t limit = is_client ? client_accept_limit : server_accept_limit;
    if (limit == 0) {
      return 0;
    }
    const size_t take = limit < len ? limit : len;
    (is_client ? client_side : server_side).written[conn].insert(
        (is_client ? client_side : server_side).written[conn].end(), data, data + take);
    return take;
  }

  void answer_pending(bool ok, OpenError err) {
    for (; answered_ < dials.size(); ++answered_) {
      const DialRequest& d = dials[answered_];
      if (server->has_connection(d.conn)) {
        server->on_dial_result(d.conn, ok, err, now_ms);
      }
    }
  }

  void deliver() {
    std::vector<std::vector<uint8_t>> s2c;
    s2c.swap(to_client);
    for (const std::vector<uint8_t>& d : s2c) {
      client->on_wire(kServerPeer, d.data(), d.size(), now_ms);
    }
    std::vector<std::vector<uint8_t>> c2s;
    c2s.swap(to_server);
    if (!mute_server) {
      for (const std::vector<uint8_t>& d : c2s) {
        server->on_wire(kClientPeer, d.data(), d.size(), now_ms);
      }
    }
  }

  Side client_side, server_side;
  std::vector<std::vector<uint8_t>> to_client, to_server;
  uint8_t salt_counter = 1;
  size_t answered_ = 0;
};

// ---- wire builders ----

std::vector<uint8_t> greeting() { return {0x05, 0x01, 0x00}; }

std::vector<uint8_t> ipv4_bytes(const char* text) {
  std::vector<uint8_t> out;
  std::istringstream in(text);
  std::string part;
  while (std::getline(in, part, '.')) {
    out.push_back(static_cast<uint8_t>(std::stoul(part)));
  }
  return out;
}

std::vector<uint8_t> socks5_request(uint8_t cmd, uint8_t atyp, const std::vector<uint8_t>& addr,
                                    uint16_t port) {
  std::vector<uint8_t> out = {0x05, cmd, 0x00, atyp};
  out.insert(out.end(), addr.begin(), addr.end());
  out.push_back(static_cast<uint8_t>(port >> 8));
  out.push_back(static_cast<uint8_t>(port & 0xFF));
  return out;
}

std::string text_of(const std::vector<uint8_t>& bytes) {
  return std::string(bytes.begin(), bytes.end());
}

bool starts_with(const std::vector<uint8_t>& v, const std::string& prefix) {
  return v.size() >= prefix.size() &&
         std::equal(prefix.begin(), prefix.end(), v.begin());
}

bool logged(const std::vector<std::string>& lines, const std::string& needle) {
  for (const std::string& line : lines) {
    if (line.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

// ---- scenarios ----

// The whole of §4.1 plus §4.3: greeting, CONNECT, dial, OPEN_OK, payload in both
// directions, and a clean close on both ends.
void socks5_round_trip() {
  Harness h{Options()};
  h.local_open(kLocalConn);
  h.local_send(kLocalConn, greeting());
  CHECK_EQ(text_of(h.app_bytes(kLocalConn)), std::string("\x05\x00", 2));

  h.local_send(kLocalConn, socks5_request(0x01, 0x01, ipv4_bytes("203.0.113.7"), 8080));
  CHECK(h.run_until([&] { return !h.dials.empty(); }, 40));
  CHECK_EQ(h.dials.size(), 1u);
  CHECK_EQ(static_cast<int>(h.dials[0].target.atyp), static_cast<int>(kAtypIpv4));
  // An IPv4 target is the four raw wire bytes; only DOMAIN is carried as text.
  const std::vector<uint8_t> want_addr = ipv4_bytes("203.0.113.7");
  CHECK_EQ(h.dials[0].target.addr, std::string(want_addr.begin(), want_addr.end()));
  CHECK_EQ(static_cast<int>(h.dials[0].target.port), 8080);
  const uint64_t target_conn = h.dials[0].conn;

  CHECK(h.run_until([&] { return h.client->counters().tunnels == 1; }, 40));
  CHECK_EQ(h.server->counters().tunnels, 1u);
  // The SOCKS5 success reply is 10 bytes with rep=0 and an unspecified bind.
  const std::vector<uint8_t> reply = h.app_bytes(kLocalConn);
  CHECK_EQ(reply.size(), 12u);  // greeting reply (2) + connect reply (10)
  CHECK_EQ(static_cast<int>(reply[3]), 0x00);

  // Payload, both ways.
  h.local_send(kLocalConn, std::vector<uint8_t>{'G', 'E', 'T'});
  CHECK(h.run_until([&] { return h.target_bytes(target_conn).size() == 3; }, 20));
  h.target_send(target_conn, std::vector<uint8_t>{'2', '0', '0'});
  CHECK(h.run_until([&] { return h.app_bytes(kLocalConn).size() == 15; }, 20));
  CHECK_EQ(text_of(h.target_bytes(target_conn)), std::string("GET"));
  CHECK_EQ(text_of(h.app_bytes(kLocalConn)).substr(12), std::string("200"));

  // Close: the application hangs up, the fin crosses, and both tables empty out.
  h.local_close(kLocalConn);
  CHECK(h.run_until([&] {
    return h.client->counters().live == 0 && h.server->counters().live == 0;
  }, 80));
  CHECK(h.app_closed(kLocalConn));
  CHECK(h.target_closed(target_conn));
  CHECK_EQ(h.client->counters().idle_closed, 0u);
}

// §4.2 with a domain target: the name crosses the wire unresolved (§14 remote
// resolution) and the local socket gets the HTTP status line, not a SOCKS reply.
void http_connect_round_trip() {
  Harness h{Options()};
  h.local_open(kLocalConn);
  h.local_send(kLocalConn,
               "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
  CHECK(h.run_until([&] { return !h.dials.empty(); }, 40));
  CHECK_EQ(static_cast<int>(h.dials[0].target.atyp), static_cast<int>(kAtypDomain));
  CHECK_EQ(h.dials[0].target.addr, std::string("example.com"));
  CHECK_EQ(static_cast<int>(h.dials[0].target.port), 443);

  CHECK(h.run_until([&] { return h.client->counters().tunnels == 1; }, 40));
  CHECK(starts_with(h.app_bytes(kLocalConn), "HTTP/1.1 200 "));

  h.local_close(kLocalConn);
  CHECK(h.run_until([&] {
    return h.client->counters().live == 0 && h.server->counters().live == 0;
  }, 80));
}

// §4.3: every OpenError has to reach the application as the code the client
// understands, and only once. The HTTP path always answers 502.
void open_error_maps_to_the_local_reply() {
  struct Case {
    OpenError err;
    uint8_t rep;
  } cases[] = {
      {OpenError::kRefused, 0x05},
      {OpenError::kDns, 0x04},
      {OpenError::kTargetTimeout, 0x06},
      {OpenError::kNotSupported, 0x08},
      {OpenError::kTooManySessions, 0x02},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    Harness h{Options()};
    h.auto_answer = false;
    const uint64_t conn = kLocalConn + i;
    h.local_open(conn);
    h.local_send(conn, greeting());
    h.local_send(conn, socks5_request(0x01, 0x01, ipv4_bytes("198.51.100.1"), 80));
    CHECK(h.run_until([&] { return !h.dials.empty(); }, 40));
    const uint64_t target_conn = h.dials[0].conn;
    h.answer_dial(false, cases[i].err);
    CHECK(h.run_until([&] { return h.client->counters().open_failed == 1; }, 40));

    const std::vector<uint8_t> reply = h.app_bytes(conn);
    CHECK_EQ(reply.size(), 12u);
    CHECK_EQ(static_cast<int>(reply[3]), static_cast<int>(cases[i].rep));
    CHECK_EQ(h.client->counters().tunnels, 0u);

    // One refusal per tunnel: a late second answer must not double-count or
    // re-open anything (§7).
    const uint32_t before = h.server->counters().open_failed;
    h.server->on_dial_result(target_conn, true, cases[i].err, h.now_ms);
    CHECK_EQ(h.server->counters().open_failed, before);

    CHECK(h.run_until([&] {
      return h.client->counters().live == 0 && h.server->counters().live == 0;
    }, 120));
  }

  // HTTP CONNECT gets the gateway status instead of a SOCKS rep.
  Harness h{Options()};
  h.auto_answer = false;
  h.local_open(kLocalConn);
  h.local_send(kLocalConn, "CONNECT 198.51.100.1:80 HTTP/1.1\r\n\r\n");
  CHECK(h.run_until([&] { return !h.dials.empty(); }, 40));
  h.answer_dial(false, OpenError::kDns);
  CHECK(h.run_until([&] { return starts_with(h.app_bytes(kLocalConn), "HTTP/1.1 502"); }, 40));
}

// §4.1/§4.2: a local request the proxy will not carry is answered on the spot,
// before the tunnel exists, and the session is dropped again.
void malformed_local_requests() {
  {  // no acceptable method
    Harness h{Options()};
    h.local_open(kLocalConn);
    h.local_send(kLocalConn, std::vector<uint8_t>{0x05, 0x01, 0x02});
    CHECK_EQ(text_of(h.app_bytes(kLocalConn)), std::string("\x05\xFF", 2));
    CHECK(h.app_closed(kLocalConn));
    CHECK_EQ(h.client->counters().bad_entry, 1u);
    CHECK_EQ(h.client->counters().live, 0u);
  }
  {  // UDP ASSOCIATE is out of scope for this proxy (§1)
    Harness h{Options()};
    h.local_open(kLocalConn);
    h.local_send(kLocalConn, greeting());
    h.local_send(kLocalConn, socks5_request(0x03, 0x01, ipv4_bytes("198.51.100.1"), 1234));
    const std::vector<uint8_t> reply = h.app_bytes(kLocalConn);
    CHECK_EQ(reply.size(), 12u);
    CHECK_EQ(static_cast<int>(reply[3]), 0x07);
    CHECK_EQ(h.client->counters().bad_entry, 1u);
  }
  {  // ATYP IPv6 is supported, but a bogus length is not
    Harness h{Options()};
    h.local_open(kLocalConn);
    h.local_send(kLocalConn, greeting());
    h.local_send(kLocalConn, socks5_request(0x01, 0x09, ipv4_bytes("1.2.3.4"), 80));
    const std::vector<uint8_t> reply = h.app_bytes(kLocalConn);
    CHECK_EQ(static_cast<int>(reply[3]), 0x08);
    CHECK_EQ(h.client->counters().bad_entry, 1u);
  }
  {  // an HTTP request that is not CONNECT
    Harness h{Options()};
    h.local_open(kLocalConn);
    h.local_send(kLocalConn, "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
    CHECK(starts_with(h.app_bytes(kLocalConn), "HTTP/1.1 405"));
    CHECK(h.app_closed(kLocalConn));
    CHECK_EQ(h.client->counters().bad_entry, 1u);
  }
  {  // a CONNECT with no target port: the request never completes, the session dies
    Harness h{Options()};
    h.local_open(kLocalConn);
    h.local_send(kLocalConn, "CONNECT example.com HTTP/1.1\r\n\r\n");
    CHECK(starts_with(h.app_bytes(kLocalConn), "HTTP/1.1 400"));
    CHECK_EQ(h.client->counters().bad_entry, 1u);
  }
}

// §7: the engine holds the only application buffer, and the window it advertises
// is what stops the far end -- not an unbounded queue inside the host.
void backpressure_closes_the_window() {
  const size_t kRcvBuf = 16 * 1024;
  Options opt;
  opt.rcv_buf_bytes = kRcvBuf;
  opt.send_window_bytes = 32 * 1024;
  Harness h{opt};
  h.local_open(kLocalConn);
  h.local_send(kLocalConn, greeting());
  h.local_send(kLocalConn, socks5_request(0x01, 0x01, ipv4_bytes("198.51.100.9"), 80));
  CHECK(h.run_until([&] { return h.client->counters().tunnels == 1; }, 60));
  const uint64_t target_conn = h.first_dial_conn();

  h.client_accept_limit = 0;  // the local socket is not draining
  const size_t kSendWindow = opt.send_window_bytes;
  size_t pushed = 0;
  size_t refused = 0;
  const std::vector<uint8_t> chunk(2048, 0x5A);
  for (int i = 0; i < 120; ++i) {
    h.step();
    const size_t taken = h.target_send(target_conn, chunk);
    if (taken == 0) {
      ++refused;
    }
    pushed += taken;
  }
  // The gate closes: a host that respects wants_target_read cannot keep feeding
  // a stalled reader, and what the reader holds is its own receive buffer plus
  // the window already on the wire -- not everything that was offered.
  CHECK(refused > 60u);
  CHECK(pushed <= kRcvBuf + 2 * kSendWindow);
  CHECK(h.client->pending_app_bytes(kLocalConn) <= kRcvBuf + 2 * kSendWindow);

  // The window reopens and everything pushed before the stall arrives, in order.
  h.client_accept_limit = kNoLimit;
  const size_t want = pushed;
  CHECK(h.run_until([&] { return h.app_bytes(kLocalConn).size() >= 12 + want; }, 800));
  CHECK_EQ(h.app_bytes(kLocalConn).size(), 12 + want);
  CHECK_EQ(text_of(h.app_bytes(kLocalConn)).substr(12), std::string(want, 0x5A));

  h.local_close(kLocalConn);
  CHECK(h.run_until([&] {
    return h.client->counters().live == 0 && h.server->counters().live == 0;
  }, 120));
}

// §3: the plaintext salt routes a datagram to its session, and the source
// address binds it -- the envelope would authenticate either way, so the binding
// is the only thing that makes a hijacked salt useless.
void salt_routing_and_replay_binding() {
  Harness h{Options()};
  h.local_open(kLocalConn);
  h.local_send(kLocalConn, greeting());
  h.local_send(kLocalConn, socks5_request(0x01, 0x01, ipv4_bytes("198.51.100.9"), 80));
  CHECK(h.run_until([&] { return h.client->counters().tunnels == 1; }, 60));

  CHECK_EQ(h.client->counters().unknown_salt, 0u);
  CHECK_EQ(h.server->counters().salt_clash, 0u);

  // A live session's datagram, replayed from a different address.
  const std::vector<uint8_t> stolen = h.last_from_client;
  h.server->on_wire(kOtherPeer, stolen.data(), stolen.size(), h.now_ms);
  CHECK_EQ(h.server->counters().salt_clash, 1u);
  CHECK_EQ(h.server->counters().live, 0u);
  CHECK(logged(h.server_log, "salt re-bound to a new address"));

  // A datagram with no salt at all is neither routed nor fatal.
  const std::vector<uint8_t> stub{0x00, 0x01};
  h.client->on_wire(kServerPeer, stub.data(), stub.size(), h.now_ms);
  CHECK_EQ(h.client->counters().unknown_salt, 1u);
}

// §5 + §3: every connection is its own session, so a burst of short connections
// has to leave both tables exactly as it found them -- and one prewarm entry per
// peer, not one per connection.
void short_connections_leave_no_state_behind() {
  Options opt;
  opt.prewarm = true;
  Harness h{opt};
  const std::vector<uint8_t> payload = {'h', 'i'};
  for (size_t i = 0; i < 20; ++i) {
    const uint64_t conn = kLocalConn + i;
    h.local_open(conn);
    h.local_send(conn, greeting());
    h.local_send(conn, socks5_request(0x01, 0x01, ipv4_bytes("192.0.2.1"), 80));
    CHECK(h.run_until([&] { return h.client->counters().tunnels == i + 1; }, 80));
    h.local_send(conn, payload);
    CHECK(h.run_until([&] { return h.target_bytes(h.last_dial_conn()).size() >= 2; }, 40));
    h.local_close(conn);
    CHECK(h.run_until(
        [&] { return h.client->counters().live == 0 && h.server->counters().live == 0; }, 120));
  }
  CHECK_EQ(h.client->counters().established, 20u);
  CHECK_EQ(h.server->counters().established, 20u);
  CHECK_EQ(h.client->counters().tunnels, 20u);
  CHECK_EQ(h.client->counters().live, 0u);
  CHECK_EQ(h.server->counters().live, 0u);
  CHECK_EQ(h.client->counters().unknown_salt, 0u);
  CHECK_EQ(h.client->counters().handshake_failed, 0u);
  // One key for the client's single peer, reused by all 20 sessions.
  CHECK_EQ(h.client->prewarm_cache().size(), 1u);
  CHECK_EQ(h.server->prewarm_cache().size(), 1u);
}

// §4.3 + §7: the dial deadline is the engine's, not the host's, and the grace
// clock only fires when nothing is moving.
void dial_timeout_and_grace_clock() {
  {  // nobody answers the dial
    Options opt;
    opt.dial_timeout_ms = 500;
    opt.flush_grace_ms = 500;
    Harness h{opt};
    h.auto_answer = false;
    h.local_open(kLocalConn);
    h.local_send(kLocalConn, greeting());
    h.local_send(kLocalConn, socks5_request(0x01, 0x01, ipv4_bytes("192.0.2.7"), 80));
    CHECK(h.run_until([&] { return !h.dials.empty(); }, 20));
    CHECK(h.run_until([&] { return h.client->counters().open_failed == 1; }, 80));
    CHECK_EQ(static_cast<int>(h.app_bytes(kLocalConn)[3]), 0x06);
    // The client tears its session down as soon as the refusal is answered, so
    // the server's OPEN_ERR and fin are never acknowledged: it waits out its own
    // grace clock. That is the cost of one session per connection, and it is
    // bounded -- the tunnel does not linger.
    CHECK(h.run_until([&] {
      return h.client->counters().live == 0 && h.server->counters().live == 0;
    }, 120));
    CHECK(logged(h.server_log, "the peer stopped acknowledging"));
  }
  {  // the local socket stops taking bytes while the tunnel still has some
    Options opt;
    opt.flush_grace_ms = 250;
    Harness h{opt};
    h.local_open(kLocalConn);
    h.local_send(kLocalConn, greeting());
    h.local_send(kLocalConn, socks5_request(0x01, 0x01, ipv4_bytes("192.0.2.7"), 80));
    CHECK(h.run_until([&] { return h.client->counters().tunnels == 1; }, 60));
    h.client_accept_limit = 0;
    h.target_send(h.first_dial_conn(), std::vector<uint8_t>(64, 0x11));
    // The bytes still have to cross the wire before the local socket is asked
    // for them, and it refuses them there, not before.
    CHECK(h.run_until([&] { return h.client->pending_app_bytes(kLocalConn) > 0; }, 20));
    h.local_close(kLocalConn);
    CHECK(h.run_until([&] { return logged(h.client_log, "closed: "); }, 80));
    CHECK_EQ(h.client->counters().live, 0u);
    CHECK(logged(h.client_log, "the application socket stopped taking bytes"));
  }
  {  // a peer that vanished mid-flush: the fin leaves but is never acknowledged
    Options opt;
    opt.flush_grace_ms = 250;
    Harness h{opt};
    h.local_open(kLocalConn);
    h.local_send(kLocalConn, greeting());
    h.local_send(kLocalConn, socks5_request(0x01, 0x01, ipv4_bytes("192.0.2.7"), 80));
    CHECK(h.run_until([&] { return h.client->counters().tunnels == 1; }, 60));
    h.local_close(kLocalConn);
    h.mute_server = true;
    CHECK(h.run_until(
        [&] { return logged(h.client_log, "the peer stopped acknowledging"); }, 60));
    CHECK_EQ(h.client->counters().live, 0u);
    // The server discovers it on its own idle clock (idle_timeout_ms), which is
    // the stream's dead-peer path and already covered by stream_test.cc; 300s of
    // virtual time to watch an engine do nothing is not worth the runtime here.
  }
}

// §3: the session ceiling is enforced on both ends, and hitting it is a refusal
// the application can see rather than a silent drop.
void session_limits() {
  {  // client: the third local socket is closed by the host, not queued
    Options opt;
    opt.client_max_sessions = 2;
    Harness h{opt};
    h.local_open(kLocalConn);
    h.local_open(kLocalConn + 1);
    h.local_open(kLocalConn + 2);
    CHECK_EQ(h.client->counters().over_limit, 1u);
    CHECK(h.app_closed(kLocalConn + 2));
    CHECK_EQ(h.client->counters().live, 2u);
  }
  {  // server: the third inbound HELLO gets no session at all
    Options opt;
    opt.server_max_sessions = 2;
    Harness h{opt};
    for (size_t i = 0; i < 3; ++i) {
      const uint64_t conn = kLocalConn + i;
      h.local_open(conn);
      h.local_send(conn, greeting());
      h.local_send(conn, socks5_request(0x01, 0x01, ipv4_bytes("192.0.2.9"), 80));
    }
    CHECK(h.run_until([&] { return h.server->counters().over_limit >= 1u; }, 40));
    // Two sessions live, the third never got one: the client is still waiting
    // for a HELLO_ACK that will not come, which is the honest outcome -- the
    // server dropped the offer rather than refusing it with a protocol message.
    CHECK_EQ(h.server->counters().live, 2u);
  }
}

// #23 regression: a partially refusing reader (the Qt host's high-water write
// cap refuses most of each app_send, like a real socket buffer) must not
// wedge the tunnel. The reader's window closes to zero, then reopens as it
// drains; the sender has to discover the reopen (probe or fresh ACK) and
// finish the transfer. This is the loopback 2MiB stall seen with the GUI host.
void zero_window_recovery_after_partial_refusal() {
  Options opt;
  opt.rcv_buf_bytes = 32 * 1024;
  opt.send_window_bytes = 64 * 1024;
  Harness h{opt};
  h.local_open(kLocalConn);
  h.local_send(kLocalConn, greeting());
  h.local_send(kLocalConn, socks5_request(0x01, 0x01, ipv4_bytes("198.51.100.9"), 80));
  CHECK(h.run_until([&] { return h.client->counters().tunnels == 1; }, 60));
  const uint64_t target_conn = h.first_dial_conn();

  // The reader drains slowly: every app_send takes at most 4 KiB, which
  // regularly refuses the rest and drives the advertised window to zero.
  h.client_accept_limit = 4 * 1024;
  const std::vector<uint8_t> chunk(2048, 0x5A);
  size_t pushed = 0;
  for (int i = 0; i < 150; ++i) {
    h.step();
    pushed += h.target_send(target_conn, chunk);
  }
  CHECK(pushed > 64 * 1024);  // the transfer got well past one window

  // The reader catches up; everything pushed has to arrive, in order.
  h.client_accept_limit = kNoLimit;
  const size_t want = pushed;
  CHECK(h.run_until([&] { return h.app_bytes(kLocalConn).size() >= 12 + want; }, 4000));
  CHECK_EQ(h.app_bytes(kLocalConn).size(), 12 + want);
  CHECK_EQ(text_of(h.app_bytes(kLocalConn)).substr(12), std::string(want, 0x5A));
  CHECK(!logged(h.client_log, "closed"));

  h.local_close(kLocalConn);
  CHECK(h.run_until([&] {
    return h.client->counters().live == 0 && h.server->counters().live == 0;
  }, 120));
}

}  // namespace


// #29a (M2 §8.1 tail race): after a session dies, its salt keeps absorbing
// the peer's tail retransmissions as tombstones — on the client instead of
// unknown_salt, and on the server without rebirthing a phantom session from
// a stale datagram.
void salt_tombstone_absorbs_tail() {
  Harness h{Options()};
  h.local_open(kLocalConn);
  h.local_send(kLocalConn, greeting());
  h.local_send(kLocalConn, socks5_request(0x01, 0x01, ipv4_bytes("198.51.100.9"), 80));
  CHECK(h.run_until([&] { return h.client->counters().tunnels == 1; }, 60));
  const std::vector<uint8_t> tail = h.last_from_client;

  h.local_close(kLocalConn);
  CHECK(h.run_until([&] {
    return h.client->counters().live == 0 && h.server->counters().live == 0;
  }, 120));

  // The client's own tail (same salt) is a tombstone now, not unknown_salt.
  h.client->on_wire(kServerPeer, tail.data(), tail.size(), h.now_ms);
  CHECK_EQ(h.client->counters().salt_tombstone, 1u);
  CHECK_EQ(h.client->counters().unknown_salt, 0u);

  // The server arm: the same datagram would have been mistaken for a fresh
  // HELLO and rebirthed a phantom session before #29a.
  h.server->on_wire(kOtherPeer, tail.data(), tail.size(), h.now_ms);
  CHECK_EQ(h.server->counters().salt_tombstone, 1u);
  CHECK_EQ(h.server->counters().live, 0u);
  CHECK_EQ(h.server->counters().established, 1u);
}

// #29a: --trace wiring. A client engine with a trace prefix writes one JSONL
// controller-trace line per accepted FECSTAT report; the file closes with the
// session, and its lines decode back into TraceEntry.
void trace_sink_writes_controller_trace() {
  Options opt;
  opt.trace_prefix = "replay_trace_test";
  Harness h{opt};
  h.local_open(kLocalConn);
  h.local_send(kLocalConn, greeting());
  h.local_send(kLocalConn, socks5_request(0x01, 0x01, ipv4_bytes("198.51.100.9"), 80));
  CHECK(h.run_until([&] { return h.client->counters().tunnels == 1; }, 60));
  // Drive >= 256 data packets through the tunnel so a report fires at the 2s
  // cadence, then settle everything so the sink's file closes.
  const std::vector<uint8_t> bulk(400 * 1336, 0x5A);
  h.local_send(kLocalConn, bulk);
  CHECK(h.run_until([&] { return h.target_bytes(h.last_dial_conn()).size() >= bulk.size(); }, 400));
  // The in-memory transfer finishes well under the 2s report cadence; keep
  // the tunnel alive until a report actually fires.
  h.run_until([] { return false; }, 100);
  h.local_close(kLocalConn);
  CHECK(h.run_until([&] {
    return h.client->counters().live == 0 && h.server->counters().live == 0;
  }, 200));

  std::FILE* f = std::fopen("replay_trace_test.101.jsonl", "rb");
  CHECK(f != nullptr);
  char line[4096];
  CHECK(std::fgets(line, sizeof(line), f) != nullptr);
  std::fclose(f);
  fcp::TraceEntry e;
  fcp::TraceConfigSnapshot snapshot{};
  CHECK(fcp::decode_trace_line(line, &e));
  CHECK(e.stat.data_expected >= fcp::kMinSamplePackets);
  // The in-memory path is lossless, so the controller is rightly still OFF;
  // what this guards is the recording plumbing, not the decision.
  CHECK(e.k_after == 0);
  CHECK(std::remove("replay_trace_test.101.jsonl") == 0);
}

int main() {
  socks5_round_trip();
  http_connect_round_trip();
  open_error_maps_to_the_local_reply();
  malformed_local_requests();
  backpressure_closes_the_window();
  zero_window_recovery_after_partial_refusal();
  salt_routing_and_replay_binding();
  short_connections_leave_no_state_behind();
  dial_timeout_and_grace_clock();
  session_limits();
  salt_tombstone_absorbs_tail();
  trace_sink_writes_controller_trace();
  return fcp_test::finish();
}
