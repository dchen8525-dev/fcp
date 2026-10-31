#include "proxy_host.h"

#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkProxy>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>
#include <QtEndian>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

#include "fcp/proxy_proto.h"
#include "fcp/session.h"

namespace {

constexpr size_t kUdpBufBytes = 2048;        // one wire datagram
constexpr int kMaxUdpPerDrain = 128;         // a flood must not starve the tick
constexpr int kReadBufBytes = 16 * 1024;     // one socket read
constexpr int kMaxReadsPerReady = 16;        // per socket per readiness
constexpr int kMaxAcceptsPerReady = 32;
constexpr qint64 kAppWriteHighWater = 256 * 1024;  // QTcpSocket buffer cap (§7.8)
constexpr size_t kWireBacklogMax = 64;       // datagrams queued before resolve

std::string host_port_text(const QString& host, quint16 port) {
  return host.toStdString() + ":" + std::to_string(port);
}

// reactor.cc's open_error_for, with Qt's error codes instead of errno.
fcp::OpenError open_error_for(QAbstractSocket::SocketError err) {
  switch (err) {
    case QAbstractSocket::SocketTimeoutError:
      return fcp::OpenError::kTargetTimeout;
    case QAbstractSocket::HostNotFoundError:
      return fcp::OpenError::kDns;
    default:
      return fcp::OpenError::kRefused;
  }
}

}  // namespace

ProxyHost::ProxyHost(QObject* parent) : QObject(parent) {
  tick_.setTimerType(Qt::PreciseTimer);
  tick_.setInterval(fcp::kSessionTickMs);
  connect(&tick_, &QTimer::timeout, this, &ProxyHost::onTick);
  connect(&udp_, &QUdpSocket::readyRead, this, &ProxyHost::drainUdp);
  // Same buffer sizing the CLI reactor applies (reactor.cc TuneUdp): the
  // default 64 KiB receive buffer overflows under window-level bursts on a
  // 180 ms WAN path, and those drops never reach the loss injector's books.
  udp_.setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, 2 * 1024 * 1024);
  udp_.setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, 2 * 1024 * 1024);
}

ProxyHost::~ProxyHost() {
  if (engine_ != nullptr) {
    stop();
  }
}

void ProxyHost::start(const Options& options) {
  if (engine_ != nullptr) {
    return;
  }
  opt_ = options;

  cfg_ = fcp::EngineConfig{};
  cfg_.role = fcp::EngineRole::kClient;
  std::memcpy(cfg_.key, opt_.key.constData(), sizeof(cfg_.key));
  cfg_.mtu = static_cast<uint16_t>(opt_.mtu);
  cfg_.pinned_k = opt_.pinned_k;
  cfg_.prewarm = opt_.prewarm;
  if (opt_.window_kib > 0) {
    const size_t bytes = static_cast<size_t>(opt_.window_kib) * 1024;
    cfg_.send_window_bytes = bytes;
    cfg_.rcv_buf_bytes = bytes;
  }

  if (!udp_.bind(QHostAddress::AnyIPv4, 0)) {
    Q_EMIT finished(Result{false, QStringLiteral("UDP 绑定失败：%1").arg(udp_.errorString()), Stats{}});
    return;
  }

  listener_ = new QTcpServer(this);
  connect(listener_, &QTcpServer::newConnection, this, &ProxyHost::acceptLocal);
  connect(listener_, &QTcpServer::acceptError, this, [this](QAbstractSocket::SocketError) {
    Q_EMIT logLine(QStringLiteral("accept 失败：%1").arg(listener_->errorString()));
  });
  const QHostAddress listen_addr(opt_.listen);
  if (listen_addr.isNull() ||
      !listener_->listen(listen_addr, opt_.listen_port)) {
    Q_EMIT finished(Result{false,
                           QStringLiteral("监听 %1:%2 失败：%3")
                               .arg(opt_.listen)
                               .arg(opt_.listen_port)
                               .arg(listener_->errorString()),
                           Stats{}});
    udp_.close();
    delete listener_;
    listener_ = nullptr;
    return;
  }

  // Host callbacks. Per §7.11 they must not re-enter the engine: these thin
  // wrappers only touch sockets and queue ids; the engine owns the re-entry
  // guards (reap/flush_dials) internally.
  fcp::EngineHost host;
  host.app_send = [this](uint64_t conn, const uint8_t* data, size_t len) {
    return appSend(conn, data, len);
  };
  host.app_close = [this](uint64_t conn) { appClose(conn); };
  host.wire_send = [this](uint64_t peer, const uint8_t* wire, size_t len) {
    wireSend(peer, wire, len);
  };
  host.dial = [this](uint64_t conn, const fcp::ProxyTarget& target) {
    dial(conn, target);
  };
  host.peer_key = [this](uint64_t peer) { return peerKey(peer); };
  host.new_salt = [](uint8_t salt[fcp::Envelope::kSaltLen]) {
    for (size_t i = 0; i < fcp::Envelope::kSaltLen; ++i) {
      salt[i] = static_cast<uint8_t>(QRandomGenerator::global()->generate() & 0xFF);
    }
  };
  host.log = [this](const std::string& line) {
    Q_EMIT logLine(QString::fromStdString(line));
    // Scripted-run diagnostics: mirror engine lines to stderr when asked.
    static const bool to_stderr = qEnvironmentVariableIsSet("FCP_PROXY_HOST_LOG");
    if (to_stderr) {
      std::fprintf(stderr, "proxy: %s\n", line.c_str());
      std::fflush(stderr);
    }
  };
  engine_ = std::make_unique<fcp::ProxyEngine>(cfg_, host);
  clock_.start();
  wire_backlog_.clear();
  resolving_ = false;
  rate_ms_ = 0;
  rate_up_base_ = 0;
  rate_down_base_ = 0;
  up_rate_ = 0.0;
  down_rate_ = 0.0;
  tick_.start();

  setState(State::kStarting);
  emitStatsNow();
  Q_EMIT logLine(QStringLiteral("代理监听 %1:%2 → FCP %3:%4")
                     .arg(opt_.listen)
                     .arg(listener_->serverPort())
                     .arg(opt_.server)
                     .arg(opt_.port));
  resolveServer();
}

void ProxyHost::stop() {
  if (engine_ != nullptr) {
    finishEngine(true, QStringLiteral("已停止"));
  }
}

bool ProxyHost::running() const {
  return state_ == State::kStarting || state_ == State::kRunning;
}

void ProxyHost::resolveServer() {
  const QHostAddress literal(opt_.server);
  if (!literal.isNull() &&
      literal.protocol() != QAbstractSocket::UnknownNetworkLayerProtocol) {
    server_addr_ = literal;
    onServerReady();
    return;
  }
  if (resolving_) {
    return;
  }
  resolving_ = true;
  const QString name = opt_.server;
  QHostInfo::lookupHost(
      name, this, [this, name](const QHostInfo& info) {
        resolving_ = false;
        if (engine_ == nullptr) {
          return;
        }
        if (info.error() != QHostInfo::NoError ||
            info.addresses().isEmpty()) {
          finishEngine(false,
                       QStringLiteral("解析 %1 失败：%2")
                           .arg(name, info.errorString()));
          return;
        }
        // Prefer IPv4 (matches the bench client and the CLI's WAN use).
        QHostAddress picked;
        for (const QHostAddress& addr : info.addresses()) {
          if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
            picked = addr;
            break;
          }
          if (picked.isNull()) {
            picked = addr;
          }
        }
        server_addr_ = picked;
        onServerReady();
      });
}

void ProxyHost::onServerReady() {
  peer_key_ = QString::fromStdString(host_port_text(
      server_addr_.toString(), opt_.port)).toStdString();
  for (std::vector<uint8_t>& dg : wire_backlog_) {
    udp_.writeDatagram(reinterpret_cast<const char*>(dg.data()),
                       static_cast<qint64>(dg.size()), server_addr_, opt_.port);
  }
  wire_backlog_.clear();
  setState(State::kRunning);
  emitStatsNow();
  Q_EMIT logLine(
      QStringLiteral("FCP 服务端地址就绪：%1:%2")
          .arg(server_addr_.toString())
          .arg(opt_.port));
}

// ---- EngineHost callbacks -------------------------------------------------

size_t ProxyHost::appSend(uint64_t conn, const uint8_t* data, size_t len) {
  QTcpSocket* sock = nullptr;
  const auto local = locals_.constFind(conn);
  if (local != locals_.constEnd()) {
    sock = local.value();
  } else {
    const auto target = targets_.constFind(conn);
    if (target != targets_.constEnd()) {
      sock = target.value().sock;
    }
  }
  if (sock == nullptr || len == 0) {
    return 0;
  }
  if (qEnvironmentVariableIsSet("FCP_PROXY_NO_CAP")) {
    // BISECT: accept everything (Qt buffers unboundedly) to isolate a stall.
    if (sock->write(reinterpret_cast<const char*>(data),
                    static_cast<qint64>(len)) < 0) {
      return 0;
    }
    return len;
  }
  // QTcpSocket::write() never refuses; capping the buffer here is what keeps
  // the §7.8 invariant (engine queue + socket buffer ≤ window bound) intact.
  const qint64 room = kAppWriteHighWater - sock->bytesToWrite();
  if (room <= 0) {
    return 0;
  }
  const size_t accepted =
      std::min<size_t>(len, static_cast<size_t>(room));
  if (sock->write(reinterpret_cast<const char*>(data),
                  static_cast<qint64>(accepted)) < 0) {
    return 0;
  }
  return accepted;
}

void ProxyHost::appClose(uint64_t conn) {
  // The engine only calls this once the tunnel is done, so whatever is still
  // queued for the application socket is real data: disconnectFromHost()
  // flushes the write buffer before closing, the way the CLI's closesocket()
  // does. abort() would drop those bytes (seen live as truncated downloads,
  // ~380 bytes lost at the tail).
  auto local = locals_.constFind(conn);
  if (local != locals_.constEnd()) {
    QTcpSocket* sock = local.value();
    locals_.erase(local);
    // disconnectFromHost flushes the write buffer, then closes; the
    // disconnected handler deleteLater()s the socket. deleteLater() here
    // instead could beat the flush and drop its tail bytes (seen live as
    // truncated downloads).
    sock->disconnectFromHost();
  }
  auto target = targets_.constFind(conn);
  if (target != targets_.constEnd()) {
    QTcpSocket* sock = target.value().sock;
    targets_.erase(target);
    if (sock != nullptr) {
      sock->disconnectFromHost();
    }
  }
}

void ProxyHost::wireSend(uint64_t, const uint8_t* wire, size_t len) {
  if (server_addr_.isNull()) {
    if (wire_backlog_.size() < kWireBacklogMax) {
      wire_backlog_.emplace_back(wire, wire + len);
    } else if (!wire_backlog_.empty()) {
      Q_EMIT logLine("服务端地址未就绪，首批 wire 报文已丢弃");
    }
    return;
  }
  udp_.writeDatagram(reinterpret_cast<const char*>(wire),
                     static_cast<qint64>(len), server_addr_, opt_.port);
}

void ProxyHost::dial(uint64_t conn, const fcp::ProxyTarget& target) {
  QString host;
  quint16 port = 0;
  if (target.atyp == fcp::kAtypDomain) {
    host = QString::fromStdString(target.addr);
  } else if (target.atyp == fcp::kAtypIpv4 && target.addr.size() == 4) {
    quint32 v4 = 0;
    std::memcpy(&v4, target.addr.data(), 4);
    host = QHostAddress(qFromBigEndian(v4)).toString();
  } else if (target.atyp == fcp::kAtypIpv6 && target.addr.size() == 16) {
    host = QHostAddress(reinterpret_cast<const quint8*>(target.addr.data())).toString();
  }
  port = target.port;  // parser already converted to host order
  if (host.isEmpty() || port == 0) {
    engine_->on_dial_result(conn, false, fcp::OpenError::kDns,
                            static_cast<int64_t>(clock_.elapsed()));
    return;
  }

  if (target.atyp != fcp::kAtypDomain) {
    connectTarget(conn, QHostAddress(host), port);
    return;
  }
  QHostInfo::lookupHost(
      host, this, [this, conn, port, host](const QHostInfo& info) {
        if (engine_ == nullptr || !engine_->has_connection(conn)) {
          return;  // the tunnel died while the name was in flight
        }
        if (info.error() != QHostInfo::NoError ||
            info.addresses().isEmpty()) {
          Q_EMIT logLine(QStringLiteral("conn %1 解析 %2 失败：%3")
                             .arg(conn)
                             .arg(host, info.errorString()));
          engine_->on_dial_result(conn, false, fcp::OpenError::kDns,
                                  static_cast<int64_t>(clock_.elapsed()));
          return;
        }
        QHostAddress picked;
        for (const QHostAddress& addr : info.addresses()) {
          if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
            picked = addr;
            break;
          }
          if (picked.isNull()) {
            picked = addr;
          }
        }
        connectTarget(conn, picked, port);
      });
}

void ProxyHost::connectTarget(uint64_t conn, const QHostAddress& addr,
                              quint16 port) {
  if (engine_ == nullptr || !engine_->has_connection(conn)) {
    return;
  }
  auto* sock = new QTcpSocket(this);
  sock->setProxy(QNetworkProxy::NoProxy);
  TargetSock entry;
  entry.sock = sock;
  targets_.insert(conn, entry);
  connect(sock, &QTcpSocket::connected, this, [this, conn] {
    auto it = targets_.find(conn);
    if (it == targets_.end() || it.value().reported || engine_ == nullptr) {
      return;
    }
    it.value().reported = true;
    engine_->on_dial_result(conn, true, fcp::OpenError::kRefused,
                            static_cast<int64_t>(clock_.elapsed()));
    Q_EMIT logLine(QStringLiteral("conn %1 目标已连接").arg(conn));
  });
  connect(
      sock, &QTcpSocket::errorOccurred, this,
      [this, conn](QAbstractSocket::SocketError err) {
        auto it = targets_.find(conn);
        if (it == targets_.end() || it.value().reported || engine_ == nullptr) {
          return;
        }
        it.value().reported = true;
        Q_EMIT logLine(QStringLiteral("conn %1 连接目标失败：%2")
                           .arg(conn)
                           .arg(it.value().sock != nullptr
                                    ? it.value().sock->errorString()
                                    : QString()));
        engine_->on_dial_result(conn, false, open_error_for(err),
                                static_cast<int64_t>(clock_.elapsed()));
      });
  connect(sock, &QTcpSocket::readyRead, this, [this, conn] {
    readTarget(conn);
  });
  connect(sock, &QTcpSocket::disconnected, this, [this, conn] {
    if (engine_ != nullptr && targets_.contains(conn)) {
      engine_->on_target_closed(conn,
                                static_cast<int64_t>(clock_.elapsed()));
    }
    targets_.remove(conn);
    if (auto* s = sender()) {
      s->deleteLater();
    }
  });
  sock->connectToHost(addr, port);
}

std::string ProxyHost::peerKey(uint64_t) {
  // Client side: the wire peer is the FCP server (§5).
  return peer_key_.empty() ? std::string("pending") : peer_key_;
}

// ---- sockets ---------------------------------------------------------------

void ProxyHost::acceptLocal() {
  if (engine_ == nullptr) {
    return;
  }
  const int64_t now = static_cast<int64_t>(clock_.elapsed());
  for (int i = 0; i < kMaxAcceptsPerReady; ++i) {
    QTcpSocket* sock = listener_->nextPendingConnection();
    if (sock == nullptr) {
      return;
    }
    sock->setProxy(QNetworkProxy::NoProxy);
    const uint64_t conn = next_local_conn_++;
    locals_.insert(conn, sock);
    const uint64_t conn_copy = conn;
    connect(sock, &QTcpSocket::readyRead, this, [this, conn_copy] {
      readLocal(conn_copy);
    });
    connect(sock, &QTcpSocket::bytesWritten, this, [this, conn_copy](qint64) {
      if (engine_ != nullptr && locals_.contains(conn_copy)) {
        engine_->on_app_writable(conn_copy,
                                 static_cast<int64_t>(clock_.elapsed()));
      }
    });
    connect(sock, &QTcpSocket::disconnected, this, [this, conn_copy] {
      if (engine_ != nullptr && locals_.contains(conn_copy)) {
        engine_->on_local_closed(conn_copy,
                                 static_cast<int64_t>(clock_.elapsed()));
      }
      locals_.remove(conn_copy);
      if (auto* s = sender()) {
        s->deleteLater();
      }
    });
    connect(sock, &QTcpSocket::errorOccurred, this,
            [this, conn_copy](QAbstractSocket::SocketError err) {
              if (err == QAbstractSocket::RemoteHostClosedError ||
                  engine_ == nullptr || !locals_.contains(conn_copy)) {
                return;  // disconnected() owns the teardown path
              }
              Q_EMIT logLine(QStringLiteral("conn %1 本地套接字错误：%2")
                                 .arg(conn_copy)
                                 .arg(locals_.value(conn_copy) != nullptr
                                          ? locals_.value(conn_copy)->errorString()
                                          : QString()));
            });
    engine_->on_local_open(conn, 0, now);
  }
}

void ProxyHost::readLocal(uint64_t conn) {
  auto it = locals_.constFind(conn);
  if (it == locals_.constEnd() || engine_ == nullptr) {
    return;
  }
  QTcpSocket* sock = it.value();
  uint8_t buf[kReadBufBytes];
  const int64_t now = static_cast<int64_t>(clock_.elapsed());
  for (int i = 0; i < kMaxReadsPerReady && sock->bytesAvailable() > 0; ++i) {
    if (!engine_->has_connection(conn) || !engine_->wants_local_read(conn)) {
      return;  // stream window closed: leave the bytes in TCP
    }
    const qint64 n = sock->read(reinterpret_cast<char*>(buf), sizeof(buf));
    if (n > 0) {
      engine_->on_local_bytes(conn, buf, static_cast<size_t>(n), now);
      continue;
    }
    if (n == 0) {
      return;
    }
    // n < 0: error path; errorOccurred/disconnected finish the conn.
    return;
  }
}

void ProxyHost::readTarget(uint64_t conn) {
  auto it = targets_.constFind(conn);
  if (it == targets_.constEnd() || engine_ == nullptr) {
    return;
  }
  QTcpSocket* sock = it.value().sock;
  if (sock == nullptr) {
    return;
  }
  uint8_t buf[kReadBufBytes];
  const int64_t now = static_cast<int64_t>(clock_.elapsed());
  for (int i = 0; i < kMaxReadsPerReady && sock->bytesAvailable() > 0; ++i) {
    if (!engine_->has_connection(conn) || !engine_->wants_target_read(conn)) {
      return;
    }
    const qint64 n = sock->read(reinterpret_cast<char*>(buf), sizeof(buf));
    if (n > 0) {
      engine_->on_target_bytes(conn, buf, static_cast<size_t>(n), now);
      continue;
    }
    return;
  }
}

void ProxyHost::drainUdp() {
  if (engine_ == nullptr) {
    return;
  }
  uint8_t buf[kUdpBufBytes];
  const int64_t now = static_cast<int64_t>(clock_.elapsed());
  // Qt's readyRead is edge-triggered: leaving pending datagrams unread would
  // stall forever once the sender goes quiet, so drain to empty here and let
  // on_tick re-check as a second line of defence.
  for (int i = 0; i < kMaxUdpPerDrain && udp_.hasPendingDatagrams(); ++i) {
    const qint64 n = udp_.readDatagram(reinterpret_cast<char*>(buf), sizeof(buf));
    if (n <= 0) {
      return;
    }
    engine_->on_wire(0, buf, static_cast<size_t>(n), now);
  }
}

// ---- tick ------------------------------------------------------------------

void ProxyHost::onTick() {
  if (engine_ == nullptr) {
    return;
  }
  const int64_t now = static_cast<int64_t>(clock_.elapsed());
  // Level-trigger safety net: readiness signals are edge-triggered in Qt, so
  // bytes left behind by a closed stream window (or a burst above the per-event
  // read budget) are picked up here once the window reopens.
  drainUdp();
  for (auto it = locals_.constBegin(); it != locals_.constEnd(); ++it) {
    QTcpSocket* sock = it.value();
    if (sock != nullptr && sock->bytesAvailable() > 0 &&
        engine_->wants_local_read(it.key())) {
      readLocal(it.key());
    }
  }
  for (auto it = targets_.constBegin(); it != targets_.constEnd(); ++it) {
    QTcpSocket* sock = it.value().sock;
    if (sock != nullptr && sock->bytesAvailable() > 0 &&
        engine_->wants_target_read(it.key())) {
      readTarget(it.key());
    }
  }
  sweepDials();
  // A window that reopened between events still has to make progress (same
  // reason the reactor flushes every tick, engine.h on_app_writable).
  for (auto it = locals_.constBegin(); it != locals_.constEnd(); ++it) {
    if (engine_->pending_app_bytes(it.key()) != 0) {
      engine_->on_app_writable(it.key(), now);
    }
  }
  for (auto it = targets_.constBegin(); it != targets_.constEnd(); ++it) {
    if (engine_->pending_app_bytes(it.key()) != 0) {
      engine_->on_app_writable(it.key(), now);
    }
  }
  engine_->on_tick(now);
  tickRates();
}

void ProxyHost::sweepDials() {
  // The engine's dial deadline may already have killed the tunnel while Qt's
  // connect is still pending; abort those sockets (reactor: expire_connects).
  if (targets_.isEmpty()) {
    return;
  }
  const int64_t now = static_cast<int64_t>(clock_.elapsed());
  QList<uint64_t> dead;
  for (auto it = targets_.constBegin(); it != targets_.constEnd(); ++it) {
    if (!engine_->has_connection(it.key())) {
      dead.append(it.key());
    }
  }
  for (uint64_t conn : dead) {
    Q_UNUSED(now);
    auto it = targets_.constFind(conn);
    QTcpSocket* sock = it.value().sock;
    targets_.erase(it);
    if (sock != nullptr) {
      sock->abort();
      sock->deleteLater();
    }
    Q_EMIT logLine(QStringLiteral("conn %1 拨号套接字已清扫").arg(conn));
  }
}

// ---- lifecycle / stats -----------------------------------------------------

void ProxyHost::finishEngine(bool ok, const QString& why) {
  tick_.stop();
  engine_.reset();
  if (listener_ != nullptr) {
    listener_->close();
    listener_->deleteLater();
    listener_ = nullptr;
  }
  udp_.close();
  auto killSockets = [](QHash<uint64_t, QTcpSocket*>& m) {
    for (auto it = m.begin(); it != m.end(); ++it) {
      it.value()->abort();
      it.value()->deleteLater();
    }
    m.clear();
  };
  killSockets(locals_);
  QHash<uint64_t, QTcpSocket*> target_socks;
  for (auto it = targets_.begin(); it != targets_.end(); ++it) {
    if (it.value().sock != nullptr) {
      target_socks.insert(it.key(), it.value().sock);
    }
  }
  targets_.clear();
  killSockets(target_socks);
  server_addr_ = QHostAddress();
  wire_backlog_.clear();
  setState(State::kIdle);
  Result result;
  result.ok = ok;
  result.error = why;
  result.stats = Stats{};
  emitStatsNow();
  Q_EMIT finished(result);
  Q_EMIT logLine(QStringLiteral("代理已结束：%1").arg(why));
}

void ProxyHost::setState(State state) {
  state_ = state;
}

void ProxyHost::emitStatsNow() {
  Stats stats;
  stats.state = state_;
  stats.elapsed_ms = engine_ != nullptr ? static_cast<qint64>(clock_.elapsed()) : 0;
  if (engine_ != nullptr) {
    const auto& c = engine_->counters();
    stats.live = static_cast<quint32>(c.live);
    stats.established = static_cast<quint32>(c.established);
    stats.tunnels = static_cast<quint32>(c.tunnels);
    stats.up_bytes = c.bytes_tx;
    stats.down_bytes = c.bytes_rx;
    stats.bad_entry = c.bad_entry;
    stats.open_failed = c.open_failed;
    stats.handshake_failed = c.handshake_failed;
    stats.salt_clash = c.salt_clash;
    stats.unknown_salt = c.unknown_salt;
    stats.reset = c.reset;
    stats.up_mbps = up_rate_;
    stats.down_mbps = down_rate_;
  }
  stats.listen_port = listener_ != nullptr ? listener_->serverPort() : opt_.listen_port;
  Q_EMIT statsUpdated(stats);
}

void ProxyHost::tickRates() {
  const qint64 now = clock_.elapsed();
  // Scripted-run diagnostics: a per-second counters trace from the client's
  // point of view, to show which side freezes when a transfer stalls.
  static const bool trace = qEnvironmentVariableIsSet("FCP_PROXY_HOST_LOG");
  if (trace && now >= trace_ms_ + 1000) {
    trace_ms_ = now;
    const auto& c = engine_ != nullptr ? engine_->counters() : last_counters_;
    std::fprintf(stderr,
                 "trace t=%lld live=%u est=%u tun=%u tx=%llu rx=%llu\n",
                 static_cast<long long>(now), static_cast<unsigned>(c.live),
                 static_cast<unsigned>(c.established),
                 static_cast<unsigned>(c.tunnels),
                 static_cast<unsigned long long>(c.bytes_tx),
                 static_cast<unsigned long long>(c.bytes_rx));
    if (engine_ != nullptr) {
      for (auto it = locals_.constBegin(); it != locals_.constEnd(); ++it) {
        QTcpSocket* s = it.value();
        std::fprintf(stderr,
                     "  conn %llu state=%d btw=%lld avail=%lld app_in=%zu\n",
                     static_cast<unsigned long long>(it.key()),
                     static_cast<int>(s->state()),
                     s->bytesToWrite(), s->bytesAvailable(),
                     engine_->pending_app_bytes(it.key()));
      }
    }
    std::fflush(stderr);
  }
  if (rate_ms_ == 0) {
    rate_ms_ = now;
    rate_up_base_ = engine_ != nullptr ? engine_->counters().bytes_tx : 0;
    rate_down_base_ = engine_ != nullptr ? engine_->counters().bytes_rx : 0;
    return;
  }
  const qint64 dt = now - rate_ms_;
  if (dt < 100) {
    return;
  }
  const auto& c = engine_->counters();
  const double up_mbps =
      static_cast<double>(c.bytes_tx - rate_up_base_) * 8.0 * 1000.0 /
      (static_cast<double>(dt) * 1000000.0);
  const double down_mbps =
      static_cast<double>(c.bytes_rx - rate_down_base_) * 8.0 * 1000.0 /
      (static_cast<double>(dt) * 1000000.0);
  rate_ms_ = now;
  rate_up_base_ = c.bytes_tx;
  rate_down_base_ = c.bytes_rx;
  up_rate_ = up_mbps;
  down_rate_ = down_mbps;
  emitStatsNow();
}
