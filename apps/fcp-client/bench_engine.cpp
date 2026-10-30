#include "bench_engine.h"

#include <QAbstractSocket>
#include <QHostAddress>
#include <QHostInfo>
#include <QVariant>

#include <algorithm>
#include <cstring>

#include "fcp/handshake.h"

namespace {

constexpr qint64 kUpStartMs = 1000;
constexpr qint64 kUpEndMs = 8000;
constexpr qint64 kTotalMs = 18000;
constexpr qint64 kHandshakeLimitMs = 6000;
constexpr qint64 kMeetTimeoutMs = 15000;
constexpr double kPhaseSeconds = (kUpEndMs - kUpStartMs) / 1000.0;
constexpr int kSocketBufferBytes = 4 * 1024 * 1024;

constexpr quint8 kMagic[8] = {'F', 'C', 'P', 'B', 'E', 'N', 'C', 'H'};

QString fmtMbps(double v) { return QString::number(v, 'f', 2); }

}  // namespace

BenchEngine::BenchEngine(QObject* parent) : QObject(parent) {
  tick_.setTimerType(Qt::PreciseTimer);
  tick_.setInterval(5);
  connect(&tick_, &QTimer::timeout, this, &BenchEngine::onTick);
  connect(&socket_, &QAbstractSocket::errorOccurred, this,
          [this](QAbstractSocket::SocketError error) {
            if (socket_error_logged_) {
              return;
            }
            if (error == QAbstractSocket::ConnectionRefusedError ||
                error == QAbstractSocket::NetworkError) {
              // A closed UDP port on Windows surfaces the ICMP reset here; it
              // is not fatal (the peer may simply not be listening yet).
              socket_error_logged_ = true;
              Q_EMIT logLine(QStringLiteral("UDP 套接字错误：%1").arg(socket_.errorString()));
            }
          });
}

BenchEngine::~BenchEngine() = default;

bool BenchEngine::running() const {
  switch (state_) {
    case State::kIdle:
    case State::kFinished:
    case State::kFailed:
      return false;
    default:
      return true;
  }
}

void BenchEngine::start(const Options& options) {
  if (running()) {
    cleanupRun();
  }
  opt_ = options;
  state_ = State::kIdle;
  last_result_ = Result{};

  tx_data_bytes_ = 0;
  tx_segs_ = 0;
  tx_wire_bytes_ = 0;
  tx_parity_ = 0;
  tx_oob_ = 0;
  tx_fail_ = 0;
  rx_datagrams_ = 0;
  rx_data_bytes_ = 0;
  rx_segs_ = 0;
  rx_data_wire_ = 0;
  rx_corrupt_ = 0;
  rx_valid_segs_ = 0;
  rx_max_sn_ = 0;

  t0_ms_ = 0;
  next_tick_ms_ = 0;
  est_ = -1;
  met_ = false;
  meet_sent_ = 0;
  next_magic_ms_ = 0;
  tokens_ = 0.0;
  token_ms_ = 0;
  up_sending_ = false;
  down_started_ = false;
  sn_ = 1;
  rate_ms_ = 0;
  rate_up_base_ = 0;
  rate_down_base_ = 0;
  up_rate_ = 0.0;
  down_rate_ = 0.0;
  up_peak_ = 0.0;
  down_peak_ = 0.0;
  socket_error_logged_ = false;
  local_port_ = 0;

  clock_.start();
  setState(State::kResolving);
  Q_EMIT logLine(QStringLiteral("解析主机 %1…").arg(opt_.host));

  QHostInfo::lookupHost(opt_.host, this, [this](const QHostInfo& info) {
    if (state_ != State::kResolving) {
      return;
    }
    if (info.error() != QHostInfo::NoError || info.addresses().isEmpty()) {
      failRun(QStringLiteral("域名解析失败：%1").arg(info.errorString()));
      return;
    }
    QHostAddress addr;
    bool found = false;
    for (const QHostAddress& candidate : info.addresses()) {
      if (candidate.protocol() == QAbstractSocket::IPv4Protocol) {
        addr = candidate;
        found = true;
        break;
      }
    }
    if (!found) {
      failRun(QStringLiteral("仅支持 IPv4 服务端地址"));
      return;
    }
    connectTo(addr);
  });

  tick_.start();
}

void BenchEngine::stop() {
  if (!running()) {
    return;
  }
  Q_EMIT logLine(QStringLiteral("已停止"));
  cleanupRun();
  setState(State::kIdle);
}

void BenchEngine::connectTo(const QHostAddress& addr) {
  socket_.setSocketOption(QAbstractSocket::SendBufferSizeSocketOption,
                          QVariant(kSocketBufferBytes));
  socket_.setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption,
                          QVariant(kSocketBufferBytes));
  socket_.connectToHost(addr, opt_.port);
  met_ = false;
  meet_sent_ = 0;
  next_magic_ms_ = 0;
  setState(State::kRendezvous);
  Q_EMIT logLine(QStringLiteral("会合中：%1:%2").arg(addr.toString()).arg(opt_.port));
}

void BenchEngine::beginSession() {
  fcp::SessionConfig cfg;
  std::memcpy(cfg.key, opt_.key.constData(), 16);
  std::memcpy(cfg.salt, opt_.salt.constData(), 8);
  cfg.send_direction = fcp::Direction::kC2S;
  cfg.recv_direction = fcp::Direction::kS2C;
  cfg.d = 10;
  cfg.p = 3;
  cfg.mtu = static_cast<uint16_t>(opt_.mtu);
  cfg.pinned_k = opt_.pinned_k;

  session_ = std::make_unique<fcp::Session>(
      cfg,
      [this](const uint8_t* wire, size_t len, fcp::SymbolType type) {
        if (type == fcp::SymbolType::kData) {
          tx_wire_bytes_ += len;
        } else if (type == fcp::SymbolType::kParity) {
          ++tx_parity_;
        } else {
          ++tx_oob_;
        }
        if (socket_.state() != QAbstractSocket::ConnectedState) {
          ++tx_fail_;
          return;
        }
        const qint64 n = socket_.write(reinterpret_cast<const char*>(wire),
                                       static_cast<qint64>(len));
        if (n != static_cast<qint64>(len)) {
          ++tx_fail_;
        }
      },
      [this](const uint8_t* payload, size_t len) {
        ++rx_segs_;
        rx_data_bytes_ += len;
        if (!payloadOk(payload, len)) {
          ++rx_corrupt_;
          return;
        }
        ++rx_valid_segs_;
        // The server numbers its download stream from 1 without gaps, so the
        // largest SN seen is exactly how many segments it sent.
        const quint32 sn = static_cast<quint32>(payload[12]) |
                           (static_cast<quint32>(payload[13]) << 8) |
                           (static_cast<quint32>(payload[14]) << 16) |
                           (static_cast<quint32>(payload[15]) << 24);
        rx_max_sn_ = std::max(rx_max_sn_, sn);
      },
      [this](const std::string& line) { Q_EMIT logLine(QString::fromStdString(line)); });

  t0_ms_ = clock_.elapsed();
  next_tick_ms_ = 0;
  est_ = -1;
  session_->start(0);
  setState(State::kHandshake);
  Q_EMIT logLine(QStringLiteral("会合完成，开始握手"));
}

void BenchEngine::onTick() {
  if (state_ == State::kIdle || state_ == State::kFinished || state_ == State::kFailed ||
      state_ == State::kResolving) {
    return;
  }
  const qint64 now = clock_.elapsed();
  if (!session_) {
    pumpRendezvous(now);
    tickRates(now);
    return;
  }

  const qint64 rel = now - t0_ms_;
  pumpSession(rel);

  if (rel >= next_tick_ms_) {
    session_->on_tick(rel);
    next_tick_ms_ = rel + fcp::kSessionTickMs;
  }
  if (!session_) {
    return;  // pumpSession may have ended the run
  }
  if (session_->state() == fcp::HandshakeState::kFailed) {
    failRun(QStringLiteral("握手失败：%1")
                .arg(QString::fromUtf8(fcp::handshake_error_text(session_->error()))));
    return;
  }
  if (est_ < 0 && session_->established()) {
    est_ = rel;
    const fcp::NegotiatedParams& params = session_->params();
    Q_EMIT logLine(QStringLiteral("握手完成：%1 ms（D=%2 P=%3）")
                     .arg(rel)
                     .arg(params.d)
                     .arg(params.p));
  }
  if (est_ < 0 && rel > kHandshakeLimitMs) {
    failRun(QStringLiteral("握手超时（6 秒）"));
    return;
  }

  if (est_ >= 0) {
    drivePhases(rel);
  }
  if (session_) {
    tickRates(now);
  }
}

void BenchEngine::pumpRendezvous(qint64 now) {
  char buf[2048];
  while (socket_.hasPendingDatagrams()) {
    const qint64 n = socket_.readDatagram(buf, sizeof(buf));
    if (n <= 0) {
      break;
    }
    ++rx_datagrams_;
    if (n == static_cast<qint64>(sizeof(kMagic)) &&
        std::memcmp(buf, kMagic, sizeof(kMagic)) == 0) {
      met_ = true;
    }
  }
  if (now >= next_magic_ms_) {
    if (socket_.state() == QAbstractSocket::ConnectedState) {
      socket_.write(reinterpret_cast<const char*>(kMagic), sizeof(kMagic));
      ++meet_sent_;
    }
    next_magic_ms_ = now + 50;
  }
  if (met_ && meet_sent_ >= 3) {
    beginSession();
    return;
  }
  if (now > kMeetTimeoutMs) {
    failRun(QStringLiteral("会合超时：请确认服务端已运行 fcp_bench server"));
  }
}

void BenchEngine::pumpSession(qint64 rel) {
  const size_t data_wire_len = 36 + static_cast<size_t>(opt_.seg);
  char buf[2048];
  while (socket_.hasPendingDatagrams()) {
    const qint64 n = socket_.readDatagram(buf, sizeof(buf));
    if (n <= 0) {
      break;
    }
    ++rx_datagrams_;
    // Late rendezvous magics are not session traffic; feeding them to the
    // session would book a bogus auth failure.
    if (n == static_cast<qint64>(sizeof(kMagic)) &&
        std::memcmp(buf, kMagic, sizeof(kMagic)) == 0) {
      continue;
    }
    if (n == static_cast<qint64>(data_wire_len)) {
      ++rx_data_wire_;
      if (rel >= kUpEndMs && !down_started_) {
        down_started_ = true;
        setState(State::kDownload);
        Q_EMIT logLine(QStringLiteral("检测到下行流"));
      }
    }
    session_->on_wire(reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(n), rel);
  }
}

void BenchEngine::drivePhases(qint64 rel) {
  if (rel >= kUpStartMs && rel < kUpEndMs) {
    if (!up_sending_) {
      up_sending_ = true;
      tokens_ = 0.0;
      token_ms_ = rel;
      setState(State::kUpload);
      Q_EMIT logLine(QStringLiteral("开始上行：目标 %1 Mbps").arg(fmtMbps(opt_.mbps)));
    }
    const double rate_bytes_per_s = opt_.mbps * 1000000.0 / 8.0;
    const double wire_per_seg = 36.0 + static_cast<double>(opt_.seg);
    tokens_ += rate_bytes_per_s * static_cast<double>(rel - token_ms_) / 1000.0;
    token_ms_ = rel;
    int burst = 0;
    while (tokens_ >= wire_per_seg && burst < 4000) {
      makeSegment(sn_, &segment_);
      session_->on_kcp_output(segment_.data(), segment_.size(), rel);
      ++sn_;
      ++tx_segs_;
      tx_data_bytes_ += segment_.size();
      tokens_ -= wire_per_seg;
      ++burst;
    }
  } else if (up_sending_) {
    up_sending_ = false;
    Q_EMIT logLine(QStringLiteral("上行结束：发送 %1 段 / %2 字节")
                     .arg(tx_segs_)
                     .arg(tx_data_bytes_));
    setState(State::kWaitingDown);
  }

  if (rel >= kTotalMs) {
    finishRun();
  }
}

void BenchEngine::finishRun() {
  Result result;
  result.ok = true;
  result.handshake_ms = est_;
  result.up_mbps = static_cast<double>(tx_data_bytes_) * 8.0 / kPhaseSeconds / 1e6;
  result.down_mbps = static_cast<double>(rx_data_bytes_) * 8.0 / kPhaseSeconds / 1e6;
  result.up_bytes = tx_data_bytes_;
  result.down_bytes = rx_data_bytes_;
  result.tx_segs = tx_segs_;
  result.rx_segs = rx_segs_;
  result.tx_parity = tx_parity_;
  if (session_) {
    result.k = session_->k();
    result.d = session_->params().d;
    result.p = session_->params().p;
    result.auth_fail = session_->auth_fail();
    result.struct_fail = session_->struct_fail();
    if (session_->settle() != nullptr) {
      result.identity_ok = session_->settle()->identity_ok();
    }
  }
  result.delivered = static_cast<quint32>(rx_valid_segs_);
  result.expected = rx_max_sn_;
  last_result_ = result;

  Q_EMIT logLine(QStringLiteral("测试完成：上行 %1 Mbps，下行 %2 Mbps")
                   .arg(fmtMbps(result.up_mbps), fmtMbps(result.down_mbps)));
  emitStatsNow();
  cleanupRun();
  setState(State::kFinished);
  Q_EMIT finished(result);
}

void BenchEngine::failRun(const QString& error) {
  Result result;
  result.ok = false;
  result.error = error;
  result.handshake_ms = est_;
  last_result_ = result;
  Q_EMIT logLine(QStringLiteral("错误：%1").arg(error));
  cleanupRun();
  setState(State::kFailed);
  Q_EMIT finished(result);
}

void BenchEngine::cleanupRun() {
  tick_.stop();
  session_.reset();
  socket_.abort();
  met_ = false;
  up_sending_ = false;
  down_started_ = false;
}

void BenchEngine::setState(State state) {
  if (state_ == state) {
    return;
  }
  state_ = state;
  emitStatsNow();
}

void BenchEngine::emitStatsNow() {
  Stats stats;
  stats.state = state_;
  stats.elapsed_ms = clock_.isValid() ? clock_.elapsed() : 0;
  stats.handshake_ms = est_;
  stats.up_mbps = up_rate_;
  stats.down_mbps = down_rate_;
  stats.up_peak_mbps = up_peak_;
  stats.down_peak_mbps = down_peak_;
  stats.up_bytes = tx_data_bytes_;
  stats.down_bytes = rx_data_bytes_;
  stats.tx_segs = tx_segs_;
  stats.tx_parity = tx_parity_;
  stats.tx_fail = tx_fail_;
  stats.rx_datagrams = rx_datagrams_;
  stats.rx_wire = rx_data_wire_;
  const quint16 live_port = socket_.localPort();
  if (live_port != 0) {
    local_port_ = live_port;
  }
  stats.local_port = local_port_;
  if (session_) {
    stats.k = session_->k();
    stats.auth_fail = session_->auth_fail();
    stats.struct_fail = session_->struct_fail();
    stats.fecstat_rx = session_->fecstat_rx();
    stats.pre_ppm = session_->last_pre_ppm();
    stats.usable_ppm = session_->last_usable_ppm();
    stats.active_sets = session_->rx() != nullptr
                            ? static_cast<quint32>(session_->rx()->active_sets())
                            : 0;
  } else if (state_ == State::kFinished || state_ == State::kFailed) {
    stats.k = last_result_.k;
    stats.auth_fail = last_result_.auth_fail;
    stats.struct_fail = last_result_.struct_fail;
  }
  Q_EMIT statsUpdated(stats);
}

void BenchEngine::tickRates(qint64 now) {
  if (now - rate_ms_ < 100) {
    return;
  }
  const double dt = static_cast<double>(now - rate_ms_) / 1000.0;
  if (dt <= 0.0) {
    return;
  }
  up_rate_ = static_cast<double>(tx_data_bytes_ - rate_up_base_) * 8.0 / 1e6 / dt;
  down_rate_ = static_cast<double>(rx_data_bytes_ - rate_down_base_) * 8.0 / 1e6 / dt;
  rate_up_base_ = tx_data_bytes_;
  rate_down_base_ = rx_data_bytes_;
  rate_ms_ = now;
  up_peak_ = std::max(up_peak_, up_rate_);
  down_peak_ = std::max(down_peak_, down_rate_);
  emitStatsNow();
}

void BenchEngine::makeSegment(quint32 sn, std::vector<quint8>* out) const {
  const size_t len = static_cast<size_t>(opt_.seg) < 16 ? 16 : static_cast<size_t>(opt_.seg);
  out->assign(len, 0);
  (*out)[12] = static_cast<quint8>(sn);
  (*out)[13] = static_cast<quint8>(sn >> 8);
  (*out)[14] = static_cast<quint8>(sn >> 16);
  (*out)[15] = static_cast<quint8>(sn >> 24);
  for (size_t i = 0; i < len; ++i) {
    if (i >= 12 && i < 16) {
      continue;
    }
    (*out)[i] = static_cast<quint8>(sn * 31 + i * 7);
  }
}

bool BenchEngine::payloadOk(const quint8* payload, size_t len) const {
  if (len != static_cast<size_t>(opt_.seg) || len < 16) {
    return false;
  }
  const quint32 sn = static_cast<quint32>(payload[12]) |
                     (static_cast<quint32>(payload[13]) << 8) |
                     (static_cast<quint32>(payload[14]) << 16) |
                     (static_cast<quint32>(payload[15]) << 24);
  for (size_t i = 0; i < len; ++i) {
    if (i >= 12 && i < 16) {
      continue;
    }
    if (payload[i] != static_cast<quint8>(sn * 31 + i * 7)) {
      return false;
    }
  }
  return true;
}
