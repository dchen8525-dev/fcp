// In-process proxy for the GUI client (docs/FCP_M2_PROXY.md §6, task #23).
//
// Drives the same socket-free fcp::ProxyEngine as the CLI reactor, with Qt
// primitives instead of select(): QTcpServer accepts the local SOCKS5/HTTP
// entry, QUdpSocket carries the FCP wire, QHostInfo resolves dial targets and
// a 25ms QTimer is the engine's only clock. Everything runs on the GUI thread,
// exactly like BenchEngine, so the two features can coexist in one process.
//
// The one contract that needs care: the engine counts the bytes its app_send
// callback actually accepted and keeps the rest (§7.8 bounds per-connection
// memory). QTcpSocket::write() always accepts everything into its own buffer,
// so app_send is implemented as a high-water-mark write: the socket only takes
// bytes while its own buffer stays under kAppWriteHighWater, and the drained
// buffer re-opens the tap via on_app_writable (bytesWritten signal + tick).

#ifndef FCP_CLIENT_PROXY_HOST_H_
#define FCP_CLIENT_PROXY_HOST_H_

#include <QElapsedTimer>
#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QUdpSocket>

#include <memory>

#include "engine.h"

class QTcpServer;
class QTcpSocket;

class ProxyHost : public QObject {
  Q_OBJECT
 public:
  enum class State {
    kIdle,
    kStarting,  // listener bound, waiting for the FCP server address
    kRunning,
  };
  Q_ENUM(State)

  struct Options {
    QString server;         // FCP server host (IP literal or domain)
    quint16 port = 40000;   // FCP server UDP port
    QByteArray key;         // 16 bytes, validated by the caller
    QString listen = QStringLiteral("127.0.0.1");
    quint16 listen_port = 1080;
    int mtu = 1400;
    int window_kib = 0;     // 0 = engine default (256 KiB)
    int pinned_k = -1;      // -1 = adaptive
    bool prewarm = true;
    // #35: M3 controller passthrough — the byte-budget ceiling and the
    // per-session controller-trace prefix (empty = no recording).
    double fec_budget = 0.50;
    QString trace_prefix;
  };

  struct Stats {
    State state = State::kIdle;
    qint64 elapsed_ms = 0;
    quint32 live = 0;
    quint32 established = 0;
    quint32 tunnels = 0;
    double up_mbps = 0.0;   // wire bytes, both parity and retransmits
    double down_mbps = 0.0;
    quint64 up_bytes = 0;
    quint64 down_bytes = 0;
    quint32 bad_entry = 0;
    quint32 open_failed = 0;
    quint32 handshake_failed = 0;
    quint32 salt_clash = 0;
    quint32 unknown_salt = 0;
    quint32 reset = 0;
    quint16 listen_port = 0;
  };

  struct Result {
    bool ok = false;
    QString error;
    Stats stats;  // final snapshot (rates zeroed)
  };

  explicit ProxyHost(QObject* parent = nullptr);
  ~ProxyHost() override;

  void start(const Options& options);
  void stop();
  bool running() const;

 Q_SIGNALS:
  void statsUpdated(const ProxyHost::Stats& stats);
  void logLine(const QString& line);
  void finished(const ProxyHost::Result& result);

 private:
  // EngineHost callback implementations (must not re-enter the engine).
  size_t appSend(uint64_t conn, const uint8_t* data, size_t len);
  void appClose(uint64_t conn);
  void wireSend(uint64_t peer, const uint8_t* wire, size_t len);
  void dial(uint64_t conn, const fcp::ProxyTarget& target);
  std::string peerKey(uint64_t peer);

  void resolveServer();
  void onServerReady();
  void connectTarget(uint64_t conn, const QHostAddress& addr, quint16 port);
  void beginEngine();
  void acceptLocal();
  void readLocal(uint64_t conn);
  void readTarget(uint64_t conn);
  void drainUdp();
  void onTick();
  void sweepDials();
  void finishEngine(bool ok, const QString& why);
  void setState(State state);
  void emitStatsNow();
  void tickRates();

  // One dialed target socket. `reported` makes on_dial_result exactly-once:
  // Qt can deliver connected() and a late error both, and the engine only
  // accepts the first (phase kDialing), but the socket must stop talking.
  struct TargetSock {
    QTcpSocket* sock = nullptr;
    bool reported = false;
  };

  Options opt_;
  fcp::EngineConfig cfg_;
  QUdpSocket udp_;
  QTimer tick_;
  QElapsedTimer clock_;
  std::unique_ptr<fcp::ProxyEngine> engine_;
  QTcpServer* listener_ = nullptr;
  QHash<uint64_t, QTcpSocket*> locals_;
  QHash<uint64_t, TargetSock> targets_;
  QHostAddress server_addr_;
  std::string peer_key_;
  uint64_t next_local_conn_ = 1;
  bool resolving_ = false;
  quint64 resolve_gen_ = 0;  // P4-3: only the newest start() owns DNS results

  std::vector<std::vector<uint8_t>> wire_backlog_;  // before the address is known

  State state_ = State::kIdle;
  fcp::ProxyEngine::Counters last_counters_;
  qint64 trace_ms_ = 0;
  qint64 rate_ms_ = 0;
  quint64 rate_up_base_ = 0;
  quint64 rate_down_base_ = 0;
  double up_rate_ = 0.0;
  double down_rate_ = 0.0;
};

Q_DECLARE_METATYPE(ProxyHost::Stats)
Q_DECLARE_METATYPE(ProxyHost::Result)

#endif  // FCP_CLIENT_PROXY_HOST_H_
