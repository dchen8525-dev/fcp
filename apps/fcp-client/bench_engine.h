// Connection and throughput probe over the FCP session, GUI flavour.
//
// Mirrors the fcp_bench client: FCPBENCH rendezvous -> handshake -> 7s upload
// (token bucket at the target rate, starting 1s after establishment) -> the
// server answers after 500ms of silence with its own 7s download stream. The
// whole run ends at t+18s. Every datagram is driven from a 5ms timer in the
// GUI thread, so the UI stays live; Stats are pushed at 10Hz.

#ifndef FCP_CLIENT_BENCH_ENGINE_H_
#define FCP_CLIENT_BENCH_ENGINE_H_

#include <QByteArray>
#include <QElapsedTimer>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QUdpSocket>

#include <memory>
#include <vector>

#include "fcp/session.h"

class BenchEngine : public QObject {
  Q_OBJECT
 public:
  enum class State {
    kIdle,
    kResolving,
    kRendezvous,
    kHandshake,
    kUpload,
    kWaitingDown,
    kDownload,
    kFinished,
    kFailed,
  };
  Q_ENUM(State)

  struct Options {
    QString host;
    quint16 port = 40000;
    QByteArray key;   // 16 bytes
    QByteArray salt;  // 8 bytes
    double mbps = 20.0;
    int seg = 1200;   // must match the server's --seg (default 1200)
    int mtu = 1400;
    int pinned_k = -1;
  };

  struct Stats {
    State state = State::kIdle;
    qint64 elapsed_ms = 0;
    qint64 handshake_ms = -1;
    double up_mbps = 0.0;
    double down_mbps = 0.0;
    double up_peak_mbps = 0.0;
    double down_peak_mbps = 0.0;
    quint64 up_bytes = 0;
    quint64 down_bytes = 0;
    quint64 tx_segs = 0;
    quint64 tx_parity = 0;
    quint64 tx_fail = 0;
    quint64 rx_datagrams = 0;
    quint64 rx_wire = 0;
    quint32 auth_fail = 0;
    quint32 struct_fail = 0;
    quint32 fecstat_rx = 0;
    quint32 pre_ppm = 0;
    quint32 usable_ppm = 0;
    int k = 0;
    quint32 active_sets = 0;
    quint16 local_port = 0;
  };

  struct Result {
    bool ok = false;
    QString error;
    double up_mbps = 0.0;
    double down_mbps = 0.0;
    qint64 handshake_ms = -1;
    quint32 delivered = 0;
    quint32 expected = 0;
    bool identity_ok = false;
    int d = 0;
    int p = 0;
    int k = 0;
    quint32 auth_fail = 0;
    quint32 struct_fail = 0;
    quint64 up_bytes = 0;
    quint64 down_bytes = 0;
    quint64 tx_segs = 0;
    quint64 rx_segs = 0;
    quint64 tx_parity = 0;
  };

  explicit BenchEngine(QObject* parent = nullptr);
  ~BenchEngine() override;

  void start(const Options& options);
  void stop();
  bool running() const;

 Q_SIGNALS:
  void statsUpdated(const BenchEngine::Stats& stats);
  void logLine(const QString& line);
  void finished(const BenchEngine::Result& result);

 private:
  void connectTo(const QHostAddress& addr);
  void beginSession();
  void onTick();
  void pumpRendezvous(qint64 now);
  void pumpSession(qint64 rel);
  void drivePhases(qint64 rel);
  void finishRun();
  void failRun(const QString& error);
  void cleanupRun();
  void setState(State state);
  void emitStatsNow();
  void tickRates(qint64 now);

  void makeSegment(quint32 sn, std::vector<quint8>* out) const;
  bool payloadOk(const quint8* payload, size_t len) const;

  QUdpSocket socket_;
  QTimer tick_;
  std::unique_ptr<fcp::Session> session_;
  Options opt_;
  Result last_result_;

  State state_ = State::kIdle;
  QElapsedTimer clock_;
  qint64 t0_ms_ = 0;
  qint64 next_tick_ms_ = 0;
  int64_t est_ = -1;

  bool met_ = false;
  int meet_sent_ = 0;
  qint64 next_magic_ms_ = 0;

  double tokens_ = 0.0;
  qint64 token_ms_ = 0;
  bool up_sending_ = false;
  bool down_started_ = false;
  quint32 sn_ = 1;
  std::vector<quint8> segment_;

  quint64 tx_data_bytes_ = 0;
  quint64 tx_segs_ = 0;
  quint64 tx_wire_bytes_ = 0;
  quint64 tx_parity_ = 0;
  quint64 tx_oob_ = 0;
  quint64 tx_fail_ = 0;
  quint64 rx_datagrams_ = 0;
  quint64 rx_data_bytes_ = 0;
  quint64 rx_segs_ = 0;
  quint64 rx_data_wire_ = 0;
  quint64 rx_corrupt_ = 0;

  qint64 rate_ms_ = 0;
  quint64 rate_up_base_ = 0;
  quint64 rate_down_base_ = 0;
  double up_rate_ = 0.0;
  double down_rate_ = 0.0;
  double up_peak_ = 0.0;
  double down_peak_ = 0.0;
  bool socket_error_logged_ = false;
  quint16 local_port_ = 0;
  quint64 rx_valid_segs_ = 0;
  quint32 rx_max_sn_ = 0;
};

Q_DECLARE_METATYPE(BenchEngine::Stats)
Q_DECLARE_METATYPE(BenchEngine::Result)

#endif  // FCP_CLIENT_BENCH_ENGINE_H_
