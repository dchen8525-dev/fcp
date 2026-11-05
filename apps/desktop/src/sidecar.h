// sidecar 管理：启动/停止 fcp-client，解析 stats 与 @speedtest 输出。
//
// 这里没有任何 UI 依赖，MainWindow 只接信号。两个子进程：
//   * 代理：`fcp-client --host=... ...`（PSK 走 FCP_PSK 环境变量），stdout 里 `stats`
//     行进统计信号，其余行进日志；stderr 全是日志。
//   * 测速：第二个 fcp-client（`--speedtest`），输出 `@speedtest {json}`。
//
// 子进程必须随 GUI 一起死：Windows 用 KILL_ON_JOB_CLOSE 的 Job Object，
// Unix 用 PR_SET_PDEATHSIG。否则任务管理器结束 GUI 后，sidecar 还会占着
// 本地监听端口和隧道，下次启动直接 "Address already in use"。

#ifndef FCP_DESKTOP_SIDECAR_H_
#define FCP_DESKTOP_SIDECAR_H_

#include <QByteArray>
#include <QJsonObject>
#include <QObject>
#include <QProcess>
#include <QString>

#include <functional>

class QTimer;

namespace fcp {

struct ProxyConfig {
  QString host;
  quint16 port = 4460;
  QString key_hex;
  QString listen = QStringLiteral("127.0.0.1");
  quint16 listen_port = 1080;
  int mtu = 1400;
  int k = -1;
  double fec_budget = 0.5;
  double rate_up_mbps = 0.0;  // 上行限速（--rate-limit=UP[:DOWN]，客户端只发 UP）
  QString trace;
};

struct SpeedTestConfig {
  QString host;
  quint16 port = 4460;
  QString key_hex;
  int seconds = 8;
  int mtu = 1400;
};

class Sidecar : public QObject {
  Q_OBJECT

 public:
  explicit Sidecar(QObject* parent = nullptr);
  ~Sidecar() override;

  Sidecar(const Sidecar&) = delete;
  Sidecar& operator=(const Sidecar&) = delete;

  // sidecar 解析顺序：FCP_PROXY_BIN → 主程序同目录。不回落 PATH。
  QString resolveBinary(QString* error) const;

  bool startProxy(const ProxyConfig& config, QString* error);
  void stopProxy();
  bool proxyRunning() const;

  bool startSpeedTest(const SpeedTestConfig& config, QString* error);
  void stopSpeedTest();
  bool speedTestRunning() const;

  // 退出前收掉两个子进程（幂等）。
  void shutdown();

  // `stats 3.5s live=2 ...` → JSON 对象。格式不符返回 false，整行按日志处理，
  // 不半解析出一份错的数字。
  static bool parseStats(const QString& line, QJsonObject* out);

 signals:
  void proxyStateChanged(bool running, int exit_code, bool abnormal);
  void proxyStats(const QJsonObject& stats);
  void proxyLog(const QString& line, bool is_stderr);

  void speedProgress(const QString& direction, quint64 bytes, double elapsed_seconds);
  void speedDone(const QJsonObject& result);
  void speedStateChanged(bool running);

 private:
  void onProxyStdout();
  void onProxyStderr();
  void onProxyFinished(int exit_code, QProcess::ExitStatus status);
  void onSpeedStdout();
  void onSpeedStderr();
  void onSpeedFinished(int exit_code, QProcess::ExitStatus status);
  void finishSpeedWithError(const QString& error);
  void handleProxyLine(const QString& line);
  void handleSpeedLine(const QString& line);
  void consumeLines(QProcess* process, QByteArray* buffer,
                    const std::function<void(const QString&)>& on_line);
  void killProcess(QProcess* process, int grace_ms);

  QProcess* proxy_ = nullptr;
  QProcess* speed_ = nullptr;
  QTimer* speed_timeout_ = nullptr;
  QByteArray proxy_out_buf_;
  QByteArray proxy_err_buf_;
  QByteArray speed_out_buf_;
  QByteArray speed_err_buf_;
  bool proxy_stopping_ = false;
  bool speed_running_ = false;
  bool speed_done_ = false;
  bool speed_killed_ = false;
  int speed_seconds_ = 8;
};

}  // namespace fcp

#endif  // FCP_DESKTOP_SIDECAR_H_
