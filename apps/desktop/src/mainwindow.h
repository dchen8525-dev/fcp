// 客户端主窗口：左栏导航 + 四块内容（连接 / 运行状态 / 链路测速 / 日志）。
//
// 行为与 Tauri 版保持一致（决策 #41/#69）：关窗/最小化只收进托盘，隧道继续
// 跑；真正退出走托盘菜单。参数、校验、stats 解析和测速协议都不在这里——
// 它们分别是 apps/cli 的 CLI 与 sidecar.h 的进程管理。

#ifndef FCP_DESKTOP_MAINWINDOW_H_
#define FCP_DESKTOP_MAINWINDOW_H_

#include <QJsonObject>
#include <QMainWindow>
#include <QVector>

#include "sidecar.h"

class QCheckBox;
class QComboBox;
class QFrame;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QStackedWidget;
class QSystemTrayIcon;
class QTimer;
class QToolButton;

namespace fcp {

class Sparkline;

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MainWindow(Sidecar* sidecar, QWidget* parent = nullptr);
  ~MainWindow() override;

 protected:
  void closeEvent(QCloseEvent* event) override;
  void changeEvent(QEvent* event) override;
  // Windows 唤醒事件（WM_POWERBROADCAST）走这里；网络切换走定时轮询。
  bool nativeEvent(const QByteArray& type, void* message, qint64* result) override;

 private:
  // 页面搭建。
  QWidget* buildRail();
  QWidget* buildConnPage();
  QWidget* buildStatusPage();
  QWidget* buildSpeedPage();
  QWidget* buildLogPage();
  QFrame* makeCard();

  // 状态与交互。
  struct Collected {
    bool ok = false;
    QString error;
    ProxyConfig config;
  };
  Collected collect() const;
  void setRunning(bool running, const QString& hint = QString());
  void setHint(const QString& text, bool error = false);
  void setAdvanced(bool open);
  void updateKeyState();
  void syncAddr();
  void appendLog(const QString& line, bool is_stderr);
  void rebuildDiag(const QJsonObject& stats);

  void loadSettings();
  void saveSettings();

  void onStart();
  void onStop();
  void onSpeedStart();
  void onStats(const QJsonObject& stats);
  void onSpeedProgress(const QString& direction, quint64 bytes, double seconds);
  void onSpeedDone(const QJsonObject& result);

  void setupTray();
  void quitApp();

  // 唤醒/网络切换后的隧道重建（P-稳定性包 5）：检测到路径变化就整组重启，
  // 比等 idle 超时或半开僵死快得多。限频见 restartTunnel。
  void restartTunnel(const QString& reason);
  void onNetWatchTick();

  static QString fmtBytes(quint64 bytes);
  static QString fmtRate(double bytes_per_second);
  static QString fmtUptime(double seconds);

  Sidecar* sidecar_ = nullptr;
  QSystemTrayIcon* tray_ = nullptr;

  QStackedWidget* stack_ = nullptr;
  QVector<QPushButton*> nav_;

  // 左栏底部。
  QLabel* dot_ = nullptr;
  QLabel* state_text_ = nullptr;
  QLabel* rail_addr_ = nullptr;
  QLabel* uptime_ = nullptr;

  // 连接页。
  QLineEdit* host_ = nullptr;
  QLineEdit* port_ = nullptr;
  QLineEdit* listen_port_ = nullptr;
  QLineEdit* key_ = nullptr;
  QLabel* key_state_ = nullptr;
  QToolButton* key_toggle_ = nullptr;
  QCheckBox* remember_ = nullptr;
  QPushButton* adv_toggle_ = nullptr;
  QWidget* adv_body_ = nullptr;
  QLineEdit* listen_ = nullptr;
  QLineEdit* mtu_ = nullptr;
  QLineEdit* budget_ = nullptr;
  QLineEdit* k_ = nullptr;
  QLineEdit* rate_ = nullptr;
  QPushButton* start_ = nullptr;
  QLabel* hint_ = nullptr;
  QLabel* conn_addr_ = nullptr;

  // 运行状态页。
  QLabel* m_live_ = nullptr;
  QLabel* m_rx_ = nullptr;
  QLabel* m_tx_ = nullptr;
  QLabel* m_est_ = nullptr;
  QLabel* m_tun_ = nullptr;
  QLabel* rate_rx_ = nullptr;
  QLabel* rate_tx_ = nullptr;
  QLabel* sample_chip_ = nullptr;
  QLabel* status_note_ = nullptr;
  Sparkline* chart_ = nullptr;
  QWidget* diag_host_ = nullptr;
  QHBoxLayout* diag_layout_ = nullptr;
  QVector<quint64> diag_values_;

  // 测速页。
  QComboBox* speed_seconds_ = nullptr;
  QPushButton* speed_start_ = nullptr;
  QLabel* speed_hint_ = nullptr;
  QLabel* sp_down_ = nullptr;
  QLabel* sp_down_sub_ = nullptr;
  QLabel* sp_up_ = nullptr;
  QLabel* sp_up_sub_ = nullptr;
  QLabel* sp_loss_in_ = nullptr;
  QLabel* sp_loss_in_n_ = nullptr;
  QLabel* sp_loss_out_ = nullptr;
  QLabel* sp_loss_out_n_ = nullptr;
  Sparkline* sp_chart_ = nullptr;
  QProgressBar* sp_progress_ = nullptr;
  // 进度事件差分缓冲（下标 0=down 1=up），用于实时速率曲线。
  quint64 sp_slope_bytes_[2] = {0, 0};
  double sp_slope_secs_[2] = {0.0, 0.0};

  // 日志页。
  QPlainTextEdit* log_ = nullptr;
  QLabel* log_count_ = nullptr;
  int log_lines_ = 0;

  bool running_ = false;
  bool speed_running_ = false;
  bool advanced_ = false;
  bool loading_ = false;
  double last_t_ = 0.0;
  double last_tx_ = 0.0;
  double last_rx_ = 0.0;

  // 唤醒/网络切换检测（Qt <6.3 没有 QNetworkInformation，Windows 用 iphlpapi
  // 5 秒轮询适配器快照）。
  QTimer* net_watch_ = nullptr;
  QByteArray net_digest_;
  QByteArray net_pending_digest_;  // 待确认的变化（连续两次相同才重建）
  qint64 tunnel_started_ms_ = 0;
};

}  // namespace fcp

#endif  // FCP_DESKTOP_MAINWINDOW_H_
