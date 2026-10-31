#ifndef FCP_CLIENT_MAIN_WINDOW_H_
#define FCP_CLIENT_MAIN_WINDOW_H_

#include <QMainWindow>

#include "bench_engine.h"
#include "proxy_host.h"

class QButtonGroup;
class QCheckBox;
class QComboBox;
class QDoubleSpinBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSizeGrip;
class QSpinBox;
class QStackedWidget;
class QTimer;
class Sparkline;

class MainWindow : public QMainWindow {
  Q_OBJECT
 public:
  explicit MainWindow(QWidget* parent = nullptr);
  ~MainWindow() override;

  void applyArgumentOverrides();

 public Q_SLOTS:
  void startTest();
  void stopTest();
  void startProxy();
  void stopProxy();

 protected:
  void closeEvent(QCloseEvent* event) override;
  void resizeEvent(QResizeEvent* event) override;

 private:
  QWidget* buildTitleBar();
  QWidget* buildSidebar();
  QWidget* buildOverview();
  QWidget* buildSettings();
  QWidget* buildProxy();
  QWidget* buildLogs();
  QWidget* makeField(const QString& label, QWidget* input);
  QWidget* makeMetric(const QString& caption, QLabel** value);

  void loadSettings();
  void saveSettings();
  void showView(int index);
  void appendLog(const QString& line);
  void onStats(const BenchEngine::Stats& stats);
  void onFinished(const BenchEngine::Result& result);
  void onProxyStats(const ProxyHost::Stats& stats);
  void onProxyFinished(const ProxyHost::Result& result);
  bool collectProxyOptions(ProxyHost::Options* options, QString* error) const;
  void setStatus(const QString& text, const QString& sub, const QString& tone);
  void updateButtons();
  BenchEngine::Options collectOptions(bool* ok, QString* error) const;

  BenchEngine* engine_ = nullptr;
  QStackedWidget* stack_ = nullptr;
  QButtonGroup* nav_ = nullptr;
  QSizeGrip* grip_ = nullptr;

  QLabel* statusDot_ = nullptr;
  QLabel* statusText_ = nullptr;
  QLabel* uptime_ = nullptr;
  QLabel* statusSub_ = nullptr;
  QLabel* testInfo_ = nullptr;
  QPushButton* startBtn_ = nullptr;
  QPushButton* stopBtn_ = nullptr;
  QLabel* serverValue_ = nullptr;
  QLabel* localValue_ = nullptr;
  QLabel* kValue_ = nullptr;
  QLabel* setsValue_ = nullptr;
  QLabel* lossValue_ = nullptr;
  QLabel* failValue_ = nullptr;
  QLabel* downRate_ = nullptr;
  QLabel* upRate_ = nullptr;
  QLabel* downCap_ = nullptr;
  QLabel* upCap_ = nullptr;
  Sparkline* downSpark_ = nullptr;
  Sparkline* upSpark_ = nullptr;
  QWidget* resultCard_ = nullptr;
  QLabel* resultUp_ = nullptr;
  QLabel* resultDown_ = nullptr;
  QLabel* resultDelivery_ = nullptr;
  QLabel* resultHandshake_ = nullptr;
  QLabel* resultMeta_ = nullptr;

  QLineEdit* hostEdit_ = nullptr;
  QSpinBox* portSpin_ = nullptr;
  QDoubleSpinBox* mbpsSpin_ = nullptr;
  QLineEdit* pskEdit_ = nullptr;
  QSpinBox* segSpin_ = nullptr;
  QSpinBox* mtuSpin_ = nullptr;
  QComboBox* fecMode_ = nullptr;
  QSpinBox* kSpin_ = nullptr;
  QCheckBox* repeatCheck_ = nullptr;
  QLabel* saveInfo_ = nullptr;

  QPlainTextEdit* logView_ = nullptr;

  QTimer* repeatTimer_ = nullptr;
  bool suppressRepeat_ = false;
  QString lastServer_;

  ProxyHost* proxy_ = nullptr;
  QLineEdit* proxyHostEdit_ = nullptr;
  QSpinBox* proxyPortSpin_ = nullptr;
  QLineEdit* proxyPskEdit_ = nullptr;
  QSpinBox* proxyListenSpin_ = nullptr;
  QSpinBox* proxyMtuSpin_ = nullptr;
  QSpinBox* proxyKSpin_ = nullptr;
  QCheckBox* proxyPrewarmCheck_ = nullptr;
  QDoubleSpinBox* proxyBudgetSpin_ = nullptr;  // #35: M3 byte-budget ceiling
  QLineEdit* proxyTraceEdit_ = nullptr;        // #35: controller-trace prefix
  QPushButton* proxyStartBtn_ = nullptr;
  QPushButton* proxyStopBtn_ = nullptr;
  QLabel* proxyInfo_ = nullptr;
  QLabel* proxyState_ = nullptr;
  QLabel* proxyLiveValue_ = nullptr;
  QLabel* proxyTunnelsValue_ = nullptr;
  QLabel* proxyUpValue_ = nullptr;
  QLabel* proxyDownValue_ = nullptr;
  QLabel* proxyUpRate_ = nullptr;
  QLabel* proxyDownRate_ = nullptr;
  QLabel* proxyUpCap_ = nullptr;
  QLabel* proxyDownCap_ = nullptr;
  Sparkline* proxyUpSpark_ = nullptr;
  Sparkline* proxyDownSpark_ = nullptr;
};

#endif  // FCP_CLIENT_MAIN_WINDOW_H_
