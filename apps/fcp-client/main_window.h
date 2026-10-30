#ifndef FCP_CLIENT_MAIN_WINDOW_H_
#define FCP_CLIENT_MAIN_WINDOW_H_

#include <QMainWindow>

#include "bench_engine.h"

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

 protected:
  void closeEvent(QCloseEvent* event) override;
  void resizeEvent(QResizeEvent* event) override;

 private:
  QWidget* buildTitleBar();
  QWidget* buildSidebar();
  QWidget* buildOverview();
  QWidget* buildSettings();
  QWidget* buildLogs();
  QWidget* makeField(const QString& label, QWidget* input);
  QWidget* makeMetric(const QString& caption, QLabel** value);

  void loadSettings();
  void saveSettings();
  void showView(int index);
  void appendLog(const QString& line);
  void onStats(const BenchEngine::Stats& stats);
  void onFinished(const BenchEngine::Result& result);
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
  QLineEdit* saltEdit_ = nullptr;
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
};

#endif  // FCP_CLIENT_MAIN_WINDOW_H_
