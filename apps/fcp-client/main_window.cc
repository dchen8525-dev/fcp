#include "main_window.h"

#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDoubleSpinBox>
#include <QFile>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QSettings>
#include <QSizeGrip>
#include <QSpinBox>
#include <QStackedWidget>
#include <QTime>
#include <QTimer>
#include <QVBoxLayout>

#include "sparkline.h"

namespace {

const QColor kInk(0x26, 0x22, 0x1a);
const QColor kPaperLine(0xe3, 0xdb, 0xc7);
const QColor kCinnabar(0xb5, 0x43, 0x2f);

QString formatDuration(qint64 ms) {
  const qint64 seconds = ms / 1000;
  return QString("%1:%2:%3")
      .arg(seconds / 3600, 2, 10, QChar('0'))
      .arg((seconds / 60) % 60, 2, 10, QChar('0'))
      .arg(seconds % 60, 2, 10, QChar('0'));
}

QString humanBytes(quint64 bytes) {
  if (bytes < 1024) {
    return QString("%1 B").arg(bytes);
  }
  const double kb = static_cast<double>(bytes) / 1024.0;
  if (kb < 1024.0) {
    return QString("%1 KB").arg(kb, 0, 'f', 1);
  }
  const double mb = kb / 1024.0;
  if (mb < 1024.0) {
    return QString("%1 MB").arg(mb, 0, 'f', 1);
  }
  return QString("%1 GB").arg(mb / 1024.0, 0, 'f', 2);
}

// A3: no shipped PSK. Every launch starts from a CSPRNG key so that copying
// the repository never yields a key that decrypts anyone's tunnels. The key is
// deliberately not persisted: QSettings is a plaintext store, and this form is
// the one place the user can still type a key shared with the peer.
QString randomHex(int bytes) {
  QByteArray raw(bytes, 0);
  for (int i = 0; i < bytes; ++i) {
    raw[i] = static_cast<char>(QRandomGenerator::system()->generate() & 0xFF);
  }
  return QString::fromLatin1(raw.toHex());
}

class Logo : public QWidget {
 public:
  explicit Logo(QWidget* parent = nullptr) : QWidget(parent) { setFixedSize(24, 24); }

 protected:
  void paintEvent(QPaintEvent*) override {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    QPen pen(kInk);
    pen.setWidthF(1.4);
    painter.setPen(pen);
    painter.setBrush(Qt::NoBrush);
    painter.drawEllipse(QPointF(12.0, 12.0), 8.0, 8.0);
    painter.drawLine(QPointF(2.5, 12.0), QPointF(21.5, 12.0));
    painter.setPen(Qt::NoPen);
    painter.setBrush(kCinnabar);
    painter.drawEllipse(QPointF(12.0, 12.0), 2.4, 2.4);
  }
};

class TitleBar : public QWidget {
 public:
  explicit TitleBar(QWidget* parent) : QWidget(parent) {}

 protected:
  void mousePressEvent(QMouseEvent* event) override {
    if (event->button() == Qt::LeftButton) {
      drag_offset_ = event->globalPosition().toPoint() - window()->pos();
      dragging_ = !window()->isMaximized();
      event->accept();
    }
  }
  void mouseMoveEvent(QMouseEvent* event) override {
    if (dragging_ && (event->buttons() & Qt::LeftButton)) {
      window()->move(event->globalPosition().toPoint() - drag_offset_);
      event->accept();
    }
  }
  void mouseReleaseEvent(QMouseEvent*) override { dragging_ = false; }
  void mouseDoubleClickEvent(QMouseEvent* event) override {
    if (event->button() == Qt::LeftButton) {
      window()->isMaximized() ? window()->showNormal() : window()->showMaximized();
    }
  }

 private:
  QPoint drag_offset_;
  bool dragging_ = false;
};

}  // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
  setWindowTitle("FCP 控制台");
  setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
  setMinimumSize(980, 660);
  resize(1060, 720);

  QFile qss(":/theme.qss");
  if (qss.open(QIODevice::ReadOnly)) {
    qApp->setStyleSheet(QString::fromUtf8(qss.readAll()));
  }

  auto* root = new QWidget;
  root->setObjectName("root");
  auto* outer = new QVBoxLayout(root);
  outer->setContentsMargins(0, 0, 0, 0);
  outer->setSpacing(0);
  outer->addWidget(buildTitleBar());

  auto* body = new QWidget;
  auto* bodyLayout = new QHBoxLayout(body);
  bodyLayout->setContentsMargins(0, 0, 0, 0);
  bodyLayout->setSpacing(0);
  bodyLayout->addWidget(buildSidebar());

  stack_ = new QStackedWidget;
  stack_->addWidget(buildOverview());
  stack_->addWidget(buildSettings());
  stack_->addWidget(buildProxy());
  stack_->addWidget(buildLogs());
  bodyLayout->addWidget(stack_, 1);
  outer->addWidget(body, 1);
  setCentralWidget(root);

  grip_ = new QSizeGrip(this);
  grip_->setFixedSize(16, 16);
  grip_->raise();

  engine_ = new BenchEngine(this);
  connect(engine_, &BenchEngine::statsUpdated, this, &MainWindow::onStats);
  connect(engine_, &BenchEngine::logLine, this, &MainWindow::appendLog);
  connect(engine_, &BenchEngine::finished, this, &MainWindow::onFinished);

  proxy_ = new ProxyHost(this);
  connect(proxy_, &ProxyHost::statsUpdated, this, &MainWindow::onProxyStats);
  connect(proxy_, &ProxyHost::logLine, this, &MainWindow::appendLog);
  connect(proxy_, &ProxyHost::finished, this, &MainWindow::onProxyFinished);

  repeatTimer_ = new QTimer(this);
  repeatTimer_->setSingleShot(true);
  connect(repeatTimer_, &QTimer::timeout, this, &MainWindow::startTest);

  loadSettings();
  showView(0);
  onStats(BenchEngine::Stats{});
  onProxyStats(ProxyHost::Stats{});
  updateButtons();
  appendLog("就绪：服务端运行 fcp_bench server 后点击「开始测试」");
}

MainWindow::~MainWindow() {
  // Stop both hosts while the UI is still alive, and mute their signals first.
  // Widget destruction order is not something to rely on here: ~ProxyHost
  // calls stop(), which emits statsUpdated/finished synchronously, and those
  // slots dereference engine_, logView_ and the buttons. Nothing on screen
  // needs the teardown events of a window that is going away.
  if (engine_ != nullptr) {
    engine_->blockSignals(true);
    engine_->stop();
  }
  if (proxy_ != nullptr) {
    proxy_->blockSignals(true);
    proxy_->stop();
  }
}

QWidget* MainWindow::buildTitleBar() {
  auto* bar = new TitleBar(this);
  bar->setObjectName("titleBar");
  bar->setFixedHeight(48);

  auto* layout = new QHBoxLayout(bar);
  layout->setContentsMargins(16, 0, 10, 0);
  layout->setSpacing(10);
  layout->addWidget(new Logo(bar));

  auto* brand = new QWidget(bar);
  auto* brandLayout = new QVBoxLayout(brand);
  brandLayout->setContentsMargins(0, 0, 0, 0);
  brandLayout->setSpacing(1);
  auto* title = new QLabel("FCP 控制台", brand);
  title->setObjectName("brandTitle");
  auto* subtitle = new QLabel("FCP V6 · 连接与测速", brand);
  subtitle->setObjectName("brandSub");
  brandLayout->addWidget(title);
  brandLayout->addWidget(subtitle);
  layout->addWidget(brand);
  layout->addStretch();

  auto makeButton = [&](const QString& text, const char* name) {
    auto* button = new QPushButton(text, bar);
    button->setObjectName(name);
    button->setCursor(Qt::PointingHandCursor);
    button->setFixedSize(36, 28);
    return button;
  };
  auto* minimizeButton = makeButton("─", "winBtn");
  auto* maximizeButton = makeButton("□", "winBtn");
  auto* closeButton = makeButton("✕", "winClose");
  layout->addWidget(minimizeButton);
  layout->addWidget(maximizeButton);
  layout->addWidget(closeButton);

  connect(minimizeButton, &QPushButton::clicked, this, &QWidget::showMinimized);
  connect(maximizeButton, &QPushButton::clicked, this, [this] {
    isMaximized() ? showNormal() : showMaximized();
  });
  connect(closeButton, &QPushButton::clicked, this, &QWidget::close);
  return bar;
}

QWidget* MainWindow::buildSidebar() {
  auto* side = new QWidget;
  side->setObjectName("side");
  side->setFixedWidth(198);

  auto* layout = new QVBoxLayout(side);
  layout->setContentsMargins(0, 20, 0, 14);
  layout->setSpacing(0);

  auto* caption = new QLabel("导  航", side);
  caption->setObjectName("sideCap");
  caption->setContentsMargins(22, 0, 0, 10);
  layout->addWidget(caption);

  nav_ = new QButtonGroup(this);
  nav_->setExclusive(true);
  const QStringList names = {"概览", "连接设置", "代理", "运行日志"};
  for (int i = 0; i < names.size(); ++i) {
    auto* button = new QPushButton(names[i], side);
    button->setObjectName("navBtn");
    button->setCheckable(true);
    button->setCursor(Qt::PointingHandCursor);
    button->setMinimumHeight(38);
    nav_->addButton(button, i);
    layout->addWidget(button);
  }
  layout->addStretch();

  auto* foot = new QLabel("纸感墨白", side);
  foot->setObjectName("sideFoot");
  foot->setAlignment(Qt::AlignCenter);
  layout->addWidget(foot);

  connect(nav_, &QButtonGroup::idClicked, this, &MainWindow::showView);
  nav_->button(0)->setChecked(true);
  return side;
}

QWidget* MainWindow::buildOverview() {
  auto* page = new QWidget;
  page->setObjectName("viewPage");
  auto* layout = new QVBoxLayout(page);
  layout->setContentsMargins(40, 26, 40, 24);
  layout->setSpacing(0);

  auto* eyebrow = new QLabel("当 前 状 态", page);
  eyebrow->setObjectName("eyebrow");
  layout->addWidget(eyebrow);

  auto* statusRow = new QWidget(page);
  auto* statusLayout = new QHBoxLayout(statusRow);
  statusLayout->setContentsMargins(0, 6, 0, 0);
  statusLayout->setSpacing(10);
  statusDot_ = new QLabel(statusRow);
  statusDot_->setObjectName("statusDot");
  statusDot_->setFixedSize(10, 10);
  statusDot_->setProperty("tone", "idle");
  statusText_ = new QLabel("未运行", statusRow);
  statusText_->setObjectName("statusText");
  uptime_ = new QLabel(QString(), statusRow);
  uptime_->setObjectName("uptime");
  uptime_->hide();
  statusLayout->addWidget(statusDot_);
  statusLayout->addWidget(statusText_);
  statusLayout->addSpacing(10);
  statusLayout->addWidget(uptime_);
  statusLayout->addStretch();
  layout->addWidget(statusRow);

  statusSub_ = new QLabel("FCP v6 · 可靠 UDP 隧道 · 自适应纠删", page);
  statusSub_->setObjectName("viewSub");
  statusSub_->setContentsMargins(0, 6, 0, 0);
  layout->addWidget(statusSub_);

  auto* rule = new QFrame(page);
  rule->setObjectName("rule");
  rule->setFixedHeight(1);
  rule->setContentsMargins(0, 14, 0, 0);
  auto* ruleWrap = new QWidget(page);
  auto* ruleLayout = new QVBoxLayout(ruleWrap);
  ruleLayout->setContentsMargins(0, 16, 0, 0);
  ruleLayout->addWidget(rule);
  layout->addWidget(ruleWrap);

  auto kv = [&](const QString& key, QLabel** out) {
    auto* cell = new QWidget(page);
    auto* cellLayout = new QVBoxLayout(cell);
    cellLayout->setContentsMargins(0, 0, 0, 0);
    cellLayout->setSpacing(4);
    auto* keyLabel = new QLabel(key, cell);
    keyLabel->setObjectName("kvKey");
    auto* valueLabel = new QLabel("—", cell);
    valueLabel->setObjectName("kvValue");
    valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    cellLayout->addWidget(keyLabel);
    cellLayout->addWidget(valueLabel);
    *out = valueLabel;
    return cell;
  };
  auto* grid = new QGridLayout;
  grid->setContentsMargins(0, 18, 0, 0);
  grid->setHorizontalSpacing(40);
  grid->setVerticalSpacing(14);
  grid->addWidget(kv("服务器", &serverValue_), 0, 0);
  grid->addWidget(kv("本地地址", &localValue_), 0, 1);
  grid->addWidget(kv("当前 k", &kValue_), 1, 0);
  grid->addWidget(kv("活动集合", &setsValue_), 1, 1);
  grid->addWidget(kv("FEC 丢包", &lossValue_), 2, 0);
  grid->addWidget(kv("校验失败", &failValue_), 2, 1);
  grid->setColumnStretch(0, 1);
  grid->setColumnStretch(1, 1);
  layout->addLayout(grid);

  auto* actions = new QWidget(page);
  auto* actionLayout = new QHBoxLayout(actions);
  actionLayout->setContentsMargins(0, 22, 0, 0);
  actionLayout->setSpacing(12);
  startBtn_ = new QPushButton("开始测试", actions);
  startBtn_->setObjectName("btnPrimary");
  startBtn_->setCursor(Qt::PointingHandCursor);
  stopBtn_ = new QPushButton("停止", actions);
  stopBtn_->setObjectName("btnGhost");
  stopBtn_->setCursor(Qt::PointingHandCursor);
  testInfo_ = new QLabel(QString(), actions);
  testInfo_->setObjectName("testResult");
  actionLayout->addWidget(startBtn_);
  actionLayout->addWidget(stopBtn_);
  actionLayout->addSpacing(6);
  actionLayout->addWidget(testInfo_);
  actionLayout->addStretch();
  layout->addWidget(actions);
  connect(startBtn_, &QPushButton::clicked, this, &MainWindow::startTest);
  connect(stopBtn_, &QPushButton::clicked, this, &MainWindow::stopTest);

  auto* card = new QFrame(page);
  card->setObjectName("card");
  auto* cardLayout = new QHBoxLayout(card);
  cardLayout->setContentsMargins(22, 16, 22, 16);
  cardLayout->setSpacing(26);
  cardLayout->addWidget(makeTrafficCell("↓ 下载", "峰值 0.00 Mbps · 累计 0 B", true, &downRate_,
                                        &downCap_, &downSpark_), 1);
  auto* divider = new QFrame(card);
  divider->setObjectName("trafficDivider");
  divider->setFixedWidth(1);
  cardLayout->addWidget(divider);
  cardLayout->addWidget(makeTrafficCell("↑ 上传", "峰值 0.00 Mbps · 累计 0 B", false, &upRate_,
                                        &upCap_, &upSpark_), 1);
  auto* cardWrap = new QWidget(page);
  auto* cardWrapLayout = new QVBoxLayout(cardWrap);
  cardWrapLayout->setContentsMargins(0, 22, 0, 0);
  cardWrapLayout->addWidget(card);
  layout->addWidget(cardWrap);

  resultCard_ = new QFrame(page);
  resultCard_->setObjectName("resultCard");
  resultCard_->setVisible(false);
  auto* resultLayout = new QHBoxLayout(resultCard_);
  resultLayout->setContentsMargins(22, 16, 22, 16);
  resultLayout->setSpacing(30);
  auto* resultTitle = new QWidget(resultCard_);
  auto* resultTitleLayout = new QVBoxLayout(resultTitle);
  resultTitleLayout->setContentsMargins(0, 0, 0, 0);
  resultTitleLayout->setSpacing(4);
  auto* resultEyebrow = new QLabel("测 试 结 果", resultTitle);
  resultEyebrow->setObjectName("eyebrow");
  resultMeta_ = new QLabel("—", resultTitle);
  resultMeta_->setObjectName("trafficCap");
  resultTitleLayout->addWidget(resultEyebrow);
  resultTitleLayout->addWidget(resultMeta_);
  resultLayout->addWidget(resultTitle);
  resultLayout->addSpacing(8);
  resultLayout->addWidget(makeMetric("上行", &resultUp_));
  resultLayout->addWidget(makeMetric("下行", &resultDown_));
  resultLayout->addWidget(makeMetric("交付率", &resultDelivery_));
  resultLayout->addWidget(makeMetric("握手", &resultHandshake_));
  resultLayout->addStretch();
  auto* resultWrap = new QWidget(page);
  auto* resultWrapLayout = new QVBoxLayout(resultWrap);
  resultWrapLayout->setContentsMargins(0, 16, 0, 0);
  resultWrapLayout->addWidget(resultCard_);
  layout->addWidget(resultWrap);
  layout->addStretch();
  return page;
}

QWidget* MainWindow::makeMetric(const QString& caption, QLabel** value) {
  auto* cell = new QWidget;
  auto* layout = new QVBoxLayout(cell);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(4);
  auto* captionLabel = new QLabel(caption, cell);
  captionLabel->setObjectName("kvKey");
  auto* valueLabel = new QLabel("—", cell);
  valueLabel->setObjectName("resultValue");
  layout->addWidget(captionLabel);
  layout->addWidget(valueLabel);
  *value = valueLabel;
  return cell;
}

QWidget* MainWindow::makeTrafficCell(const char* text, const char* cap, bool down,
                                     QLabel** rate, QLabel** capLabel, Sparkline** spark) {
  auto* cell = new QWidget;
  auto* layout = new QVBoxLayout(cell);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(4);
  auto* dir = new QLabel(QString::fromUtf8(text), cell);
  dir->setObjectName("trafficDir");
  auto* rateLabel = new QLabel("0.00 Mbps", cell);
  rateLabel->setObjectName("trafficRate");
  auto* sparkline = new Sparkline(down ? QColor(0x2e, 0x5f, 0x74) : QColor(0x47, 0x68, 0x5a), cell);
  auto* capWidget = new QLabel(QString::fromUtf8(cap), cell);
  capWidget->setObjectName("trafficCap");
  layout->addWidget(dir);
  layout->addWidget(rateLabel);
  layout->addWidget(sparkline, 1);
  layout->addWidget(capWidget);
  *rate = rateLabel;
  *capLabel = capWidget;
  *spark = sparkline;
  return cell;
}

QWidget* MainWindow::makeField(const QString& label, QWidget* input) {
  auto* field = new QWidget;
  auto* layout = new QVBoxLayout(field);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(6);
  auto* labelWidget = new QLabel(label, field);
  labelWidget->setObjectName("fldLabel");
  layout->addWidget(labelWidget);
  layout->addWidget(input);
  return field;
}

QWidget* MainWindow::buildSettings() {
  auto* page = new QWidget;
  page->setObjectName("viewPage");
  auto* layout = new QVBoxLayout(page);
  layout->setContentsMargins(40, 26, 40, 24);
  layout->setSpacing(0);

  auto* title = new QLabel("连接设置", page);
  title->setObjectName("viewTitle");
  auto* subtitle = new QLabel("点击「保存设置」后修改才会保存；开始测试按当前表单执行。", page);
  subtitle->setObjectName("viewSub");
  subtitle->setContentsMargins(0, 6, 0, 0);
  layout->addWidget(title);
  layout->addWidget(subtitle);

  hostEdit_ = new QLineEdit(page);
  hostEdit_->setPlaceholderText("服务器 IP 或域名");
  portSpin_ = new QSpinBox(page);
  portSpin_->setRange(1, 65535);
  portSpin_->setValue(40000);
  mbpsSpin_ = new QDoubleSpinBox(page);
  mbpsSpin_->setRange(0.5, 200.0);
  mbpsSpin_->setDecimals(1);
  mbpsSpin_->setValue(20.0);
  mbpsSpin_->setSuffix(" Mbps");
  pskEdit_ = new QLineEdit(page);
  pskEdit_->setObjectName("monoInput");
  pskEdit_->setMaxLength(32);
  // P2' N10: the PSK is a secret; never render it in clear text (shoulder
  // surfing, screen recording, remote support sessions).
  pskEdit_->setEchoMode(QLineEdit::Password);
  pskEdit_->setPlaceholderText("32 位十六进制（16 字节 PSK）");
  pskEdit_->setToolTip("须与服务端一致；每次启动随机生成，不写入配置文件");
  segSpin_ = new QSpinBox(page);
  segSpin_->setRange(64, 1200);
  segSpin_->setValue(1200);
  segSpin_->setSuffix(" B");
  segSpin_->setToolTip("须与服务端 fcp_bench server --seg 一致（默认 1200）");
  mtuSpin_ = new QSpinBox(page);
  mtuSpin_->setRange(576, 1400);
  mtuSpin_->setValue(1400);
  mtuSpin_->setSuffix(" B");
  mtuSpin_->setToolTip("MTU 预算；须容纳 FECSTAT oob（IPv4 至少 190）");
  fecMode_ = new QComboBox(page);
  fecMode_->addItem("自适应 FEC（推荐）");
  fecMode_->addItem("固定 k");
  kSpin_ = new QSpinBox(page);
  kSpin_->setRange(1, 7);
  kSpin_->setValue(3);
  kSpin_->setEnabled(false);
  auto* fecRow = new QWidget(page);
  auto* fecLayout = new QHBoxLayout(fecRow);
  fecLayout->setContentsMargins(0, 0, 0, 0);
  fecLayout->setSpacing(8);
  fecLayout->addWidget(fecMode_, 1);
  fecLayout->addWidget(kSpin_);

  auto* grid = new QGridLayout;
  grid->setContentsMargins(0, 20, 0, 0);
  grid->setHorizontalSpacing(22);
  grid->setVerticalSpacing(16);
  grid->addWidget(makeField("服务器地址", hostEdit_), 0, 0);
  grid->addWidget(makeField("服务器端口", portSpin_), 0, 1);
  grid->addWidget(makeField("目标上行速率", mbpsSpin_), 1, 0);
  grid->addWidget(makeField("分段大小", segSpin_), 1, 1);
  grid->addWidget(makeField("PSK", pskEdit_), 2, 0);
  grid->addWidget(makeField("MTU", mtuSpin_), 2, 1);
  grid->addWidget(makeField("FEC 模式", fecRow), 3, 0);
  grid->setColumnStretch(0, 1);
  grid->setColumnStretch(1, 1);
  layout->addLayout(grid);

  repeatCheck_ = new QCheckBox("循环测试（结束后 5 秒重新开始）", page);
  repeatCheck_->setContentsMargins(0, 18, 0, 0);
  layout->addWidget(repeatCheck_);

  auto* actions = new QWidget(page);
  auto* actionLayout = new QHBoxLayout(actions);
  actionLayout->setContentsMargins(0, 20, 0, 0);
  actionLayout->setSpacing(12);
  auto* saveBtn = new QPushButton("保存设置", actions);
  saveBtn->setObjectName("btnPrimary");
  saveBtn->setCursor(Qt::PointingHandCursor);
  saveInfo_ = new QLabel(QString(), actions);
  saveInfo_->setObjectName("testResult");
  actionLayout->addWidget(saveBtn);
  actionLayout->addWidget(saveInfo_);
  actionLayout->addStretch();
  layout->addWidget(actions);
  layout->addStretch();

  connect(saveBtn, &QPushButton::clicked, this, [this] {
    saveSettings();
    saveInfo_->setText("已保存");
    appendLog("设置已保存");
  });
  connect(fecMode_, &QComboBox::currentIndexChanged, this, [this](int index) {
    kSpin_->setEnabled(index == 1);
  });
  return page;
}

QWidget* MainWindow::buildProxy() {
  auto* page = new QWidget;
  page->setObjectName("viewPage");
  auto* layout = new QVBoxLayout(page);
  layout->setContentsMargins(40, 26, 40, 24);
  layout->setSpacing(0);

  auto* title = new QLabel("代理", page);
  title->setObjectName("viewTitle");
  auto* subtitle = new QLabel(
      "本进程内建 SOCKS5 / HTTP CONNECT 入口，经 FCP 隧道转发；每个应用连接一条会话。",
      page);
  subtitle->setObjectName("viewSub");
  subtitle->setContentsMargins(0, 6, 0, 0);
  subtitle->setWordWrap(true);
  layout->addWidget(title);
  layout->addWidget(subtitle);

  proxyHostEdit_ = new QLineEdit(page);
  proxyHostEdit_->setPlaceholderText("FCP 服务器 IP 或域名");
  proxyPortSpin_ = new QSpinBox(page);
  proxyPortSpin_->setRange(1, 65535);
  proxyPortSpin_->setValue(40000);
  proxyPskEdit_ = new QLineEdit(page);
  proxyPskEdit_->setObjectName("monoInput");
  proxyPskEdit_->setMaxLength(32);
  proxyPskEdit_->setEchoMode(QLineEdit::Password);
  proxyPskEdit_->setPlaceholderText("32 位十六进制（16 字节 PSK）");
  proxyListenSpin_ = new QSpinBox(page);
  proxyListenSpin_->setRange(1, 65535);
  proxyListenSpin_->setValue(1080);
  proxyMtuSpin_ = new QSpinBox(page);
  proxyMtuSpin_->setRange(576, 1400);
  proxyMtuSpin_->setValue(1400);
  proxyMtuSpin_->setSuffix(" B");
  proxyKSpin_ = new QSpinBox(page);
  proxyKSpin_->setRange(-1, 7);
  proxyKSpin_->setValue(-1);
  proxyKSpin_->setToolTip("-1 = 自适应；≥1 = 固定每组 parity 数");
  proxyPrewarmCheck_ = new QCheckBox("链路预热（跨连接继承 k/RTT 先验）", page);
  proxyBudgetSpin_ = new QDoubleSpinBox(page);
  proxyBudgetSpin_->setRange(0.0, 1.0);
  proxyBudgetSpin_->setSingleStep(0.05);
  proxyBudgetSpin_->setValue(fcp::kDefaultFecBudget);  // 唯一默认定义（defaults.h）
  proxyBudgetSpin_->setToolTip("冗余字节比上限 parity/data，0 = 不限（M3 §8.2）");
  proxyTraceEdit_ = new QLineEdit(page);
  proxyTraceEdit_->setPlaceholderText("留空 = 不录制（每会话一个 .jsonl）");

  auto* grid = new QGridLayout;
  grid->setContentsMargins(0, 20, 0, 0);
  grid->setHorizontalSpacing(22);
  grid->setVerticalSpacing(16);
  grid->addWidget(makeField("FCP 服务器", proxyHostEdit_), 0, 0);
  grid->addWidget(makeField("FCP 端口 (UDP)", proxyPortSpin_), 0, 1);
  grid->addWidget(makeField("PSK", proxyPskEdit_), 1, 0);
  grid->addWidget(makeField("本地监听端口", proxyListenSpin_), 1, 1);
  grid->addWidget(makeField("MTU", proxyMtuSpin_), 2, 0);
  grid->addWidget(makeField("钉 k", proxyKSpin_), 2, 1);
  grid->addWidget(makeField("FEC 预算", proxyBudgetSpin_), 3, 0);
  grid->addWidget(makeField("轨迹前缀", proxyTraceEdit_), 3, 1);
  grid->setColumnStretch(0, 1);
  grid->setColumnStretch(1, 1);
  layout->addLayout(grid);

  proxyPrewarmCheck_->setContentsMargins(0, 16, 0, 0);
  layout->addWidget(proxyPrewarmCheck_);

  auto* stateRow = new QWidget(page);
  auto* stateLayout = new QHBoxLayout(stateRow);
  stateLayout->setContentsMargins(0, 14, 0, 0);
  stateLayout->setSpacing(10);
  auto* dot = new QLabel(stateRow);
  dot->setObjectName("statusDot");
  dot->setFixedSize(10, 10);
  dot->setProperty("tone", "idle");
  proxyState_ = dot;
  proxyInfo_ = new QLabel("未运行", stateRow);
  proxyInfo_->setObjectName("statusText");
  stateLayout->addWidget(proxyState_);
  stateLayout->addWidget(proxyInfo_);
  stateLayout->addStretch();
  layout->addWidget(stateRow);

  auto* metricGrid = new QGridLayout;
  metricGrid->setContentsMargins(0, 14, 0, 0);
  metricGrid->setHorizontalSpacing(40);
  metricGrid->setVerticalSpacing(12);
  metricGrid->addWidget(makeMetric("活动连接", &proxyLiveValue_), 0, 0);
  metricGrid->addWidget(makeMetric("隧道累计", &proxyTunnelsValue_), 0, 1);
  metricGrid->addWidget(makeMetric("上行累计", &proxyUpValue_), 1, 0);
  metricGrid->addWidget(makeMetric("下行累计", &proxyDownValue_), 1, 1);
  layout->addLayout(metricGrid);

  auto* actions = new QWidget(page);
  auto* actionLayout = new QHBoxLayout(actions);
  actionLayout->setContentsMargins(0, 18, 0, 0);
  actionLayout->setSpacing(12);
  proxyStartBtn_ = new QPushButton("启动代理", actions);
  proxyStartBtn_->setObjectName("btnPrimary");
  proxyStartBtn_->setCursor(Qt::PointingHandCursor);
  proxyStopBtn_ = new QPushButton("停止", actions);
  proxyStopBtn_->setObjectName("btnGhost");
  proxyStopBtn_->setCursor(Qt::PointingHandCursor);
  actionLayout->addWidget(proxyStartBtn_);
  actionLayout->addWidget(proxyStopBtn_);
  actionLayout->addStretch();
  layout->addWidget(actions);

  auto* card = new QFrame(page);
  card->setObjectName("card");
  auto* cardLayout = new QHBoxLayout(card);
  cardLayout->setContentsMargins(22, 16, 22, 16);
  cardLayout->setSpacing(26);
  cardLayout->addWidget(makeTrafficCell("↓ 隧道下行", "累计 0 B", true, &proxyDownRate_,
                                        &proxyDownCap_, &proxyDownSpark_), 1);
  auto* divider = new QFrame(card);
  divider->setObjectName("trafficDivider");
  divider->setFixedWidth(1);
  cardLayout->addWidget(divider);
  cardLayout->addWidget(makeTrafficCell("↑ 隧道上行", "累计 0 B", false, &proxyUpRate_,
                                        &proxyUpCap_, &proxyUpSpark_), 1);
  auto* cardWrap = new QWidget(page);
  auto* cardWrapLayout = new QVBoxLayout(cardWrap);
  cardWrapLayout->setContentsMargins(0, 18, 0, 0);
  cardWrapLayout->addWidget(card);
  layout->addWidget(cardWrap);
  layout->addStretch();

  connect(proxyStartBtn_, &QPushButton::clicked, this, &MainWindow::startProxy);
  connect(proxyStopBtn_, &QPushButton::clicked, this, &MainWindow::stopProxy);
  return page;
}

bool MainWindow::collectProxyOptions(ProxyHost::Options* options, QString* error) const {
  if (proxyHostEdit_->text().trimmed().isEmpty()) {
    *error = QStringLiteral("请填写 FCP 服务器地址");
    return false;
  }
  static const QRegularExpression kHex32("^[0-9A-Fa-f]{32}$");
  const QString psk = proxyPskEdit_->text().trimmed();
  if (!kHex32.match(psk).hasMatch()) {
    *error = QStringLiteral("PSK 须为 32 位十六进制字符");
    return false;
  }
  options->server = proxyHostEdit_->text().trimmed();
  options->port = static_cast<quint16>(proxyPortSpin_->value());
  options->key = QByteArray::fromHex(psk.toLatin1());
  options->listen_port = static_cast<quint16>(proxyListenSpin_->value());
  options->mtu = proxyMtuSpin_->value();
  options->pinned_k = proxyKSpin_->value();
  options->prewarm = proxyPrewarmCheck_->isChecked();
  options->fec_budget = proxyBudgetSpin_->value();
  options->trace_prefix = proxyTraceEdit_->text().trimmed();
  return true;
}

void MainWindow::startProxy() {
  if (proxy_->running()) {
    return;
  }
  ProxyHost::Options options;
  QString error;
  if (!collectProxyOptions(&options, &error)) {
    proxyInfo_->setText(error);
    appendLog(QStringLiteral("代理参数错误：%1").arg(error));
    return;
  }
  proxyDownSpark_->clear();
  proxyUpSpark_->clear();
  proxyDownRate_->setText("0.00 Mbps");
  proxyUpRate_->setText("0.00 Mbps");
  appendLog(QStringLiteral("启动代理 → FCP %1:%2 · 本地 SOCKS5/HTTP 127.0.0.1:%3")
                .arg(options.server)
                .arg(options.port)
                .arg(options.listen_port));
  proxy_->start(options);
  updateButtons();
}

void MainWindow::stopProxy() {
  proxy_->stop();
  updateButtons();
}

void MainWindow::onProxyStats(const ProxyHost::Stats& stats) {
  const bool running = stats.state != ProxyHost::State::kIdle;
  QString text;
  QString tone = "run";
  switch (stats.state) {
    case ProxyHost::State::kIdle:
      text = "未运行";
      tone = "idle";
      break;
    case ProxyHost::State::kStarting:
      text = "解析 FCP 服务器…";
      break;
    case ProxyHost::State::kRunning:
      text = QStringLiteral("代理运行中 · SOCKS5/HTTP 127.0.0.1:%1")
                 .arg(stats.listen_port);
      break;
  }
  proxyInfo_->setText(text);
  proxyState_->setProperty("tone", tone);
  proxyState_->style()->unpolish(proxyState_);
  proxyState_->style()->polish(proxyState_);

  proxyLiveValue_->setText(QString::number(stats.live));
  proxyTunnelsValue_->setText(QString::number(stats.tunnels));
  proxyUpValue_->setText(humanBytes(stats.up_bytes));
  proxyDownValue_->setText(humanBytes(stats.down_bytes));
  proxyDownRate_->setText(QStringLiteral("%1 Mbps").arg(stats.down_mbps, 0, 'f', 2));
  proxyUpRate_->setText(QStringLiteral("%1 Mbps").arg(stats.up_mbps, 0, 'f', 2));
  proxyDownCap_->setText(
      QStringLiteral("累计 %1 · 异常 %2")
          .arg(humanBytes(stats.down_bytes))
          .arg(stats.bad_entry + stats.open_failed + stats.handshake_failed));
  proxyUpCap_->setText(
      QStringLiteral("累计 %1 · salt 冲突 %2")
          .arg(humanBytes(stats.up_bytes))
          .arg(stats.salt_clash));
  if (running) {
    proxyDownSpark_->push(stats.down_mbps);
    proxyUpSpark_->push(stats.up_mbps);
  }
  updateButtons();
}

void MainWindow::onProxyFinished(const ProxyHost::Result& result) {
  if (!result.ok) {
    proxyInfo_->setText(result.error);
    appendLog(QStringLiteral("代理异常退出：%1").arg(result.error));
  } else if (result.error == QStringLiteral("已停止")) {
    appendLog("代理已停止");
  } else {
    appendLog(QStringLiteral("代理已结束：%1").arg(result.error));
  }
  updateButtons();
}

QWidget* MainWindow::buildLogs() {
  auto* page = new QWidget;
  page->setObjectName("viewPage");
  auto* layout = new QVBoxLayout(page);
  layout->setContentsMargins(40, 26, 40, 24);
  layout->setSpacing(0);

  auto* title = new QLabel("运行日志", page);
  title->setObjectName("viewTitle");
  auto* subtitle = new QLabel("自动滚动跟随尾部 · 保留最近 1000 行", page);
  subtitle->setObjectName("viewSub");
  subtitle->setContentsMargins(0, 6, 0, 0);
  layout->addWidget(title);
  layout->addWidget(subtitle);

  logView_ = new QPlainTextEdit(page);
  logView_->setObjectName("logView");
  logView_->setReadOnly(true);
  logView_->setMaximumBlockCount(1000);
  logView_->setPlaceholderText("尚未开始测试");
  auto* wrap = new QWidget(page);
  auto* wrapLayout = new QVBoxLayout(wrap);
  wrapLayout->setContentsMargins(0, 16, 0, 0);
  wrapLayout->addWidget(logView_);
  layout->addWidget(wrap, 1);
  return page;
}

void MainWindow::loadSettings() {
  QSettings settings;
  // A3: the old factory default was the public FIPS-197 test key, and old
  // builds persisted PSKs in plaintext settings. Drop both: generate a fresh
  // key for this launch and never write it back.
  settings.remove("crypto/psk");
  settings.remove("crypto/salt");
  settings.remove("proxy/psk");
  hostEdit_->setText(settings.value("server/host").toString());
  portSpin_->setValue(settings.value("server/port", 40000).toInt());
  mbpsSpin_->setValue(settings.value("test/mbps", 20.0).toDouble());
  pskEdit_->setText(randomHex(16));
  segSpin_->setValue(settings.value("test/seg", 1200).toInt());
  mtuSpin_->setValue(settings.value("test/mtu", 1400).toInt());
  fecMode_->setCurrentIndex(settings.value("test/fec_mode", 0).toInt());
  kSpin_->setValue(settings.value("test/pinned_k", 3).toInt());
  kSpin_->setEnabled(fecMode_->currentIndex() == 1);
  repeatCheck_->setChecked(settings.value("test/repeat", false).toBool());
  proxyHostEdit_->setText(settings.value("proxy/host").toString());
  proxyPortSpin_->setValue(settings.value("proxy/port", 40000).toInt());
  proxyPskEdit_->setText(randomHex(16));
  proxyPskEdit_->setToolTip("须与服务端 --key 一致；每次启动随机生成，不写入配置文件");
  proxyListenSpin_->setValue(settings.value("proxy/listen_port", 1080).toInt());
  proxyMtuSpin_->setValue(settings.value("proxy/mtu", 1400).toInt());
  proxyKSpin_->setValue(settings.value("proxy/pinned_k", -1).toInt());
  proxyPrewarmCheck_->setChecked(settings.value("proxy/prewarm", true).toBool());
  proxyBudgetSpin_->setValue(
      settings.value("proxy/fec_budget", fcp::kDefaultFecBudget).toDouble());
  proxyTraceEdit_->setText(settings.value("proxy/trace_prefix").toString());
}

void MainWindow::saveSettings() {
  QSettings settings;
  settings.setValue("server/host", hostEdit_->text().trimmed());
  settings.setValue("server/port", portSpin_->value());
  settings.setValue("test/mbps", mbpsSpin_->value());
  settings.setValue("test/seg", segSpin_->value());
  settings.setValue("test/mtu", mtuSpin_->value());
  settings.setValue("test/fec_mode", fecMode_->currentIndex());
  settings.setValue("test/pinned_k", kSpin_->value());
  settings.setValue("test/repeat", repeatCheck_->isChecked());
  settings.setValue("proxy/host", proxyHostEdit_->text().trimmed());
  settings.setValue("proxy/port", proxyPortSpin_->value());
  settings.setValue("proxy/listen_port", proxyListenSpin_->value());
  settings.setValue("proxy/mtu", proxyMtuSpin_->value());
  settings.setValue("proxy/pinned_k", proxyKSpin_->value());
  settings.setValue("proxy/prewarm", proxyPrewarmCheck_->isChecked());
  settings.setValue("proxy/fec_budget", proxyBudgetSpin_->value());
  settings.setValue("proxy/trace_prefix", proxyTraceEdit_->text().trimmed());
}

BenchEngine::Options MainWindow::collectOptions(bool* ok, QString* error) const {
  BenchEngine::Options options;
  options.host = hostEdit_->text().trimmed();
  if (options.host.isEmpty()) {
    *ok = false;
    *error = QStringLiteral("请填写服务器地址");
    return options;
  }
  static const QRegularExpression kHex32("^[0-9A-Fa-f]{32}$");
  const QString psk = pskEdit_->text().trimmed();
  if (!kHex32.match(psk).hasMatch()) {
    *ok = false;
    *error = QStringLiteral("PSK 须为 32 位十六进制字符");
    return options;
  }
  options.port = static_cast<quint16>(portSpin_->value());
  options.mbps = mbpsSpin_->value();
  options.seg = segSpin_->value();
  options.mtu = mtuSpin_->value();
  options.key = QByteArray::fromHex(psk.toLatin1());
  options.pinned_k = fecMode_->currentIndex() == 1 ? kSpin_->value() : -1;
  if (options.seg + 36 > options.mtu - 20) {
    *ok = false;
    *error = QStringLiteral("分段过大：36 + 分段须不超过 MTU − 20");
    return options;
  }
  *ok = true;
  return options;
}

void MainWindow::startTest() {
  if (engine_->running()) {
    return;
  }
  repeatTimer_->stop();
  suppressRepeat_ = false;
  bool ok = false;
  QString error;
  const BenchEngine::Options options = collectOptions(&ok, &error);
  if (!ok) {
    testInfo_->setText(error);
    appendLog(QStringLiteral("参数错误：%1").arg(error));
    showView(1);
    return;
  }

  lastServer_ = QString("%1:%2").arg(options.host).arg(options.port);
  resultCard_->setVisible(false);
  testInfo_->clear();
  downSpark_->clear();
  upSpark_->clear();
  downRate_->setText("0.00 Mbps");
  upRate_->setText("0.00 Mbps");
  downCap_->setText("峰值 0.00 Mbps · 累计 0 B");
  upCap_->setText("峰值 0.00 Mbps · 累计 0 B");

  appendLog(QStringLiteral("开始测试 → %1 · 目标 %2 Mbps")
                .arg(lastServer_)
                .arg(options.mbps, 0, 'f', 1));
  engine_->start(options);
  updateButtons();
}

void MainWindow::stopTest() {
  suppressRepeat_ = true;
  repeatTimer_->stop();
  engine_->stop();
  testInfo_->setText("已停止");
  updateButtons();
}

void MainWindow::showView(int index) {
  stack_->setCurrentIndex(index);
  if (nav_->button(index) != nullptr) {
    nav_->button(index)->setChecked(true);
  }
}

void MainWindow::appendLog(const QString& line) {
  if (logView_ == nullptr) {
    return;
  }
  logView_->appendPlainText(
      QStringLiteral("%1  %2").arg(QTime::currentTime().toString("HH:mm:ss"), line));
}

void MainWindow::setStatus(const QString& text, const QString& sub, const QString& tone) {
  statusText_->setText(text);
  statusSub_->setText(sub);
  statusDot_->setProperty("tone", tone);
  statusDot_->style()->unpolish(statusDot_);
  statusDot_->style()->polish(statusDot_);
}

void MainWindow::updateButtons() {
  const bool running = engine_->running();
  startBtn_->setEnabled(!running);
  stopBtn_->setEnabled(running);
  const bool proxyRunning = proxy_ != nullptr && proxy_->running();
  if (proxyStartBtn_ != nullptr) {
    proxyStartBtn_->setEnabled(!proxyRunning);
    proxyStopBtn_->setEnabled(proxyRunning);
  }
}

void MainWindow::onStats(const BenchEngine::Stats& stats) {
  const bool running = engine_->running();
  QString text;
  QString sub = statusSub_->text();
  QString tone = "run";
  switch (stats.state) {
    case BenchEngine::State::kIdle:
      text = "未运行";
      sub = "FCP v6 · 可靠 UDP 隧道 · 自适应纠删";
      tone = "idle";
      break;
    case BenchEngine::State::kResolving:
      text = "解析主机";
      sub = QStringLiteral("正在解析 %1…").arg(hostEdit_->text().trimmed());
      break;
    case BenchEngine::State::kRendezvous:
      text = "等待会合";
      sub = "请确认对端已运行 fcp_bench server，且 UDP 端口可达";
      break;
    case BenchEngine::State::kHandshake:
      text = "握手中";
      sub = QStringLiteral("与 %1 协商 D/P 与会话密钥…").arg(lastServer_);
      break;
    case BenchEngine::State::kUpload:
      text = "上传测速";
      sub = QStringLiteral("目标 %1 Mbps · 分段 %2 B")
                .arg(mbpsSpin_->value(), 0, 'f', 1)
                .arg(segSpin_->value());
      break;
    case BenchEngine::State::kWaitingDown:
      text = "等待下行";
      sub = "上行结束，等待服务端回传…";
      break;
    case BenchEngine::State::kDownload:
      text = "下载测速";
      sub = "下行测速中 · 自适应 FEC 按实测丢包调整 k";
      break;
    case BenchEngine::State::kFinished:
    case BenchEngine::State::kFailed:
      break;  // onFinished owns the final status text
  }
  if (stats.state != BenchEngine::State::kFinished &&
      stats.state != BenchEngine::State::kFailed) {
    setStatus(text, sub, tone);
  }

  if (stats.state == BenchEngine::State::kIdle) {
    uptime_->hide();
  } else {
    uptime_->setText(QStringLiteral("已运行 %1").arg(formatDuration(stats.elapsed_ms)));
    uptime_->show();
  }

  serverValue_->setText(lastServer_.isEmpty() ? "—" : lastServer_);
  localValue_->setText(stats.local_port != 0
                           ? QStringLiteral("127.0.0.1:%1").arg(stats.local_port)
                           : "—");
  const bool sessionAlive = stats.state != BenchEngine::State::kIdle &&
                            stats.state != BenchEngine::State::kResolving &&
                            stats.state != BenchEngine::State::kRendezvous;
  kValue_->setText(sessionAlive ? QString::number(stats.k) : "—");
  setsValue_->setText(QString::number(stats.active_sets));
  lossValue_->setText(QStringLiteral("%1 %").arg(stats.pre_ppm / 10000.0, 0, 'f', 2));
  lossValue_->setToolTip(
      QStringLiteral("前置丢包 %1 % · 有效交付 %2 %")
          .arg(stats.pre_ppm / 10000.0, 0, 'f', 2)
          .arg(stats.usable_ppm / 10000.0, 0, 'f', 2));
  failValue_->setText(QStringLiteral("授权 %1 · 结构 %2")
                          .arg(stats.auth_fail)
                          .arg(stats.struct_fail));

  downRate_->setText(QStringLiteral("%1 Mbps").arg(stats.down_mbps, 0, 'f', 2));
  upRate_->setText(QStringLiteral("%1 Mbps").arg(stats.up_mbps, 0, 'f', 2));
  downCap_->setText(QStringLiteral("峰值 %1 Mbps · 累计 %2")
                        .arg(stats.down_peak_mbps, 0, 'f', 2)
                        .arg(humanBytes(stats.down_bytes)));
  upCap_->setText(QStringLiteral("峰值 %1 Mbps · 累计 %2")
                      .arg(stats.up_peak_mbps, 0, 'f', 2)
                      .arg(humanBytes(stats.up_bytes)));
  if (running) {
    downSpark_->push(stats.down_mbps);
    upSpark_->push(stats.up_mbps);
  }
  updateButtons();
}

void MainWindow::onFinished(const BenchEngine::Result& result) {
  if (result.ok) {
    const double delivery =
        result.expected != 0
            ? 100.0 * static_cast<double>(result.delivered) / static_cast<double>(result.expected)
            : 0.0;
    setStatus("测试完成",
              QStringLiteral("上行 %1 Mbps · 下行 %2 Mbps")
                  .arg(result.up_mbps, 0, 'f', 2)
                  .arg(result.down_mbps, 0, 'f', 2),
              "ok");
    resultUp_->setText(QStringLiteral("%1 Mbps").arg(result.up_mbps, 0, 'f', 2));
    resultDown_->setText(QStringLiteral("%1 Mbps").arg(result.down_mbps, 0, 'f', 2));
    resultDelivery_->setText(result.expected != 0
                                 ? QStringLiteral("%1 %").arg(delivery, 0, 'f', 1)
                                 : QStringLiteral("—"));
    resultHandshake_->setText(result.handshake_ms >= 0
                                  ? QStringLiteral("%1 ms").arg(result.handshake_ms)
                                  : QStringLiteral("—"));
    resultMeta_->setText(QStringLiteral("k=%1 · 结算一致 %2 · 授权失败 %3 · 结构失败 %4")
                             .arg(result.k)
                             .arg(result.identity_ok ? "✓" : "✗")
                             .arg(result.auth_fail)
                             .arg(result.struct_fail));
    resultCard_->setVisible(true);
    if (repeatCheck_->isChecked() && !suppressRepeat_) {
      testInfo_->setText("5 秒后自动重测");
      repeatTimer_->start(5000);
    } else {
      testInfo_->clear();
    }
  } else {
    setStatus("连接失败", result.error, "err");
    testInfo_->setText(result.error);
    resultCard_->setVisible(false);
  }
  updateButtons();
}

void MainWindow::closeEvent(QCloseEvent* event) {
  saveSettings();
  if (engine_->running()) {
    engine_->stop();
  }
  if (proxy_ != nullptr && proxy_->running()) {
    proxy_->stop();
  }
  QMainWindow::closeEvent(event);
}

void MainWindow::resizeEvent(QResizeEvent* event) {
  QMainWindow::resizeEvent(event);
  if (grip_ != nullptr) {
    grip_->move(width() - 18, height() - 18);
  }
}
