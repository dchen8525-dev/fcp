#include "mainwindow.h"

#include <QAction>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTextDocument>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <cmath>

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#endif

#include "sparkline.h"

namespace fcp {
namespace {

constexpr const char* kAccent = "#0f9d76";
constexpr const char* kAccentDark = "#0b8563";
constexpr const char* kMuted = "#5b6b63";
constexpr const char* kMuted2 = "#8a9a91";
constexpr const char* kErr = "#c2410c";
// 日志窗按级别上色：正文颜色即级别，DEBUG 最淡、ERROR 最重。
constexpr const char* kLogDebug = "#8a9a91";
constexpr const char* kLogInfo = "#5b6b63";
constexpr const char* kLogWarn = "#a56a12";
constexpr const char* kLogError = "#b91c1c";

QLabel* makeLabel(const QString& text, const char* role = nullptr) {
  auto* label = new QLabel(text);
  if (role) {
    label->setProperty("role", role);
  }
  return label;
}

QLabel* makeRichLabel(const QString& text, const char* role = nullptr) {
  QLabel* label = makeLabel(text, role);
  label->setTextFormat(Qt::RichText);
  return label;
}

void repolish(QWidget* widget) {
  widget->style()->unpolish(widget);
  widget->style()->polish(widget);
  widget->update();
}

// 24x24 viewBox 的线性图标，用 QPainter 画，不额外依赖 QtSvg。
QIcon makeNavIcon(int kind, const QColor& color) {
  QPixmap pixmap(32, 32);
  pixmap.setDevicePixelRatio(2.0);
  pixmap.fill(Qt::transparent);
  QPainter painter(&pixmap);
  painter.setRenderHint(QPainter::Antialiasing, true);
  painter.scale(16.0 / 24.0, 16.0 / 24.0);
  painter.setPen(QPen(color, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
  painter.setBrush(Qt::NoBrush);

  switch (kind) {
    case 0:  // 连接
      painter.drawLine(QPointF(12, 3), QPointF(12, 9));
      painter.drawPolyline(QPolygonF({QPointF(8, 6.5), QPointF(12, 10), QPointF(16, 6.5)}));
      painter.drawRoundedRect(QRectF(4, 12, 16, 8), 3, 3);
      painter.setBrush(color);
      for (double x : {8.0, 12.0, 16.0}) {
        painter.drawEllipse(QPointF(x, 16), 0.8, 0.8);
      }
      break;
    case 1:  // 运行状态
      painter.drawPolyline(QPolygonF({QPointF(3, 13), QPointF(7, 13), QPointF(9.5, 7),
                                      QPointF(13.5, 19), QPointF(16, 13), QPointF(21, 13)}));
      break;
    case 2:  // 链路测速
      painter.drawArc(QRectF(4.2, 5.2, 15.6, 15.6), 200 * 16, 140 * 16);
      painter.drawLine(QPointF(12, 14), QPointF(15, 10));
      painter.drawEllipse(QPointF(12, 14), 1.8, 1.8);
      break;
    case 3:  // 日志
      painter.drawLine(QPointF(4, 5), QPointF(20, 5));
      painter.drawLine(QPointF(4, 10), QPointF(20, 10));
      painter.drawLine(QPointF(4, 15), QPointF(14, 15));
      painter.drawLine(QPointF(4, 20), QPointF(11, 20));
      break;
    default:
      break;
  }
  painter.end();

  QIcon icon;
  icon.addPixmap(pixmap, QIcon::Normal, QIcon::Off);
  // 选中态换成品牌绿。
  if (!color.isValid() || color != QColor(kAccent)) {
    QIcon active = makeNavIcon(kind, QColor(kAccent));
    icon.addPixmap(active.pixmap(QSize(16, 16), QIcon::Normal, QIcon::On), QIcon::Normal,
                   QIcon::On);
  } else {
    icon.addPixmap(pixmap, QIcon::Normal, QIcon::On);
  }
  return icon;
}

// 密钥框的显示/隐藏按钮：同一套 24 网格线性语言（1.8 描边、圆角端点）。
// visible=false（文本隐藏）画睁眼（点下去就显示）；visible=true（文本已
// 可见）画带斜杠的闭眼——按钮展示"点下去会发生什么"。
QIcon makeEyeIcon(bool visible, const QColor& color) {
  QPixmap pixmap(32, 32);
  pixmap.setDevicePixelRatio(2.0);
  pixmap.fill(Qt::transparent);
  QPainter painter(&pixmap);
  painter.setRenderHint(QPainter::Antialiasing, true);
  painter.scale(16.0 / 24.0, 16.0 / 24.0);
  painter.setPen(QPen(color, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
  painter.setBrush(Qt::NoBrush);

  if (visible) {
    // 睁眼：上下眼睑各一条二次曲线围出杏仁形 + 实心瞳孔（和导航图标的
    // 实心圆点同一个母题）。
    QPainterPath lid;
    lid.moveTo(3.0, 12.0);
    lid.quadTo(12.0, 4.6, 21.0, 12.0);
    lid.quadTo(12.0, 19.4, 3.0, 12.0);
    painter.drawPath(lid);
    painter.setPen(Qt::NoPen);
    painter.setBrush(color);
    painter.drawEllipse(QPointF(12.0, 12.0), 2.4, 2.4);
  } else {
    // 闭眼：眼睑收扁 + 贯穿的斜杠（端点压出轮廓一点，"划掉"的意思在
    // 16px 下也立得住）+ 收小的实心瞳。
    QPainterPath lid;
    lid.moveTo(4.0, 13.0);
    lid.quadTo(12.0, 5.8, 20.0, 13.0);
    lid.quadTo(12.0, 20.2, 4.0, 13.0);
    painter.drawPath(lid);
    painter.setPen(QPen(color, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawLine(QPointF(4.5, 5.5), QPointF(19.5, 20.5));
    painter.setPen(Qt::NoPen);
    painter.setBrush(color);
    painter.drawEllipse(QPointF(12.0, 13.0), 1.1, 1.1);
  }
  painter.end();

  QIcon icon;
  icon.addPixmap(pixmap, QIcon::Normal, QIcon::Off);
  return icon;
}

QPixmap pulsePixmap() {
  QPixmap pixmap(40, 40);
  pixmap.setDevicePixelRatio(2.0);
  pixmap.fill(Qt::transparent);
  QPainter painter(&pixmap);
  painter.setRenderHint(QPainter::Antialiasing, true);
  painter.scale(20.0 / 24.0, 20.0 / 24.0);
  painter.setPen(QPen(QColor(kAccent), 2.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
  painter.drawPolyline(QPolygonF({QPointF(3, 13), QPointF(7, 13), QPointF(9.5, 7),
                                  QPointF(13.5, 19), QPointF(16, 13), QPointF(21, 13)}));
  painter.end();
  return pixmap;
}

QWidget* makeField(const QString& text, QWidget* input, const QString& note = {}) {
  auto* holder = new QWidget;
  auto* layout = new QVBoxLayout(holder);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(5);

  auto* head = new QHBoxLayout;
  head->setContentsMargins(0, 0, 0, 0);
  head->setSpacing(6);
  head->addWidget(makeLabel(text, "fieldLabel"));
  if (!note.isEmpty()) {
    head->addWidget(makeLabel(note, "fieldNote"));
  }
  head->addStretch();
  layout->addLayout(head);
  layout->addWidget(input);
  return holder;
}

#ifdef Q_OS_WIN
// 网络切换检测（稳定性包 5）：Qt 6.3 之前没有 QNetworkInformation，改用
// GetAdaptersAddresses 每 5 秒取一次适配器快照。换 Wi-Fi、插拔网线、断网、
// VPN 上下线都会让快照变化；摘要只用于相等比较，不落日志。
QByteArray adaptersDigest() {
  ULONG size = 16 * 1024;
  QByteArray buffer;
  for (int attempt = 0; attempt < 2; ++attempt) {
    buffer.resize(static_cast<int>(size));
    auto* head = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
    const ULONG err = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, head, &size);
    if (err == ERROR_SUCCESS) {
      QByteArray digest;
      for (auto* adapter = head; adapter != nullptr; adapter = adapter->Next) {
        // Only stable identity: OperStatus flaps on DHCP renew / brief link
        // blips and adapter list order is not guaranteed, so neither may
        // trigger a rebuild. Unicast addresses are the actual path change.
        digest.append(adapter->AdapterName);  // GUID 字符串，结尾含 '\0'
        digest.append(reinterpret_cast<const char*>(adapter->PhysicalAddress),
                      static_cast<int>(adapter->PhysicalAddressLength));
        for (auto* addr = adapter->FirstUnicastAddress; addr != nullptr;
             addr = addr->Next) {
          const auto* sa = addr->Address.lpSockaddr;
          if (sa != nullptr) {
            digest.append(reinterpret_cast<const char*>(sa),
                          static_cast<int>(addr->Address.iSockaddrLength));
          }
        }
      }
      return digest;
    }
    if (err != ERROR_BUFFER_OVERFLOW) {
      return QByteArray();  // 调用不可用/被拒：本 tick 跳过
    }
  }
  return QByteArray();  // 两次扩容都装不下：跳过
}
#else
QByteArray adaptersDigest() {
  return QByteArray();
}
#endif

}  // namespace

MainWindow::MainWindow(Sidecar* sidecar, QWidget* parent)
    : QMainWindow(parent), sidecar_(sidecar) {
  setWindowTitle(QStringLiteral("FCP"));
  setWindowIcon(QIcon(QStringLiteral(":/assets/fcp.png")));
  resize(960, 680);
  setMinimumSize(760, 560);

  auto* central = new QWidget;
  central->setObjectName(QStringLiteral("central"));
  auto* root = new QHBoxLayout(central);
  root->setContentsMargins(0, 0, 0, 0);
  root->setSpacing(0);

  stack_ = new QStackedWidget;
  root->addWidget(buildRail());

  auto* stage = new QWidget;
  auto* stage_layout = new QVBoxLayout(stage);
  stage_layout->setContentsMargins(18, 20, 20, 20);
  stage_layout->setSpacing(0);
  stage_layout->addWidget(stack_);
  root->addWidget(stage, 1);
  setCentralWidget(central);

  // 连接页展开高级设置后需要 ~736px 高，而默认窗口 960×680 只有约 640px
  // 可用（高分屏缩放下更紧）。空间不足时 Qt 会把布局压到 minimumSize 以下，
  // 输入框因此被裁成一条细缝。放进滚动区：放不下就整页滚动。
  auto* conn_scroll = new QScrollArea;
  conn_scroll->setWidgetResizable(true);
  conn_scroll->setFrameShape(QFrame::NoFrame);
  conn_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  conn_scroll->setWidget(buildConnPage());
  conn_scroll->viewport()->setAutoFillBackground(false);
  conn_scroll->setStyleSheet(QStringLiteral("QScrollArea{background:transparent;}"));
  stack_->addWidget(conn_scroll);
  stack_->addWidget(buildStatusPage());
  stack_->addWidget(buildSpeedPage());
  stack_->addWidget(buildLogPage());

  connect(sidecar_, &Sidecar::proxyStats, this, &MainWindow::onStats);
  connect(sidecar_, &Sidecar::proxyLog, this,
          [this](const QString& line, bool) { appendLog(line); });
  connect(sidecar_, &Sidecar::proxyStateChanged, this,
          [this](bool running, int exit_code, bool abnormal) {
            if (running) {
              setRunning(true);
              return;
            }
            const QString hint = abnormal
                                     ? QStringLiteral("代理异常退出（code %1）").arg(exit_code)
                                     : QStringLiteral("已断开");
            setRunning(false, hint);
            dot_->setStyleSheet(
                QStringLiteral("background:%1;border-radius:4px;").arg(abnormal ? kErr : "#c6d3cc"));
          });
  connect(sidecar_, &Sidecar::speedProgress, this, &MainWindow::onSpeedProgress);
  connect(sidecar_, &Sidecar::speedDone, this, &MainWindow::onSpeedDone);
  connect(sidecar_, &Sidecar::speedStateChanged, this, [this](bool running) {
    speed_running_ = running;
    speed_start_->setEnabled(!running);
    // 单程时长一旦被中途改掉，进度条的 2×时长估算就对不上了。
    speed_seconds_->setEnabled(!running);
  });

  setupTray();
  loadSettings();
  setRunning(false, QString());
  syncAddr();
  updateKeyState();

  // 网络切换轮询只在隧道运行时开着（见 setRunning）；这里的 connect 提前挂好。
  net_watch_ = new QTimer(this);
  net_watch_->setInterval(5000);
  connect(net_watch_, &QTimer::timeout, this, &MainWindow::onNetWatchTick);
}

MainWindow::~MainWindow() = default;

QFrame* MainWindow::makeCard() {
  auto* card = new QFrame;
  card->setProperty("role", "card");
  return card;
}

QWidget* MainWindow::buildRail() {
  auto* rail = new QWidget;
  rail->setObjectName(QStringLiteral("rail"));
  rail->setFixedWidth(208);

  auto* layout = new QVBoxLayout(rail);
  layout->setContentsMargins(14, 18, 14, 16);
  layout->setSpacing(6);

  auto* brand = new QHBoxLayout;
  brand->setContentsMargins(6, 4, 6, 16);
  brand->setSpacing(10);
  auto* mark = new QLabel;
  mark->setPixmap(QIcon(QStringLiteral(":/assets/fcp.png")).pixmap(32, 32));
  mark->setFixedSize(32, 32);
  brand->addWidget(mark);

  auto* brand_text = new QVBoxLayout;
  brand_text->setContentsMargins(0, 0, 0, 0);
  brand_text->setSpacing(0);
  auto* name = makeLabel(QStringLiteral("FCP"));
  name->setObjectName(QStringLiteral("brandName"));
  auto* sub = makeLabel(QStringLiteral("可靠传输客户端"));
  sub->setObjectName(QStringLiteral("brandSub"));
  brand_text->addWidget(name);
  brand_text->addWidget(sub);
  brand->addLayout(brand_text);
  brand->addStretch();
  layout->addLayout(brand);

  auto* group = new QButtonGroup(this);
  group->setExclusive(true);
  const QStringList titles{QStringLiteral("连接"), QStringLiteral("运行状态"),
                           QStringLiteral("链路测速"), QStringLiteral("日志")};
  for (int i = 0; i < titles.size(); ++i) {
    auto* button = new QPushButton(titles.at(i));
    button->setObjectName(QStringLiteral("nav"));
    button->setCheckable(true);
    button->setCursor(Qt::PointingHandCursor);
    button->setIcon(makeNavIcon(i, QColor(kMuted)));
    button->setIconSize(QSize(16, 16));
    group->addButton(button, i);
    connect(button, &QPushButton::clicked, this, [this, i] { stack_->setCurrentIndex(i); });
    nav_.append(button);
    layout->addWidget(button);
  }
  nav_.first()->setChecked(true);
  layout->addStretch();

  auto* foot = new QFrame;
  foot->setProperty("role", "railFoot");
  auto* foot_layout = new QVBoxLayout(foot);
  foot_layout->setContentsMargins(10, 9, 10, 9);
  foot_layout->setSpacing(5);

  auto* state_row = new QHBoxLayout;
  state_row->setContentsMargins(0, 0, 0, 0);
  state_row->setSpacing(8);
  dot_ = new QLabel;
  dot_->setFixedSize(8, 8);
  dot_->setStyleSheet(QStringLiteral("background:#c6d3cc;border-radius:4px;"));
  state_text_ = makeLabel(QStringLiteral("未连接"), "muted");
  state_row->addWidget(dot_, 0, Qt::AlignVCenter);
  state_row->addWidget(state_text_);
  state_row->addStretch();
  foot_layout->addLayout(state_row);

  auto* addr_row = new QHBoxLayout;
  addr_row->setContentsMargins(0, 0, 0, 0);
  addr_row->setSpacing(8);
  rail_addr_ = makeLabel(QStringLiteral("127.0.0.1:1080"), "mono");
  rail_addr_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  uptime_ = makeLabel(QStringLiteral("--"), "monoStrong");
  addr_row->addWidget(rail_addr_);
  addr_row->addStretch();
  addr_row->addWidget(uptime_);
  foot_layout->addLayout(addr_row);

  layout->addWidget(foot);
  return rail;
}

QWidget* MainWindow::buildConnPage() {
  auto* card = makeCard();
  auto* layout = new QVBoxLayout(card);
  layout->setContentsMargins(24, 20, 24, 20);
  layout->setSpacing(12);

  auto* head = new QHBoxLayout;
  head->setContentsMargins(0, 0, 0, 2);
  head->setSpacing(10);
  head->addWidget(makeLabel(QStringLiteral("连接"), "h2"));
  head->addWidget(makeLabel(QStringLiteral("修改后需重新启动生效"), "headSub"));
  head->addStretch();
  layout->addLayout(head);

  auto* form = new QWidget;
  form->setMaximumWidth(640);
  auto* form_layout = new QVBoxLayout(form);
  form_layout->setContentsMargins(0, 0, 0, 0);
  form_layout->setSpacing(12);

  host_ = new QLineEdit;
  host_->setPlaceholderText(QStringLiteral("1.2.3.4 或 vpn.example.com"));
  host_->setClearButtonEnabled(false);
  form_layout->addWidget(makeField(QStringLiteral("服务器地址"), host_));

  auto* row = new QHBoxLayout;
  row->setContentsMargins(0, 0, 0, 0);
  row->setSpacing(12);
  port_ = new QLineEdit(QStringLiteral("4460"));
  listen_port_ = new QLineEdit(QStringLiteral("1080"));
  row->addWidget(makeField(QStringLiteral("UDP 端口"), port_));
  row->addWidget(makeField(QStringLiteral("本地代理端口"), listen_port_,
                           QStringLiteral("SOCKS5 / HTTP")));
  form_layout->addLayout(row);

  auto* key_row = new QWidget;
  auto* key_layout = new QVBoxLayout(key_row);
  key_layout->setContentsMargins(0, 0, 0, 0);
  key_layout->setSpacing(5);
  auto* key_head = new QHBoxLayout;
  key_head->setContentsMargins(0, 0, 0, 0);
  key_head->setSpacing(6);
  key_head->addWidget(makeLabel(QStringLiteral("预共享密钥"), "fieldLabel"));
  key_head->addWidget(makeLabel(QStringLiteral("32 位十六进制"), "fieldNote"));
  key_head->addStretch();
  key_layout->addLayout(key_head);

  auto* key_input_row = new QHBoxLayout;
  key_input_row->setContentsMargins(0, 0, 0, 0);
  key_input_row->setSpacing(6);
  key_ = new QLineEdit;
  key_->setEchoMode(QLineEdit::Password);
  key_->setMaxLength(32);
  key_->setPlaceholderText(QStringLiteral("与服务端一致"));
  key_input_row->addWidget(key_, 1);
  key_state_ = makeLabel(QString(), "fieldNote");
  key_input_row->addWidget(key_state_);
  key_toggle_ = new QToolButton;
  key_toggle_->setObjectName(QStringLiteral("eye"));
  key_toggle_->setToolTip(QStringLiteral("显示 / 隐藏"));
  // 与 app.qss 里 #eye 的文字色一致（emoji 换矢量图标后颜色仍照同一根色）。
  key_toggle_->setIcon(makeEyeIcon(false, QColor(QStringLiteral("#5b6b63"))));
  key_toggle_->setIconSize(QSize(18, 18));
  key_toggle_->setAutoRaise(true);
  key_toggle_->setCursor(Qt::PointingHandCursor);
  key_input_row->addWidget(key_toggle_);
  key_layout->addLayout(key_input_row);
  form_layout->addWidget(key_row);

  remember_ = new QCheckBox(QStringLiteral("记住设置"));
  remember_->setChecked(true);
  form_layout->addWidget(remember_);

  adv_toggle_ = new QPushButton;
  adv_toggle_->setObjectName(QStringLiteral("link"));
  adv_toggle_->setCursor(Qt::PointingHandCursor);
  adv_toggle_->setText(QStringLiteral("▸  高级设置    MTU 1400 · FEC 0.5 · k 自适应 · 127.0.0.1"));
  form_layout->addWidget(adv_toggle_);

  adv_body_ = new QFrame;
  adv_body_->setProperty("role", "adv");
  auto* adv_layout = new QGridLayout(adv_body_);
  adv_layout->setContentsMargins(14, 12, 14, 12);
  adv_layout->setHorizontalSpacing(14);
  adv_layout->setVerticalSpacing(10);
  listen_ = new QLineEdit(QStringLiteral("127.0.0.1"));
  mtu_ = new QLineEdit(QStringLiteral("1400"));
  budget_ = new QLineEdit(QStringLiteral("0.5"));
  k_ = new QLineEdit(QStringLiteral("-1"));
  rate_ = new QLineEdit(QStringLiteral("0"));
  pmtu_max_ = new QLineEdit(QStringLiteral("1500"));
  pmtud_ = new QCheckBox(QStringLiteral("启用路径 MTU 探测（关闭后固定用上面的 MTU）"));
  pmtud_->setChecked(true);
  adv_layout->addWidget(makeField(QStringLiteral("本地监听地址"), listen_), 0, 0);
  adv_layout->addWidget(makeField(QStringLiteral("MTU"), mtu_), 0, 1);
  adv_layout->addWidget(
      makeField(QStringLiteral("FEC 冗余上限"), budget_, QStringLiteral("0–1")), 1, 0);
  adv_layout->addWidget(
      makeField(QStringLiteral("固定 k"), k_, QStringLiteral("-1 为自适应")), 1, 1);
  adv_layout->addWidget(
      makeField(QStringLiteral("上行限速 (Mbps)"), rate_, QStringLiteral("0 为不限")), 2, 0);
  adv_layout->addWidget(
      makeField(QStringLiteral("探测上限 MTU"), pmtu_max_, QStringLiteral("≤9000")), 2, 1);
  adv_layout->addWidget(pmtud_, 3, 0, 1, 2);
  auto* adv_note = makeLabel(
      QStringLiteral("不展开时按默认值提交，与显式填写效果相同。"),
      "fieldNote");
  adv_layout->addWidget(adv_note, 4, 0, 1, 2);
  adv_body_->setVisible(false);
  form_layout->addWidget(adv_body_);

  auto* actions = new QHBoxLayout;
  actions->setContentsMargins(0, 8, 0, 0);
  actions->setSpacing(10);
  start_ = new QPushButton(QStringLiteral("启动代理"));
  start_->setObjectName(QStringLiteral("primary"));
  start_->setCursor(Qt::PointingHandCursor);
  hint_ = makeLabel(QString(), "hint");
  hint_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  actions->addWidget(start_);
  actions->addWidget(hint_, 1);
  form_layout->addLayout(actions);

  layout->addWidget(form);
  layout->addStretch();

  auto* tip = new QFrame;
  tip->setProperty("role", "tip");
  auto* tip_layout = new QVBoxLayout(tip);
  tip_layout->setContentsMargins(14, 11, 14, 11);
  conn_addr_ = makeRichLabel(QString(), "muted");
  conn_addr_->setWordWrap(true);
  tip_layout->addWidget(conn_addr_);
  layout->addWidget(tip);

  // 同一个按钮：未连接时是绿色"启动代理"，连接中变红色"停止代理"——
  // 颜色与文案同时声明状态与下一次点击的作用，不会把"已启动"看成没启动。
  connect(start_, &QPushButton::clicked, this, [this] {
    running_ ? onStop() : onStart();
  });
  connect(adv_toggle_, &QPushButton::clicked, this, [this] { setAdvanced(!advanced_); });
  connect(key_toggle_, &QToolButton::clicked, this, [this] {
    const bool hidden = key_->echoMode() == QLineEdit::Password;
    key_->setEchoMode(hidden ? QLineEdit::Normal : QLineEdit::Password);
    key_toggle_->setIcon(makeEyeIcon(hidden, QColor(QStringLiteral("#5b6b63"))));
  });
  connect(key_, &QLineEdit::textChanged, this, [this] {
    updateKeyState();
    saveSettings();
  });
  connect(host_, &QLineEdit::textChanged, this, [this] { saveSettings(); });
  connect(port_, &QLineEdit::textChanged, this, [this] { saveSettings(); });
  connect(listen_port_, &QLineEdit::textChanged, this, [this] {
    syncAddr();
    saveSettings();
  });
  connect(listen_, &QLineEdit::textChanged, this, [this] {
    syncAddr();
    saveSettings();
  });
  connect(mtu_, &QLineEdit::textChanged, this, [this] { saveSettings(); });
  connect(budget_, &QLineEdit::textChanged, this, [this] { saveSettings(); });
  connect(k_, &QLineEdit::textChanged, this, [this] { saveSettings(); });
  connect(pmtu_max_, &QLineEdit::textChanged, this, [this] { saveSettings(); });
  connect(pmtud_, &QCheckBox::toggled, this, [this] { saveSettings(); });
  connect(remember_, &QCheckBox::toggled, this, [this] { saveSettings(); });
  return card;
}

QWidget* MainWindow::buildStatusPage() {
  auto* card = makeCard();
  auto* layout = new QVBoxLayout(card);
  layout->setContentsMargins(24, 20, 24, 20);
  layout->setSpacing(12);

  auto* head = new QHBoxLayout;
  head->setContentsMargins(0, 0, 0, 2);
  head->setSpacing(10);
  head->addWidget(makeLabel(QStringLiteral("运行状态"), "h2"));
  head->addWidget(makeLabel(QStringLiteral("每 0.5 秒采样"), "headSub"));
  head->addStretch();
  layout->addLayout(head);

  auto* brief = new QFrame;
  brief->setProperty("role", "brief");
  auto* brief_layout = new QHBoxLayout(brief);
  brief_layout->setContentsMargins(14, 14, 16, 14);
  brief_layout->setSpacing(14);
  auto* pulse = new QLabel;
  pulse->setPixmap(pulsePixmap());
  pulse->setFixedSize(38, 38);
  pulse->setAlignment(Qt::AlignCenter);
  pulse->setStyleSheet(QStringLiteral("background:#ffffff;border-radius:11px;"));
  brief_layout->addWidget(pulse);
  auto* live_box = new QVBoxLayout;
  live_box->setContentsMargins(0, 0, 0, 0);
  live_box->setSpacing(1);
  live_box->addWidget(makeLabel(QStringLiteral("活动会话"), "metricCap"));
  m_live_ = makeLabel(QStringLiteral("0"), "bigValue");
  live_box->addWidget(m_live_);
  brief_layout->addLayout(live_box);
  brief_layout->addStretch();
  auto* chips = new QHBoxLayout;
  chips->setContentsMargins(0, 0, 0, 0);
  chips->setSpacing(6);
  chips->addWidget(makeLabel(QStringLiteral("UDP / FEC"), "chip"), 0, Qt::AlignVCenter);
  sample_chip_ = makeRichLabel(QStringLiteral("采样 --"), "chip");
  chips->addWidget(sample_chip_, 0, Qt::AlignVCenter);
  brief_layout->addLayout(chips);
  layout->addWidget(brief);

  auto* metrics = new QHBoxLayout;
  metrics->setContentsMargins(0, 0, 0, 0);
  metrics->setSpacing(10);
  const auto add_metric = [&](const QString& cap, QLabel** value, const char* role) {
    auto* frame = new QFrame;
    frame->setProperty("role", "metric");
    auto* box = new QVBoxLayout(frame);
    box->setContentsMargins(11, 11, 11, 11);
    box->setSpacing(2);
    box->addWidget(makeLabel(cap, "metricCap"));
    *value = makeLabel(QStringLiteral("0"), role);
    box->addWidget(*value);
    metrics->addWidget(frame, 1);
  };
  add_metric(QStringLiteral("下行"), &m_rx_, "metricValueRx");
  add_metric(QStringLiteral("上行"), &m_tx_, "metricValueTx");
  add_metric(QStringLiteral("已建立会话"), &m_est_, "metricValue");
  add_metric(QStringLiteral("累计隧道"), &m_tun_, "metricValue");
  layout->addLayout(metrics);

  auto* chart_frame = new QFrame;
  chart_frame->setProperty("role", "chart");
  auto* chart_layout = new QVBoxLayout(chart_frame);
  chart_layout->setContentsMargins(12, 10, 12, 8);
  chart_layout->setSpacing(6);
  auto* chart_head = new QHBoxLayout;
  chart_head->setContentsMargins(0, 0, 0, 0);
  chart_head->setSpacing(6);
  chart_head->addWidget(makeLabel(QStringLiteral("下行"), "legendRx"));
  rate_rx_ = makeLabel(QStringLiteral("0 B/s"), "monoStrong");
  chart_head->addWidget(rate_rx_);
  chart_head->addSpacing(10);
  chart_head->addWidget(makeLabel(QStringLiteral("上行"), "legendTx"));
  rate_tx_ = makeLabel(QStringLiteral("0 B/s"), "monoStrong");
  chart_head->addWidget(rate_tx_);
  chart_head->addStretch();
  chart_head->addWidget(makeLabel(QStringLiteral("最近 60 秒"), "fieldNote"));
  chart_layout->addLayout(chart_head);
  chart_ = new Sparkline;
  chart_layout->addWidget(chart_, 1);
  layout->addWidget(chart_frame, 1);

  diag_host_ = new QWidget;
  diag_layout_ = new QHBoxLayout(diag_host_);
  diag_layout_->setContentsMargins(0, 0, 0, 0);
  diag_layout_->setSpacing(6);
  diag_layout_->addStretch();
  diag_host_->setVisible(false);
  layout->addWidget(diag_host_);

  status_note_ = makeRichLabel(QString(), "muted");
  status_note_->setWordWrap(true);
  layout->addWidget(status_note_);
  return card;
}

QWidget* MainWindow::buildSpeedPage() {
  auto* card = makeCard();
  auto* layout = new QVBoxLayout(card);
  layout->setContentsMargins(24, 20, 24, 20);
  layout->setSpacing(12);

  auto* head = new QHBoxLayout;
  head->setContentsMargins(0, 0, 0, 2);
  head->setSpacing(10);
  head->addWidget(makeLabel(QStringLiteral("链路测速"), "h2"));
  head->addWidget(makeLabel(QStringLiteral("FCP 帧层裸吞吐，上下行各跑一次"), "headSub"));
  head->addStretch();
  layout->addLayout(head);

  auto* controls = new QHBoxLayout;
  controls->setContentsMargins(0, 0, 0, 0);
  controls->setSpacing(12);
  speed_seconds_ = new QComboBox;
  speed_seconds_->setFixedWidth(170);
  speed_seconds_->addItem(QStringLiteral("5 秒"), 5);
  speed_seconds_->addItem(QStringLiteral("8 秒"), 8);
  speed_seconds_->addItem(QStringLiteral("12 秒"), 12);
  speed_seconds_->addItem(QStringLiteral("20 秒"), 20);
  speed_seconds_->setCurrentIndex(1);
  controls->addWidget(makeField(QStringLiteral("单程时长"), speed_seconds_));
  speed_start_ = new QPushButton(QStringLiteral("开始测速"));
  speed_start_->setObjectName(QStringLiteral("primary"));
  speed_start_->setCursor(Qt::PointingHandCursor);
  controls->addWidget(speed_start_, 0, Qt::AlignBottom);
  // 提示行只留给进度/错误，不常驻说明文字。
  speed_hint_ = makeLabel(QString(), "hint");
  speed_hint_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  controls->addWidget(speed_hint_, 1);
  layout->addLayout(controls);

  auto* results = new QHBoxLayout;
  results->setContentsMargins(0, 4, 0, 0);
  results->setSpacing(12);
  const auto add_tile = [&](const QString& cap, QLabel** value, QLabel** sub,
                            const QString& note) {
    auto* tile = new QFrame;
    tile->setProperty("role", "tile");
    auto* box = new QVBoxLayout(tile);
    box->setContentsMargins(16, 14, 16, 14);
    box->setSpacing(4);
    auto* cap_row = new QHBoxLayout;
    cap_row->setContentsMargins(0, 0, 0, 0);
    cap_row->setSpacing(5);
    cap_row->addWidget(makeLabel(cap, "tileCap"));
    if (!note.isEmpty()) {
      cap_row->addWidget(makeLabel(note, "fieldNote"));
    }
    cap_row->addStretch();
    box->addLayout(cap_row);
    auto* big = new QHBoxLayout;
    big->setContentsMargins(0, 0, 0, 0);
    big->setSpacing(6);
    *value = makeLabel(QStringLiteral("--"), "tileBig");
    auto* unit = makeLabel(QStringLiteral("Mbps"), "tileUnit");
    big->addWidget(*value, 0, Qt::AlignBottom);
    big->addWidget(unit, 0, Qt::AlignBottom);
    big->addStretch();
    box->addLayout(big);
    *sub = makeLabel(QStringLiteral("等待测速"), "tileSub");
    // "8.0 MiB / 8.0s · 发送速率 12.3 Mbps（含冗余，1.2 MiB 未到达）" 比格子宽，不换行时
    // QLabel 直接裁掉尾部——括号里的"未到达"正是要看的量，允许它折到第二行。
    (*sub)->setWordWrap(true);
    box->addWidget(*sub);
    results->addWidget(tile, 1);
  };
  add_tile(QStringLiteral("下行"), &sp_down_, &sp_down_sub_, QString());
  add_tile(QStringLiteral("上行"), &sp_up_, &sp_up_sub_, QString());

  auto* loss_tile = new QFrame;
  loss_tile->setProperty("role", "tile");
  auto* loss_box = new QVBoxLayout(loss_tile);
  loss_box->setContentsMargins(16, 14, 16, 14);
  loss_box->setSpacing(4);
  auto* loss_cap = new QHBoxLayout;
  loss_cap->setContentsMargins(0, 0, 0, 0);
  loss_cap->setSpacing(5);
  loss_cap->addWidget(makeLabel(QStringLiteral("链路丢包"), "tileCap"));
  loss_cap->addWidget(makeLabel(QStringLiteral("FEC 恢复前"), "fieldNote"));
  loss_cap->addStretch();
  loss_box->addLayout(loss_cap);
  const auto add_loss_row = [&](const QString& name, QLabel** value, QLabel** note) {
    auto* row = new QHBoxLayout;
    row->setContentsMargins(0, 2, 0, 0);
    row->setSpacing(8);
    row->addWidget(makeLabel(name, "muted"));
    *value = makeLabel(QStringLiteral("--"), "lossValue");
    row->addWidget(*value);
    row->addStretch();
    *note = makeLabel(QString(), "tileSub");
    row->addWidget(*note);
    loss_box->addLayout(row);
  };
  add_loss_row(QStringLiteral("下行"), &sp_loss_in_, &sp_loss_in_n_);
  add_loss_row(QStringLiteral("上行"), &sp_loss_out_, &sp_loss_out_n_);
  results->addWidget(loss_tile, 1);
  layout->addLayout(results);

  // 实时速率曲线：跟运行状态页同一块 Sparkline，沙色为上行、绿色为下行；
  // 由进度事件差分出瞬时速率，爬坡段、掉速点一目了然。
  auto* chart_frame = new QFrame;
  chart_frame->setProperty("role", "chart");
  auto* chart_layout = new QVBoxLayout(chart_frame);
  chart_layout->setContentsMargins(12, 10, 12, 8);
  chart_layout->setSpacing(6);
  auto* chart_head = new QHBoxLayout;
  chart_head->setContentsMargins(0, 0, 0, 0);
  chart_head->setSpacing(6);
  chart_head->addWidget(makeLabel(QStringLiteral("下行"), "legendRx"));
  chart_head->addSpacing(10);
  chart_head->addWidget(makeLabel(QStringLiteral("上行"), "legendTx"));
  chart_head->addStretch();
  chart_head->addWidget(makeLabel(QStringLiteral("实时速率"), "fieldNote"));
  chart_layout->addLayout(chart_head);
  sp_chart_ = new Sparkline;
  chart_layout->addWidget(sp_chart_, 1);
  layout->addWidget(chart_frame, 1);

  sp_progress_ = new QProgressBar;
  sp_progress_->setRange(0, 100);
  sp_progress_->setValue(0);
  sp_progress_->setTextVisible(false);
  sp_progress_->setFixedHeight(6);
  layout->addWidget(sp_progress_);
  layout->addStretch();

  auto* tip = new QFrame;
  tip->setProperty("role", "tip");
  auto* tip_layout = new QVBoxLayout(tip);
  tip_layout->setContentsMargins(14, 11, 14, 11);
  auto* tip_text = makeRichLabel(
      QStringLiteral(
          "测速另起 fcp-client 直连同一 UDP 端口，直接向 FCP 帧/FEC 层灌数据，"
          "量的是隧道裸吞吐。<br>"
          "丢包为 FEC 恢复前的原始丢包率，后续被补齐也不回改。"),
      "muted");
  tip_text->setWordWrap(true);
  tip_layout->addWidget(tip_text);
  layout->addWidget(tip);

  connect(speed_start_, &QPushButton::clicked, this, &MainWindow::onSpeedStart);
  connect(speed_seconds_, &QComboBox::currentIndexChanged, this, [this] { saveSettings(); });
  return card;
}

QWidget* MainWindow::buildLogPage() {
  auto* card = makeCard();
  auto* layout = new QVBoxLayout(card);
  layout->setContentsMargins(24, 20, 24, 20);
  layout->setSpacing(12);

  auto* head = new QHBoxLayout;
  head->setContentsMargins(0, 0, 0, 2);
  head->setSpacing(10);
  head->addWidget(makeLabel(QStringLiteral("日志"), "h2"));
  head->addWidget(makeLabel(QStringLiteral("时间戳 · 级别着色"), "headSub"));
  head->addStretch();
  log_count_ = makeLabel(QString(), "mono");
  head->addWidget(log_count_);
  auto* clear = new QPushButton(QStringLiteral("清空"));
  clear->setObjectName(QStringLiteral("ghost"));
  clear->setCursor(Qt::PointingHandCursor);
  head->addWidget(clear);
  layout->addLayout(head);

  log_ = new QPlainTextEdit;
  log_->setObjectName(QStringLiteral("log"));
  log_->setReadOnly(true);
  // 只是一扇窗：最近 500 行（stats 走 stdout 不进这里，窗口留给逐请求
  // 与诊断行，足以覆盖最近几分钟）。完整档案由 sidecar 的 --log-file 落在
  // 用户日志目录，翻旧账去文件，不靠窗口。
  log_->setMaximumBlockCount(500);
  log_->setWordWrapMode(QTextOption::WrapAnywhere);
  layout->addWidget(log_, 1);

  connect(clear, &QPushButton::clicked, this, [this] {
    log_->clear();
    log_count_->clear();
    log_lines_ = 0;
  });
  return card;
}

MainWindow::Collected MainWindow::collect() const {
  Collected result;
  const QString key = key_->text().trimmed();
  static const QRegularExpression kHex32(QStringLiteral("^[0-9a-fA-F]{32}$"));
  if (!kHex32.match(key).hasMatch()) {
    result.error = QStringLiteral("预共享密钥要 32 位十六进制");
    return result;
  }

  bool ok = false;
  const uint port = port_->text().trimmed().toUInt(&ok);
  if (!ok || port < 1 || port > 65535) {
    result.error = QStringLiteral("UDP 端口无效");
    return result;
  }
  const uint listen_port = listen_port_->text().trimmed().toUInt(&ok);
  if (!ok || listen_port < 1 || listen_port > 65535) {
    result.error = QStringLiteral("本地端口无效");
    return result;
  }

  const bool open = advanced_;
  const QString mtu_text = open ? mtu_->text().trimmed() : QStringLiteral("1400");
  const QString k_text = open ? k_->text().trimmed() : QStringLiteral("-1");
  const QString budget_text = open ? budget_->text().trimmed() : QStringLiteral("0.5");
  const QString rate_text = open ? rate_->text().trimmed() : QStringLiteral("0");
  const bool pmtud = open ? pmtud_->isChecked() : true;
  const QString pmtu_max_text =
      open ? pmtu_max_->text().trimmed() : QStringLiteral("1500");
  const QString listen_text =
      open ? listen_->text().trimmed() : QStringLiteral("127.0.0.1");

  const int mtu = mtu_text.toInt(&ok);
  if (!ok || mtu < 576 || mtu > 9000) {
    result.error = QStringLiteral("MTU 应在 576..9000");
    return result;
  }
  const int k = k_text.toInt(&ok);
  if (!ok || k < -1 || k > 7) {
    result.error = QStringLiteral("k 应在 -1..7");
    return result;
  }
  const double budget = budget_text.toDouble(&ok);
  if (!ok || !std::isfinite(budget) || budget < 0.0 || budget > 1.0) {
    result.error = QStringLiteral("FEC 预算应在 0..1");
    return result;
  }
  const double rate = rate_text.toDouble(&ok);
  // 0 = 不限；0 与 0.1 是 CLI 侧"一秒预算须装下一个完整数据报"的下限
  //（GUI MTU 上限 9000 < 0.1 Mbps 的 12500 B/s）。
  if (!ok || !std::isfinite(rate) || rate < 0.0 || rate > 100000.0) {
    result.error = QStringLiteral("上行限速应在 0..100000 Mbps");
    return result;
  }
  if (rate > 0.0 && rate < 0.1) {
    result.error = QStringLiteral("上行限速太小无法整形，请用 ≥0.1 Mbps 或 0（不限）");
    return result;
  }
  const int pmtu_max = pmtu_max_text.toInt(&ok);
  // 与 CLI 同一条界（1280..9000）：GUI 放行而 CLI 拒绝，会让 sidecar 启动时
  // 才报参数错误，用户还以为是别的问题。低于 mtu 时 CLI 会下钳到 mtu（等于
  // 不探测），这里不额外报错。
  if (!ok || pmtu_max < 1280 || pmtu_max > 9000) {
    result.error = QStringLiteral("PMTUD 上限应在 1280..9000");
    return result;
  }
  if (listen_text.isEmpty()) {
    result.error = QStringLiteral("本地监听地址不能为空");
    return result;
  }

  result.config.host = host_->text().trimmed();
  result.config.port = static_cast<quint16>(port);
  result.config.key_hex = key;
  result.config.listen = listen_text;
  result.config.listen_port = static_cast<quint16>(listen_port);
  result.config.mtu = mtu;
  result.config.pmtud = pmtud;
  result.config.pmtu_max_mtu = pmtu_max;
  result.config.k = k;
  result.config.fec_budget = budget;
  result.config.rate_up_mbps = rate;
  result.ok = true;
  return result;
}

void MainWindow::setRunning(bool running, const QString& hint) {
  running_ = running;
  start_->setText(running ? QStringLiteral("停止代理") : QStringLiteral("启动代理"));
  start_->setObjectName(running ? QStringLiteral("danger") : QStringLiteral("primary"));
  repolish(start_);
  for (QWidget* widget :
       {static_cast<QWidget*>(host_), static_cast<QWidget*>(port_),
        static_cast<QWidget*>(listen_port_), static_cast<QWidget*>(key_),
        static_cast<QWidget*>(remember_), static_cast<QWidget*>(listen_),
        static_cast<QWidget*>(mtu_), static_cast<QWidget*>(budget_),
        static_cast<QWidget*>(k_), static_cast<QWidget*>(rate_),
        static_cast<QWidget*>(pmtud_), static_cast<QWidget*>(pmtu_max_),
        static_cast<QWidget*>(adv_toggle_), static_cast<QWidget*>(key_toggle_)}) {
    widget->setEnabled(!running);
  }
  speed_start_->setEnabled(!speed_running_);
  if (!speed_running_) {
    speed_hint_->setText(running ? QStringLiteral("约 2 × 单程时长") : QString());
    speed_hint_->setProperty("role", "hint");
    repolish(speed_hint_);
  }
  dot_->setStyleSheet(QStringLiteral("background:%1;border-radius:4px;")
                          .arg(running ? kAccent : "#c6d3cc"));
  state_text_->setText(running ? QStringLiteral("已连接") : QStringLiteral("未连接"));
  if (!running) {
    uptime_->setText(QStringLiteral("--"));
  }
  if (!hint.isNull()) {
    setHint(hint, false);
  }
  status_note_->setVisible(!running);
  stack_->setCurrentIndex(running ? 1 : 0);
  // 自动翻页时把左栏的选中态一起带过去，否则高亮还停在“连接”。
  const int page = running ? 1 : 0;
  if (page < nav_.size()) {
    nav_.at(page)->setChecked(true);
  }
  // 网络切换检测只在隧道运行时有意义：启动时取基线快照，停止即收。
  if (running) {
    if (net_watch_ != nullptr && !net_watch_->isActive()) {
      net_digest_ = adaptersDigest();
      net_watch_->start();
    }
  } else if (net_watch_ != nullptr) {
    net_watch_->stop();
    net_digest_.clear();
    net_pending_digest_.clear();
  }
}

void MainWindow::setHint(const QString& text, bool error) {
  hint_->setText(text);
  hint_->setProperty("role", error ? "hintError" : "hint");
  repolish(hint_);
}

void MainWindow::setAdvanced(bool open) {
  advanced_ = open;
  adv_body_->setVisible(open);
  adv_toggle_->setText(open
                           ? QStringLiteral("▾  收起高级")
                           : QStringLiteral(
                                 "▸  高级设置    MTU 1400 · FEC 0.5 · k 自适应 · 127.0.0.1"));
  syncAddr();
  saveSettings();
}

void MainWindow::updateKeyState() {
  const QString value = key_->text().trimmed();
  static const QRegularExpression kHex32(QStringLiteral("^[0-9a-fA-F]{32}$"));
  if (value.isEmpty()) {
    key_state_->clear();
    key_state_->setProperty("role", "fieldNote");
  } else if (kHex32.match(value).hasMatch()) {
    key_state_->setText(QStringLiteral("✓ 32 位"));
    key_state_->setProperty("role", "keyOk");
  } else {
    key_state_->setText(QStringLiteral("%1/32").arg(value.size()));
    key_state_->setProperty("role", "keyBad");
  }
  repolish(key_state_);
}

void MainWindow::syncAddr() {
  QString host = advanced_ ? listen_->text().trimmed() : QString();
  if (host.isEmpty()) {
    host = QStringLiteral("127.0.0.1");
  }
  QString port = listen_port_->text().trimmed();
  if (port.isEmpty()) {
    port = QStringLiteral("1080");
  }
  const QString addr = QStringLiteral("%1:%2").arg(host, port);
  // 这三处里 rail_addr_ 默认 AutoText、其余是 RichText：监听地址是用户输入，
  // 不转义的话 `<x>:1080` 会被当 HTML 标签吞掉。
  const QString addr_html = addr.toHtmlEscaped();
  rail_addr_->setText(addr_html);
  // 两行：用法一行，密钥保管一行（<br> 而不是靠自动换行，窗口宽度变了
  // 也不会把一句拆到两行里）。
  conn_addr_->setText(
      QStringLiteral("启动后把浏览器或系统的 SOCKS5 / HTTP 代理指向 <b>%1</b>，"
                     "流量即经隧道转发。<br>"
                     "密钥只保存在本机，不写入日志。")
          .arg(addr_html));
  status_note_->setText(
      QStringLiteral("启动后这里显示实时吞吐与会话数；把系统的 SOCKS5 / HTTP 代理指向 "
                     "<b>%1</b> 即可走隧道。")
          .arg(addr_html));
}

void MainWindow::onStart() {
  if (running_) {
    return;
  }
  restarting_ = false;
  const Collected collected = collect();
  if (!collected.ok) {
    setHint(collected.error, true);
    return;
  }
  if (collected.config.host.isEmpty()) {
    setHint(QStringLiteral("服务器地址不能为空"), true);
    return;
  }
  setHint(QStringLiteral("正在连接…"), false);
  QString error;
  if (!sidecar_->startProxy(collected.config, &error)) {
    setHint(error, true);
    appendLog(QStringLiteral("start failed: %1").arg(error), "ERROR");
    setRunning(false, QString());
    return;
  }
  saveSettings();
  last_t_ = last_tx_ = last_rx_ = 0.0;
  tunnel_started_ms_ = QDateTime::currentMSecsSinceEpoch();
  setHint(QStringLiteral("本地代理 %1:%2 → %3:%4")
              .arg(collected.config.listen)
              .arg(collected.config.listen_port)
              .arg(collected.config.host)
              .arg(collected.config.port),
          false);
  setRunning(true);
}

void MainWindow::onStop() {
  sidecar_->stopProxy();
  setRunning(false, QStringLiteral("已断开"));
}

void MainWindow::onSpeedStart() {
  if (speed_running_) {
    return;
  }
  const Collected collected = collect();
  if (!collected.ok) {
    speed_hint_->setText(collected.error);
    speed_hint_->setProperty("role", "hintError");
    repolish(speed_hint_);
    return;
  }
  if (collected.config.host.isEmpty()) {
    speed_hint_->setText(QStringLiteral("服务器地址不能为空"));
    speed_hint_->setProperty("role", "hintError");
    repolish(speed_hint_);
    return;
  }

  const int seconds = speed_seconds_->currentData().toInt();
  speed_running_ = true;
  speed_start_->setEnabled(false);
  sp_down_->setText(QStringLiteral("--"));
  sp_up_->setText(QStringLiteral("--"));
  sp_down_sub_->setText(QStringLiteral("下行…"));
  sp_down_sub_->setProperty("role", "tileSub");
  sp_up_sub_->setText(QStringLiteral("排队中"));
  sp_up_sub_->setProperty("role", "tileSub");
  sp_loss_in_->setText(QStringLiteral("--"));
  sp_loss_in_n_->clear();
  sp_loss_out_->setText(QStringLiteral("--"));
  sp_loss_out_n_->clear();
  sp_progress_->setValue(0);
  // 曲线从零开始：清掉上一轮的折线与差分缓冲。
  sp_chart_->reset();
  sp_slope_bytes_[0] = sp_slope_bytes_[1] = 0;
  sp_slope_secs_[0] = sp_slope_secs_[1] = 0.0;
  speed_hint_->setText(QStringLiteral("测速中… 下行 %1s + 上行 %1s").arg(seconds));
  speed_hint_->setProperty("role", "hint");
  repolish(speed_hint_);

  saveSettings();
  SpeedTestConfig config;
  config.host = collected.config.host;
  config.port = collected.config.port;
  config.key_hex = collected.config.key_hex;
  config.seconds = seconds;
  config.mtu = collected.config.mtu;
  config.pmtud = collected.config.pmtud;
  config.pmtu_max_mtu = collected.config.pmtu_max_mtu;
  QString error;
  if (!sidecar_->startSpeedTest(config, &error)) {
    speed_running_ = false;
    speed_start_->setEnabled(true);
    speed_hint_->setText(error);
    speed_hint_->setProperty("role", "hintError");
    repolish(speed_hint_);
    // 起不来就把两块瓦片也退回初始文案，别留着"下行…/排队中"。
    sp_down_sub_->setText(QStringLiteral("等待测速"));
    sp_up_sub_->setText(QStringLiteral("等待测速"));
  }
}

void MainWindow::onStats(const QJsonObject& stats) {
  const auto number = [&stats](const char* key) -> quint64 {
    return static_cast<quint64>(stats.value(QLatin1String(key)).toDouble());
  };
  const double t = stats.value(QStringLiteral("t")).toDouble();
  sample_chip_->setText(QStringLiteral("采样 <b>%1 s</b>").arg(t, 0, 'f', 1));
  if (running_) {
    uptime_->setText(fmtUptime(t));
  }
  m_live_->setText(QString::number(number("live")));
  m_est_->setText(QString::number(number("up")));
  m_tun_->setText(QString::number(number("tunnels")));
  m_tx_->setText(fmtBytes(number("tx")));
  m_rx_->setText(fmtBytes(number("rx")));

  double tx_rate = 0.0;
  double rx_rate = 0.0;
  const double dt = t - last_t_;
  if (dt > 0.2) {
    tx_rate = (static_cast<double>(number("tx")) - last_tx_) / dt;
    rx_rate = (static_cast<double>(number("rx")) - last_rx_) / dt;
    last_t_ = t;
    last_tx_ = static_cast<double>(number("tx"));
    last_rx_ = static_cast<double>(number("rx"));
  }
  rate_tx_->setText(fmtRate(tx_rate));
  rate_rx_->setText(fmtRate(rx_rate));
  // dt <= 0.2 是重复/补发的采样，没有新的速率信息；塞 0 进图会把曲线砸平。
  if (dt > 0.2) {
    chart_->addSample(tx_rate, rx_rate);
  }
  rebuildDiag(stats);
}

void MainWindow::rebuildDiag(const QJsonObject& stats) {
  struct Entry {
    const char* key;
    const char* name;
  };
  static const Entry kEntries[] = {
      {"bad_entry", "坏入口"}, {"refused", "拒绝"},       {"hs_failed", "握手失败"},
      {"reset", "重置"},       {"idle", "空闲回收"},      {"clash", "salt 冲突"},
      {"over", "超会话"},      {"bad_cfg", "错配置"},     {"no_entropy", "无熵"},
      {"budget", "限速建连"},  {"unknown", "未知 salt"},
  };

  QVector<quint64> values;
  values.reserve(static_cast<int>(std::size(kEntries)));
  for (const Entry& entry : kEntries) {
    values.append(static_cast<quint64>(
        stats.value(QLatin1String(entry.key)).toDouble()));
  }
  if (values == diag_values_) {
    return;
  }
  diag_values_ = values;

  while (QLayoutItem* item = diag_layout_->takeAt(0)) {
    if (QWidget* widget = item->widget()) {
      widget->deleteLater();
    }
    delete item;
  }
  bool any = false;
  for (int i = 0; i < static_cast<int>(std::size(kEntries)); ++i) {
    if (values.at(i) == 0) {
      continue;
    }
    any = true;
    auto* chip = makeRichLabel(QStringLiteral("%1 <b>%2</b>")
                                   .arg(QString::fromUtf8(kEntries[i].name))
                                   .arg(values.at(i)),
                               "diag");
    diag_layout_->addWidget(chip, 0, Qt::AlignVCenter);
  }
  diag_layout_->addStretch();
  diag_host_->setVisible(any);
}

void MainWindow::onSpeedProgress(const QString& direction, quint64 bytes, double seconds) {
  if (!speed_running_) {
    return;
  }
  const bool up = direction == QLatin1String("up");
  const int idx = up ? 1 : 0;
  // 曲线：相邻进度事件差分出瞬时速率（Mbps）。进展字节两向都是接收端口径、
  // 单调不减（bench 层保证），零差值是真实的静默，照画。
  const double dt = seconds - sp_slope_secs_[idx];
  if (dt > 0.05) {
    const double mbps =
        static_cast<double>(bytes - sp_slope_bytes_[idx]) * 8.0 / dt / 1e6;
    sp_slope_bytes_[idx] = bytes;
    sp_slope_secs_[idx] = seconds;
    sp_chart_->addSample(up ? mbps : 0.0, up ? 0.0 : mbps);
  }
  const int total = qMax(3, speed_seconds_->currentData().toInt());
  const double base = up ? 50.0 : 0.0;
  sp_progress_->setValue(
      qMin(99, static_cast<int>(base + (seconds / total) * 50.0)));
  QLabel* sub = up ? sp_up_sub_ : sp_down_sub_;
  sub->setText(QStringLiteral("%1 / %2s").arg(fmtBytes(bytes)).arg(seconds, 0, 'f', 1));
}

void MainWindow::onSpeedDone(const QJsonObject& result) {
  if (!speed_running_) {
    return;
  }
  speed_running_ = false;
  speed_start_->setEnabled(true);

  const auto fill = [](const QJsonObject& sample, QLabel* value, QLabel* sub) {
    sub->setProperty("role", "tileSub");
    if (sample.isEmpty()) {
      value->setText(QStringLiteral("--"));
      sub->setText(QStringLiteral("未完成"));
      repolish(sub);
      return;
    }
    const double mbps = sample.value(QStringLiteral("mbps")).toDouble();
    const quint64 bytes =
        static_cast<quint64>(sample.value(QStringLiteral("bytes")).toDouble());
    const double seconds = sample.value(QStringLiteral("seconds")).toDouble();
    const bool acked =
        sample.value(QStringLiteral("acked")).isBool()
            ? sample.value(QStringLiteral("acked")).toBool()
            : true;
    value->setText(QString::number(mbps, 'f', 2));
    QString text = QStringLiteral("%1 / %2s").arg(fmtBytes(bytes)).arg(seconds, 0, 'f', 1);
    // 发送速率（含冗余）：发送端每秒送入帧层的数据量，含 FEC 冗余与封装
    // 开销；与上面的大字（接收端实际送达）之差就是冗余和丢包吃掉的。
    const double wire = sample.value(QStringLiteral("wireMbps")).toDouble();
    if (!acked) {
      sub->setProperty("role", "tileSubBad");
    }
    const QString lost =
        acked ? QString()
              : QStringLiteral("%1 未到达").arg(fmtBytes(static_cast<quint64>(
                    sample.value(QStringLiteral("lostBytes")).toDouble())));
    if (wire > 0) {
      text += QStringLiteral(" · 发送速率 %1 Mbps（含冗余%2）")
                  .arg(wire, 0, 'f', 1)
                  .arg(lost.isEmpty() ? QString()
                                      : QStringLiteral("，") + lost);
    } else if (!lost.isEmpty()) {
      text += QStringLiteral("（%1）").arg(lost);
    }
    sub->setText(text);
    repolish(sub);
  };
  fill(result.value(QStringLiteral("download")).toObject(), sp_down_, sp_down_sub_);
  fill(result.value(QStringLiteral("upload")).toObject(), sp_up_, sp_up_sub_);

  const auto apply_loss = [](const QJsonObject& sample, QLabel* pct, QLabel* note) {
    const quint64 n =
        static_cast<quint64>(sample.value(QStringLiteral("lossN")).toDouble());
    if (n == 0) {
      pct->setText(QStringLiteral("--"));
      note->clear();
      return;
    }
    const double ppm = sample.value(QStringLiteral("lossPpm")).toDouble();
    pct->setText(QStringLiteral("%1%").arg(ppm / 10000.0, 0, 'f', 2));
    note->setText(QStringLiteral("n=%1").arg(n));
  };
  const QJsonObject download = result.value(QStringLiteral("download")).toObject();
  const QJsonObject upload = result.value(QStringLiteral("upload")).toObject();
  apply_loss(download, sp_loss_in_, sp_loss_in_n_);
  apply_loss(upload, sp_loss_out_, sp_loss_out_n_);

  const QString error = result.value(QStringLiteral("error")).toString();
  // 失败就归零，别留一条满格绿条让人以为测完了。
  sp_progress_->setValue(error.isEmpty() ? 100 : 0);
  // 建立耗时与链路延迟（最小/均值）随行显示；报错时给错误本身让位。
  QString extra;
  const double setup_ms = result.value(QStringLiteral("setupMs")).toDouble();
  if (setup_ms >= 1) {
    extra = setup_ms < 1000 ? QStringLiteral("建立 %1ms").arg(setup_ms, 0, 'f', 0)
                            : QStringLiteral("建立 %1s").arg(setup_ms / 1000.0, 0, 'f', 1);
  }
  const int rtt_n = static_cast<int>(result.value(QStringLiteral("rttN")).toDouble());
  if (rtt_n > 0) {
    const int rtt_min = static_cast<int>(result.value(QStringLiteral("rttMinMs")).toDouble());
    const int rtt_avg = static_cast<int>(result.value(QStringLiteral("rttAvgMs")).toDouble());
    extra += (extra.isEmpty() ? QString() : QStringLiteral(" · ")) +
             QStringLiteral("延迟 %1/%2ms").arg(rtt_min).arg(rtt_avg);
  }
  speed_hint_->setText(error.isEmpty()
                           ? (extra.isEmpty() ? QStringLiteral("测速完成")
                                              : QStringLiteral("测速完成 · %1").arg(extra))
                           : error);
  speed_hint_->setProperty("role", error.isEmpty() ? "hint" : "hintError");
  repolish(speed_hint_);
}

void MainWindow::appendLog(const QString& line, const char* level) {
  QScrollBar* bar = log_->verticalScrollBar();
  const bool at_bottom = bar->value() >= bar->maximum() - 4;
  // CLI 侧所有日志行统一是 `YYYY-MM-DD HH:MM:SS.mmm [LEVEL] 正文`，按级别
  // 上色。GUI 自己产生的行（没有前缀）补上同样的时间戳与级别，窗口里
  // 就不会混进两种排版。
  static const QRegularExpression kStamped(
      QStringLiteral("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3} "
                     "\\[(DEBUG|INFO|WARN|ERROR)\\] "));
  QString text = line;
  QRegularExpressionMatch match = kStamped.match(line);
  if (!match.hasMatch()) {
    text = QDateTime::currentDateTime().toString(
               QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")) +
           QStringLiteral(" [") + QLatin1String(level ? level : "INFO") +
           QStringLiteral("] ") + line;
    match = kStamped.match(text);
  }
  const QString name = match.captured(1);
  const char* color = kLogInfo;
  if (name == QLatin1String("DEBUG")) {
    color = kLogDebug;
  } else if (name == QLatin1String("WARN")) {
    color = kLogWarn;
  } else if (name == QLatin1String("ERROR")) {
    color = kLogError;
  }
  log_->appendHtml(QStringLiteral("<span style=\"color:%1\">%2</span>")
                       .arg(QLatin1String(color), text.toHtmlEscaped()));
  // 自己数，不用 blockCount()：空文档的首个空段落会让计数差一。
  log_lines_ = qMin(log_lines_ + 1, 500);
  log_count_->setText(QStringLiteral("%1 行").arg(log_lines_));
  if (at_bottom) {
    bar->setValue(bar->maximum());
  }
}

void MainWindow::loadSettings() {
  loading_ = true;
  QSettings settings;
  const bool remember = settings.value(QStringLiteral("remember"), true).toBool();
  // setChecked() emits toggled -> saveSettings(). loading_ already suppresses
  // that, but the suppression must not hinge on the order of two adjacent
  // lines: the load is what the store must survive intact.
  QSignalBlocker block_toggle(remember_);
  remember_->setChecked(remember);

  if (remember) {
    host_->setText(settings.value(QStringLiteral("host")).toString());
    port_->setText(settings.value(QStringLiteral("port"), QStringLiteral("4460")).toString());
    listen_port_->setText(
        settings.value(QStringLiteral("listenPort"), QStringLiteral("1080")).toString());
    listen_->setText(
        settings.value(QStringLiteral("listen"), QStringLiteral("127.0.0.1")).toString());
    mtu_->setText(settings.value(QStringLiteral("mtu"), QStringLiteral("1400")).toString());
    budget_->setText(
        settings.value(QStringLiteral("budget"), QStringLiteral("0.5")).toString());
    k_->setText(settings.value(QStringLiteral("k"), QStringLiteral("-1")).toString());
    rate_->setText(settings.value(QStringLiteral("rate"), QStringLiteral("0")).toString());
    pmtu_max_->setText(settings.value(QStringLiteral("pmtuMax"), QStringLiteral("1500"))
                           .toString());
    pmtud_->setChecked(settings.value(QStringLiteral("pmtud"), true).toBool());
    key_->setText(settings.value(QStringLiteral("key")).toString());
    const int seconds = settings.value(QStringLiteral("speedSeconds"), 8).toInt();
    for (int i = 0; i < speed_seconds_->count(); ++i) {
      if (speed_seconds_->itemData(i).toInt() == seconds) {
        speed_seconds_->setCurrentIndex(i);
        break;
      }
    }
  }

  setAdvanced(settings.value(QStringLiteral("advanced"), false).toBool());
  loading_ = false;
}

void MainWindow::saveSettings() {
  if (loading_) {
    return;
  }
  QSettings settings;
  if (!remember_->isChecked()) {
    // 把"不记住"本身也记下来，否则下次启动复选框又弹回勾选、字段却全空了。
    settings.clear();
    settings.setValue(QStringLiteral("remember"), false);
    return;
  }
  settings.setValue(QStringLiteral("remember"), true);
  settings.setValue(QStringLiteral("host"), host_->text());
  settings.setValue(QStringLiteral("port"), port_->text());
  settings.setValue(QStringLiteral("listenPort"), listen_port_->text());
  settings.setValue(QStringLiteral("listen"), listen_->text());
  settings.setValue(QStringLiteral("mtu"), mtu_->text());
  settings.setValue(QStringLiteral("budget"), budget_->text());
  settings.setValue(QStringLiteral("k"), k_->text());
  settings.setValue(QStringLiteral("rate"), rate_->text());
  settings.setValue(QStringLiteral("pmtuMax"), pmtu_max_->text());
  settings.setValue(QStringLiteral("pmtud"), pmtud_->isChecked());
  settings.setValue(QStringLiteral("key"), key_->text());
  settings.setValue(QStringLiteral("advanced"), advanced_);
  settings.setValue(QStringLiteral("speedSeconds"), speed_seconds_->currentData().toInt());
}

void MainWindow::setupTray() {
  if (!QSystemTrayIcon::isSystemTrayAvailable()) {
    return;
  }
  tray_ = new QSystemTrayIcon(QIcon(QStringLiteral(":/assets/fcp.png")), this);
  tray_->setToolTip(QStringLiteral("FCP 客户端"));
  auto* menu = new QMenu(this);
  QAction* show = menu->addAction(QStringLiteral("显示主界面"));
  QAction* quit = menu->addAction(QStringLiteral("退出"));
  connect(show, &QAction::triggered, this, [this] {
    showNormal();
    raise();
    activateWindow();
  });
  connect(quit, &QAction::triggered, this, &MainWindow::quitApp);
  tray_->setContextMenu(menu);
  connect(tray_, &QSystemTrayIcon::activated, this,
          [this](QSystemTrayIcon::ActivationReason reason) {
            if (reason == QSystemTrayIcon::Trigger ||
                reason == QSystemTrayIcon::DoubleClick) {
              showNormal();
              raise();
              activateWindow();
            }
          });
  tray_->show();
}

void MainWindow::quitApp() {
  sidecar_->shutdown();
  if (tray_) {
    tray_->hide();
  }
  qApp->quit();
}

void MainWindow::closeEvent(QCloseEvent* event) {
  if (tray_ && tray_->isVisible()) {
    // 关窗只收进托盘，隧道（sidecar）继续跑；真正退出走托盘菜单。
    event->ignore();
    hide();
    return;
  }
  // 没有托盘就只能按老行为退出；否则窗口关了但进程还在后台。
  sidecar_->shutdown();
  event->accept();
  qApp->quit();
}

void MainWindow::changeEvent(QEvent* event) {
  QMainWindow::changeEvent(event);
  if (event->type() == QEvent::WindowStateChange && isMinimized() && tray_ &&
      tray_->isVisible()) {
    QTimer::singleShot(0, this, [this] { hide(); });
  }
}

bool MainWindow::nativeEvent(const QByteArray& type, void* message, qint64* result) {
#ifdef Q_OS_WIN
  if (type == QStringLiteral("windows_generic_MSG")) {
    auto* msg = static_cast<MSG*>(message);
    // PBT_APMRESUMEAUTOMATIC = 系统从睡眠/休眠恢复（用户触发与否都算）。
    // 唤醒后 UDP 路径通常已经换过一轮（NAT 映射失效），整组重建最干净。
    if (msg->message == WM_POWERBROADCAST && msg->wParam == PBT_APMRESUMEAUTOMATIC &&
        running_) {
      restartTunnel(QStringLiteral("系统唤醒"));
    }
  }
#endif
  return QMainWindow::nativeEvent(type, message, result);
}

void MainWindow::onNetWatchTick() {
  if (!running_) {
    return;
  }
  const QByteArray digest = adaptersDigest();
  if (digest.isEmpty()) {
    return;  // API 不可读：跳过本 tick，保留上一次的基线
  }
  // 基线为空只记快照不动作（启动后第一次拉取）。变化要连续两个 tick 一致
  // 才算真切换：一次 DHCP 续租 / 瞬断抖动不该把整条隧道拆了重建。
  if (net_digest_.isEmpty()) {
    net_digest_ = digest;
    net_pending_digest_.clear();
    return;
  }
  if (digest == net_digest_) {
    net_pending_digest_.clear();
    return;
  }
  if (digest == net_pending_digest_) {
    net_pending_digest_.clear();
    net_digest_ = digest;
    restartTunnel(QStringLiteral("网络适配器变化"));
    return;
  }
  net_pending_digest_ = digest;
}

void MainWindow::restartTunnel(const QString& reason) {
  if (!running_ || restarting_) {
    return;
  }
  // 事件风暴限频：刚 (重) 建的隧道 3 秒内再触发大概率是同一轮事件的余波，
  // 重启只会把新建的连接又拆一遍。
  const qint64 now = QDateTime::currentMSecsSinceEpoch();
  if (tunnel_started_ms_ != 0 && now - tunnel_started_ms_ < 3000) {
    appendLog(QStringLiteral("网络事件 %1 与重建隔得过近，跳过").arg(reason), "WARN");
    return;
  }
  appendLog(QStringLiteral("网络事件：%1 → 重建隧道").arg(reason), "INFO");
  // 一次重建会被两条信号重复触发（唤醒广播与适配器轮询落在同一个事件循环
  // 里）。restarting_ 让第二次直接返回：否则两次 onStart 排队，第二次撞上
  // "代理已在运行"，界面上一条红字压在一条本来跑得好好的隧道上。
  restarting_ = true;
  onStop();
  // 400ms 后再拉起；若这中间用户手动点了停止，就尊重他——不再掉钩启动。
  QTimer::singleShot(400, this, [this] {
    restarting_ = false;
    if (running_) {
      return;
    }
    onStart();
  });
}

QString MainWindow::fmtBytes(quint64 bytes) {
  if (bytes >= (1ULL << 30)) {
    return QStringLiteral("%1 GiB").arg(bytes / static_cast<double>(1ULL << 30), 0, 'f', 2);
  }
  if (bytes >= (1ULL << 20)) {
    return QStringLiteral("%1 MiB").arg(bytes / static_cast<double>(1ULL << 20), 0, 'f', 2);
  }
  if (bytes >= (1ULL << 10)) {
    return QStringLiteral("%1 KiB").arg(bytes / static_cast<double>(1ULL << 10), 0, 'f', 1);
  }
  return QStringLiteral("%1 B").arg(bytes);
}

QString MainWindow::fmtRate(double bytes_per_second) {
  if (bytes_per_second >= (1 << 20)) {
    return QStringLiteral("%1 MiB/s").arg(bytes_per_second / (1 << 20), 0, 'f', 2);
  }
  if (bytes_per_second >= (1 << 10)) {
    return QStringLiteral("%1 KiB/s").arg(bytes_per_second / (1 << 10), 0, 'f', 0);
  }
  return QStringLiteral("%1 B/s").arg(bytes_per_second, 0, 'f', 0);
}

QString MainWindow::fmtUptime(double seconds) {
  const qint64 total = qMax<qint64>(0, static_cast<qint64>(seconds));
  const qint64 h = total / 3600;
  const qint64 m = (total % 3600) / 60;
  const qint64 s = total % 60;
  if (h > 0) {
    return QStringLiteral("%1:%2:%3")
        .arg(h)
        .arg(m, 2, 10, QLatin1Char('0'))
        .arg(s, 2, 10, QLatin1Char('0'));
  }
  return QStringLiteral("%1:%2")
      .arg(m, 2, 10, QLatin1Char('0'))
      .arg(s, 2, 10, QLatin1Char('0'));
}

}  // namespace fcp
