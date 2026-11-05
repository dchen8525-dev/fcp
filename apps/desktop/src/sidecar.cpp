#include "sidecar.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonValue>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTimer>

#ifdef Q_OS_WIN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

#ifdef Q_OS_LINUX
#  include <csignal>
#  include <sys/prctl.h>
#  include <unistd.h>
#endif

namespace fcp {
namespace {

QString sidecarName() {
#ifdef Q_OS_WIN
  return QStringLiteral("fcp-client.exe");
#else
  return QStringLiteral("fcp-client");
#endif
}

#ifdef Q_OS_LINUX
void armParentDeath(QProcess* process) {
  process->setChildProcessModifier([] {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) {
      _exit(127);
    }
    // 父进程在设置之前就没了：PDEATHSIG 不会再触发，自己走，别被 init 收养。
    if (getppid() == 1) {
      _exit(127);
    }
  });
}
#else
void armParentDeath(QProcess*) {}
#endif

#ifdef Q_OS_WIN
// KILL_ON_JOB_CLOSE：GUI 进程结束时内核关闭最后一个 Job 句柄，Job 里的
// sidecar 被一起终止。句柄故意泄漏到进程结束——关闭它正是触发条件。
HANDLE reaperJob() {
  static HANDLE job = [] {
    HANDLE created = CreateJobObjectW(nullptr, nullptr);
    if (!created) {
      return static_cast<HANDLE>(nullptr);
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(created, JobObjectExtendedLimitInformation, &info,
                                 sizeof(info))) {
      CloseHandle(created);
      return static_cast<HANDLE>(nullptr);
    }
    return created;
  }();
  return job;
}

void assignToReaper(qint64 pid) {
  HANDLE job = reaperJob();
  if (!job) {
    return;
  }
  HANDLE process = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE,
                               static_cast<DWORD>(pid));
  if (!process) {
    return;
  }
  AssignProcessToJobObject(job, process);
  CloseHandle(process);
}
#else
void assignToReaper(qint64) {}
#endif

}  // namespace

Sidecar::Sidecar(QObject* parent) : QObject(parent) {}

Sidecar::~Sidecar() { shutdown(); }

QString Sidecar::resolveBinary(QString* error) const {
  const QString from_env = qEnvironmentVariable("FCP_PROXY_BIN");
  if (!from_env.isEmpty()) {
    const QFileInfo info(from_env);
    if (info.isFile()) {
      return info.absoluteFilePath();
    }
    if (error) {
      *error = QStringLiteral("FCP_PROXY_BIN=%1 不是文件").arg(from_env);
    }
    return {};
  }
  const QString beside =
      QDir(QCoreApplication::applicationDirPath()).filePath(sidecarName());
  if (QFileInfo(beside).isFile()) {
    return beside;
  }
  if (error) {
    *error = QStringLiteral("找不到 %1（应与主程序同目录，或用 FCP_PROXY_BIN 指定）")
                 .arg(sidecarName());
  }
  return {};
}

bool Sidecar::parseStats(const QString& line, QJsonObject* out) {
  if (!line.startsWith(QLatin1String("stats"))) {
    return false;
  }
  const QString rest = line.mid(5).trimmed();
  const QStringList tokens =
      rest.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
  if (tokens.isEmpty()) {
    return false;
  }
  QString first = tokens.front();
  if (!first.endsWith(QLatin1Char('s'))) {
    return false;
  }
  first.chop(1);
  bool ok = false;
  const double t = first.toDouble(&ok);
  if (!ok) {
    return false;
  }
  QJsonObject obj;
  obj.insert(QStringLiteral("t"), t);
  for (int i = 1; i < tokens.size(); ++i) {
    const QString& token = tokens.at(i);
    const int eq = token.indexOf(QLatin1Char('='));
    if (eq <= 0 || eq == token.size() - 1) {
      return false;
    }
    const QString key = token.left(eq);
    QString value = token.mid(eq + 1);
    if (value.endsWith(QLatin1Char('B'))) {
      value.chop(1);
    }
    bool value_ok = false;
    const qulonglong number = value.toULongLong(&value_ok);
    if (!value_ok) {
      return false;
    }
    obj.insert(key, static_cast<double>(number));
  }
  if (out) {
    *out = obj;
  }
  return true;
}

void Sidecar::consumeLines(QProcess* process, QByteArray* buffer,
                           const std::function<void(const QString&)>& on_line) {
  buffer->append(process->readAllStandardOutput());
  int newline = buffer->indexOf('\n');
  while (newline >= 0) {
    QByteArray raw = buffer->left(newline);
    buffer->remove(0, newline + 1);
    if (raw.endsWith('\r')) {
      raw.chop(1);
    }
    on_line(QString::fromUtf8(raw));
    newline = buffer->indexOf('\n');
  }
}

bool Sidecar::startProxy(const ProxyConfig& config, QString* error) {
  if (proxy_ && proxy_->state() != QProcess::NotRunning) {
    if (error) {
      *error = QStringLiteral("代理已在运行");
    }
    return false;
  }
  QString resolve_error;
  const QString binary = resolveBinary(&resolve_error);
  if (binary.isEmpty()) {
    if (error) {
      *error = resolve_error;
    }
    return false;
  }

  auto* process = new QProcess(this);
  process->setProcessChannelMode(QProcess::SeparateChannels);
  armParentDeath(process);
#ifdef Q_OS_WIN
  process->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* args) {
    args->flags |= CREATE_NO_WINDOW;
  });
#endif

  QStringList args{
      QStringLiteral("--host=%1").arg(config.host),
      QStringLiteral("--port=%1").arg(config.port),
      QStringLiteral("--listen=%1").arg(config.listen),
      QStringLiteral("--local-port=%1").arg(config.listen_port),
      QStringLiteral("--mtu=%1").arg(config.mtu),
      QStringLiteral("--fec-budget=%1").arg(QString::number(config.fec_budget)),
      // Raise the autotune ceiling / advertised receive capacity to 4 MiB while
      // leaving START implicit, so the prewarm cache can still seed it.
      QStringLiteral("--window=:4096"),
      // PSK 只给环境变量 FCP_PSK：未给 --key* 参数时 CLI 默认读它，
      // argv 里不再需要重复指路。
      QStringLiteral("--log=debug"),
      // stdout 上每 500ms 一行 stats（机器通道，与 --log 等级无关；
      // 采样图与连接时长就靠逐行解析它）。
      QStringLiteral("--stats=500"),
      // 每条请求的行落到用户数据目录的 log/ 子目录（Windows:
      // %LOCALAPPDATA%\FCP\FCP Client\log，Linux: ~/.local/share/…），
      // 32 MiB 轮转，关后可翻旧账。
      QStringLiteral("--log-file=%1/log/").arg(
          QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)),
  };
  if (config.k >= 0) {
    args.append(QStringLiteral("--k=%1").arg(config.k));
  }
  if (config.rate_up_mbps > 0.0) {
    // 'g' 不定长（尾部零自动裁剪）：'f',1 会把 0.05 四舍五入成 0.1（限速翻倍）
    // 或把 0.04 舍成 0.0（CLI 直接报错拒绝启动）。
    args.append(QStringLiteral("--rate-limit=%1").arg(
        QString::number(config.rate_up_mbps, 'g', 15)));
  }
  if (!config.trace.trimmed().isEmpty()) {
    args.append(QStringLiteral("--trace=%1").arg(config.trace.trimmed()));
  }

  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  env.insert(QStringLiteral("FCP_PSK"), config.key_hex.toUpper());
  process->setProcessEnvironment(env);
  process->setProgram(binary);
  process->setArguments(args);

  proxy_ = process;
  proxy_out_buf_.clear();
  proxy_err_buf_.clear();
  proxy_stopping_ = false;

  connect(process, &QProcess::readyReadStandardOutput, this, &Sidecar::onProxyStdout);
  connect(process, &QProcess::readyReadStandardError, this, &Sidecar::onProxyStderr);
  connect(process, &QProcess::finished, this, &Sidecar::onProxyFinished);
  connect(process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError err) {
    if (err == QProcess::FailedToStart && proxy_) {
      emit proxyLog(QStringLiteral("启动 sidecar 失败：%1").arg(proxy_->errorString()), true);
    }
  });

  process->start();
  if (!process->waitForStarted(5000)) {
    if (error) {
      *error = QStringLiteral("启动 %1 失败：%2").arg(binary, process->errorString());
    }
    proxy_ = nullptr;
    process->deleteLater();
    return false;
  }
  assignToReaper(process->processId());
  return true;
}

void Sidecar::onProxyStdout() {
  if (!proxy_) {
    return;
  }
  consumeLines(proxy_, &proxy_out_buf_, [this](const QString& line) {
    handleProxyLine(line);
  });
}

void Sidecar::handleProxyLine(const QString& line) {
  QJsonObject stats;
  if (parseStats(line, &stats)) {
    emit proxyStats(stats);
  } else {
    emit proxyLog(line, false);
  }
}

void Sidecar::onProxyStderr() {
  if (!proxy_) {
    return;
  }
  proxy_err_buf_.append(proxy_->readAllStandardError());
  int newline = proxy_err_buf_.indexOf('\n');
  while (newline >= 0) {
    QByteArray raw = proxy_err_buf_.left(newline);
    proxy_err_buf_.remove(0, newline + 1);
    if (raw.endsWith('\r')) {
      raw.chop(1);
    }
    emit proxyLog(QString::fromUtf8(raw), true);
    newline = proxy_err_buf_.indexOf('\n');
  }
}

void Sidecar::onProxyFinished(int exit_code, QProcess::ExitStatus status) {
  QProcess* process = proxy_;
  proxy_ = nullptr;
  // 尾巴上没有换行的最后一行也要报出来（可能是一条 stats，不能整行丢给日志）。
  if (!proxy_out_buf_.isEmpty()) {
    handleProxyLine(QString::fromUtf8(proxy_out_buf_));
    proxy_out_buf_.clear();
  }
  if (!proxy_err_buf_.isEmpty()) {
    emit proxyLog(QString::fromUtf8(proxy_err_buf_), true);
    proxy_err_buf_.clear();
  }
  if (process) {
    process->deleteLater();
  }
  if (!proxy_stopping_) {
    const bool abnormal = status != QProcess::NormalExit || exit_code != 0;
    emit proxyStateChanged(false, exit_code, abnormal);
  }
  proxy_stopping_ = false;
}

void Sidecar::stopProxy() {
  if (!proxy_) {
    return;
  }
  QProcess* process = proxy_;
  proxy_ = nullptr;
  proxy_stopping_ = true;
  process->disconnect(this);
  killProcess(process, 1500);
  process->deleteLater();
}

bool Sidecar::proxyRunning() const {
  return proxy_ && proxy_->state() != QProcess::NotRunning;
}

void Sidecar::killProcess(QProcess* process, int grace_ms) {
  if (!process || process->state() == QProcess::NotRunning) {
    return;
  }
#ifdef Q_OS_WIN
  Q_UNUSED(grace_ms);
  process->kill();
  process->waitForFinished(3000);
#else
  process->terminate();
  if (!process->waitForFinished(grace_ms)) {
    process->kill();
    process->waitForFinished(1000);
  }
#endif
}

bool Sidecar::startSpeedTest(const SpeedTestConfig& config, QString* error) {
  if (speed_running_) {
    if (error) {
      *error = QStringLiteral("测速正在进行");
    }
    return false;
  }
  QString resolve_error;
  const QString binary = resolveBinary(&resolve_error);
  if (binary.isEmpty()) {
    if (error) {
      *error = resolve_error;
    }
    return false;
  }

  auto* process = new QProcess(this);
  process->setProcessChannelMode(QProcess::SeparateChannels);
  armParentDeath(process);
#ifdef Q_OS_WIN
  process->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* args) {
    args->flags |= CREATE_NO_WINDOW;
  });
#endif

  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  env.insert(QStringLiteral("FCP_PSK"), config.key_hex.toUpper());
  process->setProcessEnvironment(env);
  process->setProgram(binary);
  process->setArguments({
      QStringLiteral("--host=%1").arg(config.host),
      QStringLiteral("--port=%1").arg(config.port),
      QStringLiteral("--mtu=%1").arg(config.mtu),
      QStringLiteral("--speedtest-seconds=%1").arg(config.seconds),
      QStringLiteral("--speedtest"),
      // 测速进程独立 pid → 独立文件（fcp-client-<pid>.log），看得清谁是谁。
      QStringLiteral("--log-file=%1/log/").arg(
          QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)),
  });

  speed_ = process;
  speed_out_buf_.clear();
  speed_err_buf_.clear();
  speed_running_ = true;
  speed_done_ = false;
  speed_killed_ = false;
  speed_seconds_ = config.seconds;

  connect(process, &QProcess::readyReadStandardOutput, this, &Sidecar::onSpeedStdout);
  connect(process, &QProcess::readyReadStandardError, this, &Sidecar::onSpeedStderr);
  connect(process, &QProcess::finished, this, &Sidecar::onSpeedFinished);

  if (!speed_timeout_) {
    speed_timeout_ = new QTimer(this);
    speed_timeout_->setSingleShot(true);
    connect(speed_timeout_, &QTimer::timeout, this, [this] {
      if (!speed_running_ || speed_done_) {
        return;
      }
      speed_killed_ = true;
      finishSpeedWithError(QStringLiteral("测速进程超时退出"));
      if (speed_) {
        speed_->kill();
      }
    });
  }
  speed_timeout_->start((speed_seconds_ * 2 + 60) * 1000);

  process->start();
  if (!process->waitForStarted(5000)) {
    if (error) {
      *error = QStringLiteral("启动 %1 失败：%2").arg(binary, process->errorString());
    }
    speed_running_ = false;
    speed_ = nullptr;
    speed_timeout_->stop();
    process->deleteLater();
    return false;
  }
  assignToReaper(process->processId());
  emit speedStateChanged(true);
  return true;
}

void Sidecar::onSpeedStdout() {
  if (!speed_) {
    return;
  }
  consumeLines(speed_, &speed_out_buf_, [this](const QString& line) {
    handleSpeedLine(line);
  });
}

void Sidecar::handleSpeedLine(const QString& line) {
  static const QString kPrefix = QStringLiteral("@speedtest ");
  if (!line.startsWith(kPrefix)) {
    emit proxyLog(line, false);
    return;
  }
  QJsonParseError parse_error{};
  const QJsonDocument doc =
      QJsonDocument::fromJson(line.mid(kPrefix.size()).toUtf8(), &parse_error);
  if (parse_error.error != QJsonParseError::NoError || !doc.isObject()) {
    return;
  }
  const QJsonObject value = doc.object();
  const QString event = value.value(QStringLiteral("event")).toString();
  if (event == QLatin1String("progress")) {
    emit speedProgress(value.value(QStringLiteral("direction")).toString(),
                       static_cast<quint64>(
                           value.value(QStringLiteral("bytes")).toDouble()),
                       value.value(QStringLiteral("elapsedMs")).toDouble() / 1000.0);
  } else if (event == QLatin1String("done")) {
    speed_done_ = true;
    if (speed_timeout_) {
      speed_timeout_->stop();
    }
    emit speedDone(value);
  }
}

void Sidecar::onSpeedStderr() {
  if (!speed_) {
    return;
  }
  speed_err_buf_.append(speed_->readAllStandardError());
  int newline = speed_err_buf_.indexOf('\n');
  while (newline >= 0) {
    QByteArray raw = speed_err_buf_.left(newline);
    speed_err_buf_.remove(0, newline + 1);
    if (raw.endsWith('\r')) {
      raw.chop(1);
    }
    emit proxyLog(QString::fromUtf8(raw), true);
    newline = speed_err_buf_.indexOf('\n');
  }
}

void Sidecar::onSpeedFinished(int exit_code, QProcess::ExitStatus status) {
  Q_UNUSED(exit_code);
  Q_UNUSED(status);
  // 尾巴上没有换行的最后一行也要报出来，否则收尾的 done 事件会被吞掉，
  // 明明跑完却报"测速进程异常退出"。
  if (!speed_out_buf_.isEmpty()) {
    handleSpeedLine(QString::fromUtf8(speed_out_buf_));
    speed_out_buf_.clear();
  }
  if (!speed_err_buf_.isEmpty()) {
    emit proxyLog(QString::fromUtf8(speed_err_buf_), true);
    speed_err_buf_.clear();
  }
  if (!speed_done_) {
    finishSpeedWithError(speed_killed_
                             ? QStringLiteral("测速进程超时退出")
                             : QStringLiteral("测速进程异常退出（确认服务端以 --speedtest 启动）"));
  }
  if (speed_) {
    speed_->deleteLater();
    speed_ = nullptr;
  }
  if (speed_running_) {
    speed_running_ = false;
    emit speedStateChanged(false);
  }
}

void Sidecar::finishSpeedWithError(const QString& error) {
  if (speed_done_) {
    return;
  }
  speed_done_ = true;
  if (speed_timeout_) {
    speed_timeout_->stop();
  }
  QJsonObject result;
  result.insert(QStringLiteral("download"), QJsonValue::Null);
  result.insert(QStringLiteral("upload"), QJsonValue::Null);
  result.insert(QStringLiteral("error"), error);
  emit speedDone(result);
}

void Sidecar::stopSpeedTest() {
  if (speed_timeout_) {
    speed_timeout_->stop();
  }
  if (!speed_) {
    speed_running_ = false;
    return;
  }
  QProcess* process = speed_;
  speed_ = nullptr;
  speed_running_ = false;
  process->disconnect(this);
  killProcess(process, 1500);
  process->deleteLater();
}

bool Sidecar::speedTestRunning() const { return speed_running_; }

void Sidecar::shutdown() {
  stopProxy();
  stopSpeedTest();
}

}  // namespace fcp
