#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStyleFactory>
#include <QTextStream>

#include "mainwindow.h"
#include "sidecar.h"

namespace {

QString envOrDefault(const char* name, const QString& fallback) {
  const QString value = qEnvironmentVariable(name);
  return value.isEmpty() ? fallback : value;
}

void writeSelftestResult(const QString& text) {
  const QString path = QDir(QDir::tempPath()).filePath(QStringLiteral("fcp-speedtest.txt"));
  QFile file(path);
  if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    file.write(text.toUtf8());
  }
}

// 无界面的测速自检：`FCP.exe --fcp-speedtest-selftest`（参数走环境变量）。
// 和界面走同一条路径（第二个 fcp-client 进程），服务端需以 --speedtest 启动；
// 结果同时写到临时目录的 fcp-speedtest.txt（release 是 GUI 子系统，没有控制台）。
int speedtestSelftest() {
  const auto fail = [](const QString& text) {
    QTextStream(stdout) << text << '\n';
    writeSelftestResult(text);
    return 1;
  };

  fcp::Sidecar sidecar;
  QString error;
  const QString binary = sidecar.resolveBinary(&error);
  if (binary.isEmpty()) {
    return fail(error);
  }

  QString key = qEnvironmentVariable("FCP_SPEEDTEST_KEY");
  if (key.isEmpty()) {
    key = qEnvironmentVariable("FCP_PSK");
  }
  bool ok = false;
  int seconds = envOrDefault("FCP_SPEEDTEST_SECONDS", QStringLiteral("8")).toInt(&ok);
  if (!ok) {
    seconds = 8;
  }
  seconds = qBound(3, seconds, 30);

  QProcess process;
  process.setProgram(binary);
  process.setArguments({
      QStringLiteral("--host=%1").arg(envOrDefault("FCP_SPEEDTEST_HOST",
                                                   QStringLiteral("127.0.0.1"))),
      QStringLiteral("--port=%1").arg(envOrDefault("FCP_SPEEDTEST_PORT",
                                                   QStringLiteral("4460"))),
      QStringLiteral("--speedtest-seconds=%1").arg(seconds),
      QStringLiteral("--speedtest"),
      QStringLiteral("--key-env=FCP_PSK"),
  });
  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  env.insert(QStringLiteral("FCP_PSK"), key);
  process.setProcessEnvironment(env);
  process.setStandardInputFile(QProcess::nullDevice());

  process.start();
  if (!process.waitForStarted(10000)) {
    return fail(QStringLiteral("启动 %1 失败：%2").arg(binary, process.errorString()));
  }
  if (!process.waitForFinished((seconds * 2 + 120) * 1000)) {
    process.kill();
    process.waitForFinished(3000);
    return fail(QStringLiteral("测速进程超时退出"));
  }

  const QString stdout_text = QString::fromLocal8Bit(process.readAllStandardOutput());
  const QString stderr_text = QString::fromLocal8Bit(process.readAllStandardError());

  QString text;
  for (const QString& line : stdout_text.split(QLatin1Char('\n'))) {
    if (!line.startsWith(QLatin1String("@speedtest "))) {
      continue;
    }
    const QString rest = line.mid(11).trimmed();
    QJsonParseError parse_error{};
    const QJsonDocument doc = QJsonDocument::fromJson(rest.toUtf8(), &parse_error);
    if (parse_error.error != QJsonParseError::NoError || !doc.isObject()) {
      continue;
    }
    const QJsonObject value = doc.object();
    if (value.value(QStringLiteral("event")).toString() == QLatin1String("done")) {
      text = QString::fromUtf8(QJsonDocument(value).toJson(QJsonDocument::Indented));
    }
  }
  if (text.isEmpty()) {
    QJsonObject fallback;
    fallback.insert(QStringLiteral("error"), QStringLiteral("测速没有完成"));
    fallback.insert(QStringLiteral("stderr"), stderr_text.trimmed());
    text = QString::fromUtf8(QJsonDocument(fallback).toJson(QJsonDocument::Indented));
  }

  QTextStream(stdout) << text;
  writeSelftestResult(text);
  if (!stderr_text.trimmed().isEmpty()) {
    QTextStream(stderr) << stderr_text;
  }
  return text.contains(QStringLiteral("\"mbps\"")) ? 0 : 1;
}

void applyStyle(QApplication& app) {
  app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
  QFile qss(QStringLiteral(":/assets/app.qss"));
  if (qss.open(QIODevice::ReadOnly)) {
    app.setStyleSheet(QString::fromUtf8(qss.readAll()));
  }
}

}  // namespace

int main(int argc, char** argv) {
  bool selftest = false;
  for (int i = 1; i < argc; ++i) {
    if (qstrcmp(argv[i], "--fcp-speedtest-selftest") == 0) {
      selftest = true;
      break;
    }
  }
  if (selftest) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("FCP"));
    QCoreApplication::setApplicationName(QStringLiteral("FCP Client"));
    return speedtestSelftest();
  }

  QApplication app(argc, argv);
  QApplication::setOrganizationName(QStringLiteral("FCP"));
  QApplication::setApplicationName(QStringLiteral("FCP Client"));
  QApplication::setApplicationDisplayName(QStringLiteral("FCP"));
  // 关窗/最小化收进托盘，隧道继续跑；退出走托盘菜单或没有托盘时的关窗。
  QApplication::setQuitOnLastWindowClosed(false);

  applyStyle(app);

  fcp::Sidecar sidecar;
  QObject::connect(&app, &QCoreApplication::aboutToQuit, &sidecar,
                   &fcp::Sidecar::shutdown);

  fcp::MainWindow window(&sidecar);
  window.show();
  return app.exec();
}
