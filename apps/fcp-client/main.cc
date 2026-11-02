#include <QApplication>
#include <QFont>
#include <QStyleFactory>
#include <QTimer>

#include "main_window.h"

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  QApplication::setOrganizationName("FCP");
  QApplication::setApplicationName("FCPClient");
  // 发布物/关于对话框里显示的版本；由 CMake 从仓库根 VERSION 注入。
  QApplication::setApplicationVersion(
#ifdef FCP_APP_VERSION
      QStringLiteral(FCP_APP_VERSION)
#else
      QStringLiteral("0.0.0-dev")
#endif
  );
  QApplication::setStyle(QStyleFactory::create("Fusion"));

  // Windows keeps the paper-and-ink UI font; on Linux the AppImage build uses
  // the desktop's default family (Microsoft YaHei UI is normally absent).
#if defined(Q_OS_WIN)
  QFont font = QApplication::font();
  font.setFamily("Microsoft YaHei UI");
  font.setPointSize(9);
  QApplication::setFont(font);
#endif

  MainWindow window;
  window.show();

  // Test hooks only: the GUI has visual inputs and QSettings, so configuration
  // does not belong on its command line (scripted runs use fcp-proxy-client).
  // --autostart fires one benchmark run immediately, --proxy-autostart starts
  // the proxy page, both against whatever the form currently holds.
  if (QCoreApplication::arguments().contains("--autostart")) {
    QTimer::singleShot(400, &window, &MainWindow::startTest);
  }
  if (QCoreApplication::arguments().contains("--proxy-autostart")) {
    QTimer::singleShot(800, &window, &MainWindow::startProxy);
  }
  // Test hook only: prove the deployed runtime can start the GUI and then exit
  // cleanly, so packaging smoke tests do not have to kill a live GUI process
  // (and can assert an exit code instead).
  if (QCoreApplication::arguments().contains("--smoke-test")) {
    QTimer::singleShot(2500, [] { QCoreApplication::quit(); });
  }
  return app.exec();
}
