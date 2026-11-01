#include <QApplication>
#include <QFont>
#include <QStyleFactory>
#include <QTimer>

#include "main_window.h"

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  QApplication::setOrganizationName("FCP");
  QApplication::setApplicationName("FCPClient");
  // 安装包/关于对话框里显示的版本；由 CMake 从仓库根 VERSION 注入。
  QApplication::setApplicationVersion(
#ifdef FCP_APP_VERSION
      QStringLiteral(FCP_APP_VERSION)
#else
      QStringLiteral("0.0.0-dev")
#endif
  );
  QApplication::setStyle(QStyleFactory::create("Fusion"));

  QFont font = QApplication::font();
  font.setFamily("Microsoft YaHei UI");
  font.setPointSize(9);
  QApplication::setFont(font);

  MainWindow window;
  window.applyArgumentOverrides();
  window.show();

  // Test hook: --host/--port/--mbps override the saved form, --autostart fires
  // one run immediately (used for smoke tests against a local bench server).
  if (QCoreApplication::arguments().contains("--autostart")) {
    QTimer::singleShot(400, &window, &MainWindow::startTest);
  }
  // Same idea for the proxy page (used for scripted curl runs through the GUI).
  if (QCoreApplication::arguments().contains("--proxy-autostart")) {
    QTimer::singleShot(800, &window, &MainWindow::startProxy);
  }
  return app.exec();
}
