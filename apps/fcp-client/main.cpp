#include <QApplication>
#include <QFont>
#include <QStyleFactory>
#include <QTimer>

#include "main_window.h"

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  QApplication::setOrganizationName("FCP");
  QApplication::setApplicationName("FCPClient");
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
  return app.exec();
}
