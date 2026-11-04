// 最近 60 秒的上下行速率折线（stats 每 0.5s 一条，保留 120 点）。
// 没有引入 QtCharts：两三条折线用 QPainter 画更轻，样式也好控制。

#ifndef FCP_DESKTOP_SPARKLINE_H_
#define FCP_DESKTOP_SPARKLINE_H_

#include <QVector>
#include <QWidget>

namespace fcp {

class Sparkline : public QWidget {
  Q_OBJECT

 public:
  explicit Sparkline(QWidget* parent = nullptr);

  void addSample(double tx_bps, double rx_bps);
  void reset();

 protected:
  void paintEvent(QPaintEvent* event) override;

 private:
  static constexpr int kMaxPoints = 120;
  QVector<double> tx_;
  QVector<double> rx_;
};

}  // namespace fcp

#endif  // FCP_DESKTOP_SPARKLINE_H_
