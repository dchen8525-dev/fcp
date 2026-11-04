#include "sparkline.h"

#include <QPainter>
#include <QPainterPath>

#include <algorithm>

namespace fcp {

Sparkline::Sparkline(QWidget* parent) : QWidget(parent) {
  setMinimumHeight(92);
  setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
}

void Sparkline::addSample(double tx_bps, double rx_bps) {
  tx_.append(tx_bps);
  rx_.append(rx_bps);
  while (tx_.size() > kMaxPoints) {
    tx_.removeFirst();
    rx_.removeFirst();
  }
  update();
}

void Sparkline::reset() {
  tx_.clear();
  rx_.clear();
  update();
}

void Sparkline::paintEvent(QPaintEvent* event) {
  Q_UNUSED(event);
  QPainter painter(this);
  painter.setRenderHint(QPainter::Antialiasing, true);

  const double w = width();
  const double h = height();
  if (w <= 1 || h <= 1) {
    return;
  }

  // 网格线：四条横线，与界面其余部分的 --line 同色。
  painter.setPen(QPen(QColor(0xe6, 0xed, 0xe9), 1));
  for (int i = 1; i <= 3; ++i) {
    const double y = h * i / 4.0;
    painter.drawLine(QPointF(0, y), QPointF(w, y));
  }

  double peak = 1024;
  for (double v : tx_) {
    peak = std::max(peak, v);
  }
  for (double v : rx_) {
    peak = std::max(peak, v);
  }

  const auto plot = [&](const QVector<double>& values, const QColor& color) {
    if (values.size() < 2) {
      return;
    }
    QPainterPath path;
    const double step = w / (kMaxPoints - 1);
    for (int i = 0; i < values.size(); ++i) {
      const double x = w - (values.size() - 1 - i) * step;
      const double y = h - 1 - (values.at(i) / peak) * (h - 4);
      if (i == 0) {
        path.moveTo(x, y);
      } else {
        path.lineTo(x, y);
      }
    }
    painter.setPen(QPen(color, 1.6, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawPath(path);
  };

  // 上行沙色、下行品牌绿，跟左侧图例一致。
  plot(tx_, QColor(0xc0, 0x7f, 0x15));
  plot(rx_, QColor(0x0f, 0x9d, 0x76));
}

}  // namespace fcp
