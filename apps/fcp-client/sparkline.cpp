#include "sparkline.h"

#include <QPainter>
#include <QPainterPath>

Sparkline::Sparkline(const QColor& color, QWidget* parent) : QWidget(parent), color_(color) {
  setMinimumHeight(30);
  setAttribute(Qt::WA_TransparentForMouseEvents);
}

void Sparkline::push(double value) {
  values_.push_back(qMax(0.0, value));
  if (values_.size() > capacity_) {
    values_.remove(0, values_.size() - capacity_);
  }
  update();
}

void Sparkline::clear() {
  values_.clear();
  update();
}

void Sparkline::paintEvent(QPaintEvent*) {
  QPainter painter(this);
  painter.setRenderHint(QPainter::Antialiasing);

  const QRectF area = QRectF(rect()).adjusted(0.5, 3.0, -0.5, -1.0);
  painter.setPen(QPen(QColor(0xe3, 0xdb, 0xc7), 1.0));
  painter.drawLine(area.bottomLeft(), area.bottomRight());

  if (values_.isEmpty()) {
    return;
  }
  double peak = 1.0;
  for (const double value : values_) {
    peak = qMax(peak, value);
  }

  const int count = values_.size();
  QPainterPath line;
  QPainterPath fill;
  bool first = true;
  for (int i = 0; i < count; ++i) {
    const double t = static_cast<double>(count - 1 - i) / static_cast<double>(capacity_ - 1);
    const double x = area.right() - area.width() * t;
    const double y = area.bottom() - area.height() * (values_[i] / peak);
    if (first) {
      line.moveTo(x, y);
      fill.moveTo(x, area.bottom());
      fill.lineTo(x, y);
      first = false;
    } else {
      line.lineTo(x, y);
      fill.lineTo(x, y);
    }
  }
  if (count > 1) {
    fill.lineTo(area.right() - area.width() * static_cast<double>(count - 1) /
                                    static_cast<double>(capacity_ - 1),
                area.bottom());
    fill.closeSubpath();
    painter.setPen(Qt::NoPen);
    QColor wash = color_;
    wash.setAlpha(36);
    painter.setBrush(wash);
    painter.drawPath(fill);
    painter.setBrush(Qt::NoBrush);
    painter.setPen(QPen(color_, 1.4));
    painter.drawPath(line);
  } else {
    painter.setPen(Qt::NoPen);
    painter.setBrush(color_);
    const double y = area.bottom() - area.height() * (values_.first() / peak);
    painter.drawEllipse(QPointF(area.right(), y), 2.0, 2.0);
  }
}
