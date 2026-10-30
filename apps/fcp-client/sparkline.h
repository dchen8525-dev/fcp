#ifndef FCP_CLIENT_SPARKLINE_H_
#define FCP_CLIENT_SPARKLINE_H_

#include <QColor>
#include <QVector>
#include <QWidget>

class Sparkline : public QWidget {
  Q_OBJECT
 public:
  explicit Sparkline(const QColor& color, QWidget* parent = nullptr);

  void push(double value);
  void clear();

 protected:
  void paintEvent(QPaintEvent* event) override;

 private:
  QColor color_;
  QVector<double> values_;
  int capacity_ = 120;  // 10Hz * 12s
};

#endif  // FCP_CLIENT_SPARKLINE_H_
