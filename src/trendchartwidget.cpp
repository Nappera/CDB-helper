#include "trendchartwidget.h"

#include <QPainter>
#include <QPainterPath>
#include <algorithm>

#include <utility>

TrendChartWidget::TrendChartWidget(QString title, QString unit, QColor color, QWidget* parent)
    : QWidget(parent), title_(std::move(title)), unit_(std::move(unit)), color_(color)
{
    setMinimumHeight(150);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
}

void TrendChartWidget::Append(double value)
{
    values_.append(value);
    if(values_.size() > 180)
    {
        values_.remove(0, values_.size() - 180);
    }
    update();
}

void TrendChartWidget::Clear()
{
    values_.clear();
    currentText_.clear();
    update();
}

void TrendChartWidget::SetCurrentText(const QString& text)
{
    currentText_ = text;
    update();
}

void TrendChartWidget::paintEvent(QPaintEvent*)
{
    QPainter painter(this);
    painter.fillRect(rect(), QColor(QStringLiteral("#ffffff")));
    painter.setRenderHint(QPainter::Antialiasing);
    const QRectF chart = rect().adjusted(12, 38, -12, -24);
    painter.setPen(QColor(QStringLiteral("#d9e2e8")));
    for(int index = 0; index <= 4; ++index)
    {
        const qreal y = chart.top() + chart.height() * index / 4.0;
        painter.drawLine(QPointF(chart.left(), y), QPointF(chart.right(), y));
    }
    painter.setPen(QColor(QStringLiteral("#263238")));
    painter.setFont(QFont(QStringLiteral("Microsoft YaHei"), 10, QFont::DemiBold));
    painter.drawText(QRectF(12, 8, width() - 24, 20), title_);
    painter.setPen(QColor(QStringLiteral("#607d8b")));
    painter.setFont(QFont(QStringLiteral("Consolas"), 9));
    painter.drawText(QRectF(12, height() - 20, width() - 24, 16), currentText_);

    if(values_.isEmpty())
    {
        painter.setPen(QColor(QStringLiteral("#90a4ae")));
        painter.drawText(chart, Qt::AlignCenter, QStringLiteral("等待采样"));
        return;
    }

    const auto minmax = std::minmax_element(values_.cbegin(), values_.cend());
    double minimum = *minmax.first;
    double maximum = *minmax.second;
    if(qFuzzyCompare(minimum + 1.0, maximum + 1.0))
    {
        minimum -= 1.0;
        maximum += 1.0;
    }
    painter.setPen(QPen(color_, 2.0));
    QPainterPath path;
    for(int index = 0; index < values_.size(); ++index)
    {
        const qreal x = values_.size() == 1 ? chart.left()
                                             : chart.left() + chart.width() * index / (values_.size() - 1.0);
        const qreal y = chart.bottom() - chart.height() * (values_[index] - minimum) / (maximum - minimum);
        index == 0 ? path.moveTo(x, y) : path.lineTo(x, y);
    }
    painter.drawPath(path);
    painter.setPen(QColor(QStringLiteral("#607d8b")));
    painter.drawText(QRectF(chart.left(), chart.top() - 18, chart.width(), 16), Qt::AlignRight,
                     QStringLiteral("%1 %2").arg(maximum, 0, 'f', 1).arg(unit_));
}
