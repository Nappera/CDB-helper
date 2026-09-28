#pragma once

#include <QColor>
#include <QVector>
#include <QWidget>

class TrendChartWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TrendChartWidget(QString title, QString unit, QColor color, QWidget* parent = nullptr);

    void Append(double value);
    void Clear();
    void SetCurrentText(const QString& text);

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    QString title_;
    QString unit_;
    QString currentText_;
    QColor color_;
    QVector<double> values_;
};
