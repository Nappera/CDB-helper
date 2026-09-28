#pragma once

#include "processsample.h"

#include <QObject>
#include <QTimer>

class ProcessSampler : public QObject
{
    Q_OBJECT

public:
    explicit ProcessSampler(QObject* parent = nullptr);

public slots:
    void Start(quint32 processId, int intervalMilliseconds);
    void Stop();

signals:
    void sampleReady(const ProcessSample& sample);
    void targetUnavailable(const QString& reason);

private slots:
    void CaptureOnce();

private:
    quint32 processId_ = 0;
    QTimer timer_;
    quint64 previousCpuTime100ns_ = 0;
    qint64 previousWallMilliseconds_ = 0;
};
