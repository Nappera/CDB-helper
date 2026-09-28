#pragma once

#include <QDateTime>
#include <QMetaType>
#include <QString>

struct ProcessSample
{
    QDateTime capturedAt;
    qint64 privateBytes = 0;
    qint64 workingSetBytes = 0;
    quint32 handleCount = 0;
    quint32 threadCount = 0;
    double cpuPercent = 0.0;
};
Q_DECLARE_METATYPE(ProcessSample)

enum class FindingSeverity
{
    Info,
    Warning,
    Error,
};

struct DiagnosticFinding
{
    FindingSeverity severity = FindingSeverity::Info;
    QString title;
    QString detail;
};
