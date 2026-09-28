#pragma once

#include <QDateTime>
#include <QStringList>

class WindowsEventReader
{
public:
    static QStringList ReadApplicationFailures(const QDateTime& startedAt);
};
