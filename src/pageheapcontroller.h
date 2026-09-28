#pragma once

#include <QString>

class PageHeapController
{
public:
    static QString FindGflags(const QString& requestedPath);
    static QString BuildCommand(const QString& executablePath, bool enable);
    static bool RunElevated(const QString& gflagsPath, const QString& executablePath, bool enable, QString* error);
};
