#pragma once

#include <QProcess>
#include <QStringList>
#include <QFile>

QString BuildWinDbgCommand(const QString& dumpPath, const QStringList& symbolPaths);

class DumpCollector
{
public:
    bool Start(const QString& procDumpPath, quint32 processId, const QString& dumpDirectory, QString* error);
    void Stop();
    bool isRunning() const;

private:
    QFile log_;
    QProcess process_;
};
