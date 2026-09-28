#include "dumpcollector.h"

#include <QDir>
#include <QFileInfo>

QString BuildWinDbgCommand(const QString& dumpPath, const QStringList& symbolPaths)
{
    const QString symbolCommand = symbolPaths.isEmpty()
                                      ? QStringLiteral(".symfix")
                                      : QStringLiteral(".symfix; .sympath+ %1").arg(symbolPaths.join(';'));
    return QStringLiteral("%1; .reload; .opendump %2; !analyze -v; kb")
        .arg(symbolCommand, dumpPath);
}

bool DumpCollector::Start(const QString& procDumpPath, quint32 processId, const QString& dumpDirectory, QString* error)
{
    log_.setFileName(QFileInfo(dumpDirectory).absolutePath() + "/procdump.log");
    if(!log_.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        if(error) *error = QStringLiteral("无法写入 ProcDump 诊断日志：%1").arg(log_.errorString());
        return false;
    }
    log_.write(QString("准备捕获 PID %1 的未处理异常。工具：%2\n普通退出不会触发本模式。\n").arg(processId).arg(procDumpPath).toUtf8());
    log_.flush();
    if(!QFileInfo::exists(procDumpPath))
    {
        if(error) *error = QStringLiteral("未找到 ProcDump：%1").arg(procDumpPath);
        log_.write("ProcDump executable not found.\n"); log_.flush();
        return false;
    }
    if(!QDir().mkpath(dumpDirectory))
    {
        if(error) *error = QStringLiteral("无法创建 dump 目录：%1").arg(dumpDirectory);
        log_.write("Cannot create dump directory.\n"); log_.flush();
        return false;
    }

    process_.setProgram(procDumpPath);
    process_.setProcessChannelMode(QProcess::MergedChannels);
    QObject::connect(&process_, &QProcess::readyRead, &process_, [this] {
        log_.write(QString::fromLocal8Bit(process_.readAll()).toUtf8());
        log_.flush();
    });
    QObject::connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), &process_, [this](int code, QProcess::ExitStatus) {
        log_.write(QString::fromLocal8Bit(process_.readAll()).toUtf8());
        log_.write(QString("\nProcDump 已结束，工具退出码=%1（不是目标程序退出码）。\n").arg(code).toUtf8());
        log_.flush();
    });
    process_.setArguments(QStringList{QStringLiteral("-accepteula"), QStringLiteral("-ma"), QStringLiteral("-e"),
                                      QString::number(processId), dumpDirectory});
    process_.start();
    if(!process_.waitForStarted(3000))
    {
        if(error) *error = QStringLiteral("ProcDump 启动失败：%1").arg(process_.errorString());
        log_.write(process_.errorString().toUtf8()); log_.flush();
        return false;
    }
    log_.write("ProcDump process started; attachment result follows in tool output.\n"); log_.flush();
    return true;
}

void DumpCollector::Stop()
{
    if(process_.state() == QProcess::NotRunning)
    {
        return;
    }
    log_.write(QStringLiteral("\n会话要求停止 ProcDump。若此前未出现写入成功信息，现场文件可能缺失或不完整。\n").toUtf8());
    log_.flush();
    process_.terminate();
    if(!process_.waitForFinished(1500))
    {
        process_.kill();
        process_.waitForFinished(1500);
    }
}

bool DumpCollector::isRunning() const
{
    return process_.state() != QProcess::NotRunning;
}
