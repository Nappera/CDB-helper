#pragma once

#include <QObject>
#include <QProcess>
#include <QStringList>
#include <QTimer>
#include <QFile>

struct StackCapture
{
    bool requested = false;
    bool debuggerStarted = false;
    bool exceptionObserved = false;
    QString exceptionCode;
    QString exceptionModule;
    QStringList stackLines;
    QString rawLogPath;
    QString diagnostic;
    bool exitPathObserved = false;
    bool targetExitCodeKnown = false;
    quint32 targetExitCode = 0;
    int debuggerExitCode = 0;
    QString symbolStatus;
    QString dumpStatus;
};
Q_DECLARE_METATYPE(StackCapture)

QString FindDefaultCdbPath();
QStringList BuildCdbArguments(const QString& targetPath, const QStringList& targetArguments,
                             const QString& dumpPath = {}, bool captureExit = false, const QString& symbolPath = {});
StackCapture ParseCdbLog(const QString& log, const QString& logPath);

class CdbStackCollector : public QObject
{
    Q_OBJECT

public:
    explicit CdbStackCollector(QObject* parent = nullptr);

    bool Start(const QString& cdbPath, const QString& targetPath, const QStringList& targetArguments,
               const QString& logPath, QString* error, bool captureExit = false, const QString& symbolPath = {});
    void Stop();
    bool isRunning() const;

signals:
    void targetStarted(quint32 processId);
    void finished(int debuggerExitCode, const StackCapture& capture);
    void errorOccurred(const QString& message);

private slots:
    void PollTargetProcess();
    void OnFinished(int exitCode, QProcess::ExitStatus exitStatus);

private:
    static quint32 FindDirectChildProcessId(quint32 parentProcessId, const QString& targetPath);
    void AppendAvailableOutput();

    QProcess process_;
    QTimer childPollTimer_;
    QString targetPath_;
    QString logPath_;
    QString rawLog_;
    QFile liveLog_;
    bool logWriteFailed_ = false;
    quint32 targetProcessId_ = 0;
};
