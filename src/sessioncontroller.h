#pragma once

#include "processsample.h"
#include "sessionstore.h"

#include <QProcess>
#include <QSet>
#include <QThread>

#include <memory>

class ProcessSampler;
class DumpCollector;
class CdbStackCollector;

enum class SessionState
{
    Idle,
    Launching,
    Watching,
    Stopping,
    Finished,
    Failed,
};
Q_DECLARE_METATYPE(SessionState)

class SessionController : public QObject
{
    Q_OBJECT

public:
    explicit SessionController(QObject* parent = nullptr);
    ~SessionController() override;

    bool Launch(const QString& executable, const QStringList& arguments, const QString& outputRoot, int intervalMilliseconds,
                bool captureDump, const QString& procDumpPath, bool captureStack = false, const QString& cdbPath = {},
                bool captureExit = false, const QString& symbolPath = {});
    bool Attach(quint32 processId, const QString& outputRoot, int intervalMilliseconds,
                bool captureDump, const QString& procDumpPath);
    void StopWatching();
    bool AddMarker(const QString& text);
    SessionState state() const;

signals:
    void stateChanged(SessionState state);
    void statusChanged(const QString& message);
    void sampleReady(const ProcessSample& sample);
    void findingReady(const DiagnosticFinding& finding);
    void sessionFinished(const SessionSummary& summary, const QString& sessionDirectory);
    void startSampler(quint32 processId, int intervalMilliseconds);
    void stopSampler();

private slots:
    void OnLaunched();
    void OnLaunchedFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void OnCdbTargetStarted(quint32 processId);
    void OnCdbFinished(int debuggerExitCode, const StackCapture& capture);
    void OnSampleReady(const ProcessSample& sample);
    void OnTargetUnavailable(const QString& reason);

private:
    bool BeginWatching(quint32 processId, const QString& targetPath, const QString& arguments,
                       const QString& outputRoot, int intervalMilliseconds, bool captureDump, const QString& procDumpPath);
    void Finish(int exitCode, const QString& reason);
    void SetState(SessionState state);

    SessionState state_ = SessionState::Idle;
    QProcess launchedProcess_;
    QThread samplerThread_;
    ProcessSampler* sampler_ = nullptr;
    std::unique_ptr<SessionStore> store_;
    std::unique_ptr<DumpCollector> dumpCollector_;
    std::unique_ptr<CdbStackCollector> cdbCollector_;
    QList<ProcessSample> samples_;
    QDateTime startedAt_;
    quint32 processId_ = 0;
    QString targetPath_;
    QString arguments_;
    QString pendingOutputRoot_;
    int pendingIntervalMilliseconds_ = 1000;
    bool pendingCaptureDump_ = false;
    QString pendingProcDumpPath_;
    bool usingCdb_ = false;
    StackCapture stackCapture_;
    QSet<QString> emittedLiveFindingTitles_;
};
