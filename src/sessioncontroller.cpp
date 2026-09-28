#include "sessioncontroller.h"

#include "processsampler.h"
#include "sessionanalysis.h"
#include "windowseventreader.h"
#include "dumpcollector.h"
#include "cdbstackcollector.h"

#include <QDir>
#include <QFileInfo>

SessionController::SessionController(QObject* parent) : QObject(parent)
{
    qRegisterMetaType<ProcessSample>();
    sampler_ = new ProcessSampler;
    sampler_->moveToThread(&samplerThread_);
    connect(&samplerThread_, &QThread::finished, sampler_, &QObject::deleteLater);
    connect(this, &SessionController::startSampler, sampler_, &ProcessSampler::Start, Qt::QueuedConnection);
    connect(this, &SessionController::stopSampler, sampler_, &ProcessSampler::Stop, Qt::QueuedConnection);
    connect(sampler_, &ProcessSampler::sampleReady, this, &SessionController::OnSampleReady, Qt::QueuedConnection);
    connect(sampler_, &ProcessSampler::targetUnavailable, this, &SessionController::OnTargetUnavailable, Qt::QueuedConnection);
    connect(&launchedProcess_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this, &SessionController::OnLaunchedFinished);
    connect(&launchedProcess_, &QProcess::started, this, &SessionController::OnLaunched);
    samplerThread_.start();
}

SessionController::~SessionController()
{
    emit stopSampler();
    samplerThread_.quit();
    samplerThread_.wait(3000);
}

bool SessionController::Launch(const QString& executable, const QStringList& arguments, const QString& outputRoot, int intervalMilliseconds,
                               bool captureDump, const QString& procDumpPath, bool captureStack, const QString& cdbPath,
                               bool captureExit, const QString& symbolPath)
{
    if(state_ == SessionState::Watching || state_ == SessionState::Launching
       || launchedProcess_.state() != QProcess::NotRunning || (cdbCollector_ && cdbCollector_->isRunning()) || executable.isEmpty())
    {
        return false;
    }
    targetPath_ = executable;
    processId_ = 0;
    arguments_ = arguments.join(' ');
    pendingOutputRoot_ = outputRoot;
    pendingIntervalMilliseconds_ = intervalMilliseconds;
    pendingCaptureDump_ = captureDump;
    pendingProcDumpPath_ = procDumpPath;
    usingCdb_ = captureStack;
    stackCapture_ = {};
    SetState(SessionState::Launching);
    if(captureStack)
    {
        startedAt_ = QDateTime::currentDateTime();
        samples_.clear();
        emittedLiveFindingTitles_.clear();
        store_ = std::make_unique<SessionStore>(outputRoot, QFileInfo(executable).fileName());
        if(!store_->Start())
        {
            store_.reset();
            SetState(SessionState::Failed);
            emit statusChanged(QStringLiteral("无法创建会话输出目录。"));
            return false;
        }
        cdbCollector_ = std::make_unique<CdbStackCollector>();
        connect(cdbCollector_.get(), &CdbStackCollector::targetStarted, this, &SessionController::OnCdbTargetStarted);
        connect(cdbCollector_.get(), &CdbStackCollector::finished, this, &SessionController::OnCdbFinished);
        QString error;
        if(!cdbCollector_->Start(cdbPath, executable, arguments, store_->cdbLogPath(), &error, captureExit, symbolPath))
        {
            stackCapture_.requested = true;
            stackCapture_.diagnostic = error;
            Finish(-1, error);
            return false;
        }
        connect(cdbCollector_.get(), &CdbStackCollector::errorOccurred, this, [this](const QString& message) {
            stackCapture_.requested = true;
            stackCapture_.diagnostic = message;
            Finish(-1, message);
        });
        emit statusChanged(QStringLiteral("CDB 已启动，正在等待目标进程启动。会话目录：%1").arg(store_->sessionDirectory()));
        return true;
    }
    launchedProcess_.setProgram(executable);
    launchedProcess_.setArguments(arguments);
    launchedProcess_.start();
    return true;
}

bool SessionController::Attach(quint32 processId, const QString& outputRoot, int intervalMilliseconds,
                               bool captureDump, const QString& procDumpPath)
{
    if(state_ == SessionState::Watching || processId == 0)
    {
        return false;
    }
    return BeginWatching(processId, QStringLiteral("PID %1").arg(processId), {}, outputRoot, intervalMilliseconds,
                         captureDump, procDumpPath);
}

void SessionController::StopWatching()
{
    if((state_ == SessionState::Watching || state_ == SessionState::Launching) && usingCdb_ && cdbCollector_)
    {
        SetState(SessionState::Stopping);
        cdbCollector_->Stop();
        emit statusChanged(QStringLiteral("正在停止 CDB 调用栈采集。"));
    }
    else if(state_ == SessionState::Watching)
    {
        Finish(-1, QStringLiteral("用户停止监视；目标进程未被强制结束。"));
    }
}

bool SessionController::AddMarker(const QString& text)
{
    const QString trimmed = text.trimmed();
    if(state_ != SessionState::Watching || !store_ || trimmed.isEmpty())
    {
        return false;
    }
    store_->AddMarker({QDateTime::currentDateTime(), trimmed});
    emit statusChanged(QStringLiteral("操作标记：%1").arg(trimmed));
    return true;
}

SessionState SessionController::state() const { return state_; }

void SessionController::OnLaunched()
{
    BeginWatching(static_cast<quint32>(launchedProcess_.processId()), targetPath_, arguments_,
                  pendingOutputRoot_, pendingIntervalMilliseconds_, pendingCaptureDump_, pendingProcDumpPath_);
}

void SessionController::OnLaunchedFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if(state_ == SessionState::Watching)
    {
        Finish(exitCode, exitStatus == QProcess::CrashExit
                             ? QStringLiteral("目标进程异常退出。")
                             : QStringLiteral("目标进程正常退出。"));
    }
}

void SessionController::OnCdbTargetStarted(quint32 processId)
{
    BeginWatching(processId, targetPath_, arguments_, pendingOutputRoot_, pendingIntervalMilliseconds_,
                  pendingCaptureDump_, pendingProcDumpPath_);
}

void SessionController::OnCdbFinished(int debuggerExitCode, const StackCapture& capture)
{
    stackCapture_ = capture;
    stackCapture_.debuggerExitCode = debuggerExitCode;
    const QString reason = capture.exceptionObserved
                               ? QStringLiteral("目标进程异常结束；CDB 已捕获调用栈。")
                               : QStringLiteral("CDB 会话结束：%1").arg(capture.diagnostic);
    Finish(capture.targetExitCodeKnown ? static_cast<int>(capture.targetExitCode) : -1, reason);
}

void SessionController::OnSampleReady(const ProcessSample& sample)
{
    if(state_ != SessionState::Watching || !store_)
    {
        return;
    }
    samples_.append(sample);
    store_->Append(sample);
    emit sampleReady(sample);
    const QList<DiagnosticFinding> liveFindings = SessionAnalysis::Analyze(samples_);
    for(const DiagnosticFinding& finding : liveFindings)
    {
        if(!emittedLiveFindingTitles_.contains(finding.title))
        {
            emittedLiveFindingTitles_.insert(finding.title);
            emit findingReady(finding);
            emit statusChanged(QStringLiteral("趋势预警：%1。%2").arg(finding.title, finding.detail));
        }
    }
}

void SessionController::OnTargetUnavailable(const QString& reason)
{
    if(state_ == SessionState::Watching)
    {
        if(usingCdb_)
        {
            emit stopSampler();
            emit statusChanged(QStringLiteral("目标进程已结束，正在等待 CDB 输出调用栈。"));
            return;
        }
        Finish(-1, reason);
    }
}

bool SessionController::BeginWatching(quint32 processId, const QString& targetPath, const QString& arguments,
                                      const QString& outputRoot, int intervalMilliseconds,
                                      bool captureDump, const QString& procDumpPath)
{
    processId_ = processId;
    targetPath_ = targetPath;
    arguments_ = arguments;
    if(!store_)
    {
        startedAt_ = QDateTime::currentDateTime();
        samples_.clear();
        emittedLiveFindingTitles_.clear();
        store_ = std::make_unique<SessionStore>(outputRoot, QFileInfo(targetPath).fileName());
        if(!store_->Start())
        {
            store_.reset();
            SetState(SessionState::Failed);
            emit statusChanged(QStringLiteral("无法创建会话输出目录。"));
            return false;
        }
    }
    SetState(SessionState::Watching);
    emit statusChanged(QStringLiteral("正在监视 PID %1。会话目录：%2").arg(processId_).arg(store_->sessionDirectory()));
    if(captureDump && !usingCdb_)
    {
        dumpCollector_ = std::make_unique<DumpCollector>();
        QString error;
        if(dumpCollector_->Start(procDumpPath, processId_, store_->dumpsDirectory(), &error))
        {
            emit statusChanged(QStringLiteral("ProcDump 进程已启动，仅捕获未处理异常；是否附加成功请查看会话中的 procdump.log。"));
        }
        else
        {
            dumpCollector_.reset();
            emit statusChanged(QStringLiteral("未启用 ProcDump：%1").arg(error));
        }
    }
    else if(captureDump && usingCdb_)
    {
        emit statusChanged(QStringLiteral("CDB 调用栈采集期间不同时启动 ProcDump。"));
    }
    emit startSampler(processId_, intervalMilliseconds);
    return true;
}

void SessionController::Finish(int exitCode, const QString& reason)
{
    if(!store_)
    {
        SetState(SessionState::Finished);
        return;
    }
    emit stopSampler();
    if(dumpCollector_)
    {
        dumpCollector_->Stop();
    }
    SessionSummary summary;
    summary.targetPath = targetPath_;
    summary.arguments = arguments_;
    summary.processId = processId_;
    summary.exitCode = exitCode;
    summary.exitCodeKnown = usingCdb_ ? stackCapture_.targetExitCodeKnown : exitCode != -1;
    summary.startedAt = startedAt_.toString(Qt::ISODateWithMs);
    summary.endedAt = QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
    summary.eventsXml = WindowsEventReader::ReadApplicationFailures(startedAt_);
    summary.stackCapture = stackCapture_;
    const QDir dumpDirectory(store_->dumpsDirectory());
    const QFileInfoList dumpFiles = dumpDirectory.entryInfoList({QStringLiteral("*.dmp")}, QDir::Files, QDir::Time);
    for(const QFileInfo& dump : dumpFiles)
    {
        summary.dumpPaths.append(dump.absoluteFilePath());
    }
    summary.findings = SessionAnalysis::Analyze(samples_);
    for(const DiagnosticFinding& finding : summary.findings)
    {
        if(!emittedLiveFindingTitles_.contains(finding.title))
        {
            emit findingReady(finding);
        }
    }
    if(stackCapture_.requested)
    {
        DiagnosticFinding stackFinding;
        stackFinding.severity = stackCapture_.exceptionObserved ? FindingSeverity::Warning : FindingSeverity::Info;
        stackFinding.title = stackCapture_.exceptionObserved ? QStringLiteral("已捕获异常调用栈")
                            : stackCapture_.exitPathObserved ? QStringLiteral("已捕获退出路径（不一定是崩溃）") : QStringLiteral("退出原因尚未捕获");
        stackFinding.detail = stackCapture_.diagnostic;
        if(!stackCapture_.exceptionCode.isEmpty())
        {
            stackFinding.detail += QStringLiteral(" 异常码：%1。").arg(stackCapture_.exceptionCode);
        }
        if(!stackCapture_.exceptionModule.isEmpty())
        {
            stackFinding.detail += QStringLiteral(" 模块：%1。").arg(stackCapture_.exceptionModule);
        }
        summary.findings.prepend(stackFinding);
        summary.findings.append({summary.dumpPaths.isEmpty() ? FindingSeverity::Warning : FindingSeverity::Info,
                                summary.dumpPaths.isEmpty() ? QStringLiteral("没有找到现场文件") : QStringLiteral("现场文件已保留"),
                                stackCapture_.dumpStatus + QStringLiteral(" 文件数：%1；原始证据见 cdb.log。").arg(summary.dumpPaths.size())});
        summary.findings.append({FindingSeverity::Info, QStringLiteral("源码定位能力"), stackCapture_.symbolStatus});
    }
    DiagnosticFinding reasonFinding;
    reasonFinding.severity = (exitCode == 0 && !stackCapture_.exceptionObserved) ? FindingSeverity::Info : FindingSeverity::Warning;
    reasonFinding.title = QStringLiteral("会话结束");
    reasonFinding.detail = reason;
    summary.findings.prepend(reasonFinding);
    if(!store_->Finalize(summary))
        emit statusChanged(QStringLiteral("报告写入未全部成功，请检查会话目录权限或磁盘空间；保留已有 cdb.log / dump。"));
    const QString directory = store_->sessionDirectory();
    store_.reset();
    dumpCollector_.reset();
    if(cdbCollector_)
    {
        CdbStackCollector* collector = cdbCollector_.release();
        collector->deleteLater();
    }
    usingCdb_ = false;
    SetState(SessionState::Finished);
    emit statusChanged(reason);
    emit sessionFinished(summary, directory);
}

void SessionController::SetState(SessionState state)
{
    if(state_ == state)
    {
        return;
    }
    state_ = state;
    emit stateChanged(state_);
}
