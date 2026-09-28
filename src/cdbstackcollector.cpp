#include "cdbstackcollector.h"

#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSaveFile>
#include <QCoreApplication>

#ifdef Q_OS_WIN
#include <Windows.h>
#include <TlHelp32.h>
#endif

namespace
{
const QString kStackBegin = QStringLiteral("=== RELEASE_DEBUG_STUDIO_STACK_BEGIN ===");
const QString kStackEnd = QStringLiteral("=== RELEASE_DEBUG_STUDIO_STACK_END ===");

QString ReadEnvPath(const char* name)
{
    return QString::fromLocal8Bit(qgetenv(name));
}
}

QString FindDefaultCdbPath()
{
#ifdef Q_OS_WIN
    // 优先使用助手旁的便携工具，整目录移动后仍能找到。
    const QString bundled = QDir(QCoreApplication::applicationDirPath())
            .filePath(QStringLiteral("thirdparty/debuggers-x64/cdb.exe"));
    if(QFileInfo(bundled).isFile()) return QDir::toNativeSeparators(bundled);
    const QString suffix = QStringLiteral("Windows Kits/10/Debuggers/x64/cdb.exe");
    const QStringList roots = {ReadEnvPath("ProgramFiles(x86)"), ReadEnvPath("ProgramFiles")};
    for(const QString& root : roots)
    {
        if(root.isEmpty())
        {
            continue;
        }
        const QString candidate = QDir(root).filePath(suffix);
        if(QFileInfo(candidate).isFile())
        {
            return QDir::toNativeSeparators(candidate);
        }
    }
#endif
    return {};
}

// 配置异常取证；可选在退出 API 处保留现场，不把正常关闭误认为异常。
QStringList BuildCdbArguments(const QString& targetPath, const QStringList& targetArguments,
                             const QString& dumpPath, bool captureExit, const QString& symbolPath)
{
    const QString dumpCommand = dumpPath.isEmpty() ? QString() : QStringLiteral(".dump /ma /u \"%1\"; ").arg(QDir::toNativeSeparators(dumpPath));
    const QString captureCommand = QStringLiteral(".echo %1; .exr -1; kb; lm; %3.echo %2; q").arg(kStackBegin, kStackEnd, dumpCommand);
    // Qt 和 MSVC 正常流程会频繁产生且处理 first-chance C++ EH。
    // 只在 second-chance AV / 断点 / C++ EH 时停止并导出栈，避免正常会话被误判为崩溃。
    QString initialCommand = QStringLiteral(".symopt- 0x40; !sym noisy; .reload; sxd av; sxd bpe; sxd eh; ");
    initialCommand += QStringLiteral("sxe -c \".echo RDS_PROCESS_EXIT; .lastevent; q\" epr; ");
    if(captureExit)
    {
        // 不监视子进程；NtTerminateProcess 只在伪句柄 -1（本进程）时停住。
        initialCommand += QStringLiteral("bu ntdll!RtlExitUserProcess; bp ntdll!NtTerminateProcess \".if (@rcx != 0xffffffffffffffff) {gc}\"; ");
    }
    initialCommand += QStringLiteral("g; ");
    if(captureExit)
    {
        initialCommand += QStringLiteral(".if (@rip == ntdll!RtlExitUserProcess) { .echo RDS_EXIT_PATH; kb; %1bc *; g; } ")
                              .arg(dumpCommand);
        initialCommand += QStringLiteral(".elsif (@rip == ntdll!NtTerminateProcess) { .echo RDS_EXIT_PATH; kb; %1bc *; g; } .else { %2 }")
                              .arg(dumpCommand, captureCommand);
    }
    else initialCommand += captureCommand;
    QString paths = QFileInfo(targetPath).absolutePath();
    if(!symbolPath.trimmed().isEmpty()) paths += ';' + symbolPath.trimmed();
    QStringList result{
        QStringLiteral("-pd"),
        QStringLiteral("-y"), paths,
        QStringLiteral("-c"),
        initialCommand,
        targetPath
    };
    result.append(targetArguments);
    return result;
}

StackCapture ParseCdbLog(const QString& log, const QString& logPath)
{
    StackCapture capture;
    capture.rawLogPath = logPath;
    capture.exitPathObserved = log.contains(QStringLiteral("\nRDS_EXIT_PATH"));
    const QRegularExpression exitPattern(QStringLiteral("(?:exited with code|Exit process[^\\r\\n]*, code)\\s+(?:0x)?([0-9a-fA-F]+)"), QRegularExpression::CaseInsensitiveOption);
    auto exits = exitPattern.globalMatch(log);
    while(exits.hasNext())
    {
        const auto match = exits.next();
        capture.targetExitCode = match.captured(1).toUInt(&capture.targetExitCodeKnown, 16);
    }
    capture.symbolStatus = log.contains("mismatched pdb", Qt::CaseInsensitive)
            ? QStringLiteral("发现不匹配的 PDB，未强制加载；行号不能据此确认。")
            : log.contains("private symbols", Qt::CaseInsensitive)
              ? QStringLiteral("已加载部分私有符号；具体模块覆盖情况见 cdb.log。")
              : QStringLiteral("尚未确认目标模块的私有符号已加载；有函数名不等于有准确源码行。 ");
    capture.dumpStatus = log.contains("Dump successfully written", Qt::CaseInsensitive)
            ? QStringLiteral("调试器确认 dump 写入成功。")
            : log.contains(".dump /ma")
              ? QStringLiteral("未确认 dump 写入成功；请查看 cdb.log 中写入命令及错误。")
              : QStringLiteral("未执行现场写入；可能未触发捕获条件或进程已结束。 ");

    const int end = log.lastIndexOf(kStackEnd);
    const int begin = end < 0 ? -1 : log.lastIndexOf(kStackBegin, end - 1);
    const QString section = begin >= 0 && end > begin
                                ? log.mid(begin + kStackBegin.size(), end - begin - kStackBegin.size())
                                : QString();

    const QRegularExpression codePattern(
        QStringLiteral("(?:exception\\s*-\\s*code|ExceptionCode:)\\s+([0-9a-fA-F]{8})"),
        QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatchIterator codeMatches = codePattern.globalMatch(section);
    while(codeMatches.hasNext())
    {
        capture.exceptionCode = QStringLiteral("0x") + codeMatches.next().captured(1).toLower();
    }
    capture.exceptionObserved = !capture.exceptionCode.isEmpty();
    if(capture.exitPathObserved && section.isEmpty())
    {
        const QString exitSection = log.mid(log.lastIndexOf(QStringLiteral("\nRDS_EXIT_PATH")));
        for(const auto& line : exitSection.split('\n'))
            if(line.contains('!')) capture.stackLines.append(line.trimmed());
    }

    if(begin >= 0 && end > begin)
    {
        for(const QString& line : section.split(QRegularExpression(QStringLiteral("\\r?\\n")), Qt::SkipEmptyParts))
        {
            const int bang = line.indexOf(QLatin1Char('!'));
            if(bang > 0 || QRegularExpression(QStringLiteral("^\\s*[0-9a-fA-F`]+\\s+.*\\+0x[0-9a-fA-F]+\\s*$")).match(line).hasMatch())
            {
                const QString trimmed = line.trimmed();
                capture.stackLines.append(trimmed);
                if(capture.exceptionModule.isEmpty() && bang > 0)
                {
                    const QString prefix = trimmed.left(trimmed.indexOf(QLatin1Char('!'))).trimmed();
                    const int separator = qMax(prefix.lastIndexOf(QLatin1Char(' ')), prefix.lastIndexOf(QLatin1Char(':')));
                    capture.exceptionModule = prefix.mid(separator + 1);
                }
            }
        }
    }

    if(capture.exceptionObserved && !capture.stackLines.isEmpty())
    {
        capture.diagnostic = QStringLiteral("已从 CDB 输出解析异常调用栈。");
    }
    else if(capture.exceptionObserved)
    {
        capture.diagnostic = QStringLiteral("CDB 观察到异常，但没有解析到调用栈；请查看 cdb.log。");
    }
    else
    {
        capture.diagnostic = capture.exitPathObserved
                ? QStringLiteral("已捕获程序退出路径。正常关闭也会经过这里；请结合操作时间判断是否意外。")
                : capture.targetExitCodeKnown
                  ? QStringLiteral("已记录程序退出，但没有捕获到异常或主动退出调用栈；不能据此确定退出原因。")
                  : QStringLiteral("未捕获到明确的退出原因，目标退出码未知。请查看原始日志。 ");
    }
    return capture;
}

CdbStackCollector::CdbStackCollector(QObject* parent) : QObject(parent)
{
    process_.setProcessChannelMode(QProcess::MergedChannels);
    childPollTimer_.setInterval(100);
    connect(&childPollTimer_, &QTimer::timeout, this, &CdbStackCollector::PollTargetProcess);
    connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, &CdbStackCollector::OnFinished);
    connect(&process_, &QProcess::readyRead, this, &CdbStackCollector::AppendAvailableOutput);
    connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        if(process_.state() == QProcess::NotRunning && rawLog_.isEmpty())
        {
            emit errorOccurred(QStringLiteral("CDB 启动失败：%1").arg(process_.errorString()));
        }
    });
}

bool CdbStackCollector::Start(const QString& cdbPath, const QString& targetPath, const QStringList& targetArguments,
                              const QString& logPath, QString* error, bool captureExit, const QString& symbolPath)
{
    if(process_.state() != QProcess::NotRunning)
    {
        if(error) *error = QStringLiteral("CDB 正在运行。");
        return false;
    }
    if(!QFileInfo(cdbPath).isFile())
    {
        if(error) *error = QStringLiteral("未找到 CDB：%1").arg(cdbPath);
        return false;
    }
    if(!QFileInfo(targetPath).isFile())
    {
        if(error) *error = QStringLiteral("未找到目标程序：%1").arg(targetPath);
        return false;
    }
    if(!QDir().mkpath(QFileInfo(logPath).absolutePath()))
    {
        if(error) *error = QStringLiteral("无法创建 CDB 日志目录：%1").arg(QFileInfo(logPath).absolutePath());
        return false;
    }

    targetPath_ = targetPath;
    logPath_ = logPath;
    rawLog_.clear();
    // CDB 命令字符串不接受引号或换行注入；分号仅允许在符号路径列表里。
    if(logPath.contains('"') || logPath.contains('\n') || logPath.contains('\r'))
    {
        if(error) *error = QStringLiteral("日志路径不能含引号或换行。");
        return false;
    }
    liveLog_.setFileName(logPath);
    if(!liveLog_.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        if(error) *error = QStringLiteral("无法写入诊断日志：%1").arg(liveLog_.errorString());
        return false;
    }
    logWriteFailed_ = false;
    const QString dumpDirectory = QFileInfo(logPath).absolutePath() + "/dumps";
    if(!QDir().mkpath(dumpDirectory))
    {
        if(error) *error = QStringLiteral("无法创建 dump 目录：%1").arg(dumpDirectory);
        liveLog_.close();
        return false;
    }
    targetProcessId_ = 0;
    process_.setProgram(cdbPath);
    process_.setWorkingDirectory(QFileInfo(targetPath).absolutePath());
    process_.setArguments(BuildCdbArguments(targetPath, targetArguments, dumpDirectory + "/capture.dmp", captureExit, symbolPath));
    liveLog_.write(QString("开始监控：%1\n模式：异常捕获%2\n符号目录：%3;%4\n注意：完整 dump 可能较大并包含敏感内存。\n")
                   .arg(targetPath, captureExit ? QStringLiteral(" + 直接退出取证") : QString(), QFileInfo(targetPath).absolutePath(), symbolPath).toUtf8());
    liveLog_.flush();
    process_.start();
    if(!process_.waitForStarted(3000))
    {
        if(error) *error = QStringLiteral("CDB 启动失败：%1").arg(process_.errorString());
        liveLog_.write(process_.errorString().toUtf8());
        liveLog_.close();
        return false;
    }
    childPollTimer_.start();
    return true;
}

void CdbStackCollector::Stop()
{
    childPollTimer_.stop();
    if(process_.state() != QProcess::NotRunning)
    {
        process_.terminate();
    }
}

bool CdbStackCollector::isRunning() const
{
    return process_.state() != QProcess::NotRunning;
}

void CdbStackCollector::PollTargetProcess()
{
    if(targetProcessId_ != 0)
    {
        childPollTimer_.stop();
        return;
    }
    targetProcessId_ = FindDirectChildProcessId(static_cast<quint32>(process_.processId()), targetPath_);
    if(targetProcessId_ != 0)
    {
        childPollTimer_.stop();
        emit targetStarted(targetProcessId_);
    }
}

void CdbStackCollector::OnFinished(int exitCode, QProcess::ExitStatus)
{
    childPollTimer_.stop();
    QTimer::singleShot(500, this, [this, exitCode] {
        AppendAvailableOutput();
        StackCapture capture = ParseCdbLog(rawLog_, logPath_);
        capture.requested = true;
        capture.debuggerStarted = true;
        capture.debuggerExitCode = exitCode;
        liveLog_.close();
        if(logWriteFailed_) capture.diagnostic += QStringLiteral(" 原始日志写入失败，证据可能不完整。");
        emit finished(exitCode, capture);
    });
}

quint32 CdbStackCollector::FindDirectChildProcessId(quint32 parentProcessId, const QString& targetPath)
{
#ifdef Q_OS_WIN
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    const QString targetName = QFileInfo(targetPath).fileName();
    if(Process32FirstW(snapshot, &entry))
    {
        do
        {
            if(entry.th32ParentProcessID == parentProcessId
               && QString::fromWCharArray(entry.szExeFile).compare(targetName, Qt::CaseInsensitive) == 0)
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while(Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
#else
    Q_UNUSED(parentProcessId)
    Q_UNUSED(targetPath)
#endif
    return 0;
}

void CdbStackCollector::AppendAvailableOutput()
{
    const QString chunk = QString::fromLocal8Bit(process_.readAll());
    rawLog_ += chunk;
    const QByteArray utf8 = chunk.toUtf8();
    if(!utf8.isEmpty() && (liveLog_.write(utf8) != utf8.size() || !liveLog_.flush()))
        logWriteFailed_ = true;
}
