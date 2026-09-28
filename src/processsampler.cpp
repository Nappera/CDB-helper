#include "processsampler.h"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

namespace
{
quint64 FileTimeToUint64(const FILETIME& value)
{
    ULARGE_INTEGER integer{};
    integer.LowPart = value.dwLowDateTime;
    integer.HighPart = value.dwHighDateTime;
    return integer.QuadPart;
}

quint32 CountThreads(quint32 processId)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    quint32 count = 0;
    if(Thread32First(snapshot, &entry))
    {
        do
        {
            if(entry.th32OwnerProcessID == processId)
            {
                ++count;
            }
        } while(Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return count;
}
}

ProcessSampler::ProcessSampler(QObject* parent) : QObject(parent)
{
    timer_.setParent(this);
}

void ProcessSampler::Start(quint32 processId, int intervalMilliseconds)
{
    processId_ = processId;
    previousCpuTime100ns_ = 0;
    previousWallMilliseconds_ = 0;
    timer_.setInterval(qMax(250, intervalMilliseconds));
    connect(&timer_, &QTimer::timeout, this, &ProcessSampler::CaptureOnce, Qt::UniqueConnection);
    timer_.start();
    CaptureOnce();
}

void ProcessSampler::Stop()
{
    timer_.stop();
    processId_ = 0;
}

void ProcessSampler::CaptureOnce()
{
    if(processId_ == 0)
    {
        return;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, processId_);
    if(!process)
    {
        emit targetUnavailable(QStringLiteral("无法打开目标进程，进程可能已经退出或权限不足。"));
        Stop();
        return;
    }

    PROCESS_MEMORY_COUNTERS_EX counters{};
    if(!GetProcessMemoryInfo(process, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters)))
    {
        CloseHandle(process);
        emit targetUnavailable(QStringLiteral("无法读取目标进程内存信息。"));
        Stop();
        return;
    }

    DWORD handles = 0;
    GetProcessHandleCount(process, &handles);

    FILETIME created{};
    FILETIME exited{};
    FILETIME kernel{};
    FILETIME user{};
    GetProcessTimes(process, &created, &exited, &kernel, &user);
    CloseHandle(process);

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const quint64 cpuTime100ns = FileTimeToUint64(kernel) + FileTimeToUint64(user);
    double cpuPercent = 0.0;
    if(previousWallMilliseconds_ > 0 && now > previousWallMilliseconds_)
    {
        const double elapsed100ns = static_cast<double>(now - previousWallMilliseconds_) * 10000.0;
        cpuPercent = (static_cast<double>(cpuTime100ns - previousCpuTime100ns_) / elapsed100ns) * 100.0;
    }
    previousCpuTime100ns_ = cpuTime100ns;
    previousWallMilliseconds_ = now;

    ProcessSample sample;
    sample.capturedAt = QDateTime::currentDateTime();
    sample.privateBytes = static_cast<qint64>(counters.PrivateUsage);
    sample.workingSetBytes = static_cast<qint64>(counters.WorkingSetSize);
    sample.handleCount = handles;
    sample.threadCount = CountThreads(processId_);
    sample.cpuPercent = qMax(0.0, cpuPercent);
    emit sampleReady(sample);
}
