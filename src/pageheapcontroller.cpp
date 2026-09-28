#include "pageheapcontroller.h"

#include <windows.h>
#include <shellapi.h>

#include <QFileInfo>
#include <QStandardPaths>
#include <QCoreApplication>
#include <QDir>

namespace
{
QString Quote(const QString& value)
{
    return QStringLiteral("\"") + value + QStringLiteral("\"");
}
}

QString PageHeapController::FindGflags(const QString& requestedPath)
{
    if(!requestedPath.isEmpty() && QFileInfo::exists(requestedPath))
    {
        return requestedPath;
    }
    // 明确指定的路径优先，其次取发布目录自带的工具。
    const QString bundled = QDir(QCoreApplication::applicationDirPath())
            .filePath(QStringLiteral("thirdparty/debuggers-x64/gflags.exe"));
    if(QFileInfo(bundled).isFile()) return QDir::toNativeSeparators(bundled);
    return QStandardPaths::findExecutable(QStringLiteral("gflags.exe"));
}

QString PageHeapController::BuildCommand(const QString& executablePath, bool enable)
{
    const QString imageName = QFileInfo(executablePath).fileName();
    return enable ? QStringLiteral("gflags.exe /p /enable %1 /full").arg(Quote(imageName))
                  : QStringLiteral("gflags.exe /p /disable %1").arg(Quote(imageName));
}

bool PageHeapController::RunElevated(const QString& gflagsPath, const QString& executablePath, bool enable, QString* error)
{
    if(!QFileInfo::exists(gflagsPath))
    {
        if(error) *error = QStringLiteral("未找到 gflags.exe。请安装 Windows Debugging Tools 或指定路径。");
        return false;
    }
    const QString parameters = enable
                                   ? QStringLiteral("/p /enable %1 /full").arg(Quote(QFileInfo(executablePath).fileName()))
                                   : QStringLiteral("/p /disable %1").arg(Quote(QFileInfo(executablePath).fileName()));
    SHELLEXECUTEINFOW execute{};
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS;
    execute.lpVerb = L"runas";
    execute.lpFile = reinterpret_cast<LPCWSTR>(gflagsPath.utf16());
    execute.lpParameters = reinterpret_cast<LPCWSTR>(parameters.utf16());
    execute.nShow = SW_HIDE;
    if(!ShellExecuteExW(&execute))
    {
        if(error) *error = QStringLiteral("管理员操作未完成，Windows 错误码：%1").arg(GetLastError());
        return false;
    }
    if(execute.hProcess)
    {
        CloseHandle(execute.hProcess);
    }
    return true;
}
