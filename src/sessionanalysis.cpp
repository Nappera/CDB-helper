#include "sessionanalysis.h"

namespace
{
constexpr int kMinimumSamples = 8;
constexpr qint64 kMiB = 1024LL * 1024LL;

template<typename ValueGetter>
bool IsStrictlyIncreasing(const QList<ProcessSample>& samples, ValueGetter getValue)
{
    for(int index = 1; index < samples.size(); ++index)
    {
        if(getValue(samples[index]) <= getValue(samples[index - 1]))
        {
            return false;
        }
    }
    return true;
}

template<typename ValueGetter>
void AppendGrowthFinding(const QList<ProcessSample>& samples,
                         ValueGetter getValue,
                         qint64 minimumIncrease,
                         const QString& title,
                         const QString& unit,
                         QList<DiagnosticFinding>* findings)
{
    if(samples.size() < kMinimumSamples)
    {
        return;
    }

    const QList<ProcessSample> recentSamples = samples.mid(samples.size() - kMinimumSamples);
    if(!IsStrictlyIncreasing(recentSamples, getValue))
    {
        return;
    }

    const qint64 increase = getValue(recentSamples.back()) - getValue(recentSamples.front());
    if(increase < minimumIncrease)
    {
        return;
    }

    DiagnosticFinding finding;
    finding.severity = FindingSeverity::Warning;
    finding.title = title;
    finding.detail = QStringLiteral("连续 %1 个采样点单调上升，累计增加 %2 %3；这是疑似持续增长，需要结合资源生命周期继续定位。")
                         .arg(recentSamples.size())
                         .arg(unit == QStringLiteral("MiB") ? QString::number(increase / kMiB) : QString::number(increase))
                         .arg(unit);
    findings->append(finding);
}
}

QList<DiagnosticFinding> SessionAnalysis::Analyze(const QList<ProcessSample>& samples)
{
    QList<DiagnosticFinding> findings;
    AppendGrowthFinding(samples,
                         [](const ProcessSample& sample) { return sample.privateBytes; },
                         64 * kMiB,
                         QStringLiteral("私有内存疑似持续增长"),
                         QStringLiteral("MiB"),
                         &findings);
    AppendGrowthFinding(samples,
                         [](const ProcessSample& sample) { return static_cast<qint64>(sample.handleCount); },
                         100,
                         QStringLiteral("句柄数疑似持续增长"),
                         QStringLiteral("个"),
                         &findings);
    AppendGrowthFinding(samples,
                         [](const ProcessSample& sample) { return static_cast<qint64>(sample.threadCount); },
                         100,
                         QStringLiteral("线程数疑似持续增长"),
                         QStringLiteral("个"),
                         &findings);
    return findings;
}
