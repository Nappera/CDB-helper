#include "sessionstore.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QTextStream>

#include <utility>

namespace
{
QString CsvEscape(QString value)
{
    value.replace('"', QStringLiteral("\"\""));
    return QStringLiteral("\"") + value + QStringLiteral("\"");
}

QString SeverityText(FindingSeverity severity)
{
    switch(severity)
    {
    case FindingSeverity::Warning: return QStringLiteral("警告");
    case FindingSeverity::Error: return QStringLiteral("错误");
    default: return QStringLiteral("信息");
    }
}
}

SessionStore::SessionStore(QString outputRoot, QString targetName)
    : outputRoot_(std::move(outputRoot)), targetName_(std::move(targetName))
{
}

bool SessionStore::Start()
{
    const QString normalizedName = QFileInfo(targetName_).completeBaseName().isEmpty()
                                       ? QStringLiteral("process")
                                       : QFileInfo(targetName_).completeBaseName();
    const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"));
    QDir root(outputRoot_);
    if(!root.exists() && !QDir().mkpath(outputRoot_))
    {
        return false;
    }

    sessionDirectory_ = root.filePath(normalizedName + QStringLiteral("-") + stamp);
    int duplicateIndex = 1;
    while(QFileInfo::exists(sessionDirectory_))
    {
        sessionDirectory_ = root.filePath(normalizedName + QStringLiteral("-") + stamp + QStringLiteral("-%1").arg(duplicateIndex++));
    }
    return QDir().mkpath(dumpsDirectory());
}

void SessionStore::Append(const ProcessSample& sample)
{
    samples_.append(sample);
}

void SessionStore::AddMarker(const SessionMarker& marker)
{
    markers_.append(marker);
}

bool SessionStore::Finalize(const SessionSummary& summary)
{
    if(sessionDirectory_.isEmpty())
    {
        return false;
    }
    return WriteTextFile(samplesPath(), BuildSamplesCsv())
           && WriteTextFile(markersPath(), BuildMarkersCsv())
           && WriteTextFile(sessionJsonPath(), BuildSessionJson(summary))
           && WriteTextFile(eventsPath(), BuildEventsXml(summary))
           && WriteTextFile(reportPath(), BuildReportHtml(summary));
}

QString SessionStore::sessionDirectory() const { return sessionDirectory_; }
QString SessionStore::samplesPath() const { return QDir(sessionDirectory_).filePath(QStringLiteral("samples.csv")); }
QString SessionStore::sessionJsonPath() const { return QDir(sessionDirectory_).filePath(QStringLiteral("session.json")); }
QString SessionStore::eventsPath() const { return QDir(sessionDirectory_).filePath(QStringLiteral("events.xml")); }
QString SessionStore::markersPath() const { return QDir(sessionDirectory_).filePath(QStringLiteral("markers.csv")); }
QString SessionStore::reportPath() const { return QDir(sessionDirectory_).filePath(QStringLiteral("report.html")); }
QString SessionStore::dumpsDirectory() const { return QDir(sessionDirectory_).filePath(QStringLiteral("dumps")); }
QString SessionStore::cdbLogPath() const { return QDir(sessionDirectory_).filePath(QStringLiteral("cdb.log")); }

bool SessionStore::WriteTextFile(const QString& path, const QString& text) const
{
    QSaveFile file(path);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        return false;
    }
    file.write(text.toUtf8());
    return file.commit();
}

QString SessionStore::BuildSamplesCsv() const
{
    QString text = QStringLiteral("time,private_bytes,working_set_bytes,handles,threads,cpu_percent\n");
    QTextStream stream(&text);
    for(const ProcessSample& sample : samples_)
    {
        stream << CsvEscape(sample.capturedAt.toString(Qt::ISODateWithMs)) << ','
               << sample.privateBytes << ',' << sample.workingSetBytes << ','
               << sample.handleCount << ',' << sample.threadCount << ',' << sample.cpuPercent << '\n';
    }
    return text;
}

QString SessionStore::BuildMarkersCsv() const
{
    QString text = QStringLiteral("time,note\n");
    QTextStream stream(&text);
    for(const SessionMarker& marker : markers_)
    {
        stream << CsvEscape(marker.createdAt.toString(Qt::ISODateWithMs)) << ','
               << CsvEscape(marker.text) << '\n';
    }
    return text;
}

QString SessionStore::BuildSessionJson(const SessionSummary& summary) const
{
    QJsonObject object;
    object.insert(QStringLiteral("targetPath"), summary.targetPath);
    object.insert(QStringLiteral("arguments"), summary.arguments);
    object.insert(QStringLiteral("processId"), static_cast<int>(summary.processId));
    object.insert(QStringLiteral("exitCode"), summary.exitCodeKnown ? QJsonValue(summary.exitCode) : QJsonValue(QJsonValue::Null));
    object.insert(QStringLiteral("exitCodeKnown"), summary.exitCodeKnown);
    object.insert(QStringLiteral("startedAt"), summary.startedAt);
    object.insert(QStringLiteral("endedAt"), summary.endedAt);
    object.insert(QStringLiteral("sampleCount"), samples_.size());
    QJsonArray markers;
    for(const SessionMarker& marker : markers_)
    {
        markers.append(QJsonObject{{QStringLiteral("time"), marker.createdAt.toString(Qt::ISODateWithMs)},
                                   {QStringLiteral("note"), marker.text}});
    }
    object.insert(QStringLiteral("markers"), markers);
    QJsonArray findings;
    for(const DiagnosticFinding& finding : summary.findings)
    {
        findings.append(QJsonObject{{QStringLiteral("severity"), SeverityText(finding.severity)},
                                    {QStringLiteral("title"), finding.title},
                                    {QStringLiteral("detail"), finding.detail}});
    }
    object.insert(QStringLiteral("findings"), findings);
    QJsonArray dumpPaths;
    for(const QString& dumpPath : summary.dumpPaths)
    {
        dumpPaths.append(dumpPath);
    }
    object.insert(QStringLiteral("dumpPaths"), dumpPaths);
    QJsonArray stackLines;
    for(const QString& line : summary.stackCapture.stackLines)
    {
        stackLines.append(line);
    }
    object.insert(QStringLiteral("stackCapture"), QJsonObject{
        {QStringLiteral("requested"), summary.stackCapture.requested},
        {QStringLiteral("debuggerStarted"), summary.stackCapture.debuggerStarted},
        {QStringLiteral("exceptionObserved"), summary.stackCapture.exceptionObserved},
        {QStringLiteral("exceptionCode"), summary.stackCapture.exceptionCode},
        {QStringLiteral("exitPathObserved"), summary.stackCapture.exitPathObserved},
        {QStringLiteral("targetExitCodeKnown"), summary.stackCapture.targetExitCodeKnown},
        {QStringLiteral("debuggerExitCode"), summary.stackCapture.debuggerExitCode},
        {QStringLiteral("symbolStatus"), summary.stackCapture.symbolStatus},
        {QStringLiteral("dumpStatus"), summary.stackCapture.dumpStatus},
        {QStringLiteral("exceptionModule"), summary.stackCapture.exceptionModule},
        {QStringLiteral("stackLines"), stackLines},
        {QStringLiteral("rawLogPath"), summary.stackCapture.rawLogPath},
        {QStringLiteral("diagnostic"), summary.stackCapture.diagnostic}
    });
    return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Indented));
}

QString SessionStore::BuildEventsXml(const SessionSummary& summary) const
{
    QString text = QStringLiteral("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Events>\n");
    for(const QString& eventXml : summary.eventsXml)
    {
        text += eventXml + '\n';
    }
    text += QStringLiteral("</Events>\n");
    return text;
}

QString SessionStore::BuildReportHtml(const SessionSummary& summary) const
{
    QString findings;
    for(const DiagnosticFinding& finding : summary.findings)
    {
        findings += QStringLiteral("<li><strong>%1：%2</strong><br>%3</li>")
                        .arg(SeverityText(finding.severity).toHtmlEscaped(),
                             finding.title.toHtmlEscaped(),
                             finding.detail.toHtmlEscaped());
    }
    if(findings.isEmpty())
    {
        findings = QStringLiteral("<li>未发现满足持续增长规则的指标；这不代表程序绝对没有问题。</li>");
    }

    QString stackSection;
    if(summary.stackCapture.requested)
    {
        stackSection = QStringLiteral("<h2>这次留下了什么</h2><p>%1</p><p>%2</p><p>%3</p><p>调试器退出码：%4（不是目标程序退出码）。完整 dump 可能包含敏感数据，请仅分享给可信的开发人员。</p>")
                .arg(summary.stackCapture.diagnostic.toHtmlEscaped(), summary.stackCapture.dumpStatus.toHtmlEscaped(),
                     summary.stackCapture.symbolStatus.toHtmlEscaped()).arg(summary.stackCapture.debuggerExitCode);
        QString stackLines;
        for(const QString& line : summary.stackCapture.stackLines.mid(0, 20))
        {
            stackLines += line.toHtmlEscaped() + QStringLiteral("\n");
        }
        if(stackLines.isEmpty())
        {
            stackLines = QStringLiteral("未解析到调用栈；请查看 cdb.log。");
        }
        stackSection += QStringLiteral("<details><summary>查看技术详情：调用栈、异常码和日志路径</summary><table><tr><th>状态</th><td>%1</td></tr><tr><th>异常码</th><td>%2</td></tr><tr><th>栈中模块（不代表根因）</th><td>%3</td></tr><tr><th>CDB 日志</th><td class=\"path\">%4</td></tr></table><pre>%5</pre></details>")
                           .arg(summary.stackCapture.diagnostic.toHtmlEscaped(),
                                summary.stackCapture.exceptionCode.toHtmlEscaped(),
                                summary.stackCapture.exceptionModule.toHtmlEscaped(),
                                summary.stackCapture.rawLogPath.toHtmlEscaped(),
                                stackLines);
    }

    QString markerRows;
    for(const SessionMarker& marker : markers_)
    {
        markerRows += QStringLiteral("<tr><td>%1</td><td>%2</td></tr>")
                          .arg(marker.createdAt.toString(Qt::ISODateWithMs).toHtmlEscaped(), marker.text.toHtmlEscaped());
    }
    const QString markerSection = markerRows.isEmpty()
                                      ? QStringLiteral("<p>本次会话没有人工操作标记。</p>")
                                      : QStringLiteral("<table><tr><th>时间</th><th>操作标记</th></tr>%1</table>").arg(markerRows);

    return QStringLiteral(R"(<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>诊断会话报告</title><style>body{font-family:"Microsoft YaHei",sans-serif;max-width:980px;margin:32px auto;color:#20242a;line-height:1.65}h1{color:#146c94}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d8dee4;padding:8px;text-align:left}th{background:#edf7fb}.path,pre{font-family:Consolas,monospace;background:#f5f7f8;padding:8px;white-space:pre-wrap;word-break:break-all}</style></head><body><h1>诊断会话报告</h1><table><tr><th>目标</th><td>%1</td></tr><tr><th>PID</th><td>%2</td></tr><tr><th>退出码</th><td>%3</td></tr><tr><th>采样数</th><td>%4</td></tr></table><h2>诊断结论</h2><ul>%5</ul><h2>操作时间线</h2>%6%7<h2>证据</h2><ul><li class="path">samples.csv</li><li class="path">markers.csv</li><li class="path">session.json</li><li class="path">events.xml</li><li class="path">cdb.log（启用 CDB 时）</li><li class="path">dumps/</li></ul><h2>WinDbg</h2><p>若 dumps 目录中存在 .dmp，打开后执行：<code>.symfix; .reload; !analyze -v; kb</code></p></body></html>)")
        .arg(summary.targetPath.toHtmlEscaped())
        .arg(summary.processId)
        .arg(summary.exitCodeKnown ? QString("0x%1 (%2)").arg(static_cast<quint32>(summary.exitCode), 8, 16, QChar('0')).arg(summary.exitCode) : QStringLiteral("未知（未取得可靠的目标退出码）"))
        .arg(samples_.size())
        .arg(findings, markerSection, stackSection);
}
