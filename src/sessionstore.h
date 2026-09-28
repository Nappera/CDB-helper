#pragma once

#include "cdbstackcollector.h"
#include "processsample.h"

#include <QList>
#include <QString>

struct SessionMarker
{
    QDateTime createdAt;
    QString text;
};

struct SessionSummary
{
    QString targetPath;
    QString arguments;
    quint32 processId = 0;
    int exitCode = 0;
    bool exitCodeKnown = false;
    QString startedAt;
    QString endedAt;
    QList<DiagnosticFinding> findings;
    QStringList eventsXml;
    QStringList dumpPaths;
    StackCapture stackCapture;
};

class SessionStore
{
public:
    SessionStore(QString outputRoot, QString targetName);

    bool Start();
    void Append(const ProcessSample& sample);
    void AddMarker(const SessionMarker& marker);
    bool Finalize(const SessionSummary& summary);

    QString sessionDirectory() const;
    QString samplesPath() const;
    QString sessionJsonPath() const;
    QString eventsPath() const;
    QString markersPath() const;
    QString reportPath() const;
    QString dumpsDirectory() const;
    QString cdbLogPath() const;

private:
    bool WriteTextFile(const QString& path, const QString& text) const;
    QString BuildSamplesCsv() const;
    QString BuildMarkersCsv() const;
    QString BuildSessionJson(const SessionSummary& summary) const;
    QString BuildEventsXml(const SessionSummary& summary) const;
    QString BuildReportHtml(const SessionSummary& summary) const;

    QString outputRoot_;
    QString targetName_;
    QString sessionDirectory_;
    QList<ProcessSample> samples_;
    QList<SessionMarker> markers_;
};
