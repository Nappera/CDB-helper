#pragma once

#include "processsample.h"

#include <QList>

class SessionAnalysis
{
public:
    static QList<DiagnosticFinding> Analyze(const QList<ProcessSample>& samples);
};
