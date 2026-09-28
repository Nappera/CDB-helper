#include "windowseventreader.h"

#include <windows.h>
#include <winevt.h>

#include <QRegularExpression>
#include <QVector>

namespace
{
QString RenderEventXml(EVT_HANDLE event)
{
    DWORD used = 0;
    DWORD propertyCount = 0;
    EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &propertyCount);
    if(GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0)
    {
        return {};
    }
    QVector<wchar_t> buffer(static_cast<int>(used / sizeof(wchar_t)) + 1);
    if(!EvtRender(nullptr, event, EvtRenderEventXml, used, buffer.data(), &used, &propertyCount))
    {
        return {};
    }
    return QString::fromWCharArray(buffer.constData());
}
}

QStringList WindowsEventReader::ReadApplicationFailures(const QDateTime& startedAt)
{
    const QString query = QStringLiteral("*[System[Provider[@Name='Application Error'] or Provider[@Name='Windows Error Reporting']]]");
    EVT_HANDLE handle = EvtQuery(nullptr, L"Application", reinterpret_cast<LPCWSTR>(query.utf16()),
                                 EvtQueryChannelPath | EvtQueryReverseDirection);
    if(!handle)
    {
        return {};
    }

    QStringList events;
    EVT_HANDLE batch[16]{};
    DWORD returned = 0;
    while(EvtNext(handle, 16, batch, 0, 0, &returned))
    {
        for(DWORD index = 0; index < returned; ++index)
        {
            const QString xml = RenderEventXml(batch[index]);
            EvtClose(batch[index]);
            const QRegularExpression timePattern(QStringLiteral("SystemTime=['\\\"]([^'\\\"]+)['\\\"]"));
            const QRegularExpressionMatch timeMatch = timePattern.match(xml);
            if(timeMatch.hasMatch())
            {
                const QDateTime eventTime = QDateTime::fromString(timeMatch.captured(1), Qt::ISODateWithMs);
                if(eventTime.isValid() && eventTime < startedAt)
                {
                    EvtClose(handle);
                    return events;
                }
            }
            if(!xml.isEmpty())
            {
                events.append(xml);
            }
        }
    }
    EvtClose(handle);
    return events;
}
