#pragma once

#include "sessioncontroller.h"

#include <QMainWindow>

class QLabel;
class QCheckBox;
class QRadioButton;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class TrendChartWidget;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    // 从程序旁的 help.xml 读取分类指南，以可读帮助窗口显示。
    void ShowHelp();
    void BrowseExecutable();
    void StartMonitoring();
    void AttachProcess();
    void StopMonitoring();
    void OpenSessionDirectory();
    void BrowseProcDump();
    void BrowseCdb();
    void FindCdb();
    void BrowseGflags();
    void ConfigurePageHeap(bool enable);
    void AddMarker();
    void AppendSample(const ProcessSample& sample);
    void ShowSessionSummary(const SessionSummary& summary, const QString& directory);
    void UpdateState(SessionState state);

private:
    void AddTimeline(const QString& message);
    static QString FormatBytes(qint64 bytes);

    SessionController* controller_ = nullptr;
    QLineEdit* executableEdit_ = nullptr;
    QLineEdit* argumentsEdit_ = nullptr;
    QLineEdit* outputEdit_ = nullptr;
    QLineEdit* procDumpEdit_ = nullptr;
    QLineEdit* cdbEdit_ = nullptr;
    QLineEdit* gflagsEdit_ = nullptr;
    QRadioButton* captureDumpCheck_ = nullptr;
    QRadioButton* captureStackCheck_ = nullptr;
    QCheckBox* captureExitCheck_ = nullptr;
    QLineEdit* symbolPathEdit_ = nullptr;
    QSpinBox* intervalSpin_ = nullptr;
    QSpinBox* pidSpin_ = nullptr;
    QPushButton* startButton_ = nullptr;
    QPushButton* attachButton_ = nullptr;
    QPushButton* stopButton_ = nullptr;
    QPushButton* openSessionButton_ = nullptr;
    QLabel* stateLabel_ = nullptr;
    QPlainTextEdit* timeline_ = nullptr;
    QLineEdit* markerEdit_ = nullptr;
    QPushButton* markerButton_ = nullptr;
    QListWidget* findingsList_ = nullptr;
    TrendChartWidget* privateChart_ = nullptr;
    TrendChartWidget* workingSetChart_ = nullptr;
    TrendChartWidget* handlesChart_ = nullptr;
    TrendChartWidget* threadsChart_ = nullptr;
    QString lastSessionDirectory_;
};
