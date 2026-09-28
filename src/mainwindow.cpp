#include "mainwindow.h"

#include "trendchartwidget.h"
#include "pageheapcontroller.h"
#include "cdbstackcollector.h"

#include <QCoreApplication>
#include <QCheckBox>
#include <QRadioButton>
#include <QButtonGroup>
#include <QToolButton>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QSplitter>
#include <QUrl>
#include <QVBoxLayout>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QDialog>
#include <QTextBrowser>
#include <QFile>
#include <QXmlStreamReader>

#include <climits>

namespace
{
QString StateText(SessionState state)
{
    switch(state)
    {
    case SessionState::Launching: return QStringLiteral("正在启动");
    case SessionState::Watching: return QStringLiteral("监视中");
    case SessionState::Stopping: return QStringLiteral("正在停止");
    case SessionState::Finished: return QStringLiteral("会话完成");
    case SessionState::Failed: return QStringLiteral("会话失败");
    default: return QStringLiteral("空闲");
    }
}
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("Release 调试助手"));
    resize(1440, 860);
    setMinimumSize(1080, 760);
    setStyleSheet(QStringLiteral(
        "QMainWindow, QDialog { background:#edf2f7; }"
        "QWidget { color:#21364b; font-family:'Microsoft YaHei UI'; font-size:12px; }"
        "QGroupBox { background:white; border:1px solid #d7e2ed; border-radius:8px; margin-top:14px; padding:14px 10px 8px; font-weight:600; }"
        "QGroupBox::title { subcontrol-origin:margin; left:14px; padding:0 6px; color:#136b9a; }"
        "QLineEdit, QSpinBox { background:#f7f9fc; border:1px solid #d7e2ed; border-radius:4px; padding:5px 8px; min-height:20px; selection-background-color:#147dba; }"
        "QLineEdit:focus, QSpinBox:focus { border:1px solid #147dba; background:white; }"
        "QPushButton { background:white; border:1px solid #c8d7e5; border-radius:4px; padding:6px 12px; min-height:20px; }"
        "QPushButton:hover { background:#eaf5fc; border-color:#147dba; }"
        "QPushButton:pressed { background:#d9edf9; }"
        "QPushButton#primary { background:#147dba; color:white; border-color:#147dba; font-weight:600; }"
        "QPushButton#primary:hover { background:#09689f; }"
        "QPushButton:disabled, QLineEdit:disabled { color:#91a0af; background:#f0f3f6; border-color:#e0e7ee; }"
        "QCheckBox { spacing:7px; padding:4px 0; }"
        "QPlainTextEdit, QListWidget, QTextBrowser { background:white; border:1px solid #d7e2ed; border-radius:5px; padding:8px; }"
        "QListWidget::item { padding:7px; }"
        "QListWidget::item:selected { background:#e2f1fa; color:#174b6c; }"
        "QMenuBar { background:white; padding:3px 8px; border-bottom:1px solid #d7e2ed; }"
        "QMenuBar::item:selected, QMenu::item:selected { background:#e2f1fa; }"
        "QMenu { background:white; border:1px solid #c8d7e5; } QMenu::item { padding:7px 24px; }"
        "QToolTip { color:#21364b; background:#f0f8ff; border:1px solid #a7c8df; padding:6px; }"
        "QSplitter::handle { background:#edf2f7; }"
        "QLabel#state { color:#136b9a; font-weight:600; padding:4px 8px; }"));
    auto* helpAction = menuBar()->addMenu(QStringLiteral("帮助"))->addAction(QStringLiteral("使用指南"));
    helpAction->setShortcut(QKeySequence::HelpContents);
    helpAction->setToolTip(QStringLiteral("按问题选择诊断方式，并学习如何阅读报告和调用栈。快捷键 F1。"));
    connect(helpAction, &QAction::triggered, this, &MainWindow::ShowHelp);
    controller_ = new SessionController(this);

    auto* root = new QWidget(this);
    auto* rootLayout = new QVBoxLayout(root);
    rootLayout->setContentsMargins(16, 8, 16, 14);
    rootLayout->setSpacing(10);
    auto* targetBox = new QGroupBox(QStringLiteral("目标程序"), root);
    auto* targetLayout = new QGridLayout(targetBox);
    targetLayout->setColumnStretch(1, 3);
    targetLayout->setColumnStretch(2, 1);
    targetLayout->setColumnStretch(4, 1);
    executableEdit_ = new QLineEdit(targetBox);
    argumentsEdit_ = new QLineEdit(targetBox);
    outputEdit_ = new QLineEdit(targetBox);
    intervalSpin_ = new QSpinBox(targetBox);
    intervalSpin_->setRange(250, 60000);
    intervalSpin_->setValue(1000);
    intervalSpin_->setSuffix(QStringLiteral(" ms"));
    const QString defaultOutput = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("sessions"));
    outputEdit_->setText(defaultOutput);
    auto* browse = new QPushButton(QStringLiteral("选择 EXE"), targetBox);
    startButton_ = new QPushButton(QStringLiteral("启动并监视"), targetBox);
    startButton_->setObjectName(QStringLiteral("primary"));
    stopButton_ = new QPushButton(QStringLiteral("停止监视"), targetBox);
    stopButton_->setEnabled(false);
    pidSpin_ = new QSpinBox(targetBox);
    pidSpin_->setRange(0, INT_MAX);
    attachButton_ = new QPushButton(QStringLiteral("附加 PID"), targetBox);
    stateLabel_ = new QLabel(QStringLiteral("● 空闲"), targetBox);
    stateLabel_->setObjectName(QStringLiteral("state"));
    targetLayout->addWidget(new QLabel(QStringLiteral("EXE："), targetBox), 0, 0);
    targetLayout->addWidget(executableEdit_, 0, 1, 1, 4);
    targetLayout->addWidget(browse, 0, 5);
    targetLayout->addWidget(new QLabel(QStringLiteral("参数："), targetBox), 1, 0);
    targetLayout->addWidget(argumentsEdit_, 1, 1, 1, 2);
    targetLayout->addWidget(new QLabel(QStringLiteral("采样："), targetBox), 1, 3);
    targetLayout->addWidget(intervalSpin_, 1, 4);
    targetLayout->addWidget(startButton_, 1, 5);
    targetLayout->addWidget(new QLabel(QStringLiteral("输出："), targetBox), 2, 0);
    targetLayout->addWidget(outputEdit_, 2, 1, 1, 3);
    targetLayout->addWidget(stopButton_, 2, 4);
    targetLayout->addWidget(stateLabel_, 2, 5);
    targetLayout->addWidget(new QLabel(QStringLiteral("附加 PID："), targetBox), 3, 0);
    targetLayout->addWidget(pidSpin_, 3, 1);
    targetLayout->addWidget(attachButton_, 3, 2);
    rootLayout->addWidget(targetBox);

    auto* advancedBox = new QGroupBox(QStringLiteral("诊断方式"), root);
    auto* advancedLayout = new QVBoxLayout(advancedBox);
    advancedLayout->setSpacing(8);
    auto* modes = new QHBoxLayout;
    auto* monitorMode = new QRadioButton(QStringLiteral("仅资源监视"), advancedBox);
    captureStackCheck_ = new QRadioButton(QStringLiteral("抓闪退（CDB）"), advancedBox);
    captureDumpCheck_ = new QRadioButton(QStringLiteral("抓 dump（ProcDump）"), advancedBox);
    monitorMode->setObjectName("monitorMode");
    captureStackCheck_->setObjectName("cdbMode");
    captureDumpCheck_->setObjectName("dumpMode");
    auto* modeGroup = new QButtonGroup(this);
    for(auto* mode : {monitorMode, captureStackCheck_, captureDumpCheck_})
    {
        modeGroup->addButton(mode);
        modes->addWidget(mode);
    }
    modes->addStretch();
    monitorMode->setChecked(true);
    monitorMode->setToolTip(QStringLiteral("只记录内存、句柄、线程和操作时间，不抓异常栈或 dump；不需要安装调试工具。"));
    advancedLayout->addLayout(modes);
    auto* modeHint = new QLabel(QStringLiteral("观察资源增长；无需额外工具。抓闪退请先切换到 CDB，再启动。"), advancedBox);
    modeHint->setWordWrap(true);
    advancedLayout->addWidget(modeHint);

    auto* cdbPanel = new QWidget(advancedBox);
    cdbPanel->setObjectName("cdbSettings");
    auto* cdbLayout = new QGridLayout(cdbPanel);
    cdbLayout->setContentsMargins(0, 0, 0, 0);
    cdbLayout->setColumnStretch(1, 1);
    captureExitCheck_ = new QCheckBox(QStringLiteral("追踪直接退出：程序突然消失、没有 dump 时开启"), cdbPanel);
    captureExitCheck_->setToolTip(QStringLiteral("CDB 模式下额外捕获退出路径。正常关闭也会保存一次退出现场，不等于崩溃；外部强杀不保证有调用栈。"));
    symbolPathEdit_ = new QLineEdit(cdbPanel);
    symbolPathEdit_->setPlaceholderText(QStringLiteral("默认搜索 EXE 目录；可追加 PDB 目录，多个用分号隔开"));
    cdbEdit_ = new QLineEdit(cdbPanel);
    cdbEdit_->setText(FindDefaultCdbPath());
    auto* browseCdb = new QPushButton(QStringLiteral("选择 CDB"), cdbPanel);
    auto* findCdb = new QPushButton(QStringLiteral("自动查找 CDB"), cdbPanel);
    cdbLayout->addWidget(new QLabel(QStringLiteral("CDB 路径"), cdbPanel), 0, 0);
    cdbLayout->addWidget(cdbEdit_, 0, 1);
    cdbLayout->addWidget(browseCdb, 0, 2);
    cdbLayout->addWidget(findCdb, 0, 3);
    cdbLayout->addWidget(new QLabel(QStringLiteral("PDB 目录（可选）"), cdbPanel), 1, 0);
    cdbLayout->addWidget(symbolPathEdit_, 1, 1, 1, 3);
    cdbLayout->addWidget(captureExitCheck_, 2, 1, 1, 3);
    advancedLayout->addWidget(cdbPanel);

    auto* dumpPanel = new QWidget(advancedBox);
    dumpPanel->setObjectName("dumpSettings");
    auto* dumpLayout = new QHBoxLayout(dumpPanel);
    dumpLayout->setContentsMargins(0, 0, 0, 0);
    procDumpEdit_ = new QLineEdit(dumpPanel);
    const QString bundledProcDump = QDir(QCoreApplication::applicationDirPath())
            .filePath(QStringLiteral("thirdparty/procdump-x64/procdump64.exe"));
    if(QFileInfo(bundledProcDump).isFile()) procDumpEdit_->setText(QDir::toNativeSeparators(bundledProcDump));
    auto* browseProcDump = new QPushButton(QStringLiteral("选择 ProcDump"), dumpPanel);
    dumpLayout->addWidget(new QLabel(QStringLiteral("ProcDump 路径"), dumpPanel));
    dumpLayout->addWidget(procDumpEdit_, 1);
    dumpLayout->addWidget(browseProcDump);
    advancedLayout->addWidget(dumpPanel);
    cdbPanel->hide();
    dumpPanel->hide();
    connect(captureStackCheck_, &QRadioButton::toggled, cdbPanel, &QWidget::setVisible);
    connect(captureDumpCheck_, &QRadioButton::toggled, dumpPanel, &QWidget::setVisible);
    connect(captureStackCheck_, &QRadioButton::toggled, this, [this, modeHint](bool enabled) {
        if(!enabled) captureExitCheck_->setChecked(false);
        else modeHint->setText(QStringLiteral("从助手启动程序，捕获异常调用栈并尝试保存完整 dump。取证会暂停程序，dump 可能较大且含敏感内存。"));
    });
    connect(captureDumpCheck_, &QRadioButton::toggled, this, [modeHint](bool enabled) {
        if(enabled) modeHint->setText(QStringLiteral("用 ProcDump 保存崩溃现场，支持启动或附加已有 PID。不保证捕获主动退出，附加结果看 procdump.log。"));
    });
    connect(monitorMode, &QRadioButton::toggled, this, [modeHint](bool enabled) {
        if(enabled) modeHint->setText(QStringLiteral("观察资源增长；无需额外工具。抓闪退请先切换到 CDB，再启动。"));
    });

    auto* heapToggle = new QToolButton(advancedBox);
    heapToggle->setObjectName("heapToggle");
    heapToggle->setText(QStringLiteral("内存越界诊断（高级）"));
    heapToggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    heapToggle->setArrowType(Qt::RightArrow);
    heapToggle->setCheckable(true);
    heapToggle->setToolTip(QStringLiteral("展开 PageHeap 设置。只在怀疑堆越界时使用，普通抓闪退不需要；折叠不会撤销已启用的配置。"));
    advancedLayout->addWidget(heapToggle, 0, Qt::AlignLeft);
    auto* heapPanel = new QWidget(advancedBox);
    heapPanel->setObjectName("heapSettings");
    auto* heapLayout = new QGridLayout(heapPanel);
    heapLayout->setContentsMargins(0, 0, 0, 0);
    heapLayout->setColumnStretch(1, 1);
    gflagsEdit_ = new QLineEdit(heapPanel);
    gflagsEdit_->setText(PageHeapController::FindGflags({}));
    auto* browseGflags = new QPushButton(QStringLiteral("选择 gflags"), heapPanel);
    auto* enablePageHeap = new QPushButton(QStringLiteral("启用 PageHeap"), heapPanel);
    auto* disablePageHeap = new QPushButton(QStringLiteral("关闭 PageHeap"), heapPanel);
    heapLayout->addWidget(new QLabel(QStringLiteral("gflags 路径"), heapPanel), 0, 0);
    heapLayout->addWidget(gflagsEdit_, 0, 1);
    heapLayout->addWidget(browseGflags, 0, 2);
    auto* heapButtons = new QHBoxLayout;
    heapButtons->addWidget(enablePageHeap);
    heapButtons->addWidget(disablePageHeap);
    heapButtons->addStretch();
    heapLayout->addLayout(heapButtons, 1, 1, 1, 2);
    auto* heapHint = new QLabel(QStringLiteral("需要管理员权限和重启目标；会增加内存与耗时。用完请关闭，收起面板不会关闭 PageHeap。"), heapPanel);
    heapHint->setWordWrap(true);
    heapLayout->addWidget(heapHint, 2, 0, 1, 3);
    advancedLayout->addWidget(heapPanel);
    heapPanel->hide();
    connect(heapToggle, &QToolButton::toggled, this, [heapPanel, heapToggle](bool expanded) {
        heapPanel->setVisible(expanded);
        heapToggle->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
    });
    rootLayout->addWidget(advancedBox);

    auto* splitter = new QSplitter(Qt::Horizontal, root);
    auto* charts = new QWidget(splitter);
    auto* chartsLayout = new QGridLayout(charts);
    privateChart_ = new TrendChartWidget(QStringLiteral("私有内存"), QStringLiteral("MiB"), QColor(QStringLiteral("#0d8a9b")), charts);
    workingSetChart_ = new TrendChartWidget(QStringLiteral("工作集"), QStringLiteral("MiB"), QColor(QStringLiteral("#5a67d8")), charts);
    handlesChart_ = new TrendChartWidget(QStringLiteral("句柄数"), QStringLiteral("个"), QColor(QStringLiteral("#c05621")), charts);
    threadsChart_ = new TrendChartWidget(QStringLiteral("线程数"), QStringLiteral("个"), QColor(QStringLiteral("#2f855a")), charts);
    chartsLayout->addWidget(privateChart_, 0, 0);
    chartsLayout->addWidget(workingSetChart_, 0, 1);
    chartsLayout->addWidget(handlesChart_, 1, 0);
    chartsLayout->addWidget(threadsChart_, 1, 1);
    splitter->addWidget(charts);

    auto* details = new QWidget(splitter);
    auto* detailsLayout = new QVBoxLayout(details);
    detailsLayout->addWidget(new QLabel(QStringLiteral("事件时间线"), details));
    auto* markerLayout = new QHBoxLayout;
    markerEdit_ = new QLineEdit(details);
    markerEdit_->setPlaceholderText(QStringLiteral("例如：打开特征助手、滚轮放大第 20 次"));
    markerButton_ = new QPushButton(QStringLiteral("标记步骤"), details);
    markerLayout->addWidget(markerEdit_, 1);
    markerLayout->addWidget(markerButton_);
    detailsLayout->addLayout(markerLayout);
    timeline_ = new QPlainTextEdit(details);
    timeline_->setReadOnly(true);
    detailsLayout->addWidget(timeline_, 2);
    detailsLayout->addWidget(new QLabel(QStringLiteral("诊断结论"), details));
    findingsList_ = new QListWidget(details);
    detailsLayout->addWidget(findingsList_, 2);
    openSessionButton_ = new QPushButton(QStringLiteral("打开最近会话目录"), details);
    openSessionButton_->setEnabled(false);
    detailsLayout->addWidget(openSessionButton_);
    splitter->addWidget(details);
    splitter->setSizes({900, 440});
    rootLayout->addWidget(splitter, 1);
    setCentralWidget(root);

    browse->setToolTip(QStringLiteral("选择发生问题的 EXE，不是快捷方式。使用与问题现场相同的版本。"));
    executableEdit_->setToolTip(browse->toolTip());
    argumentsEdit_->setToolTip(QStringLiteral("目标程序需要的启动参数；不需要就留空。含空格的单个参数用双引号包住。"));
    outputEdit_->setToolTip(QStringLiteral("报告、采样和 dump 的保存根目录，每次自动新建会话文件夹。完整 dump 需要较多磁盘空间。"));
    intervalSpin_->setToolTip(QStringLiteral("资源采样间隔，单位毫秒。建议 1000；越小记录越密、开销越大，不改变异常捕获时机。"));
    // QSpinBox 内部编辑框也保留相同提示。
    intervalSpin_->findChild<QLineEdit*>()->setToolTip(intervalSpin_->toolTip());
    startButton_->setToolTip(QStringLiteral("按当前配置启动 EXE 并监视。先关闭同一单实例程序；取证选项须在启动前勾选。"));
    stopButton_->setToolTip(QStringLiteral("结束本次监视并保存报告；不是关闭目标程序。正在写 dump 时不要点，以免现场不完整。"));
    pidSpin_->setToolTip(QStringLiteral("已运行程序的进程号，可在任务管理器“详细信息”中查看。由助手启动时不必填写。"));
    pidSpin_->findChild<QLineEdit*>()->setToolTip(pidSpin_->toolTip());
    attachButton_->setToolTip(QStringLiteral("监视这个已运行的 PID，不会新启动程序。支持普通监视或 ProcDump；不支持本助手的 CDB 取证。"));
    captureDumpCheck_->setToolTip(QStringLiteral("用 ProcDump 在未处理异常时保存完整 dump。先指定工具路径；与 CDB 二选一，不保证捕获主动退出。"));
    procDumpEdit_->setToolTip(QStringLiteral("ProcDump 可执行文件路径，仅启用 ProcDump 时需要。附加是否成功请看 procdump.log。"));
    browseProcDump->setToolTip(procDumpEdit_->toolTip());
    captureStackCheck_->setToolTip(QStringLiteral("抓闪退时勾选：从助手启动目标，捕获异常调用栈并尝试保存完整 dump。不能与其他调试器同时附加。"));
    cdbEdit_->setToolTip(QStringLiteral("Windows SDK 中 x64 cdb.exe 的路径。本助手的退出追踪面向 x64 目标。"));
    browseCdb->setToolTip(cdbEdit_->toolTip());
    findCdb->setToolTip(QStringLiteral("优先查找助手 thirdparty 目录，其次查找 Windows SDK；不会下载或安装。未找到时手动选择。"));
    gflagsEdit_->setToolTip(QStringLiteral("Windows SDK 的 gflags.exe，仅 PageHeap 诊断需要。它不是异常捕获工具。"));
    browseGflags->setToolTip(gflagsEdit_->toolTip());
    enablePageHeap->setToolTip(QStringLiteral("仅怀疑堆越界或释放后使用时启用。需管理员权限并重启目标，会明显增加内存和耗时；配置持续生效，用完请关闭。"));
    disablePageHeap->setToolTip(QStringLiteral("关闭所选 EXE 名称的 PageHeap 配置，再重启目标恢复正常运行。关闭助手不会自动关闭它。"));
    symbolPathEdit_->setToolTip(QStringLiteral("填写与该版 EXE/DLL 匹配的 PDB 所在文件夹，不填 .pdb 文件名。多个目录用分号分隔；留空默认搜索 EXE 目录。"));
    markerEdit_->setToolTip(QStringLiteral("在关键操作前输入简短说明，例如“第3次切换到D02”，便于与异常时间对应。"));
    markerButton_->setToolTip(QStringLiteral("把输入的操作说明和当前时间写入会话；仅监视中可用，也可按回车。"));
    openSessionButton_->setToolTip(QStringLiteral("打开最近已结束会话的文件夹。先读 report.html，再看 session.json、cdb.log 和 dumps。"));
    stateLabel_->setToolTip(QStringLiteral("这里是会话状态；“监视中”不等于 dump 必然成功，取证结果需查看日志。"));
    timeline_->setToolTip(QStringLiteral("记录启动、工具状态和人工标记。用于对齐复现步骤与异常时间。"));
    findingsList_->setToolTip(QStringLiteral("自动摘要不是最终根因；请用原始日志、调用栈和对应源码核实。"));
    privateChart_->setToolTip(QStringLiteral("进程私有提交内存，单位 MiB。重复相同操作后持续增长值得排查，但不能单凭曲线判定泄漏。"));
    workingSetChart_->setToolTip(QStringLiteral("当前驻留物理内存，单位 MiB；受系统回收和缓存影响。CPU 显示在当前值旁。"));
    handlesChart_->setToolTip(QStringLiteral("进程持有的系统句柄数量。反复打开关闭后持续增长，可能有句柄未释放。"));
    threadsChart_->setToolTip(QStringLiteral("进程线程数。任务结束后长期不回落时，检查线程生命周期。"));

    connect(browse, &QPushButton::clicked, this, &MainWindow::BrowseExecutable);
    connect(startButton_, &QPushButton::clicked, this, &MainWindow::StartMonitoring);
    connect(attachButton_, &QPushButton::clicked, this, &MainWindow::AttachProcess);
    connect(stopButton_, &QPushButton::clicked, this, &MainWindow::StopMonitoring);
    connect(openSessionButton_, &QPushButton::clicked, this, &MainWindow::OpenSessionDirectory);
    connect(browseProcDump, &QPushButton::clicked, this, &MainWindow::BrowseProcDump);
    connect(browseCdb, &QPushButton::clicked, this, &MainWindow::BrowseCdb);
    connect(findCdb, &QPushButton::clicked, this, &MainWindow::FindCdb);
    connect(browseGflags, &QPushButton::clicked, this, &MainWindow::BrowseGflags);
    connect(enablePageHeap, &QPushButton::clicked, this, [this] { ConfigurePageHeap(true); });
    connect(disablePageHeap, &QPushButton::clicked, this, [this] { ConfigurePageHeap(false); });
    connect(markerButton_, &QPushButton::clicked, this, &MainWindow::AddMarker);
    connect(markerEdit_, &QLineEdit::returnPressed, this, &MainWindow::AddMarker);
    connect(controller_, &SessionController::sampleReady, this, &MainWindow::AppendSample);
    connect(controller_, &SessionController::findingReady, this, [this](const DiagnosticFinding& finding) {
        findingsList_->addItem(QStringLiteral("%1\n%2").arg(finding.title, finding.detail));
    });
    connect(controller_, &SessionController::sessionFinished, this, &MainWindow::ShowSessionSummary);
    connect(controller_, &SessionController::stateChanged, this, &MainWindow::UpdateState);
    connect(controller_, &SessionController::statusChanged, this, &MainWindow::AddTimeline);
}

// 每次打开重新读取 XML，修改帮助文档无需重新编译；只渲染文本，不执行外部内容。
void MainWindow::ShowHelp()
{
    const QString path = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("help.xml"));
    QFile file(path);
    if(!file.open(QIODevice::ReadOnly))
    {
        QMessageBox::warning(this, QStringLiteral("帮助文件无法打开"),
                             QStringLiteral("请将 help.xml 放在助手 EXE 同级目录。\n%1").arg(path));
        return;
    }
    QXmlStreamReader xml(&file);
    QString contents;
    QString navigation;
    int section = 0;
    while(!xml.atEnd())
    {
        xml.readNext();
        if(!xml.isStartElement()) continue;
        if(xml.name() == QStringLiteral("section"))
        {
            const QString title = xml.attributes().value(QStringLiteral("title")).toString().toHtmlEscaped();
            const QString anchor = QStringLiteral("topic%1").arg(++section);
            navigation += QStringLiteral("<p><a href='#%1'>%2</a></p>").arg(anchor, title);
            contents += QStringLiteral("<h2><a name='%1'></a>%2</h2>").arg(anchor, title);
        }
        else if(xml.name() == QStringLiteral("p"))
            contents += QStringLiteral("<p>%1</p>").arg(xml.readElementText().toHtmlEscaped());
    }
    if(xml.hasError() || section == 0)
    {
        QMessageBox::warning(this, QStringLiteral("帮助文件格式错误"),
                             QStringLiteral("%1\n第 %2 行：%3").arg(path).arg(xml.lineNumber())
                                 .arg(xml.hasError() ? xml.errorString() : QStringLiteral("未找到帮助章节")));
        return;
    }
    auto* dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(QStringLiteral("使用指南 · Release 调试助手"));
    dialog->resize(880, 700);
    auto* layout = new QVBoxLayout(dialog);
    auto* browser = new QTextBrowser(dialog);
    browser->setOpenExternalLinks(false);
    browser->setHtml(QStringLiteral("<html><head><style>body{color:#21364b;font-size:13px;}h1{color:#136b9a;}h2{color:#136b9a;margin-top:24px;}p{line-height:150%;}a{color:#147dba;}</style></head><body><h1>遇到问题，先选取证方式</h1><p>先确认捕获已启动，再复现；先看证据，再判断根因。</p>%1<hr>%2</body></html>")
                         .arg(navigation, contents));
    layout->addWidget(browser);
    auto* close = new QPushButton(QStringLiteral("关闭"), dialog);
    close->setToolTip(QStringLiteral("关闭帮助页，不影响正在进行的监视。"));
    connect(close, &QPushButton::clicked, dialog, &QDialog::close);
    layout->addWidget(close, 0, Qt::AlignRight);
    dialog->show();
}

void MainWindow::BrowseExecutable()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("选择要诊断的程序"), executableEdit_->text(),
                                                      QStringLiteral("Windows 程序 (*.exe);;所有文件 (*.*)"));
    if(!path.isEmpty())
    {
        executableEdit_->setText(path);
    }
}

void MainWindow::StartMonitoring()
{
    if(executableEdit_->text().isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("缺少目标"), QStringLiteral("请先选择要诊断的 EXE。"));
        return;
    }
    privateChart_->Clear(); workingSetChart_->Clear(); handlesChart_->Clear(); threadsChart_->Clear();
    findingsList_->clear();
    const QStringList arguments = QProcess::splitCommand(argumentsEdit_->text());
    if(captureStackCheck_->isChecked() && cdbEdit_->text().isEmpty())
    {
        FindCdb();
        if(cdbEdit_->text().isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("未找到 CDB"),
                                 QStringLiteral("自动调用栈需要 Windows SDK 的 cdb.exe；请点击“选择 CDB”指定路径。"));
            return;
        }
    }
    if(!controller_->Launch(executableEdit_->text(), arguments, outputEdit_->text(), intervalSpin_->value(),
                            captureDumpCheck_->isChecked(), procDumpEdit_->text(),
                            captureStackCheck_->isChecked(), cdbEdit_->text(),
                            captureExitCheck_->isChecked(), symbolPathEdit_->text()))
    {
        QMessageBox::warning(this, QStringLiteral("无法启动"), QStringLiteral("当前已有会话，或目标路径无效。"));
    }
}

void MainWindow::AttachProcess()
{
    if(captureStackCheck_->isChecked())
    {
        QMessageBox::information(this, QStringLiteral("CDB 调用栈"),
                                 QStringLiteral("自动调用栈只支持由本工具启动目标；附加已有 PID 请使用 ProcDump 或普通监视。"));
        return;
    }
    if(!controller_->Attach(static_cast<quint32>(pidSpin_->value()), outputEdit_->text(), intervalSpin_->value(),
                            captureDumpCheck_->isChecked(), procDumpEdit_->text()))
    {
        QMessageBox::warning(this, QStringLiteral("无法附加"), QStringLiteral("请输入有效 PID，且当前不能有正在监视的会话。"));
    }
}

void MainWindow::StopMonitoring() { controller_->StopWatching(); }

void MainWindow::AddMarker()
{
    if(!controller_->AddMarker(markerEdit_->text()))
    {
        AddTimeline(QStringLiteral("操作标记未写入：请在监视开始后输入说明。"));
        return;
    }
    markerEdit_->clear();
}

void MainWindow::OpenSessionDirectory()
{
    if(!lastSessionDirectory_.isEmpty())
    {
        QDesktopServices::openUrl(QUrl::fromLocalFile(lastSessionDirectory_));
    }
}

void MainWindow::BrowseProcDump()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("选择 ProcDump"), procDumpEdit_->text(), QStringLiteral("ProcDump (procdump.exe procdump64.exe)"));
    if(!path.isEmpty()) procDumpEdit_->setText(path);
}

void MainWindow::BrowseCdb()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("选择 CDB"), cdbEdit_->text(), QStringLiteral("cdb.exe"));
    if(!path.isEmpty()) cdbEdit_->setText(path);
}

void MainWindow::FindCdb()
{
    const QString path = FindDefaultCdbPath();
    if(!path.isEmpty())
    {
        cdbEdit_->setText(path);
        AddTimeline(QStringLiteral("已找到 CDB：%1").arg(path));
    }
}

void MainWindow::BrowseGflags()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("选择 gflags.exe"), gflagsEdit_->text(), QStringLiteral("gflags.exe"));
    if(!path.isEmpty()) gflagsEdit_->setText(path);
}

void MainWindow::ConfigurePageHeap(bool enable)
{
    if(executableEdit_->text().isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("缺少目标"), QStringLiteral("请选择 EXE 后再配置 PageHeap。"));
        return;
    }
    const QString command = PageHeapController::BuildCommand(executableEdit_->text(), enable);
    const auto answer = QMessageBox::warning(this, enable ? QStringLiteral("启用 PageHeap") : QStringLiteral("关闭 PageHeap"),
                                             QStringLiteral("将以管理员权限执行：\n%1\n\n%2")
                                                 .arg(command, enable ? QStringLiteral("启用后必须完整重启目标程序；运行会显著变慢。")
                                                                      : QStringLiteral("仅关闭指定 EXE 的 PageHeap 配置。")),
                                             QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel);
    if(answer != QMessageBox::Ok) return;
    QString error;
    const QString gflags = PageHeapController::FindGflags(gflagsEdit_->text());
    if(PageHeapController::RunElevated(gflags, executableEdit_->text(), enable, &error))
    {
        AddTimeline(enable ? QStringLiteral("PageHeap 配置请求已提交；请完整重启目标程序后复现。")
                           : QStringLiteral("PageHeap 关闭请求已提交。"));
    }
    else
    {
        QMessageBox::warning(this, QStringLiteral("PageHeap 操作失败"), error);
    }
}

void MainWindow::AppendSample(const ProcessSample& sample)
{
    const double privateMib = sample.privateBytes / (1024.0 * 1024.0);
    const double workingMib = sample.workingSetBytes / (1024.0 * 1024.0);
    privateChart_->Append(privateMib);
    workingSetChart_->Append(workingMib);
    handlesChart_->Append(sample.handleCount);
    threadsChart_->Append(sample.threadCount);
    privateChart_->SetCurrentText(QStringLiteral("当前 %1").arg(FormatBytes(sample.privateBytes)));
    workingSetChart_->SetCurrentText(QStringLiteral("当前 %1，CPU %2%%").arg(FormatBytes(sample.workingSetBytes)).arg(sample.cpuPercent, 0, 'f', 1));
    handlesChart_->SetCurrentText(QStringLiteral("当前 %1 个").arg(sample.handleCount));
    threadsChart_->SetCurrentText(QStringLiteral("当前 %1 个").arg(sample.threadCount));
}

void MainWindow::ShowSessionSummary(const SessionSummary& summary, const QString& directory)
{
    lastSessionDirectory_ = directory;
    openSessionButton_->setEnabled(true);
    findingsList_->clear();
    for(const DiagnosticFinding& finding : summary.findings)
    {
        findingsList_->addItem(QStringLiteral("%1\n%2").arg(finding.title, finding.detail));
    }
    AddTimeline(QStringLiteral("会话证据已写入：%1；匹配事件：%2 条。")
                    .arg(directory).arg(summary.eventsXml.size()));
}

void MainWindow::UpdateState(SessionState state)
{
    stateLabel_->setText(QStringLiteral("● %1").arg(StateText(state)));
    const bool watching = state == SessionState::Watching || state == SessionState::Launching || state == SessionState::Stopping;
    startButton_->setEnabled(!watching);
    attachButton_->setEnabled(!watching);
    stopButton_->setEnabled(watching);
    markerEdit_->setEnabled(state == SessionState::Watching);
    markerButton_->setEnabled(state == SessionState::Watching);
}

void MainWindow::AddTimeline(const QString& message)
{
    timeline_->appendPlainText(QStringLiteral("[%1] %2").arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")), message));
}

QString MainWindow::FormatBytes(qint64 bytes)
{
    return QStringLiteral("%1 MiB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 1);
}
