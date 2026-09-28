#include "mainwindow.h"

#include <QApplication>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Release 调试助手"));
    MainWindow window;
    window.show();
    return app.exec();
}
