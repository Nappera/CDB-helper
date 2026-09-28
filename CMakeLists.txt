cmake_minimum_required(VERSION 3.16)

project(ReleaseDebugStudio LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Widgets)

# 帮助源文件修改后自动同步到构建目录。
configure_file(help.xml help.xml COPYONLY)

add_executable(release_debug_studio
    src/main.cpp
    src/mainwindow.h
    src/mainwindow.cpp
    src/processsample.h
    src/processsampler.h
    src/processsampler.cpp
    src/sessionanalysis.h
    src/sessionanalysis.cpp
    src/sessionstore.h
    src/sessionstore.cpp
    src/sessioncontroller.h
    src/sessioncontroller.cpp
    src/windowseventreader.h
    src/windowseventreader.cpp
    src/dumpcollector.h
    src/dumpcollector.cpp
    src/cdbstackcollector.h
    src/cdbstackcollector.cpp
    src/pageheapcontroller.h
    src/pageheapcontroller.cpp
    src/trendchartwidget.h
    src/trendchartwidget.cpp
)

target_link_libraries(release_debug_studio PRIVATE
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Gui
    Qt${QT_VERSION_MAJOR}::Widgets
    Psapi Wevtapi Shell32
)
target_include_directories(release_debug_studio PRIVATE src)
if(MSVC)
    target_compile_options(release_debug_studio PRIVATE /utf-8)
endif()
add_custom_command(TARGET release_debug_studio POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/help.xml $<TARGET_FILE_DIR:release_debug_studio>/help.xml
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt${QT_VERSION_MAJOR}::Core> $<TARGET_FILE_DIR:release_debug_studio>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt${QT_VERSION_MAJOR}::Gui> $<TARGET_FILE_DIR:release_debug_studio>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt${QT_VERSION_MAJOR}::Widgets> $<TARGET_FILE_DIR:release_debug_studio>
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:release_debug_studio>/platforms
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:Qt${QT_VERSION_MAJOR}::QWindowsIntegrationPlugin>
        $<TARGET_FILE_DIR:release_debug_studio>/platforms/$<TARGET_FILE_NAME:Qt${QT_VERSION_MAJOR}::QWindowsIntegrationPlugin>
)
