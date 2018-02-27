TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    lpcapsocket.cpp

HEADERS += \
    lpcapsocket.h
unix:!macx: LIBS += -L/usr/lib/i386-linux-gnu/ -lpcap

#INCLUDEPATH += ../sigmaLibraries/PhoneParams
#DEPENDPATH += ../sigmaLibraries/PhoneParams

