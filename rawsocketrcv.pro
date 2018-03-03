TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
SOURCES += main.cpp \
    lpcapsocket.cpp

HEADERS += \
    lpcapsocket.h

#thread
unix:!macx: LIBS += -L/usr/lib/i386-linux-gnu/ -pthread
#QMAKE_CXXFLAGS += -Wl,--no-as-needed -std=c++11
#pcap
unix:!macx: LIBS += -L/usr/lib/i386-linux-gnu/ -lpcap

#app modules
unix:!macx: LIBS += -L../rawsocketrcv/modules/ubus/ -lubus_publish

INCLUDEPATH += ../rawsocketrcv/modules/ubus
DEPENDPATH += ../rawsocketrcv/modules/ubus

unix:!macx: PRE_TARGETDEPS += ../rawsocketrcv/modules/ubus/libubus_publish.a

#ubus
unix:!macx: LIBS += -L/usr/local/lib/ -lubox
unix:!macx: PRE_TARGETDEPS += /usr/local/lib/libubox.a

unix:!macx: LIBS += -L/usr/local/lib/ -lubus
