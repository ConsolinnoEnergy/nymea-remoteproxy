CONFIG += testcase
QT += testlib

INCLUDEPATH += ../../libnymea-remoteproxy

TARGET = jsonrpcprivacy

HEADERS += jsonrpcprivacytest.h

SOURCES += jsonrpcprivacytest.cpp

target.path = $$[QT_INSTALL_PREFIX]/share/tests/nymea-remoteproxy/
INSTALLS += target