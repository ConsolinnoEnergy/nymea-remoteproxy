include(../../nymea-remoteproxy.pri)
include(../testbase/testbase.pri)

TARGET = jsonrpcprivacy

HEADERS += jsonrpcprivacytest.h

SOURCES += jsonrpcprivacytest.cpp

target.path = $$[QT_INSTALL_PREFIX]/share/tests/nymea-remoteproxy/
INSTALLS += target