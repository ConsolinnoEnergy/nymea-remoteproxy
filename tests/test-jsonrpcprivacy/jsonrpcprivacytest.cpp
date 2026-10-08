// SPDX-License-Identifier: LGPL-3.0-or-later

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
* nymea-remoteproxy
* Tunnel proxy server for the nymea remote access
*
* Copyright (C) 2024 - 2026, Consolinno Energy GmbH
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "jsonrpcprivacytest.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QVariantMap>

using namespace remoteproxy;

void JsonRpcPrivacyTest::redactedParamsToken()
{
    QByteArray data = "{\"id\":1,\"method\":\"TunnelProxy.RegisterServerWithToken\","
                      "\"params\":{\"serverName\":\"test\",\"serverUuid\":\"{uuid}\","
                      "\"token\":\"SECRET-JWT\"}}";

    QByteArray redacted = redactedLogPayload(data);

    QVERIFY2(!redacted.contains("SECRET-JWT"), "The token must not appear in the log output");
    QVERIFY(redacted.contains("[redacted]"));

    QVariantMap message = QJsonDocument::fromJson(redacted).toVariant().toMap();
    QCOMPARE(message.value("id").toInt(), 1);
    QCOMPARE(message.value("method").toString(), QStringLiteral("TunnelProxy.RegisterServerWithToken"));
    QCOMPARE(message.value("params").toMap().value("token").toString(), QStringLiteral("[redacted]"));
    QCOMPARE(message.value("params").toMap().value("serverName").toString(), QStringLiteral("test"));
}

void JsonRpcPrivacyTest::redactedTopLevelToken()
{
    // A flat parameters object: valid JSON on its own (e.g. a TCP fragment
    // matching exactly the inner params object) carries the token top-level.
    QByteArray data = "{\"serverName\":\"test\",\"token\":\"SECRET-JWT\"}";

    QByteArray redacted = redactedLogPayload(data);

    QVERIFY2(!redacted.contains("SECRET-JWT"), "A top-level token must not appear in the log output");
    QVERIFY(redacted.contains("[redacted]"));

    QVariantMap message = QJsonDocument::fromJson(redacted).toVariant().toMap();
    QCOMPARE(message.value("token").toString(), QStringLiteral("[redacted]"));
    QCOMPARE(message.value("serverName").toString(), QStringLiteral("test"));
}

void JsonRpcPrivacyTest::redactParamsTokensVariantMap()
{
    // Nested: params.token
    QVariantMap nested;
    nested.insert("method", QStringLiteral("TunnelProxy.RegisterServerWithToken"));
    QVariantMap nestedParams;
    nestedParams.insert("serverName", QStringLiteral("test"));
    nestedParams.insert("token", QStringLiteral("SECRET-JWT"));
    nested.insert("params", nestedParams);

    QVariantMap redacted = redactParamsTokens(nested);
    QVERIFY2(!QJsonDocument::fromVariant(redacted).toJson().contains("SECRET-JWT"), "params.token must be redacted");
    QCOMPARE(redacted.value("params").toMap().value("token").toString(), QStringLiteral("[redacted]"));

    // Flat: top-level token
    QVariantMap flat;
    flat.insert("serverName", QStringLiteral("test"));
    flat.insert("token", QStringLiteral("SECRET-JWT"));
    redacted = redactParamsTokens(flat);
    QVERIFY2(!QJsonDocument::fromVariant(redacted).toJson().contains("SECRET-JWT"), "top-level token must be redacted");
    QCOMPARE(redacted.value("token").toString(), QStringLiteral("[redacted]"));
}

void JsonRpcPrivacyTest::fragmentedPayloadPlaceholder()
{
    // A TCP fragment (incomplete JSON) must not leak its content
    QByteArray data = "{\"params\":{\"token\":\"SECRET-JW";

    QByteArray redacted = redactedLogPayload(data);

    QVERIFY2(!redacted.contains("SECRET-JW"), "Fragment content must not appear in the log output");
    QVERIFY(redacted.startsWith("<fragmented or invalid payload,"));
    QVERIFY(redacted.endsWith("bytes>"));
}

void JsonRpcPrivacyTest::cleanPayloadUntouched()
{
    QByteArray data = "{\"id\":2,\"method\":\"RemoteProxy.Hello\",\"params\":{\"client\":\"app\"}}";

    QByteArray redacted = redactedLogPayload(data);

    QVariantMap message = QJsonDocument::fromJson(redacted).toVariant().toMap();
    QCOMPARE(message.value("id").toInt(), 2);
    QCOMPARE(message.value("method").toString(), QStringLiteral("RemoteProxy.Hello"));
    QCOMPARE(message.value("params").toMap().value("client").toString(), QStringLiteral("app"));
    QVERIFY2(!redacted.contains("[redacted]"), "Nothing should be redacted in a credential-free message");
}

QTEST_MAIN(JsonRpcPrivacyTest)