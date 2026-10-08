// SPDX-License-Identifier: LGPL-3.0-or-later

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
* nymea-remoteproxy
* Tunnel proxy server for the nymea remote access
*
* Copyright (C) 2013 - 2024, nymea GmbH
* Copyright (C) 2024 - 2025, chargebyte austria GmbH
*
* This file is part of nymea-remoteproxy.
*
* nymea-remoteproxy is free software: you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License
* as published by the Free Software Foundation, either version 3
* of the License, or (at your option) any later version.
*
* nymea-remoteproxy is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with nymea-remoteproxy. If not, see <https://www.gnu.org/licenses/>.
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "proxyjsonrpcclient.h"
#include "proxyconnection.h"
#include "../common/slipdataprocessor.h"

#include <QJsonDocument>

Q_LOGGING_CATEGORY(dcRemoteProxyClientJsonRpc, "RemoteProxyClientJsonRpc")
Q_LOGGING_CATEGORY(dcRemoteProxyClientJsonRpcTraffic, "RemoteProxyClientJsonRpcTraffic")

namespace remoteproxyclient {

JsonRpcClient::JsonRpcClient(ProxyConnection *connection, QObject *parent) :
    QObject(parent),
    m_connection(connection)
{

}

JsonReply *JsonRpcClient::callHello()
{
    JsonReply *reply = new JsonReply(m_commandId, "RemoteProxy", "Hello", QVariantMap(), this);
    qCDebug(dcRemoteProxyClientJsonRpc()) << "Calling" << QString("%1.%2").arg(reply->nameSpace()).arg(reply->method());
    sendRequest(reply->requestMap());
    m_replies.insert(m_commandId, reply);
    return reply;
}

JsonReply *JsonRpcClient::callRegisterServer(const QUuid &serverUuid, const QString &serverName)
{
    QVariantMap params;
    params.insert("serverName", serverName);
    params.insert("serverUuid", serverUuid.toString());

    JsonReply *reply = new JsonReply(m_commandId, "TunnelProxy", "RegisterServer", params, this);
    qCDebug(dcRemoteProxyClientJsonRpc()) << "Calling" << QString("%1.%2").arg(reply->nameSpace()).arg(reply->method());
    sendRequest(reply->requestMap());
    m_replies.insert(m_commandId, reply);
    return reply;
}

JsonReply *JsonRpcClient::callRegisterServerWithToken(const QUuid &serverUuid, const QString &serverName, const QString &token)
{
    QVariantMap params;
    params.insert("serverName", serverName);
    params.insert("serverUuid", serverUuid.toString());
    params.insert("token", token);

    JsonReply *reply = new JsonReply(m_commandId, "TunnelProxy", "RegisterServerWithToken", params, this);

    // The token is a credential that can be replayed until it expires.
    // Never transmit it over an unencrypted transport.
    const QString scheme = m_connection->serverUrl().scheme();
    if (scheme == QStringLiteral("tcp") || scheme == QStringLiteral("ws")) {
        qCWarning(dcRemoteProxyClientJsonRpc()) << "Refusing to send a registration token over an unencrypted transport" << m_connection->serverUrl().toString();
        QVariantMap errorResponse;
        errorResponse.insert("id", reply->commandId());
        errorResponse.insert("status", "error");
        errorResponse.insert("error", "Token registration requires an encrypted transport");
        reply->setResponse(errorResponse);
        emit reply->finished();
        return reply;
    }

    qCDebug(dcRemoteProxyClientJsonRpc()) << "Calling" << QString("%1.%2").arg(reply->nameSpace()).arg(reply->method());
    sendRequest(reply->requestMap());
    m_replies.insert(m_commandId, reply);
    return reply;
}

JsonReply *JsonRpcClient::callRegisterClient(const QUuid &clientUuid, const QString &clientName, const QUuid &serverUuid)
{
    QVariantMap params;
    params.insert("clientUuid", clientUuid);
    params.insert("clientName", clientName);
    params.insert("serverUuid", serverUuid.toString());

    JsonReply *reply = new JsonReply(m_commandId, "TunnelProxy", "RegisterClient", params, this);
    qCDebug(dcRemoteProxyClientJsonRpc()) << "Calling" << QString("%1.%2").arg(reply->nameSpace()).arg(reply->method());
    sendRequest(reply->requestMap());
    m_replies.insert(m_commandId, reply);
    return reply;
}

JsonReply *JsonRpcClient::callDisconnectClient(quint16 socketAddress)
{
    QVariantMap params;
    params.insert("socketAddress", socketAddress);

    JsonReply *reply = new JsonReply(m_commandId, "TunnelProxy", "DisconnectClient", params, this);
    qCDebug(dcRemoteProxyClientJsonRpc()) << "Calling" << QString("%1.%2").arg(reply->nameSpace()).arg(reply->method());
    sendRequest(reply->requestMap(), true);
    m_replies.insert(m_commandId, reply);
    return reply;
}

JsonReply *JsonRpcClient::callPing(uint timestamp)
{
    QVariantMap params;
    params.insert("timestamp", timestamp);

    JsonReply *reply = new JsonReply(m_commandId, "TunnelProxy", "Ping", params, this);
    qCDebug(dcRemoteProxyClientJsonRpc()) << "Calling" << QString("%1.%2").arg(reply->nameSpace()).arg(reply->method());
    sendRequest(reply->requestMap(), true);
    m_replies.insert(m_commandId, reply);
    return reply;
}

void JsonRpcClient::sendRequest(const QVariantMap &request, bool slipEnabled)
{
    // Redact credential-bearing params (e.g. the signed JWT of
    // RegisterServerWithToken) from the logging copy. The transmitted
    // request must remain unchanged.
    QVariantMap logRequest = request;
    QVariantMap logParams = logRequest.value("params").toMap();
    if (logParams.contains("token")) {
        logParams.insert("token", QStringLiteral("[redacted]"));
        logRequest.insert("params", logParams);
    }

    QByteArray data = QJsonDocument::fromVariant(request).toJson(QJsonDocument::Compact) + "\n";
    QByteArray logData = QJsonDocument::fromVariant(logRequest).toJson(QJsonDocument::Compact) + "\n";

    if (slipEnabled) {
        SlipDataProcessor::Frame frame;
        frame.socketAddress = 0x0000;
        frame.data = data;
        data = SlipDataProcessor::serializeData(SlipDataProcessor::buildFrame(frame));

        SlipDataProcessor::Frame logFrame;
        logFrame.socketAddress = 0x0000;
        logFrame.data = logData;
        logData = SlipDataProcessor::serializeData(SlipDataProcessor::buildFrame(logFrame));
    }

    qCDebug(dcRemoteProxyClientJsonRpcTraffic()) << "Sending" << qUtf8Printable(logData);
    m_connection->sendData(data);
}

void JsonRpcClient::processDataPacket(const QByteArray &data)
{
    QJsonParseError error;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(data, &error);
    if (error.error != QJsonParseError::NoError) {
        qCWarning(dcRemoteProxyClientJsonRpc()) << "Invalid JSON data recived" << error.errorString();
        return;
    }

    QVariantMap dataMap = jsonDoc.toVariant().toMap();

    qCDebug(dcRemoteProxyClientJsonRpcTraffic()) << "Data received" << qUtf8Printable(data);

    // check if this is a reply to a request
    int commandId = dataMap.value("id").toInt();
    JsonReply *reply = m_replies.take(commandId);
    if (reply) {
        qCDebug(dcRemoteProxyClientJsonRpcTraffic()) << QString("Got response for %1.%2: %3").arg(reply->nameSpace(), reply->method(), QString::fromUtf8(jsonDoc.toJson(QJsonDocument::Indented)));

        if (dataMap.value("status").toString() == "error") {
            qCWarning(dcRemoteProxyClientJsonRpc()) << "Api error happend" << dataMap.value("error").toString();
            // FIMXME: handle json layer errors
        }

        reply->setResponse(dataMap);
        emit reply->finished();
        return;
    }

    // check if this is a notification
    if (dataMap.contains("notification")) {
        QStringList notification = dataMap.value("notification").toString().split(".");
        QString nameSpace = notification.first();
        QString notificationName = notification.last();
        QVariantMap notificationParams = dataMap.value("params").toMap();

        qCDebug(dcRemoteProxyClientJsonRpc()) << "Notification received" << nameSpace << notificationName;

        if (nameSpace == "RemoteProxy" && notificationName == "TunnelEstablished") {
            QString clientName = notificationParams.value("name").toString();
            QString clientUuid = notificationParams.value("uuid").toString();
            emit tunnelEstablished(clientName, clientUuid);
        } else if (nameSpace == "TunnelProxy" && notificationName == "ClientConnected") {
            QString clientName = notificationParams.value("clientName").toString();
            QUuid clientUuid = notificationParams.value("clientUuid").toUuid();
            QString clientPeerAddress = notificationParams.value("clientPeerAddress").toString();
            quint16 socketAddress = static_cast<quint16>(notificationParams.value("socketAddress").toUInt());
            emit tunnelProxyClientConnected(clientName, clientUuid, clientPeerAddress, socketAddress);
        } else if (nameSpace == "TunnelProxy" && notificationName == "ClientDisconnected") {
            quint16 socketAddress = static_cast<quint16>(notificationParams.value("socketAddress").toUInt());
            emit tunnelProxyClientDisonnected(socketAddress);
        }
    }
}

void JsonRpcClient::processData(const QByteArray &data)
{
    qCDebug(dcRemoteProxyClientJsonRpcTraffic()) << "Received data:" << data;

    // Handle packet fragmentation
    m_dataBuffer.append(data);
    int splitIndex = m_dataBuffer.indexOf("}\n{");
    while (splitIndex > -1) {
        processDataPacket(m_dataBuffer.left(splitIndex + 1));
        m_dataBuffer = m_dataBuffer.right(m_dataBuffer.length() - splitIndex - 2);
        splitIndex = m_dataBuffer.indexOf("}\n{");
    }
    if (m_dataBuffer.endsWith("}\n") || m_dataBuffer.endsWith("}")) {
        processDataPacket(m_dataBuffer);
        m_dataBuffer.clear();
    }
}

}
