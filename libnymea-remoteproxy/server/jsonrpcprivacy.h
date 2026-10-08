// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef JSONRPCPRIVACY_H
#define JSONRPCPRIVACY_H

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QString>
#include <QVariantMap>

namespace remoteproxy {

// JSON-RPC requests may carry credentials (e.g. the signed JWT of
// RegisterServerWithToken). Traffic logs must never expose those values:
// a valid JWT can be replayed until it expires.
//
// Returns a logging-safe copy of the given raw payload:
//  - complete JSON messages are re-serialized with credential-bearing
//    params (currently "params.token") redacted
//  - fragmented or invalid data is represented by a placeholder without
//    content, since any fragment may contain (part of) a credential
inline QByteArray redactedLogPayload(const QByteArray &data)
{
    QJsonParseError parseError;
    QJsonDocument document = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return QByteArray("<fragmented or invalid payload, " + QByteArray::number(data.size()) + " bytes>");
    }

    QVariantMap message = document.toVariant().toMap();
    QVariantMap params = message.value("params").toMap();
    if (params.contains("token")) {
        params.insert("token", QStringLiteral("[redacted]"));
        message.insert("params", params);
    }

    return QJsonDocument::fromVariant(message).toJson(QJsonDocument::Compact);
}

}

#endif // JSONRPCPRIVACY_H