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
//    params ("params.token" and a top-level "token") redacted
//  - fragmented or invalid data is represented by a placeholder without
//    content, since any fragment may contain (part of) a credential
// Variant-map redaction: replaces credential-bearing params in
// already-parsed JSON-RPC messages. Redacts the nested "params.token"
// as well as a top-level "token", since some callers pass flat
// parameter objects and a TCP fragment may contain exactly the inner
// parameters object.
inline QVariantMap redactParamsTokens(const QVariantMap &message)
{
    QVariantMap redacted = message;
    if (redacted.contains("token")) {
        redacted.insert("token", QStringLiteral("[redacted]"));
    }
    QVariantMap params = redacted.value("params").toMap();
    if (params.contains("token")) {
        params.insert("token", QStringLiteral("[redacted]"));
        redacted.insert("params", params);
    }
    return redacted;
}

inline QByteArray redactedLogPayload(const QByteArray &data)
{
    QJsonParseError parseError;
    QJsonDocument document = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return QByteArray("<fragmented or invalid payload, " + QByteArray::number(data.size()) + " bytes>");
    }

    return QJsonDocument::fromVariant(redactParamsTokens(document.toVariant().toMap())).toJson(QJsonDocument::Compact);
}

}

#endif // JSONRPCPRIVACY_H