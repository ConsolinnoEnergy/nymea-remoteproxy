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
// Variant-map/variant redaction: replaces credential-bearing "token"
// keys in already-parsed JSON-RPC messages. Redacts recursively, so it
// covers "params.token", a top-level "token" (flat parameter objects),
// and tokens inside array-valued params (e.g. {"params":[{"token":...}]}).
inline QVariant redactTokenValues(const QVariant &value)
{
    if (value.type() == QVariant::Map) {
        QVariantMap map = value.toMap();
        for (const QString &key : map.keys()) {
            if (key == QStringLiteral("token")) {
                map.insert(key, QStringLiteral("[redacted]"));
            } else {
                map.insert(key, redactTokenValues(map.value(key)));
            }
        }
        return map;
    }
    if (value.type() == QVariant::List) {
        QVariantList list = value.toList();
        for (int i = 0; i < list.count(); ++i) {
            list.replace(i, redactTokenValues(list.at(i)));
        }
        return list;
    }
    return value;
}

inline QVariantMap redactParamsTokens(const QVariantMap &message)
{
    QVariantMap redacted = message;
    if (redacted.contains(QStringLiteral("token"))) {
        redacted.insert(QStringLiteral("token"), QStringLiteral("[redacted]"));
    }
    for (const QString &key : redacted.keys()) {
        if (key == QStringLiteral("token")) {
            continue;
        }
        redacted.insert(key, redactTokenValues(redacted.value(key)));
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