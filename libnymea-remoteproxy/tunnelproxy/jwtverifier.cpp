// SPDX-License-Identifier: LGPL-3.0-or-later

#include "jwtverifier.h"

#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QStringList>

#include <memory>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace remoteproxy {
namespace {

bool decodeBase64Url(const QString &encodedText, QByteArray *decoded)
{
    QByteArray encoded = encodedText.toLatin1();
    for (char character : encoded) {
        if (!((character >= 'A' && character <= 'Z')
              || (character >= 'a' && character <= 'z')
              || (character >= '0' && character <= '9')
              || character == '-' || character == '_')) {
            return false;
        }
    }

    if (encoded.size() % 4 == 1) {
        return false;
    }

    encoded.replace('-', '+');
    encoded.replace('_', '/');
    if (encoded.size() % 4 != 0) {
        encoded.append(QByteArray(4 - encoded.size() % 4, '='));
    }
    *decoded = QByteArray::fromBase64(encoded);
    return !decoded->isEmpty();
}

bool parseJsonObject(const QString &encodedText, QJsonObject *object)
{
    QByteArray json;
    if (!decodeBase64Url(encodedText, &json)) {
        return false;
    }

    QJsonParseError error;
    QJsonDocument document = QJsonDocument::fromJson(json, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) {
        return false;
    }

    *object = document.object();
    return true;
}

bool claimsAreCurrent(const QJsonObject &claims)
{
    const QJsonValue expiresAt = claims.value("exp");
    if (!expiresAt.isDouble() || expiresAt.toDouble() <= QDateTime::currentSecsSinceEpoch()) {
        return false;
    }

    if (claims.contains("nbf")) {
        const QJsonValue notBefore = claims.value("nbf");
        if (!notBefore.isDouble() || notBefore.toDouble() > QDateTime::currentSecsSinceEpoch()) {
            return false;
        }
    }

    return true;
}

QJsonArray selectRsaKeys(const QJsonArray &keys, const QString &keyId)
{
    QJsonArray selectedKeys;
    for (const QJsonValue &value : keys) {
        if (!value.isObject()) {
            continue;
        }

        const QJsonObject key = value.toObject();
        if (key.value("kty").toString() != QLatin1String("RSA")) {
            continue;
        }
        if (key.contains("use") && key.value("use").toString() != QLatin1String("sig")) {
            continue;
        }
        if (key.contains("alg") && key.value("alg").toString() != QLatin1String("RS256")) {
            continue;
        }
        if (!keyId.isEmpty() && key.value("kid").toString() != keyId) {
            continue;
        }

        if (key.contains("key_ops")) {
            const QJsonArray operations = key.value("key_ops").toArray();
            if (!operations.contains(QLatin1String("verify"))) {
                continue;
            }
        }

        selectedKeys.append(key);
    }

    return selectedKeys;
}

bool verifyRsaSha256(const QByteArray &signingInput, const QByteArray &signature, const QJsonObject &key)
{
    QByteArray modulusBytes;
    QByteArray exponentBytes;
    if (!decodeBase64Url(key.value("n").toString(), &modulusBytes)
        || !decodeBase64Url(key.value("e").toString(), &exponentBytes)) {
        return false;
    }

    std::unique_ptr<BIGNUM, decltype(&BN_free)> modulus(BN_bin2bn(reinterpret_cast<const unsigned char *>(modulusBytes.constData()), modulusBytes.size(), nullptr), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> exponent(BN_bin2bn(reinterpret_cast<const unsigned char *>(exponentBytes.constData()), exponentBytes.size(), nullptr), BN_free);
    std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);
    if (!modulus || !exponent || !rsa || RSA_set0_key(rsa.get(), modulus.get(), exponent.get(), nullptr) != 1) {
        return false;
    }
    modulus.release();
    exponent.release();

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> publicKey(EVP_PKEY_new(), EVP_PKEY_free);
    if (!publicKey || EVP_PKEY_set1_RSA(publicKey.get(), rsa.get()) != 1) {
        return false;
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, publicKey.get()) != 1) {
        return false;
    }

    return EVP_DigestVerify(context.get(), reinterpret_cast<const unsigned char *>(signature.constData()),
                            static_cast<size_t>(signature.size()),
                            reinterpret_cast<const unsigned char *>(signingInput.constData()),
                            static_cast<size_t>(signingInput.size())) == 1;
}

}

bool verifyJwt(const QString &token, const QString &jwksFilePath)
{
    const QStringList parts = token.split(QLatin1Char('.'));
    if (parts.size() != 3 || parts.at(0).isEmpty() || parts.at(1).isEmpty() || parts.at(2).isEmpty()) {
        return false;
    }

    QJsonObject header;
    QJsonObject claims;
    QByteArray signature;
    if (!parseJsonObject(parts.at(0), &header)
        || !parseJsonObject(parts.at(1), &claims)
        || !decodeBase64Url(parts.at(2), &signature)) {
        return false;
    }
    if (header.value("alg").toString() != QLatin1String("RS256")
        || header.contains("crit")
        || (header.contains("b64") && !header.value("b64").toBool(true))
        || !claimsAreCurrent(claims)) {
        return false;
    }

    QFile jwksFile(jwksFilePath);
    if (!jwksFile.open(QIODevice::ReadOnly)) {
        return false;
    }

    QJsonParseError jwksError;
    const QJsonDocument jwksDocument = QJsonDocument::fromJson(jwksFile.readAll(), &jwksError);
    if (jwksError.error != QJsonParseError::NoError || !jwksDocument.isObject()) {
        return false;
    }

    const QJsonArray keys = jwksDocument.object().value("keys").toArray();
    const QString keyId = header.value("kid").toString();
    const QJsonArray candidateKeys = selectRsaKeys(keys, keyId);
    if (candidateKeys.isEmpty() || (!keyId.isEmpty() && candidateKeys.size() != 1)) {
        return false;
    }

    const QByteArray signingInput = parts.at(0).toLatin1() + '.' + parts.at(1).toLatin1();
    int matchingSignatures = 0;
    for (const QJsonValue &value : candidateKeys) {
        if (verifyRsaSha256(signingInput, signature, value.toObject())) {
            ++matchingSignatures;
            if (matchingSignatures > 1) {
                return false;
            }
        }
    }

    return matchingSignatures == 1;
}

}