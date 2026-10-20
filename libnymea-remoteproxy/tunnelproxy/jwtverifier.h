// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef JWTVERIFIER_H
#define JWTVERIFIER_H

#include <QString>

namespace remoteproxy {

// Loads and parses the JWKS file once. The keys are kept in memory and used
// by verifyJwt(token) for all subsequent verifications. Returns false if the
// file cannot be read or parsed.
bool loadJwks(const QString &jwksFilePath = QStringLiteral("/config/jwks.json"));

// Verifies a token against the keys cached by loadJwks().
bool verifyJwt(const QString &token);

// Verifies a token against the given JWKS file without touching the cache.
// Mostly useful for tests and tooling.
bool verifyJwt(const QString &token, const QString &jwksFilePath);

}

#endif // JWTVERIFIER_H