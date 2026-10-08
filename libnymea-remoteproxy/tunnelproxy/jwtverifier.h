// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef JWTVERIFIER_H
#define JWTVERIFIER_H

#include <QString>

namespace remoteproxy {

bool verifyJwt(const QString &token, const QString &jwksFilePath = QStringLiteral("/config/jwks.json"));

}

#endif // JWTVERIFIER_H