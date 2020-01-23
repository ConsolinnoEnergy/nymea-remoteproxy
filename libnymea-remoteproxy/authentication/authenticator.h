/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
*  Copyright 2013 - 2020, nymea GmbH
*  Contact: contact@nymea.io
*
*  This file is part of nymea.
*  This project including source code and documentation is protected by copyright law, and
*  remains the property of nymea GmbH. All rights, including reproduction, publication,
*  editing and translation, are reserved. The use of this project is subject to the terms of a
*  license agreement to be concluded with nymea GmbH in accordance with the terms
*  of use of nymea GmbH, available under https://nymea.io/license
*
*  GNU General Public License Usage
*  Alternatively, this project may be redistributed and/or modified under
*  the terms of the GNU General Public License as published by the Free Software Foundation,
*  GNU version 3. this project is distributed in the hope that it will be useful, but WITHOUT ANY
*  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
*  PURPOSE. See the GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License along with this project.
*  If not, see <https://www.gnu.org/licenses/>.
*
*  For any further details and any questions please contact us under contact@nymea.io
*  or see our FAQ/Licensing Information on https://nymea.io/license/faq
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <QUuid>
#include <QObject>

namespace remoteproxy {

class ProxyClient;
class AuthenticationReply;

class Authenticator : public QObject
{
    Q_OBJECT
public:
    enum AuthenticationError {
        AuthenticationErrorNoError,
        AuthenticationErrorUnknown,
        AuthenticationErrorTimeout,
        AuthenticationErrorAborted,
        AuthenticationErrorAuthenticationFailed,
        AuthenticationErrorProxyError
    };
    Q_ENUM(AuthenticationError)

    explicit Authenticator(QObject *parent = nullptr);
    virtual ~Authenticator() = 0;

    virtual QString name() const = 0;

public slots:
    virtual AuthenticationReply *authenticate(ProxyClient *proxyClient) = 0;

protected:
    void setReplyError(AuthenticationReply *reply, AuthenticationError error);
    void setReplyFinished(AuthenticationReply *reply);

    AuthenticationReply *createAuthenticationReply(ProxyClient *proxyClient, QObject *parent = nullptr);
};

}

#endif // AUTHENTICATOR_H
