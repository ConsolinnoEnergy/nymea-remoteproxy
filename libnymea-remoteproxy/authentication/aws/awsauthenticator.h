/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                               *
 * Copyright (C) 2018 Simon Stürz <simon.stuerz@guh.io>                          *
 *                                                                               *
 * This file is part of nymea-remoteproxy.                                       *
 *                                                                               *
 * This program is free software: you can redistribute it and/or modify          *
 * it under the terms of the GNU General Public License as published by          *
 * the Free Software Foundation, either version 3 of the License, or             *
 * (at your option) any later version.                                           *
 *                                                                               *
 * This program is distributed in the hope that it will be useful,               *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of                *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                 *
 * GNU General Public License for more details.                                  *
 *                                                                               *
 * You should have received a copy of the GNU General Public License             *
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.         *
 *                                                                               *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef AWSAUTHENTICATOR_H
#define AWSAUTHENTICATOR_H

#include <QObject>
#include <QNetworkAccessManager>

#include "awscredentialprovider.h"
#include "authenticationprocess.h"
#include "authentication/authenticator.h"
#include "authentication/authenticationreply.h"

namespace remoteproxy {

class AwsAuthenticator : public Authenticator
{
    Q_OBJECT
public:
    explicit AwsAuthenticator(const QUrl &awsCredentialsUrl, QObject *parent = nullptr);
    ~AwsAuthenticator() override;

    QString name() const override;

private:
    QNetworkAccessManager *m_manager = nullptr;
    AwsCredentialProvider *m_credentialsProvider = nullptr;
    QHash<AuthenticationProcess *, AuthenticationReply *> m_runningProcesses;

private slots:
    void onAuthenticationProcessFinished(Authenticator::AuthenticationError error, const UserInformation &userInformation);

public slots:
    AuthenticationReply *authenticate(ProxyClient *proxyClient) override;

};

}

#endif // AWSAUTHENTICATOR_H
