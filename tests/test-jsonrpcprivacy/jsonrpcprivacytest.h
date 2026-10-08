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

#ifndef JSONRPCPRIVACYTEST_H
#define JSONRPCPRIVACYTEST_H

#include <QObject>
#include <QtTest>
#include <QMutex>

#include "jsonrpc/jsonrpcprivacy.h"
#include "jsonrpc/jsontypes.h"

using namespace remoteproxy;

class JsonRpcPrivacyTest : public QObject
{
    Q_OBJECT

private slots:
    void redactedParamsToken();
    void redactedTopLevelToken();
    void redactedArrayValuedParams();
    void redactedNestedToken();
    void validationWarningsRedacted();
    void redactParamsTokensVariantMap();
    void fragmentedPayloadPlaceholder();
    void cleanPayloadUntouched();
};

#endif // JSONRPCPRIVACYTEST_H