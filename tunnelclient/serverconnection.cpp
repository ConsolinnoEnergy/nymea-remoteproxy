#include "serverconnection.h"

ServerConnection::ServerConnection(const QUrl &serverUrl, const QString &name, const QUuid &uuid, bool insecure, QObject *parent) :
    QObject(parent),
    m_serverUrl(serverUrl),
    m_name(name),
    m_uuid(uuid),
    m_insecure(insecure)
{

    m_socketServer = new TunnelProxySocketServer(m_uuid, m_name, this);

    connect(m_socketServer, &TunnelProxySocketServer::clientConnected, this, [=](TunnelProxySocket *tunnelProxySocket){
        qDebug() << "[+] Client connected" << tunnelProxySocket;
    });

    connect(m_socketServer, &TunnelProxySocketServer::clientDisconnected, this, [=](TunnelProxySocket *tunnelProxySocket){
        qDebug() << "[-] Client disconnected" << tunnelProxySocket;
    });

    connect(m_socketServer, &TunnelProxySocketServer::runningChanged, this, [=](bool running){
        if (running) {
            qDebug() << "Connected with" << m_socketServer->remoteProxyServer() << m_socketServer->remoteProxyServerName() << m_socketServer->remoteProxyServerVersion() << m_socketServer->remoteProxyApiVersion();
        }
        qDebug() << "--> The tunnel proxy server is" << (running ? "running and listening for incoming connections" : "not running any more");
    });

    connect(m_socketServer, &TunnelProxySocketServer::sslErrors, this, [=](const QList<QSslError> &errors){
        if (m_insecure) {
            m_socketServer->ignoreSslErrors(errors);
        } else {
            qWarning() << "SSL errors occurred:";
            foreach (const QSslError &sslError, errors) {
                qWarning() << "  --> " << sslError.errorString();
            }
        }
    });

}

void ServerConnection::startServer()
{
    m_socketServer->startServer(m_serverUrl);
}
