/*
 * Copyright (c) 2002-2009 Moxie Marlinspike
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include "SSLBridge.hpp"
#include <string.h>
#ifdef __FreeBSD__
#include <machine/atomic.h>
#endif
#include <unistd.h>
#include "http/http_template.h"
#include "util/json_helper.h"
#include "util/yara_utils.h"
#include "global.h"

using namespace boost::asio;

volatile unsigned int g_session_id = 0;

X509* SSLBridge::getServerCertificate() {
  return SSL_get_peer_certificate(serverSession);
}

void SSLBridge::buildClientContext(SSL_CTX *context, Certificate *leaf, std::list<Certificate*> *chain) {

  SSL_CTX_sess_set_new_cb(context, &SessionCache::setNewSessionIdTramp);
  SSL_CTX_sess_set_get_cb(context, &SessionCache::getSessionIdTramp);

  SSL_CTX_use_certificate(context, leaf->getCert());
  SSL_CTX_use_PrivateKey(context, leaf->getKey());

  if (SSL_CTX_check_private_key(context) == 0) {
    std::cerr << "*** Assertion Failed - Generated PrivateKey Doesn't Work." << std::endl;
    throw SSLConnectionError();
  }

  std::list<Certificate*>::iterator i   = chain->begin();
  std::list<Certificate*>::iterator end = chain->end();

  for (;i != end; i++) {
    SSL_CTX_add_extra_chain_cert(context, (*i)->getCert());
  }

  // if (chain != NULL)
  //   SSL_CTX_add_extra_chain_cert(context, chain->getCert());

  SSL_CTX_set_mode(context, SSL_MODE_AUTO_RETRY);
}

ip::tcp::endpoint SSLBridge::getRemoteEndpoint() {
  return serverSocket->remote_endpoint();
}

ip::tcp::endpoint SSLBridge::getClientEndpoint() {
  return clientSocket->remote_endpoint();
}

void SSLBridge::setServerName() {
  X509 *serverCertificate    = getServerCertificate();
  X509_NAME *serverNameField = X509_get_subject_name(serverCertificate);
  char *serverNameStr        = X509_NAME_oneline(serverNameField, NULL, 0);

  this->serverName = std::string((const char*)serverNameStr);
  int commonNameIndex;

  if ((commonNameIndex = this->serverName.find("CN=")) != std::string::npos)
    this->serverName = this->serverName.substr(commonNameIndex+3);
  
  free(serverNameStr);
}

extern "C" void SSLBridge_CompleteConnections(SSLBridge *bridge, const char *host_name)
{
    if (host_name != NULL) {
        bridge->mHostname = host_name;
    }
    if (bridge->mCompleteServerHandshake == false) {
        bridge->handshakeWithServer();
        bridge->handshakeWithClientStage3();
        bridge->mCompleteServerHandshake = true;
    }
}

extern "C" int ssl_servername_cb(SSL *s, int *ad, void *arg)
{
    const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    SSLBridge_CompleteConnections((SSLBridge*)arg, servername);
    return SSL_TLSEXT_ERR_NOACK;
}

extern "C" void ssl_msg_callback(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    if (version <= SSL3_VERSION && write_p == 0 && (content_type == 0 || content_type == 22)) {
        SSLBridge_CompleteConnections((SSLBridge*)arg, "");
    }
}

void SSLBridge::handshakeWithClientStage1() {
    //Certificate *leaf;
    //std::list<Certificate*> *chain;
    log_trace(stdout, "[%s]Enter\n", __FUNCTION__);

    //ip::tcp::endpoint endpoint = getRemoteEndpoint();
    //manager.getCertificateForTarget(endpoint, wildcardOK, getServerCertificate(), &leaf, &chain);

    //setServerName();

    SSL_CTX *clientContext = SSL_CTX_new(SSLv23_server_method());
    //buildClientContext(clientContext, leaf, chain);

    SSL *clientSession = SSL_new(clientContext);
    SSL_set_fd(clientSession, clientSocket->native());

    this->clientSession = clientSession;

    SSL_CTX_set_msg_callback(clientContext, ssl_msg_callback);
    SSL_CTX_set_msg_callback_arg(clientContext, (SSLBridge *)this);
    SSL_CTX_set_tlsext_servername_callback(clientContext, ssl_servername_cb);
    SSL_CTX_set_tlsext_servername_arg(clientContext, (SSLBridge *)this);
}

void SSLBridge::handshakeWithClientStage2() {
    if (SSL_accept(clientSession) == 0) {
        Logger::logError("SSL Accept Failed!");
        throw SSLConnectionError();
    }
}

void SSLBridge::handshakeWithClientStage3() {
    Certificate *leaf;
    std::list<Certificate*> *chain;

    ip::tcp::endpoint endpoint = getRemoteEndpoint();
    mManager->getCertificateForTarget(endpoint, mWildcardOK, getServerCertificate(), &leaf, &chain);
    setServerName();
    SSL_CTX *new_ctx = SSL_CTX_new(SSLv23_server_method());
    //SSL_CTX_set_cipher_list(new_ctx, "LOW");
    buildClientContext(new_ctx, leaf, chain);
    SSL_set_SSL_CTX(clientSession, new_ctx);
}

void SSLBridge::handshakeWithClient(CertificateManager &manager, bool wildcardOK) {
    Certificate *leaf;
    std::list<Certificate*> *chain;
    log_trace(stdout, "[%s]Enter\n", __FUNCTION__);

    ip::tcp::endpoint endpoint = getRemoteEndpoint();
    manager.getCertificateForTarget(endpoint, wildcardOK, getServerCertificate(), &leaf, &chain);

    setServerName();

    SSL_CTX *clientContext = SSL_CTX_new(SSLv23_server_method());
    buildClientContext(clientContext, leaf, chain);

    SSL *clientSession = SSL_new(clientContext);
    SSL_set_fd(clientSession, clientSocket->native());

    if (SSL_accept(clientSession) == 0) {
        Logger::logError("SSL Accept Failed!");
        throw SSLConnectionError();
    }

    this->clientSession = clientSession;
}

void SSLBridge::handshakeWithServer() {
  int bogus;

  ip::address_v4 serverAddress = serverSocket->remote_endpoint().address().to_v4();
  SSL_CTX *serverCtx           = SSL_CTX_new(SSLv23_client_method());;
  SSL *serverSession           = SSL_new(serverCtx);;
  SSL_SESSION *sessionId       = cache->getSessionId(serverSession, 
						     serverAddress.to_bytes().data(), 
						     serverAddress.to_bytes().size(),
						     &bogus);

  if (sessionId != NULL) {
    SSL_set_session(serverSession, sessionId);
    SSL_SESSION_free(sessionId);
  }

  //disable v1.1 and v1.2
  //SSL_CTX_set_options(serverCtx, SSL_OP_NO_TLSv1_1);
  //SSL_CTX_set_options(serverCtx, SSL_OP_NO_TLSv1_2);
  //

  SSL_set_connect_state(serverSession);
  SSL_set_fd(serverSession, serverSocket->native());
  SSL_set_options(serverSession, SSL_OP_ALL);

  if (mHostname.length() > 0) {
      SSL_set_tlsext_host_name(serverSession, mHostname.c_str());
  }
  
  if (SSL_connect(serverSession) < 0) {
    Logger::logError("Error on SSL Connect.");
    throw SSLConnectionError();
  }

  cache->setNewSessionId(serverSession, SSL_get1_session(serverSession), 
			 serverAddress.to_bytes().data(), 
			 serverAddress.to_bytes().size());

  this->serverSession = serverSession;
}

void SSLBridge::BuildMiddleSessions(CertificateManager &manager, bool wildcardOK) {
    this->mManager = &manager;
    this->mWildcardOK = wildcardOK;
    handshakeWithClientStage1();
    handshakeWithClientStage2();
}

int SSL_write_safe(SSL *ssl, const void *buf, int num)
{
    int n;
    int e;
    int off;
    int back;
    n = 0;
    off = 0;
    back = 1;
    while (off < num && back < 6*1000)
    {
        n = SSL_write(ssl, buf, num);
        if (n > 0)
        {
            off += n;
            back = 1;
        }
        else
        {
            e = SSL_get_error(ssl, n);
            if (e == SSL_ERROR_WANT_WRITE)
            {
                usleep(1000 * back);
            }
            else
            {
                off = n;
                break;
            }
        }
    }
    return off;
}

void SSLBridge::shuttleData() {
  struct pollfd fds[2] = {{clientSocket->native(), POLLIN | POLLPRI | POLLHUP | POLLERR, 0},
			  {serverSocket->native(), POLLIN | POLLPRI | POLLHUP | POLLERR, 0}};

  unsigned int cur_time;
  char filename[260];
  session_id = __sync_add_and_fetch(&g_session_id, 1);
  cur_time = time(NULL);
  sprintf(filename,
    "%s/%s_%d-%s_%d-%x-%s%x.data", 
    g_datadir,
    this->getClientEndpoint().address().to_string().c_str(), 
    this->getClientEndpoint().port(),
    this->getRemoteEndpoint().address().to_string().c_str(),
    this->getRemoteEndpoint().port(),
    cur_time,
    "c",
    session_id);

  this->client_fp = fopen(filename, "wb"); 
  sprintf(filename,
      "%s/%s_%d-%s_%d-%x-%s%x.data",
      g_datadir,
      this->getClientEndpoint().address().to_string().c_str(),
      this->getClientEndpoint().port(),
      this->getRemoteEndpoint().address().to_string().c_str(),
      this->getRemoteEndpoint().port(),
      cur_time,
      "s",
      session_id);
  this->server_fp = fopen(filename, "wb");

  socket_dumper_init(&this->dumper,
      session_id,
      inet_addr(this->getClientEndpoint().address().to_string().c_str()),
      htons(this->getClientEndpoint().port()),
      inet_addr(this->getRemoteEndpoint().address().to_string().c_str()),
      htons(this->getRemoteEndpoint().port()),
      pcap_dumper);

  for (;;) {
    if (poll(fds, 2, -1) < 0)        break; //return;
    if (isAvailable(fds[0].revents)) if (!readFromClient()) break; //return;
    if (isAvailable(fds[1].revents)) if (!readFromServer()) break; //return;
    if (isClosed(fds[0].revents))    break; //return;
    if (isClosed(fds[1].revents))    break; //return;
  }
  
  if(this->client_fp != NULL) {
    fclose(this->client_fp);
  }
  if(this->server_fp != NULL) {
    fclose(this->server_fp);
  }  
  socket_dumper_close(&dumper);
}

int SSLBridge::isAvailable(int revents) {
  return revents & POLLIN || revents & POLLPRI;
}

int SSLBridge::isClosed(int revents) {
  return revents & POLLERR || revents & POLLHUP;
}

bool SSLBridge::readFromClient() {
  char buf[4096+1];
  int bytesRead;
  int bytesWritten;
  int ssl_err;
  HANDLER_USER_CONTEXT handler_ctx;

  log_debug(stdout, "[%s]->.\n", __FUNCTION__);
  
  do {
    if ((bytesRead = SSL_read(clientSession, buf, sizeof(buf) - 1)) <= 0)   
    	{
        ssl_err = SSL_get_error(clientSession, bytesRead);
    	log_error(stderr, 
            "[%s]SSL_read failed, bytesRead: %d, Error code: %d.\n", 
            __FUNCTION__, 
            bytesRead, 
            ssl_err);
      //return SSL_get_error(clientSession, bytesRead) == SSL_ERROR_WANT_READ ? true : false;
        return ssl_err == SSL_ERROR_WANT_READ ? true : false;
    	}

        if (bytesRead < sizeof(buf)) {
            buf[bytesRead] = '\0';
        }

        handler_ctx.from = clientSession;
        handler_ctx.to = serverSession;
        handler_ctx.send_cb = (void *(*)(void*, unsigned char*, int))SSL_write_safe;
        if (FILTER_DROP == lock_filter_data(&g_vars.client_rules, 
            (unsigned char *)buf, 
            bytesRead, 
            &handler_ctx))
        {
            return false;
        }
        
        fwrite(buf, 1, bytesRead, client_fp);

        pthread_mutex_lock(&json_mutex);
        json_write(json_fp,
            session_id,
            this->getClientEndpoint().address().to_string().c_str(),
            this->getClientEndpoint().port(),
            this->getRemoteEndpoint().address().to_string().c_str(),
            this->getRemoteEndpoint().port(),
            buf,
            bytesRead);
        pthread_mutex_unlock(&json_mutex);

        pthread_mutex_lock(&pcap_mutex);
        socket_dumper_send(&dumper, (unsigned char *)buf, bytesRead);
        pthread_mutex_unlock(&pcap_mutex);

        if ((bytesWritten = SSL_write_safe(serverSession, buf, bytesRead)) < bytesRead)
    	{
            ssl_err = SSL_get_error(clientSession, bytesWritten);
            log_error(stderr, 
                "[%s]SSL_write failed, bytesRead: %d, bytesWritten: %d, Error code: %d.\n", 
                __FUNCTION__, 
                bytesRead, 
                bytesWritten, 
                ssl_err);
            return false; // FIXME
    	}

    Logger::logFromClient(serverName, buf, bytesRead);

  } while (SSL_pending(clientSession));

  log_debug(stdout, "[%s]<-.\n", __FUNCTION__);

  return true;
}

bool SSLBridge::readFromServer() {
  char buf[4096+1];
  int bytesRead;
  int bytesWritten;
  int ssl_err;
  unsigned char *pmatch;
  int pattern_len;
  HANDLER_USER_CONTEXT handler_ctx;

  do {
    if ((bytesRead    = SSL_read(serverSession, buf, sizeof(buf) - 1)) <= 0)
    	{
        ssl_err = SSL_get_error(clientSession, bytesRead);
        log_error(stderr, 
            "[%s]SSL_read failed, bytesRead: %d, Error code: %d.\n", 
            __FUNCTION__, 
            bytesRead, 
            ssl_err);
      //return SSL_get_error(serverSession, bytesRead) == SSL_ERROR_WANT_READ ? true : false;
        return ssl_err == SSL_ERROR_WANT_READ ? true : false;
    	}

        if (bytesRead < sizeof(buf)) {
            buf[bytesRead] = '\0';
        }

        handler_ctx.from = serverSession;
        handler_ctx.to = clientSession;
        handler_ctx.send_cb = (void *(*)(void*, unsigned char*, int))SSL_write_safe;
        if (FILTER_DROP == lock_filter_data(&g_vars.server_rules, 
            (unsigned char *)buf, 
            bytesRead, 
            &handler_ctx))
        {
            return false;
        }

        fwrite(buf, 1, bytesRead, server_fp);

        pthread_mutex_lock(&json_mutex);
        json_write(json_fp,
            session_id,
            this->getRemoteEndpoint().address().to_string().c_str(),
            this->getRemoteEndpoint().port(),
            this->getClientEndpoint().address().to_string().c_str(),
            this->getClientEndpoint().port(),
            buf,
            bytesRead);
        pthread_mutex_unlock(&json_mutex);

        pthread_mutex_lock(&pcap_mutex);
        socket_dumper_recv(&dumper, (unsigned char *)buf, bytesRead);
        pthread_mutex_unlock(&pcap_mutex);

        if ((bytesWritten = SSL_write_safe(clientSession, buf, bytesRead)) < bytesRead)
    	{
            ssl_err = SSL_get_error(clientSession, bytesWritten);
            log_error(stderr, 
                "[%s]SSL_write failed, bytesRead: %d, bytesWritten: %d, Error code: %d.\n", 
                __FUNCTION__, 
                bytesRead, 
                bytesWritten, 
                ssl_err);
            return false; // FIXME
    	}

    Logger::logFromServer(serverName, buf, bytesRead);
  } while (SSL_pending(serverSession));

  return true;
}

void SSLBridge::close() {
  if (closed)        return;
  else               closed = true;

  if (serverSession) SSL_free(serverSession);
  if (clientSession) SSL_free(clientSession);
  
  clientSocket->close();
  serverSocket->close();
}

