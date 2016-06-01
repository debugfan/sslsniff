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

#include "CertificateManager.hpp"

Certificate* CertificateManager::readCredentialsFromFile(const path &file, bool resolve) {
  X509 *cert    = loadCertificateFromFile(system_complete(file).string().c_str());
  EVP_PKEY *key = loadKeyFromFile(system_complete(file).string().c_str());

  if (!cert || !key) throw BadCertificateException();

  return new Certificate(cert, key, resolve);
}

X509* CertificateManager::loadCertificateFromFile(const char* file) {
  SSL_CTX *context = SSL_CTX_new(SSLv23_server_method());
  if(SSL_CTX_use_certificate_file(context, file, SSL_FILETYPE_PEM) < 0)
  	{
  		printf("SSL_CTX_use_certificate_file failed.\n");
  	}
 
  //return SSL_get_certificate(SSL_new(context));
  SSL*     tmp_ssl = SSL_new(context);
  if(tmp_ssl == NULL)
  	{
  		printf("SSL_new failed\n");
  	}
  	return SSL_get_certificate(tmp_ssl);
}

EVP_PKEY* CertificateManager::loadKeyFromFile(const char* file) {
  SSL_CTX *context = SSL_CTX_new(SSLv23_server_method());
  SSL_CTX_use_PrivateKey_file(context, file, SSL_FILETYPE_PEM);

  return SSL_get_privatekey(SSL_new(context));
}

