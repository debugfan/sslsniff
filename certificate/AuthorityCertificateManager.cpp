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

#include "AuthorityCertificateManager.hpp"
#include "CertList.h"
#include "../util/debug.h"

AuthorityCertificateManager::AuthorityCertificateManager(std::string &file, std::string &chain) {
  path certPath(file);
  path chainPath(chain);

  fprintf(stdout, "certPath: %s, chainPath: %s\n", file.c_str(), chain.c_str());
  this->authority = readCredentialsFromFile(certPath, false);
  chainList.push_back(this->authority);

  if (!chain.empty()) {
    Certificate *chain = readCredentialsFromFile(chainPath, false);
    chainList.push_back(chain);
  }

  this->leafPair  = buildKeysForClient();
  set_gencerts_dir("output");
  load_gencerts();
}

bool AuthorityCertificateManager::isOCSPAddress(boost::asio::ip::tcp::endpoint &endpoint) {
  boost::asio::ip::address address      = endpoint.address();
  return this->authority->isOCSPAddress(address);
}

bool AuthorityCertificateManager::isValidTarget(boost::asio::ip::tcp::endpoint &end, 
						bool wildcardOK) 
{
  return true;
}

#ifdef STACK_OF
#define STACK_OF(type) struct stack_st_##type
#endif

#ifndef EXTNAME_LEN
#define EXTNAME_LEN 256
#endif

int add_ext(X509 *cert, int nid, char *value)
	{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
	}

void AuthorityCertificateManager::getCertificateForTarget(boost::asio::ip::tcp::endpoint &endpoint,
							  bool wildcardOK,
							  X509 *serverCertificate,
							  Certificate **cert,
							  std::list<Certificate*> **chainList)
{
  *cert = find_cert(endpoint);
  if(*cert != NULL) 
  {
    *chainList = &(this->chainList);
    return;
  }
  
  X509_NAME *serverName   = X509_get_subject_name(serverCertificate);
  X509_NAME *issuerName   = X509_get_subject_name(authority->getCert());
  X509 *request           = X509_new();

  //X509_set_version(request, 3);
  X509_set_version(request, 2);
  X509_set_subject_name(request, serverName);
  X509_set_issuer_name(request, issuerName);

  ASN1_INTEGER_set(X509_get_serialNumber(request), generateRandomSerial());
  X509_gmtime_adj(X509_get_notBefore(request), -365);
  X509_gmtime_adj(X509_get_notAfter(request), (long)60*60*24*365);
  X509_set_pubkey(request, this->leafPair);

  if(1)
  	{
  		STACK_OF(X509_EXTENSION) *exts = serverCertificate->cert_info->extensions;

		int num_of_exts;
		if (exts) {       
			num_of_exts = sk_X509_EXTENSION_num(exts);
		} else {
			num_of_exts = 0;
		}

		log_trace(stdout, "num_of_exts: %d\n", num_of_exts);

		for (int i=0; i < num_of_exts; i++) {
				X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
				//IFNULL_FAIL(ex, "unable to extract extension from stack");
				if(ex == NULL)
					{
					printf("unable to extract extension from stack.\n");
					}
				ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
				//IFNULL_FAIL(obj, "unable to extract ASN1 object from extension");
				if(obj == NULL)
					{
					printf("unable to extract ASN1 object from extension.\n");
					}
			
				BIO *ext_bio = BIO_new(BIO_s_mem());
				//IFNULL_FAIL(ext_bio, "unable to allocate memory for extension value BIO");
				if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
					M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
				}
			
				BUF_MEM *bptr;
				BIO_get_mem_ptr(ext_bio, &bptr);
				BIO_set_close(ext_bio, BIO_NOCLOSE);

				#if 0
				// remove newlines
				int lastchar = bptr->length;
				if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
					printf("set null.\n");
					bptr->data[lastchar-1] = (char) 0;
				}
				if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
					printf("set null.\n");
					bptr->data[lastchar] = (char) 0;
				}
				#endif
			
				BIO_free(ext_bio);

				unsigned nid = OBJ_obj2nid(obj);
                log_trace(stdout, "nid: %u\n", nid);
				if (nid == NID_undef) {
					// no lookup found for the provided OID so nid came back as undefined.
					char extname[EXTNAME_LEN];
					OBJ_obj2txt(extname, EXTNAME_LEN, (const ASN1_OBJECT *) obj, 1);
                    log_trace(stdout, "extension name is %s\n", extname);
				} else {
					// the OID translated to a NID which implies that the OID has a known sn/ln
					const char *c_ext_name = OBJ_nid2ln(nid);
					//IFNULL_FAIL(c_ext_name, "invalid X509v3 extension name");
					if(c_ext_name == NULL)
						{
                            log_trace(stdout, "invalid X509v3 extension name\n");
						}
                    log_trace(stdout, "extension name is %s\n", c_ext_name);
				}
				
				log_trace(stdout, "extension length is %u\n", bptr->length);
                log_trace(stdout, "extension value is %s\n", bptr->data);

				if(nid == NID_subject_alt_name)
				{
					char *new_ptr = (char *)malloc(bptr->length+1);
					memcpy(new_ptr, bptr->data, bptr->length);
					new_ptr[bptr->length] = '\0';
					add_ext(request, nid, new_ptr);
					free(new_ptr);
				}
			}
  	}

#if 0
  	/* Add various extensions: standard extensions */
	add_ext(request, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(request, NID_key_usage, "critical,keyCertSign,cRLSign");

	add_ext(request, NID_subject_key_identifier, "hash");

	/* Some Netscape specific extensions */
	add_ext(request, NID_netscape_cert_type, "sslCA");

	add_ext(request, NID_netscape_comment, "example comment extension");

	if(authority->getKey() == NULL)
		{
			printf("getKey failed.\n");
		}
#endif	

  if(0 == X509_sign(request, authority->getKey(), EVP_sha256()))
  	{
  		log_error(stderr, "X509_sign failed.\n");
  	}

  if(X509_verify(request, authority->getKey()) <= 0)
  	{
        log_error(stderr, "X509_verify failed.\n");
  	}

  Certificate *leaf = new Certificate();
  leaf->setCert(request);
  leaf->setKey(this->leafPair);

  *cert  = leaf;
  *chainList = &(this->chainList);
  // *chain = this->authority;
  save_cert(endpoint, *cert);
}

unsigned int AuthorityCertificateManager::generateRandomSerial() {
  unsigned int serial;
  RAND_bytes((unsigned char*)&serial, sizeof(serial));

  return serial;
}

EVP_PKEY* AuthorityCertificateManager::buildKeysForClient() {
  RSA *rsaKeyPair          = RSA_generate_key(1024, RSA_F4, NULL, NULL);
  EVP_PKEY *rsaKeyPairSpec = EVP_PKEY_new();
  
  EVP_PKEY_assign_RSA(rsaKeyPairSpec, rsaKeyPair);

  return rsaKeyPairSpec;
}
