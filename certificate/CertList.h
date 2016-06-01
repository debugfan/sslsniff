#ifndef CERT_LIST_H
#define CERT_LIST_H

#include <list>
#include <map>
#include <string>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <boost/asio.hpp>

#include "Certificate.hpp"

void set_gencerts_dir(const char *dirname);
void load_gencerts();

bool save_cert(const boost::asio::ip::tcp::endpoint &endpoint, Certificate* cert);
Certificate *find_cert(const boost::asio::ip::tcp::endpoint &endpoint);

#endif
