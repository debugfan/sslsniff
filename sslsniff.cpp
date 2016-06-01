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

#include <openssl/ssl.h>

#include <string>
#include <sys/types.h>
#include <unistd.h>

#include <boost/asio.hpp>

#include "SSLConnectionManager.hpp"
#include "UpdateManager.hpp"
#include "http/HttpConnectionManager.hpp"
#include "certificate/TargetedCertificateManager.hpp"
#include "certificate/AuthorityCertificateManager.hpp"
#include "sslsniff.hpp"
#include "Logger.hpp"
#include "FingerprintManager.hpp"
#include "util/debug.h"
#include "util/sys_utils.h"
#include "util/json_helper.h"
#include "util/dump_socket.h"
#include "util/yara_utils.h"
#include "global.h"

static void printUsage(char *command) {
  fprintf(stderr, "Usage: %s [options]\n\n"
	  "Modes:\n"
	  "-a\tAuthority mode.  Specify a certificate that will act as a CA.\n"
	  "-t\tTargeted mode.  Specify a directory full of certificates to target.\n\n"
	  "Required Options:\n" 
	  "-c <file|directory>\tFile containing CA cert/key (authority mode) or \n\t\t\tdirectory containing a collection of certs/keys\n\t\t\t(targeted mode)\n"
	  "-s <port>\t\tPort to listen on for SSL interception.\n"
	  "-w <file>\t\tFile to log to\n"
	  "\nOptional Options:\n"
	  "-u <updateLocation>\tLoction of any Firefox XML update files.\n"
	  "-m <certificateChain>\tLocation of any intermediary certificates.\n"
	  "-h <port>\t\tPort to listen on for HTTP interception (required for\n\t\t\tfingerprinting).\n"
	  "-f <ff,ie,safari,opera,ios>\tOnly intercept requests from the specified browser(s).\n"
	  "-d\t\t\tDeny OCSP requests for our certificates.\n"
	  "-p\t\t\tOnly log HTTP POSTs\n"
	  "-e <url>\t\tIntercept Mozilla Addon Updates\n"
	  "-j <sha256>\t\tThe sha256sum value of the addon to inject\n\n", command);
  exit(1);
}

static bool isOptionsValid(Options &options) {
  //if (options.certificateLocation.empty()   || 
  //    options.sslListenPort == -1           || 
  //    options.logLocation.empty())             return false;  // No cert, listen port, or log.
  if (options.certificateLocation.empty()   || 
      options.sslListenPort == -1)             return false;  // No cert, listen port, or log.
  else if (options.httpListenPort == -1     &&
	   !options.fingerprintList.empty())   return false;  // Fingerprinting but no http port.
  else if (options.httpListenPort != -1     &&
	   options.fingerprintList.empty())    return false;  // Http port but no fingerprinting.
  else if (!options.addonLocation.empty()   &&
	   options.addonHash.empty())          return false;
  else                                         return true;
}

static void set_output_filenames(const char *dirname)
{
    char filename[260];
    time_t utm = time(NULL);
    struct tm *stm = localtime(&utm);

    if (g_vars.log_file.length() <= 0) {
        sprintf(filename, "%s/ss%04d%02d%02d%02d%02d%02d.log",
            dirname,
            stm->tm_year + 1900,
            stm->tm_mon + 1,
            stm->tm_mday,
            stm->tm_hour,
            stm->tm_min,
            stm->tm_sec);
        g_vars.log_file = filename;
    }

    if (g_vars.json_file.length() <= 0) {
        sprintf(filename, "%s/ss%04d%02d%02d-%02d%02d%02d.json",
            dirname,
            stm->tm_year + 1900,
            stm->tm_mon + 1,
            stm->tm_mday,
            stm->tm_hour,
            stm->tm_min,
            stm->tm_sec);
        g_vars.json_file = filename;
    }

    if (g_vars.pcap_file.length() <= 0) {
        sprintf(filename, "%s/ss%04d%02d%02d-%02d%02d%02d.pcap",
            dirname,
            stm->tm_year + 1900,
            stm->tm_mon + 1,
            stm->tm_mday,
            stm->tm_hour,
            stm->tm_min,
            stm->tm_sec);
        g_vars.pcap_file = filename;
    }
}

static int parseArguments(int argc, char* argv[], Options &options) {
  int c;
  extern char *optarg;

  options.denyOCSP          = false;
  options.postOnly          = false;
  options.targetedMode      = false;
  options.sslListenPort     = -1;
  options.httpListenPort    = -1;
  options.httpsListenPort   = -1;
  options.datahome          = "output";
  options.rule_path = "etc/rules/";

  while ((c = getopt(argc, argv, "ats:h:c:w:f:m:u:pdj:e:o:y:r:")) != -1) {
    switch (c) {
    case 'w': options.logLocation         = std::string(optarg); break;
    case 'a': options.targetedMode        = false;               break;
    case 't': options.targetedMode        = true;                break;
    case 'c': options.certificateLocation = std::string(optarg); break;
    case 's': options.sslListenPort       = atoi(optarg);        break;
    case 'h': options.httpListenPort      = atoi(optarg);        break;
    case 'y': options.httpsListenPort     = atoi(optarg);        break;
    case 'f': options.fingerprintList     = std::string(optarg); break;
    case 'm': options.chainLocation       = std::string(optarg); break;
    case 'p': options.postOnly            = true;                break;
    case 'u': options.updateLocation      = std::string(optarg); break;
    case 'd': options.denyOCSP            = true;                break;
    case 'e': options.addonLocation       = std::string(optarg); break;
    case 'j': options.addonHash           = std::string(optarg); break;
    case 'o': options.datahome             = std::string(optarg); break;
    case 'r': options.rule_path = std::string(optarg); break;
    default:
      return -1;
    }
  }
    
    char final_datadir[260];
    time_t utm = time(NULL);
    struct tm *stm = localtime(&utm);
    sprintf(final_datadir, 
        "%s/%04d%02d%02d-%02d%02d%02d",
        options.datahome.c_str(),
        stm->tm_year+1900,
        stm->tm_mon+1,
        stm->tm_mday,
        stm->tm_hour,
        stm->tm_min,
        stm->tm_sec);
    strcpy(g_datadir, final_datadir);
    if (0 != multi_mkdir(g_datadir, 0755)) {
        printf("mkdir failed: %s. err: %s\n", g_datadir, strerror(errno));
        return -1;
    }

    set_output_filenames(g_datadir);

  if (isOptionsValid(options)) return 1;
  else                         return -1;	 
}

static void initializeOpenSSL() {
  SSL_library_init();
  SSL_load_error_strings();
}

static void initializeLogging(Options &options) {
  Logger::initialize(options.logLocation, options.postOnly);
  //json_fp = fopen(options.jsonLocation.c_str(), "w");
  json_fp = fopen(g_vars.json_file.c_str(), "w");
  if (json_fp == NULL)
  {
      fprintf(stderr, 
          "Unable to open file %s\n", 
          g_vars.json_file.c_str());
  }
  //pcap_dumper = open_pcap_file(options.pcapLocation.c_str());
  pcap_dumper = open_pcap_file(g_vars.pcap_file.c_str());
  if (pcap_dumper == NULL)
  {
      fprintf(stderr, 
          "Unable to open dump file %s\n", 
          g_vars.pcap_file.c_str());
  }
}

static CertificateManager* initializeCertificateManager(Options &options) {
  if (options.targetedMode) return new TargetedCertificateManager(options.certificateLocation,
								  options.chainLocation);
  else                      return new AuthorityCertificateManager(options.certificateLocation,
								   options.chainLocation);
}

int main(int argc, char* argv[]) {
  Options options;
  boost::asio::io_service io_service;
  //return test_filter();

  if (parseArguments(argc, argv, options) < 0) {
    printUsage(argv[0]);
  }

  initializeLogging(options);
  initializeOpenSSL();
  yr_initialize();
  g_vars.client_rules.rules = parse_rule_file((options.rule_path + "client.rules").c_str());
  g_vars.client_rules.mutex = PTHREAD_MUTEX_INITIALIZER;
  g_vars.server_rules.rules = parse_rule_file((options.rule_path + "server.rules").c_str());
  g_vars.server_rules.mutex = PTHREAD_MUTEX_INITIALIZER;

  log_debug(stdout, "options.chainLocation: %s\n", options.chainLocation.c_str());

  CertificateManager *certs = initializeCertificateManager(options);  

  FingerprintManager::getInstance()->setValidUserAgents(options.fingerprintList);
  UpdateManager::getInstance()->initialize(options.updateLocation, options.addonLocation, options.addonHash);

  log_debug(stdout, 
      "httpListenPort: %d, sslListenPort: %d, httpsListenPort: %d\n", 
      options.httpListenPort, 
      options.sslListenPort,
      options.httpsListenPort);

  HttpConnectionManager httpConnectionManager(io_service, options.httpListenPort, *certs, options.denyOCSP);
  SSLConnectionManager sslConnectionManager(io_service, *certs, options.sslListenPort, SSL_TYPE_COMMON);
  SSLConnectionManager httpsConnectionManager(io_service, *certs, options.httpsListenPort, SSL_TYPE_HTTPS);
  
  std::cout << "sslsniff " << VERSION << " by Moxie Marlinspike running..." << std::endl;

  io_service.run();

  yr_finalize();

  return 1;
}
