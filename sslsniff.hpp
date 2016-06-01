#ifndef __SSLSNIFF_HPP__
#define __SSLSNIFF_HPP__

#include <openssl/ssl.h>
#include "util/yara_utils.h"

typedef struct {
  std::string updateLocation;
  std::string addonLocation;
  std::string addonHash;
  std::string chainLocation;
  std::string certificateLocation;
  std::string fingerprintList;
  std::string datahome;
  std::string rule_path;
  bool denyOCSP;
  bool postOnly;
  bool targetedMode;
  int sslListenPort;
  int httpListenPort;
  int httpsListenPort;
  std::string logLocation;
  //std::string jsonLocation;
  //std::string pcapLocation;
} Options;

#endif
