AM_CXXFLAGS = -g

bin_PROGRAMS = sslsniff

sslsniff_SOURCES = Bridge.hpp SSLConnectionManager.cpp FingerprintManager.hpp FirefoxAddonUpdater.hpp FirefoxUpdater.hpp HTTPSBridge.hpp Logger.hpp RawBridge.hpp SessionCache.hpp SSLBridge.hpp SSLConnectionManager.hpp sslsniff.hpp UpdateManager.hpp certificate/AuthorityCertificateManager.hpp certificate/Certificate.hpp certificate/CertificateManager.hpp certificate/TargetedCertificateManager.hpp http/HttpBridge.hpp http/HttpConnectionManager.hpp http/HttpHeaders.hpp http/OCSPDenier.hpp util/Destination.cpp util/Destination.hpp util/Util.hpp FirefoxUpdater.cpp Logger.cpp SessionCache.cpp SSLBridge.cpp HTTPSBridge.cpp sslsniff.cpp FingerprintManager.cpp certificate/AuthorityCertificateManager.cpp certificate/TargetedCertificateManager.cpp certificate/CertificateManager.cpp http/HttpBridge.cpp http/HttpConnectionManager.cpp http/HttpHeaders.cpp UpdateManager.cpp http/OCSPDenier.cpp FirefoxAddonUpdater.cpp certificate/CertList.cpp util/sys_utils.c util/yara_utils.cpp util/dump_socket.cpp util/packet_check.c util/json_helper.cpp http/ftrie.c http/http_template.c http/lstring.c http/mango.c global.cpp 

sslsniff_LDFLAGS = -lssl -lboost_filesystem -lpthread -lboost_thread -llog4cpp -lcrypto -lboost_system -lpcap -lyara

EXTRA_DIST = certs/wildcard IPSCACLASEA1.crt leafcert.pem updates/Darwin_Universal-gcc3.xml updates/Linux_x86-gcc3.xml updates/WINNT_x86-msvc.xml
