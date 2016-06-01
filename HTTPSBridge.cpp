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

#include "HTTPSBridge.hpp"
#include <string.h>

using namespace boost::asio;

void HTTPSBridge::buildRequestFromHeaders(HttpHeaders &headers, std::string &request) {

	printf("[%s]->.\n", __FUNCTION__);
	
  std::ostringstream requestStream;
  requestStream << headers.getMethod()  << " "
	  << headers.getRequest() << " "
	  //<< "HTTP/1.0\r\n";
      << headers.getVersion() << "\r\n";
      
  std::map<std::string,std::string>::iterator iter;
  std::map<std::string,std::string,ci_less>& headersMap = headers.getHeaders();
  for( iter = headersMap.begin(); iter != headersMap.end(); ++iter ) {
    std::string key   = iter->first;
    std::string value = iter->second;

    Util::trimString(key);
    Util::trimString(value);
#ifdef NO_HTTP_1_1   
    if (key != "Accept-Encoding" && key != "Connection" && key != "Keep-Alive")
      requestStream << key << ": " << value << "\r\n";
#endif
    requestStream << key << ": " << value << "\r\n";    
  }
  
#ifdef NO_HTTP_1_1  
  requestStream << "Connection: Close" << "\r\n\r\n";
#endif  

  requestStream << "\r\n";
  
  if (headers.isPost()) requestStream << headers.getPostData();

  request = requestStream.str();
}

bool HTTPSBridge::readFromClient() {
  char buf[4096];
  int bytesRead;
  int bytesWritten;
  int error_code;

  printf("[%s]->.\n", __FUNCTION__);
  memset(buf, 0, sizeof(buf));

  do {
    if ((bytesRead = SSL_read(clientSession, buf, sizeof(buf))) <= 0) 
    	{
    	error_code = SSL_get_error(clientSession, bytesRead);
    	printf("[%s]SSL_read failed, bytesRead: %d, error_code: %d.\n", __FUNCTION__, bytesRead, error_code);
        //return error_code == SSL_ERROR_WANT_READ ? true : false;
        if(error_code == SSL_ERROR_WANT_READ) {
            return true;
        }
        //if(error_code == SSL_ERROR_ZERO_RETURN) {
        //    return true;
        //}
        return false;
    	}

	printf("[%s]bytesRead: %d.\n", __FUNCTION__, bytesRead);
	printf("[%s]Read: ->\n", __FUNCTION__);
	printf("%s\n", buf);
	printf("[%s]<-\n", __FUNCTION__);
    Logger::logFromClient(serverName, buf, bytesRead);

    if (headers.process(buf, bytesRead)) {
      std::string request;

      buildRequestFromHeaders(headers, request);
	  printf("[%s]Build: ->\n", __FUNCTION__);
	  printf("%s\n", request.c_str());
	  printf("[%s]<-\n", __FUNCTION__);
      SSL_write(serverSession, request.c_str(), request.length());

      if (headers.isPost()) Logger::logFromClient(serverName, headers);
     
      headers.resetif();
    }
  } while (SSL_pending(serverSession));

  return true;
}
