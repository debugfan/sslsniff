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

#ifndef __UTIL_H__
#define __UTIL_H__

#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <list>

#include <boost/asio.hpp>
#include "debug.h"

class UnresolvableCertificateException : public std::exception {
public:
  virtual const char* what() const throw() {
    return "Could not resolve common name...";
  }
};

class Util {

public:
  
  template <class T>
  static bool fromString(T& t, 
			 std::string& s, 
			 std::ios_base& (*f)(std::ios_base&))
  {
    trimString(s);
    std::istringstream iss(s);
    return !(iss >> f >> t).fail();
  }

  static void trimString( std::string& str) {  
    size_t startpos = str.find_first_not_of(" \t\r\n");
    size_t endpos = str.find_last_not_of(" \t\r\n"); 
    
    if(( std::string::npos == startpos ) || ( std::string::npos == endpos)) 
      str = "";  
    else 
      str = str.substr( startpos, endpos-startpos+1 );
  }    

  static void tokenizeString(std::string &str, 
			     std::string &delimiters, 
			     std::vector<std::string> &tokens) 
  {
    std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
    std::string::size_type pos     = str.find_first_of(delimiters, lastPos);
    
    while (std::string::npos != pos || std::string::npos != lastPos) {
      tokens.push_back(str.substr(lastPos, pos - lastPos));
      lastPos = str.find_first_not_of(delimiters, pos);
      pos     = str.find_first_of(delimiters, lastPos);
    }

    if (lastPos != std::string::npos)
      tokens.push_back(str.substr(lastPos));

  }

  static void resolveName(std::string &name, std::list<boost::asio::ip::address> &results) {
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service);

    log_debug(stdout, "Query name: %s\n", name.c_str());
	
    boost::asio::ip::tcp::resolver::query query(name, "https");    
    //boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
    boost::asio::ip::tcp::resolver::iterator endpoint_iterator;
    boost::asio::ip::tcp::resolver::iterator end;
    boost::asio::ip::address addr;
    
//    while (endpoint_iterator != end) {
////       std::cout << "Resolved To: " << (*endpoint_iterator).endpoint().address().to_string() << std::endl;
//      results.push_back((*endpoint_iterator++).endpoint().address());
//    }

    try
    {
        for (endpoint_iterator = resolver.resolve(query); endpoint_iterator != end; endpoint_iterator++)
        {
            addr = (*endpoint_iterator).endpoint().address();
            log_debug(stdout, "Resolved to ip: %s\n", addr.to_string().c_str());
            results.push_back(addr);
        }
    }
    catch (...)
    {
        log_error(stderr, "An error occured when resolving name: %s.\n", name.c_str());
    }
    
    //if (results.empty()) throw UnresolvableCertificateException();
    if (results.empty())
    {
        log_error(stderr, "results is empty. use 1.1.1.1 as a dummy\n");
        results.push_back(boost::asio::ip::address::from_string("1.1.1.1"));
    }
  }

};


#endif
