AC_INIT([sslsniff], [0.8])
AC_CONFIG_SRCDIR([sslsniff.cpp])
AM_INIT_AUTOMAKE([subdir-objects])
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_LANG_CPLUSPLUS
AC_CHECK_HEADER([log4cpp/Category.hh],
	[],
	AC_MSG_ERROR([log4cpp library is not installed.]))
AC_CHECK_HEADER([boost/asio.hpp],
	[],
	AC_MSG_ERROR([libboost1.35-dev library is not installed.]))
AC_CHECK_HEADER([boost/filesystem.hpp],
	[],
	AC_MSG_ERROR([libboost-filesystem1.35-dev library is not installed.]))
AC_CHECK_HEADER([boost/thread.hpp],
	[],
	AC_MSG_ERROR([libboost-thread1.35-dev library is not installed.]))
AC_CHECK_HEADER([openssl/ssl.h],
	[],
	AC_MSG_ERROR([openssl (libssl-dev) library not installed.]))
AC_CHECK_HEADER([yara.h],
	[],
	AC_MSG_ERROR([yara library not installed.]))    
AC_OUTPUT(Makefile)
