AC_INIT([Bitpeer], [0.1])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_HEADERS([config.h])

AC_PROG_CC_C99
AM_PROG_CC_C_O

PKG_CHECK_MODULES([openssl], [libcrypto])
AC_CHECK_LIB([crypto], [SHA256_Init], [], [AC_MSG_ERROR([libcrpyto not found])])
AC_CHECK_HEADERS([openssl/sha.h], [], [AC_MSG_ERROR([openssl headers not found])])

PKG_CHECK_MODULES([libevent], [libevent >= 2.1])
AC_CHECK_HEADERS([event2/buffer.h], [], [AC_MSG_ERROR([libevent headers not found])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
