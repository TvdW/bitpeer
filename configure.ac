AC_INIT([Bitpeer], [0.1])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_HEADERS([config.h])

AC_PROG_CC_C99
AM_PROG_CC_C_O

AC_CHECK_LIB([ssl], [SHA256_Init])
AC_CHECK_HEADERS([openssl/sha.h])

AC_CHECK_LIB([event], [bufferevent_write])
AC_CHECK_HEADERS([event2/event.h])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
