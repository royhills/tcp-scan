dnl $Id$
dnl Process this file with autoconf to produce a configure script.

AC_INIT([tcp-scan], [1.14], [tcp-scan@nta-monitor.com])
AC_PREREQ(2.59)
AC_REVISION($Revision$)
AC_CONFIG_SRCDIR([tcp-scan.c])
AM_INIT_AUTOMAKE(1.9)

AM_CONFIG_HEADER([config.h])

dnl Checks for programs.
AC_PROG_CC
 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
 fi
AC_PROG_INSTALL
AC_PROG_LN_S
dnl Check endian-ness. MD5 and SHA1 hash functions need to know this.
AC_C_BIGENDIAN

dnl Checks for libraries.
dnl Solaris 8 needs nsl and socket.  Linux and {Free,Open}BSD do not.
dnl Just about everything will need pcap.
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([pcap_open_live], [pcap])

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h sys/socket.h sys/time.h unistd.h getopt.h pcap.h sys/ioctl.h net/if.h sys/utsname.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Check for the uint{8,16,32}_t types and, if we don't have them, define
dnl them using types which will work on most systems.
AC_NTA_CHECK_TYPE(uint8_t, unsigned char)
AC_NTA_CHECK_TYPE(uint16_t, unsigned short)
AC_NTA_CHECK_TYPE(uint32_t, unsigned int)

dnl Checks for 64-bit integer types.  These checks are from postgresql.
dnl Check to see if we have a working 64-bit integer type.
dnl This breaks down into two steps:
dnl (1) figure out if the compiler has a 64-bit int type with working
dnl arithmetic, and if so
dnl (2) see whether snprintf() can format the type correctly.

PGAC_TYPE_64BIT_INT([long int])

if test x"$HAVE_LONG_INT_64" = x"yes" ; then
  INT64_TYPE="long int"
  UINT64_TYPE="unsigned long int"
else
  PGAC_TYPE_64BIT_INT([long long int])
    if test x"$HAVE_LONG_LONG_INT_64" = x"yes" ; then
      INT64_TYPE="long long int"
      UINT64_TYPE="unsigned long long int"
    else
      AC_MSG_ERROR([cannot determine 64-bit integer type])
    fi
fi

AC_DEFINE_UNQUOTED(ARP_INT64, $INT64_TYPE,
                   [Define to the appropriate type for 64-bit ints.])
AC_DEFINE_UNQUOTED(ARP_UINT64, $UINT64_TYPE,
                   [Define to the appropriate type for unsigned 64-bit ints.])

dnl If we found "long int" is 64 bits, assume snprintf handles it.  If
dnl we found we need to use "long long int", better check.  We cope with
dnl snprintfs that use %lld, %qd, or %I64d as the format.
dnl
if test "$HAVE_LONG_LONG_INT_64" = yes ; then
  PGAC_FUNC_SNPRINTF_LONG_LONG_INT_FORMAT
  if test "$LONG_LONG_INT_FORMAT" = ""; then
    AC_MSG_ERROR([cannot determine snprintf format string for long long int])
  fi
  LONG_LONG_UINT_FORMAT=`echo "$LONG_LONG_INT_FORMAT" | sed 's/d$/u/'`
  INT64_FORMAT="\"$LONG_LONG_INT_FORMAT\""
  UINT64_FORMAT="\"$LONG_LONG_UINT_FORMAT\""
else
  # Here if we are not using 'long long int' at all
  INT64_FORMAT='"%ld"'
  UINT64_FORMAT='"%lu"'
fi

AC_DEFINE_UNQUOTED(ARP_INT64_FORMAT, $INT64_FORMAT,
                   [Define to the appropriate snprintf format for 64-bit ints.])

AC_DEFINE_UNQUOTED(ARP_UINT64_FORMAT, $UINT64_FORMAT,
                   [Define to the appropriate snprintf format for unsigned 64-bit ints.])

dnl Checks for library functions.
AC_CHECK_FUNCS([malloc gethostbyname gettimeofday inet_ntoa memset select socket strerror])

dnl Determine type for 3rd arg to accept()
dnl This is normally socklen_t, but can sometimes be size_t or int.
AC_NTA_NET_SIZE_T

dnl Check if the Posix regular expression functions "regcomp" and "regexec"
dnl and the header file "regex.h" are present.
AC_MSG_CHECKING([for posix regular expression support])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <regex.h>]],
[[regcomp(0, 0, 0);
regexec(0, 0, 0, 0, 0)]])],
[ac_nta_posix_regex=yes],
[ac_nta_posic_regex=no])
AC_MSG_RESULT([$ac_nta_posix_regex])
if test $ac_nta_posix_regex = no; then
   AC_MSG_ERROR([You don't seem to have posix regular expression support])
else
   AC_DEFINE(HAVE_REGEX_H, 1, [Define to 1 if you have posix regex support])
fi

dnl GNU systems e.g. Linux have getopt_long_only, but many other systems
dnl e.g. FreeBSD 4.3 and Solaris 8 do not.  For systems that don't have it,
dnl use the GNU getopt sources (obtained from glibc).
AC_CHECK_FUNC([getopt_long_only], ,
  [ AC_LIBOBJ(getopt)
    AC_LIBOBJ(getopt1)
    AC_LIBSOURCE(getopt.h) ])

dnl Check for strlcat and strlcpy.  If we don't have them, use the replacement
dnl functions from OpenBSD.  Most modern C libraries have these functions,
dnl but some such as as glibc don't.
AC_CHECK_FUNC([strlcat],
              [AC_DEFINE(HAVE_STRLCAT, 1, [Define to 1 if the C library includes the strlcat function])],
              [AC_LIBOBJ(strlcat)])
AC_CHECK_FUNC([strlcpy],
              [AC_DEFINE(HAVE_STRLCPY, 1, [Define to 1 if the C library includes the strlcpy function])],
              [AC_LIBOBJ(strlcpy)])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
