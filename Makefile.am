# $Id$
# Process this file with automake to produce Makefile.in
#
AUTOMAKE_OPTIONS = foreign
#
bin_PROGRAMS = tcp-scan icmp-scan
#
#generic_ip_scan_SOURCES = rawip-scan-engine.c rawip-scan-engine.h generic-ip-scan.c generic-ip-scan.h error.c wrappers.c
#generic_ip_scan_LDADD = @COMPAT_OBJS@
#generic_ip_scan_DEPENDENCIES = @COMPAT_OBJS@
#EXTRA_generic_ip_scan_SOURCES = getopt.c getopt.h getopt1.c
#
tcp_scan_SOURCES = rawip-scan-engine.c rawip-scan-engine.h tcp-scan.c tcp-scan.h error.c md5.c md5.h wrappers.c
tcp_scan_LDADD = @COMPAT_OBJS@
tcp_scan_DEPENDENCIES = @COMPAT_OBJS@
EXTRA_tcp_scan_SOURCES = getopt.c getopt.h getopt1.c
#
icmp_scan_SOURCES = rawip-scan-engine.c rawip-scan-engine.h icmp-scan.c icmp-scan.h error.c md5.c md5.h wrappers.c
icmp_scan_LDADD = @COMPAT_OBJS@
icmp_scan_DEPENDENCIES = @COMPAT_OBJS@
EXTRA_icmp_scan_SOURCES = getopt.c getopt.h getopt1.c
