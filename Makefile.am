# $Id$
# Process this file with automake to produce Makefile.in
#
bin_PROGRAMS = generic-ip-scan tcp-scan
#
generic_ip_scan_SOURCES = rawip-scan-engine.c rawip-scan-engine.h generic-ip-scan.c generic-ip-scan.h error.c
generic_ip_scan_LDADD = @COMPAT_OBJS@
generic_ip_scan_DEPENDENCIES = @COMPAT_OBJS@
EXTRA_generic_ip_scan_SOURCES = getopt.c getopt.h getopt1.c
#
tcp_scan_SOURCES = rawip-scan-engine.c rawip-scan-engine.h tcp-scan.c tcp-scan.h error.c
tcp_scan_LDADD = @COMPAT_OBJS@
tcp_scan_DEPENDENCIES = @COMPAT_OBJS@
EXTRA_tcp_scan_SOURCES = getopt.c getopt.h getopt1.c
