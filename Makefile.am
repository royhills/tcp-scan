# $Id$
# Process this file with automake to produce Makefile.in
#
AUTOMAKE_OPTIONS = foreign
#
bin_PROGRAMS = tcp-scan icmp-scan
#
dist_check_SCRIPTS = check-tcp-scan-run1 check-icmp-scan-run1
#
#generic_ip_scan_SOURCES = rawip-scan-engine.c rawip-scan-engine.h generic-ip-scan.c generic-ip-scan.h error.c wrappers.c
#
tcp_scan_SOURCES = rawip-scan-engine.c rawip-scan-engine.h tcp-scan.c tcp-scan.h error.c md5.c md5.h wrappers.c
tcp_scan_LDADD = $(LIBOBJS)
tcp_scan_CPPFLAGS = -DLIST_ENTRY_NAME=\"ports\"
#
icmp_scan_SOURCES = rawip-scan-engine.c rawip-scan-engine.h icmp-scan.c icmp-scan.h error.c md5.c md5.h wrappers.c
icmp_scan_LDADD = $(LIBOBJS)
icmp_scan_CPPFLAGS = -DLIST_ENTRY_NAME=\"hosts\"
#
TESTS = $(dist_check_SCRIPTS)
