# $Id$
# Process this file with automake to produce Makefile.in
#
bin_PROGRAMS = tcp-scan
#
dist_check_SCRIPTS = check-tcp-scan-run1
#
tcp_scan_SOURCES = rawip-scan-engine.c rawip-scan-engine.h tcp-scan.c tcp-scan.h error.c md5.c md5.h wrappers.c ip.h tcp.h
tcp_scan_LDADD = $(LIBOBJS)
tcp_scan_CPPFLAGS = -DLIST_ENTRY_NAME=\"ports\"
#
TESTS = $(dist_check_SCRIPTS)
