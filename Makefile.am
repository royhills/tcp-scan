# $Id$
# Process this file with automake to produce Makefile.in
#
bin_PROGRAMS = tcp-scan
#
dist_check_SCRIPTS = check-tcp-scan-run1
#
tcp_scan_SOURCES = tcp-scan.c tcp-scan.h error.c md5.c md5.h wrappers.c utils.c ip.h tcp.h mt19937ar.c
tcp_scan_LDADD = $(LIBOBJS)
#
TESTS = $(dist_check_SCRIPTS)
