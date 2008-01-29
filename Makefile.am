# $Id$
# Process this file with automake to produce Makefile.in
#
AM_CPPFLAGS = -DDATADIR=\"$(pkgdatadir)\"
#
bin_PROGRAMS = tcp-scan
#
dist_check_SCRIPTS = check-tcp-scan-run1
#
dist_man_MANS = tcp-scan.1
#
tcp_scan_SOURCES = tcp-scan.c tcp-scan.h error.c wrappers.c utils.c ip.h tcp.h mt19937ar.c
tcp_scan_LDADD = $(LIBOBJS)
#
dist_pkgdata_DATA = tcp-scan-services
#
TESTS = $(dist_check_SCRIPTS)
