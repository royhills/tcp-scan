# $Id$
# Process this file with automake to produce Makefile.in
#
bin_PROGRAMS = sql-slammer-scan dns-scan
#
sql_slammer_scan_SOURCES = udp-scan-engine.c udp-scan-engine.h sql-slammer-scan.c sql-slammer-scan.h error.c
sql_slammer_scan_LDADD = @COMPAT_OBJS@
sql_slammer_scan_DEPENDENCIES = @COMPAT_OBJS@
EXTRA_sql_slammer_scan_SOURCES = getopt.c getopt.h getopt1.c
#
dns_scan_SOURCES = udp-scan-engine.c udp-scan-engine.h dns-scan.c dns-scan.h error.c
dns_scan_LDADD = @COMPAT_OBJS@ -lresolv /usr/lib/libresolv.a
dns_scan_DEPENDENCIES = @COMPAT_OBJS@
EXTRA_dns_scan_SOURCES = getopt.c getopt.h getopt1.c
