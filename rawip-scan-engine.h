/*
 * The UDP Scan Engine (udp-scan-engine) is Copyright (C) 2003 Roy Hills,
 * NTA Monitor Ltd.
 *
 * $Id$
 *
 * udp-scan-engine.h -- Header file for UDP Scan Engine
 *
 * Author:	Roy Hills
 * Date:	20 February 2003
 *
 * This header file contains definitions required by both the generic UDP scan
 * engine and also the protocol-specific code.
 */

/* Includes */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <math.h>
#else
#error This program requires the ANSI C Headers
#endif

#include <sys/types.h>  /* FreeBSD needs explicit include for sys/types.h */

#ifdef __CYGWIN__
#include <windows.h>	/* Include windows.h if compiling under Cygwin */
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
/* Include getopt.h for the sake of getopt_long.
   We don't need the declaration of getopt, and it could conflict
   with something from a system header file, so effectively nullify that.  */
#define getopt getopt_loser
#include "getopt.h"
#undef getopt
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>	/* For struct sockaddr */
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define MAXUDP 65507			/* Max UDP data size = 64k - 20 - 8 */
#define SYSLOG 1			/* Use syslog if defined */
#define SYSLOG_FACILITY LOG_USER	/* Syslog facility to use */

/* Structures */
struct host_entry {
   struct host_entry *prev;	/* Previous pointer */
   struct host_entry *next;	/* Next pointer */
   unsigned n;			/* Ordinal number for this entry */
   struct in_addr addr;		/* Host IP address */
   u_char live;			/* Set when awaiting response */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   unsigned timeout;		/* Timeout for this host in ms */
   unsigned short num_sent;	/* Number of packets sent */
   unsigned short num_recv;	/* Number of packets received */
};

/* Functions */

void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void info_syslog(const char *, ...);
void err_print(int, int, const char *, va_list);
void usage(void);
void add_host(char *, unsigned);
void send_packet(int, struct host_entry *, int, struct timeval *);
int recvfrom_wto(int, char *, int, struct sockaddr *, int);
void remove_host(struct host_entry *);
void timeval_diff(struct timeval *, struct timeval *, struct timeval *);
struct host_entry *find_host_by_ip(struct host_entry *, struct in_addr *);
void display_packet(int, char *, struct host_entry *, struct in_addr *, unsigned *);
void advance_cursor(void);
void dump_list(void);
void print_times(void);
void initialise(void);
void clean_up(void);
void udp_scan_version(void);
void local_version(void);
