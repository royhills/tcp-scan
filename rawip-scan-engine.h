/*
 * The TCP Scanner (tcp-scan) is Copyright (C) 2003-2007 Roy Hills,
 * NTA Monitor Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * $Id$
 *
 * rawip-scan-engine.h -- Header file for RAWIP Scan Engine
 *
 * Author:	Roy Hills
 * Date:	20 February 2003
 *
 * This header file contains definitions required by both the generic RAWIP scan
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

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define MAXIP 65515			/* Max IP data size = 64k - 20 */
#define REALLOC_COUNT 1000		/* Entries to realloc at once */
#define DEFAULT_BANDWIDTH 56000		/* Default bandwidth in bits/sec */
#define MINIMUM_FRAME_SIZE 46		/* Minimum data size for layer 2 */
#define PACKET_OVERHEAD 18		/* Size of Ethernet header */

/* Structures */
typedef union {
   struct in_addr v4;
   struct in6_addr v6;
} ip_address;

struct host_entry {
   unsigned n;			/* Ordinal number for this entry */
   unsigned timeout;		/* Timeout for this host in us */
   ip_address addr;		/* Host IP address */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   unsigned short num_sent;	/* Number of packets sent */
   unsigned short num_recv;	/* Number of packets received */
   uint16_t dport;		/* Destination port */
   unsigned char live;		/* Set when awaiting response */
};

/* Functions */

void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void info_syslog(const char *, ...);
void err_print(int, const char *, va_list);
void usage(int);
void add_host(char *, unsigned);
int send_packet(int, struct host_entry *, int, struct timeval *);
void recvfrom_wto(int, unsigned char *, int, struct sockaddr *, int);
void remove_host(struct host_entry **);
void timeval_diff(const struct timeval *, const struct timeval *,
                  struct timeval *);
struct host_entry *find_host(struct host_entry **, struct in_addr *,
                             const unsigned char *, int);
void display_packet(int, const unsigned char *, struct host_entry *,
                    struct in_addr *);
void advance_cursor(void);
void dump_list(void);
void print_times(void);
void initialise(void);
void clean_up(void);
void rawip_scan_version(void);
void local_version(void);
void local_help(void);
int local_add_host(char *, unsigned);
int local_find_host(struct host_entry **, struct host_entry **,
                    struct in_addr *, const unsigned char *, int);
char *make_message(const char *, ...);
char *printable(const unsigned char*, size_t);
void callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_options(int, char *[]);
int local_process_options(int, char *[]);
ip_address *get_host_address(const char *, int, ip_address *, char **);
const char *my_ntoa(ip_address);
/* Wrappers */
int Gettimeofday(struct timeval *);
void *Malloc(size_t);
void *Realloc(void *, size_t);
unsigned long int Strtoul(const char *, int);
/* The following functions are just to prevent rcsid being optimised away */
void wrappers_use_rcsid(void);
void error_use_rcsid(void);
