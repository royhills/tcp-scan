/*
 * The TCP Scanner (tcp-scan) is Copyright (C) 2003-2008 Roy Hills,
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
 * tcp-scan.h -- Header file for TCP protocol specific scanner
 *
 * Author:	Roy Hills
 * Date:	16 September 2003
 *
 * This header file contains definitions required by only the protocol-
 * specific code.
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
#include <windows.h>    /* Include windows.h if compiling under Cygwin */
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
#include <sys/socket.h> /* For struct sockaddr */
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>	/* Posix regular expression support */
#endif

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#include "ip.h"
#include "tcp.h"

/* Defines */

#define MAXLINE 255                     /* Max line length for input files */
#define MAXIP 65515                     /* Max IP data size = 64k - 20 */
#define REALLOC_COUNT 1000              /* Entries to realloc at once */
#define DEFAULT_BANDWIDTH 56000         /* Default bandwidth in bits/sec */
#define MINIMUM_FRAME_SIZE 46           /* Minimum data size for layer 2 */
#define PACKET_OVERHEAD 18              /* Size of Ethernet header */
/* IP protocol 6 = TCP */
#define IP_PROTOCOL 6			/* Default IP Protocol */
#define DEFAULT_BACKOFF_FACTOR 1.5      /* Default timeout backoff factor */
#define DEFAULT_RETRY 3                 /* Default number of retries */
#define DEFAULT_TIMEOUT 500             /* Default per-host timeout in ms */
#define SNAPLEN 94			/* 14 (ether) + 20 (IP) + 60 (TCP) */
#define PROMISC 0			/* Enable promiscuous mode */
#define TO_MS 0				/* Timeout for pcap_open_live() */
#define OPTIMISE 1			/* Optimise pcap filter */
#define DEFAULT_WINDOW 5840		/* TCP Window */
#define DEFAULT_MSS 1460		/* TCP MSS */
#define DEFAULT_TTL 64			/* IP TTL */
#define DEFAULT_DF 1			/* IP DF Flag */
#define DEFAULT_TOS 0			/* IP TOS Field */
#define SERVICE_FILE "tcp-scan-services"

/* Structures */

typedef union {
   struct in_addr v4;
   struct in6_addr v6;
} ip_address;

typedef struct {
   unsigned n;                  /* Ordinal number for this entry */
   unsigned timeout;            /* Timeout for this host in us */
   ip_address addr;             /* Host IP address */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   unsigned short num_sent;     /* Number of packets sent */
   unsigned short num_recv;     /* Number of packets received */
   uint16_t dport;              /* Destination port */
   unsigned char live;          /* Set when awaiting response */
} host_entry;

typedef struct {
   int cwr;
   int ecn;
   int urg;
   int ack;
   int psh;
   int rst;
   int syn;
   int fin;
} tcp_flags_struct;

/* Functions */

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void info_syslog(const char *, ...);
void err_print(int, const char *, va_list);
void usage(int, int);
void add_host(char *, unsigned);
int send_packet(int, host_entry *, int, struct timeval *);
void recvfrom_wto(int, unsigned char *, int, struct sockaddr *, int);
void remove_host(host_entry **);
void timeval_diff(const struct timeval *, const struct timeval *,
                  struct timeval *);
host_entry *find_host(host_entry **, struct in_addr *,
                      const unsigned char *, int);
void display_packet(int, const unsigned char *, host_entry *,
                    struct in_addr *);
void advance_cursor(void);
void dump_list(void);
void print_times(void);
void initialise(void);
void clean_up(void);
void tcp_scan_version(void);
char *make_message(const char *, ...);
char *printable(const unsigned char*, size_t);
void callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_options(int, char *[]);
ip_address *get_host_address(const char *, int, ip_address *, char **);
const char *my_ntoa(ip_address, int);
/* Wrappers */
int Gettimeofday(struct timeval *);
void *Malloc(size_t);
void *Realloc(void *, size_t);
unsigned long int Strtoul(const char *, int);
long int Strtol(const char *, int);
unsigned int hstr_i(const char *);
uint16_t in_cksum(uint16_t *, int);
uint32_t get_source_ip(char *);
void add_host_port(char *, unsigned, unsigned);
void create_port_list(char *);
void process_tcp_flags(const char *);
/* MT19937 prototypes */
void init_genrand(unsigned long);
void init_by_array(unsigned long[], int);
unsigned long genrand_int32(void);
long genrand_int31(void);
double genrand_real1(void);
double genrand_real2(void);
double genrand_real3(void);
double genrand_res53(void);
/* The following functions are just to prevent rcsid being optimised away */
void wrappers_use_rcsid(void);
void error_use_rcsid(void);
void utils_use_rcsid(void);
