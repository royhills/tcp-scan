/*
 * The ICMP scanner (icmp-scan) is Copyright (C) 2005 Roy Hills,
 * NTA Monitor Ltd.
 *
 * $Id$
 *
 * icmp-scan.h -- Header file for ICMP protocol specific scanner
 *
 * Author:	Roy Hills
 * Date:	1 February 2005
 *
 * This header file contains definitions required by only the protocol-
 * specific code.
 */

/* Includes */
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/utsname.h>
#include "md5.h"
#include "ip_icmp.h"

/* Defines */

/* IP protocol 1 = ICMP */
#define DEFAULT_IP_PROTOCOL 1		/* Default IP Protocol */
#define DEFAULT_INTERVAL 10             /* Default delay between packets (ms) */
#define DEFAULT_BACKOFF_FACTOR 1.5      /* Default timeout backoff factor */
#define DEFAULT_RETRY 3                 /* Default number of retries */
#define DEFAULT_TIMEOUT 500             /* Default per-host timeout in ms */
#define SNAPLEN 94			/* 14 (ether) + 20 (IP) + 60 */
#define PROMISC 0			/* Enable promiscuous mode */
#define TO_MS 0				/* Timeout for pcap_open_live() */
#define OPTIMISE 1			/* Optimise pcap filter */
#define DEFAULT_TTL 64			/* IP TTL */
#define DEFAULT_DF 1			/* IP DF Flag */
#define DEFAULT_TOS 0			/* IP TOS Field */
#define DEFAULT_ICMP_TYPE 8
#define UNREACH_PROTO 99		/* IP proto for proto unreachable */

/* Structures */

typedef struct {
   int id;                      /* ICMP IDs are 8 bits */
   char *name;
} id_name_map;

/* Functions */

unsigned int hstr_i(char *);
uint16_t in_cksum(uint16_t *, int);
uint32_t get_source_ip(char *);
void add_host_port(char *, unsigned, unsigned);
char *id_to_name(int, const id_name_map[]);
char *numstr(unsigned);
