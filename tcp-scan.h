/*
 * The RAWIP Scan Engine (rawip-scan-engine) is Copyright (C) 2003 Roy Hills,
 * NTA Monitor Ltd.
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
#include <netinet/ip.h>
#include "tcp.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/utsname.h>
#include "md5.h"

/* Defines */

/* IP protocol 6 = TCP */
#define DEFAULT_IP_PROTOCOL 6		/* Default IP Protocol */
/* Packet size is 40 bytes.  10ms = 32,000 bps */
#define DEFAULT_INTERVAL 10             /* Default delay between packets (ms) */
#define DEFAULT_BACKOFF_FACTOR 1.5      /* Default timeout backoff factor */
#define DEFAULT_RETRY 3                 /* Default number of retries */
#define DEFAULT_TIMEOUT 500             /* Default per-host timeout in ms */
#define SNAPLEN 94			/* 14 (ether) + 20 (IP) + 60 (TCP) */
#define PROMISC 0			/* Enable promiscuous mode */
#define TO_MS 0				/* Timeout for pcap_open_live() */
#define OPTIMISE 1			/* Optimise pcap filter */
#define DEFAULT_WINDOW 5840		/* TCP Window */
#define DEFAULT_MSS 1460		/* TCP MSS */

/* Structures */

struct tcp_data {
   uint16_t dport;	/* Destination port */
};

struct port_entry {
   struct port_entry *next;
   uint16_t port;
};

/* Functions */

unsigned int hstr_i(char *);
uint16_t in_cksum(uint16_t *, int);
uint32_t get_source_ip(char *);
void add_host_port(char *, unsigned, unsigned);
void create_port_list(char *);
void free_port_list(void);
