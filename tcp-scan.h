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
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* Defines */

#define DEFAULT_IP_PROTOCOL 6		/* Default IP Protocol */
#define DEFAULT_INTERVAL 10             /* Default delay between packets (ms) */
#define DEFAULT_BACKOFF_FACTOR 1.5      /* Default timeout backoff factor */
#define DEFAULT_RETRY 3                 /* Default number of retries */
#define DEFAULT_TIMEOUT 500             /* Default per-host timeout in ms */

/* Structures */

struct tcp_data {
   uint32_t seq;	/* Sequence number */
   uint16_t sport;	/* Source port */
   uint16_t dport;	/* Source port */
};

/* Functions */

unsigned int hstr_i(char *);
uint16_t in_cksum(uint16_t *, int);
uint32_t get_source_ip(char *);
