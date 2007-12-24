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
 * tcp-scan.h -- Header file for TCP protocol specific scanner
 *
 * Author:	Roy Hills
 * Date:	16 September 2003
 *
 * This header file contains definitions required by only the protocol-
 * specific code.
 */

/* Includes */
#include "ip.h"
#include "tcp.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/utsname.h>
#include "md5.h"

/* Defines */

/* IP protocol 6 = TCP */
#define DEFAULT_IP_PROTOCOL 6		/* Default IP Protocol */
/* Packet size is 40 bytes.  10ms = 32,000 bps */
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
#define SERVICE_FILE "/usr/lib/strobe.services"

/* Structures */

struct tcp_flags_struct {
   int cwr;
   int ecn;
   int urg;
   int ack;
   int psh;
   int rst;
   int syn;
   int fin;
};

/* Functions */

unsigned int hstr_i(char *);
uint16_t in_cksum(uint16_t *, int);
uint32_t get_source_ip(char *);
void add_host_port(char *, unsigned, unsigned);
void create_port_list(char *);
void process_tcp_flags(const char *);
