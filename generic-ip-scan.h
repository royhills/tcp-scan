/*
 * The RAWIP Scan Engine (rawip-scan-engine) is Copyright (C) 2003 Roy Hills,
 * NTA Monitor Ltd.
 *
 * $Id$
 *
 * generic-ip-scan.h -- Header file for Generic IP protocol specific scanner
 *
 * Author:	Roy Hills
 * Date:	16 September 2003
 *
 * This header file contains definitions required by only the protocol-
 * specific code.
 */

/* Includes */
#include <netinet/ip.h>

/* Defines */

#define DEFAULT_IP_PROTOCOL 42		/* Default IP Protocol */
#define DEFAULT_INTERVAL 10             /* Default delay between packets (ms) */
#define DEFAULT_BACKOFF_FACTOR 1.5      /* Default timeout backoff factor */
#define DEFAULT_RETRY 3                 /* Default number of retries */
#define DEFAULT_TIMEOUT 500             /* Default per-host timeout in ms */

/* Functions */

unsigned int hstr_i(char *);
