/*
 * The UDP Scan Engine (udp-scan-engine) is Copyright (C) 2003 Roy Hills,
 * NTA Monitor Ltd.
 *
 * $Id$
 *
 * generic-udp-scan.h -- Header file for Generic UDP protocol specific scanner
 *
 * Author:	Roy Hills
 * Date:	16 September 2003
 *
 * This header file contains definitions required by only the protocol-
 * specific code.
 */

/* Includes */

/* Defines */

#define DEFAULT_DEST_PORT 12345		/* Default UDP destination port */
#define DEFAULT_INTERVAL 10             /* Default delay between packets (ms) */
#define DEFAULT_BACKOFF_FACTOR 1.5      /* Default timeout backoff factor */
#define DEFAULT_RETRY 3                 /* Default number of retries */
#define DEFAULT_TIMEOUT 500             /* Default per-host timeout in ms */
#define DEFAULT_SOURCE_PORT 0           /* Default UDP source port */

/* Functions */

unsigned int hstr_i(char *);
