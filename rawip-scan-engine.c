/*
 * The SQL Slammer Scanner (sql-slammer-scan) is Copyright (C) 2003 Roy Hills,
 * NTA Monitor Ltd.
 *
 * $Id$
 *
 * sql-slammer-scan -- The SQL Slammer Scanner
 *
 * Author:	Roy Hills
 * Date:	11 September 2002
 *
 * Usage:
 *    sql-slammer-scan [options] [host...]
 *
 * Description:
 *
 * sql-slammer-scan sends probe packets to UDP port 1434 on the specified
 * hosts and displays any responses received.
 * 
 */

#include "udp-scan-engine.h"

static char const rcsid[] = "$Id$";	/* RCS ID for ident(1) */

/* Global variables */
struct host_entry *rrlist = NULL;	/* Round-robin linked list "the list" */
struct host_entry *cursor;		/* Pointer to current list entry */
unsigned num_hosts = 0;			/* Number of entries in the list */
unsigned responders = 0;		/* Number of hosts which responded */
unsigned live_count;			/* Number of entries awaiting reply */
int verbose=0;				/* Verbose level */
int debug = 0;				/* Debug flag */
extern int dest_port;			/* UDP destination port */

int
main(int argc, char *argv[]) {
   struct option long_options[] = {
      {"file", required_argument, 0, 'f'},
      {"help", no_argument, 0, 'h'},
      {"sport", required_argument, 0, 's'},
      {"dport", required_argument, 0, 'p'},
      {"retry", required_argument, 0, 'r'},
      {"timeout", required_argument, 0, 't'},
      {"interval", required_argument, 0, 'i'},
      {"backoff", required_argument, 0, 'b'},
      {"selectwait", required_argument, 0, 'w'},
      {"verbose", no_argument, 0, 'v'},
      {"version", no_argument, 0, 'V'},
      {"debug", no_argument, 0, 'd'},
      {0, 0, 0, 0}
   };
   const char *short_options = "f:hs:p:r:t:i:b:w:vVd";
   int arg;
   char arg_str[MAXLINE];	/* Args as string for syslog */
   int options_index=0;
   char filename[MAXLINE];
   int filename_flag=0;
   int sockfd;			/* UDP socket file descriptor */
   struct sockaddr_in sa_local;
   struct sockaddr_in sa_peer;
   struct timeval now;
   char packet_in[MAXUDP];	/* Received packet */
   int n;
   struct host_entry *temp_cursor;
   struct hostent *hp;
   struct timeval diff;		/* Difference between two timevals */
   unsigned long loop_timediff;	/* Time since last packet sent in ms */
   unsigned long host_timediff; /* Time since last packet sent to this host */
   int arg_str_space;		/* Used to avoid buffer overruns when copying */
   unsigned retry = DEFAULT_RETRY;		/* Number of retries */
   unsigned timeout = DEFAULT_TIMEOUT;	/* Per-host timeout */
   unsigned interval = DEFAULT_INTERVAL;	/* Interval between packets */
   unsigned select_timeout = DEFAULT_SELECT_TIMEOUT;	/* Select timeout */
   float backoff = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
   int source_port = DEFAULT_SOURCE_PORT;	/* UDP source port */
   struct timeval last_packet_time;	/* Time last packet was sent */
/*
 *	Open syslog channel and log arguments if required.
 *	We must be careful here to avoid overflowing the arg_str buffer
 *	which could result in a buffer overflow vulnerability.  That's why
 *	we use strncat and keep track of the remaining buffer space.
 */
#ifdef SYSLOG
   openlog("sql-slammer-scan", LOG_PID, SYSLOG_FACILITY);
   arg_str[0] = '\0';
   arg_str_space = MAXLINE;	/* Amount of space in the arg_str buffer */
   for (arg=0; arg<argc; arg++) {
      arg_str_space -= strlen(argv[arg]);
      if (arg_str_space > 0) {
         strncat(arg_str, argv[arg], arg_str_space);
         if (arg < (argc-1)) {
            strcat(arg_str, " ");
            arg_str_space--;
         }
      }
   }
   info_syslog("Starting: %s", arg_str);
#endif
/*
 *	Call initialisation routine to perform any initial setup required.
 */
   initialise();
/*
 *	Process options and arguments.
 */
   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         case 'f':	/* --file */
            strncpy(filename, optarg, MAXLINE);
            filename_flag=1;
            break;
         case 'h':	/* --help */
            usage();
            break;
         case 's':	/* --sport */
            source_port=atoi(optarg);
            break;
         case 'p':	/* --dport */
            dest_port=atoi(optarg);
            break;
         case 'r':	/* --retry */
            retry=atoi(optarg);
            break;
         case 't':	/* --timeout */
            timeout=atoi(optarg);
            break;
         case 'i':	/* --interval */
            interval=atoi(optarg);
            break;
         case 'b':	/* --backoff */
            backoff=atof(optarg);
            break;
         case 'w':	/* --selectwait */
            select_timeout=atoi(optarg);
            break;
         case 'v':	/* --verbose */
            verbose++;
            break;
         case 'V':	/* --version */
            udp_scan_version();
            exit(0);
            break;
         case 'd':	/* --debug */
            debug++;
            break;
         default:	/* Unknown option */
            usage();
            break;
      }
   }
   if (debug) {print_times(); printf("main: Start\n");}
/*
 *	If we're not reading from a file, then we must have some hosts
 *	given as command line arguments.
 */
   hp = gethostbyname("sql-slammer-scan-target.test.nta-monitor.com");
   if (!filename_flag) 
      if ((argc - optind) < 1)
         usage();
/*
 *	Populate the list from the specified file if --file was specified, or
 *	otherwise from the remaining command line arguments.
 */
   if (filename_flag) {	/* Populate list from file */
      FILE *fp;
      char line[MAXLINE];
      char host[MAXLINE];

      if ((strcmp(filename, "-")) == 0) {	/* Filename "-" means stdin */
         if ((fp = fdopen(0, "r")) == NULL) {
            err_sys("fdopen");
         }
      } else {
         if ((fp = fopen(filename, "r")) == NULL) {
            err_sys("fopen");
         }
      }

      while (fgets(line, MAXLINE, fp)) {
         if ((sscanf(line, "%s", host)) == 1) {
            add_host(host, timeout);
         }
      }
      fclose(fp);
   } else {		/* Populate list from command line arguments */
      argv=&argv[optind];
      while (*argv) {
         add_host(*argv, timeout);
         argv++;
      }
   }
/*
 *	Check that we have at least one entry in the list.
 */
   if (!num_hosts)
      err_msg("No hosts to process.");
/*
 *	Create UDP socket and bind to local source port.
 */
   if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      err_sys("socket");

   memset(&sa_local, '\0', sizeof(sa_local));
   sa_local.sin_family = AF_INET;
   sa_local.sin_addr.s_addr = htonl(INADDR_ANY);
   sa_local.sin_port = htons(source_port);

   if ((bind(sockfd, (struct sockaddr *)&sa_local, sizeof(sa_local))) < 0) {
      err_sys("bind");
   }
/*
 *	Set current host pointer (cursor) to start of list, zero
 *	last packet sent time, and set last receive time to now.
 */
   live_count = num_hosts;
   cursor = rrlist;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
/*
 *	Display initial message.
 */
   printf("Starting %s with %u hosts\n", PACKAGE_STRING, num_hosts);
/*
 *	Display the lists if verbose setting is 3 or more.
 */
   if (verbose > 2)
      dump_list();
/*
 *	Main loop: send packets to all hosts in order until a response
 *	has been received or the host has exhausted it's retry limit.
 *
 *	The loop exits when all hosts have either responded or timed out.
 */
   while (live_count) {
      if (debug) {print_times(); printf("main: Top of loop\n");}
/*
 *	Obtain current time and calculate deltas since last packet and
 *	last packet to this host.
 */
      if ((gettimeofday(&now, NULL)) != 0) {
         err_sys("gettimeofday");
      }
/*
 *	If the last packet was sent more than interval ms ago, then we can
 *	potentially send a packet to the current host.
 */
      timeval_diff(&now, &last_packet_time, &diff);
      loop_timediff = 1000*diff.tv_sec + diff.tv_usec/1000;
      if (loop_timediff >= interval) {
         if (debug) {print_times(); printf("main: Can send packet now.  loop_timediff=%lu\n", loop_timediff);}
/*
 *	If the last packet to this host was sent more than the current
 *	timeout for this host ms ago, then we can potentially send a packet
 *	to it.
 */
         timeval_diff(&now, &(cursor->last_send_time), &diff);
         host_timediff = 1000*diff.tv_sec + diff.tv_usec/1000;
         if (host_timediff >= cursor->timeout) {
            if (debug) {print_times(); printf("main: Can send packet to host %d now.  host_timediff=%lu\n", cursor->n, host_timediff);}
/*
 *	If we've exceeded our retry limit, then this host has timed out so
 *	remove it from the list.  Otherwise, increase the timeout by the
 *	backoff factor if this is not the first packet sent to this host
 *	and send a packet.
 */
            if (cursor->num_sent >= retry) {
               if (verbose)
                  warn_msg("---\tRemoving host entry %u (%s) - Timeout", cursor->n, inet_ntoa(cursor->addr));
               remove_host(cursor);
            } else {	/* Retry limit not reached for this host */
               if (cursor->num_sent) {
                  cursor->timeout *= backoff;
               }
               send_packet(sockfd, cursor, dest_port, &last_packet_time);
               advance_cursor();
            }
         } else {	/* We can't send a packet to this host yet */
/*
 *	Note that there is no point calling advance_cursor() here because if
 *	host n is not ready to send, then host n+1 will not be ready either.
 */
            if (debug) {print_times(); printf("main: Can't send packet to host %d yet. host_timediff=%lu\n", cursor->n, host_timediff);}
         } /* End If */
      } else {		/* We can't send a packet yet */
         if (debug) {print_times(); printf("main: Can't send packet yet.  loop_timediff=%lu\n", loop_timediff);}
      } /* End If */

      n=recvfrom_wto(sockfd, packet_in, MAXUDP, (struct sockaddr *)&sa_peer, select_timeout);
      if (n > 0) {
/*
 *	We've received a response.  Try to match up the packet by IP address
 *
 *	Note: If the protocol includes a unique ID with a large enough range
 *	      i.e. 32 bits or more, we could match by that instead of IP
 *	      address.  We do this with ike-scan using the 64-bit cookie value.
 */
         temp_cursor=find_host_by_ip(cursor, &(sa_peer.sin_addr));
         if (temp_cursor) {
/*
 *	We found an IP match for the packet. 
 */
            if (verbose > 1)
               warn_msg("---\tReceived packet #%u from %s",temp_cursor->num_recv ,inet_ntoa(sa_peer.sin_addr));
            display_packet(n, packet_in, temp_cursor, &(sa_peer.sin_addr),
                           &responders);
            if (verbose)
               warn_msg("---\tRemoving host entry %u (%s) - Received %d bytes", temp_cursor->n, inet_ntoa(sa_peer.sin_addr), n);
            remove_host(temp_cursor);
         } else {
/*
 *	The received packet is not from an IP address in the list
 *	Issue a message to that effect and ignore the packet.
 */
            warn_msg("---\tIgnoring %d bytes from unknown host %s", n, inet_ntoa(sa_peer.sin_addr));
         }
      } /* End If */
   } /* End While */

   printf("\n");        /* Ensure we have a blank line */

   close(sockfd);
   clean_up();
#ifdef SYSLOG
   info_syslog("Ending: %u hosts scanned. %u responded", num_hosts, responders);
#endif
   printf("Ending %s: %u hosts scanned.  %u responded\n", PACKAGE_STRING, num_hosts, responders);
   if (debug) {print_times(); printf("main: End\n");}
   return(0);
}

/*
 *	add_host -- Add a new host to the list.
 *
 *	Inputs:
 *
 *	name = The Name or IP address of the host.
 *	timeout = The initial host timeout in ms.
 */
void
add_host(char *name, unsigned timeout) {
   struct hostent *hp;
   struct host_entry *he;
   struct timeval now;

   if ((hp = gethostbyname(name)) == NULL)
      err_sys("gethostbyname");

   if ((he = malloc(sizeof(struct host_entry))) == NULL)
      err_sys("malloc");

   num_hosts++;

   if ((gettimeofday(&now,NULL)) != 0) {
      err_sys("gettimeofday");
   }

   he->n = num_hosts;
   memcpy(&(he->addr), hp->h_addr_list[0], sizeof(struct in_addr));
   he->live = 1;
   he->timeout = timeout;
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;

   if (rrlist) {	/* List is not empty so add entry */
      he->next = rrlist;
      he->prev = rrlist->prev;
      he->prev->next = he;
      he->next->prev = he;
   } else {		/* List is empty so initialise with this entry */
      rrlist = he;
      he->next = he;
      he->prev = he;
   }
}

/*
 * 	remove_host -- Remove the specified host from the list
 *
 *	If the host being removed is the one pointed to by the cursor, this
 *	function updates cursor so that it points to the next entry.
 */
void
remove_host(struct host_entry *he) {
   if (he->live) {
      he->live = 0;
      live_count--;
      if (he == cursor)
         advance_cursor();
      if (debug) {print_times(); printf("remove_host: live_count now %d\n", live_count);}
   } else {
      warn_msg("***\tremove_host called on non-live host entry: SHOULDN'T HAPPEN");
   }
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 *
 *	Does nothing if there are no live entries in the list.
 */
void
advance_cursor(void) {
   if (live_count) {
      do {
         cursor = cursor->next;
      } while (!cursor->live);
   } /* End If */
   if (debug) {print_times(); printf("advance_cursor: cursor now %d\n", cursor->n);}
}

/*
 *	find_host_by_ip	-- Find a host in the list by IP address
 *
 *	he points to current position in list.  Search runs backwards
 *	starting from this point.
 *
 *	addr points to the IP address to find in the list.
 *
 *	Returns a pointer to the host entry associated with the specified IP
 *	or NULL if no match found.
 */
struct host_entry *
find_host_by_ip(struct host_entry *he,struct in_addr *addr) {
   struct host_entry *p;
   int found;

   p = he;
   found = 0;

   do {
      if (p->addr.s_addr == addr->s_addr) {
         found = 1;
      } else {
         p = p->prev;
      }
   } while (!found && p != he);

   if (found) {
      return p;
   } else {
      return NULL;
   }
}

/*
 *	recvfrom_wto -- Receive packet with timeout
 *
 *	Returns number of characters received, or -1 for timeout.
 */
int
recvfrom_wto(int s, char *buf, int len, struct sockaddr *saddr, int tmo) {
   fd_set readset;
   struct timeval to;
   int n;
   NET_SIZE_T saddr_len;

   FD_ZERO(&readset);
   FD_SET(s, &readset);
   to.tv_sec  = tmo/1000;
   to.tv_usec = (tmo - 1000*to.tv_sec) * 1000;
   n = select(s+1, &readset, NULL, NULL, &to);
   if (debug) {print_times(); printf("recvfrom_wto: select end, tmo=%d, n=%d\n", tmo, n);}
   if (n < 0) {
      err_sys("select");
   } else if (n == 0) {
      return -1;	/* Timeout */
   }
   saddr_len = sizeof(struct sockaddr);
   if ((n = recvfrom(s, buf, len, 0, saddr, &saddr_len)) < 0) {
      if (errno == ECONNREFUSED) {
/*
 *	Treat connection refused as timeout.
 *	It would be nice to remove the associated host, but we can't because
 *	we cannot tell which host the connection refused relates to.
 */
         return -1;
      } else {
         err_sys("recvfrom");
      }
   }
   return n;
}

/*
 *	Calculates the difference between two timevals and returns this
 *	difference in a third timeval.
 *	diff = a - b.
 */
void
timeval_diff(struct timeval *a, struct timeval *b, struct timeval *diff) {

   /* Perform the carry for the later subtraction by updating y. */
   if (a->tv_usec < b->tv_usec) {
     int nsec = (b->tv_usec - a->tv_usec) / 1000000 + 1;
     b->tv_usec -= 1000000 * nsec;
     b->tv_sec += nsec;
   }
   if (a->tv_usec - b->tv_usec > 1000000) {
     int nsec = (a->tv_usec - b->tv_usec) / 1000000;
     b->tv_usec += 1000000 * nsec;
     b->tv_sec -= nsec;
   }
 
   /* Compute the time difference
      tv_usec is certainly positive. */
   diff->tv_sec = a->tv_sec - b->tv_sec;
   diff->tv_usec = a->tv_usec - b->tv_usec;
}

/*
 *	dump_list -- Display contents of host list for debugging
 */
void
dump_list(void) {
   struct host_entry *p;

   p = rrlist;

   printf("Host List:\n\n");
   printf("Entry\tIP Address\n");
   do {
      printf("%u\t%s\n", p->n, inet_ntoa(p->addr));
      p = p->next;
   } while (p != rrlist);
   printf("\nTotal of %u host entries.\n\n", num_hosts);
}

/*
 *	usage -- display usage message and exit
 */
void
usage(void) {
   fprintf(stderr, "Usage: sql-slammer-scan [options] [hosts...]\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Hosts are specified on the command line unless the --file option is specified.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Options:\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "--help or -h\t\tDisplay this usage message and exit.\n");
   fprintf(stderr, "\n--file=<fn> or -f <fn>\tRead hostnames or addresses from the specified file\n");
   fprintf(stderr, "\t\t\tinstead of from the command line. One name or IP\n");
   fprintf(stderr, "\t\t\taddress per line.  Use \"-\" for standard input.\n");
   fprintf(stderr, "\n--sport=<p> or -s <p>\tSet UDP source port to <p>, default=%d, 0=random.\n", DEFAULT_SOURCE_PORT);
   fprintf(stderr, "\n--dport=<p> or -p <p>\tSet UDP destination port to <p>, default=%d.\n", dest_port);
   fprintf(stderr, "\n--retry=<n> or -r <n>\tSet total number of attempts per host to <n>,\n");
   fprintf(stderr, "\t\t\tdefault=%d.\n", DEFAULT_RETRY);
   fprintf(stderr, "\n--timeout=<n> or -t <n>\tSet initial per host timeout to <n> ms, default=%d.\n", DEFAULT_TIMEOUT);
   fprintf(stderr, "\t\t\tThis timeout is for the first packet sent to each host.\n");
   fprintf(stderr, "\t\t\tsubsequent timeouts are multiplied by the backoff\n");
   fprintf(stderr, "\t\t\tfactor which is set with --backoff.\n");
   fprintf(stderr, "\n--interval=<n> or -i <n> Set minimum packet interval to <n> ms, default=%d.\n", DEFAULT_INTERVAL);
   fprintf(stderr, "\t\t\tThis controls the outgoing bandwidth usage by limiting\n");
   fprintf(stderr, "\t\t\tthe rate at which packets can be sent.  The packet\n");
   fprintf(stderr, "\t\t\tinterval will be greater than or equal to this number\n");
   fprintf(stderr, "\t\t\tand will be a multiple of the select wait specified\n");
   fprintf(stderr, "\t\t\twith --selectwait.  Thus --interval=75 --selectwait=10\n");
   fprintf(stderr, "\t\t\twill result in a packet interval of 80ms.\n");
   fprintf(stderr, "\n--backoff=<b> or -b <b>\tSet timeout backoff factor to <b>, default=%.2f.\n", DEFAULT_BACKOFF_FACTOR);
   fprintf(stderr, "\t\t\tThe per-host timeout is multiplied by this factor\n");
   fprintf(stderr, "\t\t\tafter each timeout.  So, if the number of retrys\n");
   fprintf(stderr, "\t\t\tis 3, the initial per-host timeout is 500ms and the\n");
   fprintf(stderr, "\t\t\tbackoff factor is 1.5, then the first timeout will be\n");
   fprintf(stderr, "\t\t\t500ms, the second 750ms and the third 1125ms.\n");
   fprintf(stderr, "\n--selectwait=<n> or -w <n> Set select wait to <n> ms, default=%d.\n", DEFAULT_SELECT_TIMEOUT);
   fprintf(stderr, "\t\t\tThis controls the timeout used in the select(2) call.\n");
   fprintf(stderr, "\t\t\tIt defines the lower bound and granularity of the\n");
   fprintf(stderr, "\t\t\tpacket interval set with --interval.  Smaller values\n");
   fprintf(stderr, "\t\t\tallow more accurate and lower packet intervals;\n");
   fprintf(stderr, "\t\t\tlarger values reduce CPU usage.  You don't need\n");
   fprintf(stderr, "\t\t\tto change this unless you want to reduce the packet\n");
   fprintf(stderr, "\t\t\tinterval close to or below the default selectwait time.\n");
   fprintf(stderr, "\n--verbose or -v\t\tDisplay verbose progress messages.\n");
   fprintf(stderr, "\t\t\tUse more than once for greater effect:\n");
   fprintf(stderr, "\t\t\t1 - Show when hosts are removed from the list and\n");
   fprintf(stderr, "\t\t\t    when packets with invalid cookies are received.\n");
   fprintf(stderr, "\t\t\t2 - Show each packet sent and received.\n");
   fprintf(stderr, "\t\t\t3 - Display the host list before\n");
   fprintf(stderr, "\t\t\t    scanning starts.\n");
   fprintf(stderr, "\n--version or -V\t\tDisplay program version and exit.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Report bugs or send suggestions to %s\n", PACKAGE_BUGREPORT);
   exit(1);
}

void
print_times(void) {
   static struct timeval time_first;	/* When print_times() was first called */
   static struct timeval time_last;	/* When print_times() was last called */
   static int first_call=1;
   struct timeval time_now;
   struct timeval time_delta1;
   struct timeval time_delta2;

   if ((gettimeofday(&time_now, NULL)) != 0) {
      err_sys("gettimeofday");
   }
   
   if (first_call) {
      first_call=0;
      time_first.tv_sec  = time_now.tv_sec;
      time_first.tv_usec = time_now.tv_usec;
      printf("%lu.%.6lu (0.000000) [0.000000]\t", time_now.tv_sec,
             time_now.tv_usec);
   } else {
      timeval_diff(&time_now, &time_last, &time_delta1);
      timeval_diff(&time_now, &time_first, &time_delta2);
      printf("%lu.%.6lu (%lu.%.6lu) [%lu.%.6lu]\t", time_now.tv_sec,
             time_now.tv_usec, time_delta1.tv_sec, time_delta1.tv_usec,
             time_delta2.tv_sec, time_delta2.tv_usec);
   }
   time_last.tv_sec  = time_now.tv_sec;
   time_last.tv_usec = time_now.tv_usec;
}

void
udp_scan_version (void) {
   fprintf(stderr, "%s\n\n", PACKAGE_STRING);
   fprintf(stderr, "Copyright (C) 2003 Roy Hills, NTA Monitor Ltd.\n");
   fprintf(stderr, "\n");
/* We use rcsid here to prevent it being optimised away */
   fprintf(stderr, "%s\n", rcsid);
/* Call scanner-specific version routine */
   local_version();
}
