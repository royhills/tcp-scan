/*
 * The RAWIP Scan Engine (rawip-scan-engine) is Copyright (C) 2003-2004 Roy Hills,
 * NTA Monitor Ltd.
 *
 * $Id$
 *
 * rawip-scan-engine -- The RAWIP Scan Engine
 *
 * Author:	Roy Hills
 * Date:	11 September 2002
 *
 * Usage:
 *    <protocol-specific-scanner> [options] [host...]
 *
 * Description:
 *
 * rawip-scan-engine sends probe packets to the specified hosts and displays
 * any responses received.  It is a protocol-neutral engine which needs some
 * protocol specific functions (in a seperate source file) to build a working
 * scanner.
 * 
 */

#include "rawip-scan-engine.h"

static char const rcsid[] = "$Id$";	/* RCS ID for ident(1) */

/* Global variables */
struct host_entry *helist = NULL;	/* Array of host entries */
struct host_entry **helistptr;		/* Array of pointers to host entries */
struct host_entry **cursor;		/* Pointer to current host entry ptr */
unsigned num_hosts = 0;			/* Number of entries in the list */
unsigned responders = 0;		/* Number of hosts which responded */
unsigned live_count;			/* Number of entries awaiting reply */
unsigned max_iter;			/* Max iterations in find_host() */
int verbose=0;				/* Verbose level */
int debug = 0;				/* Debug flag */
char *local_data=NULL;			/* Local data for scanner */
pcap_t *handle;
int pcap_fd;				/* Pcap file descriptor */
char filename[MAXLINE];
int filename_flag=0;
int random_flag=0;			/* Randomise the list */

extern unsigned interval;		/* Desired interval between packets */
extern char const scanner_name[];	/* Scanner Name */
extern char const scanner_version[];	/* Scanner Version */
extern unsigned retry;			/* Number of retries */
extern unsigned timeout;		/* Per-host timeout */
extern float backoff_factor;		/* Backoff factor */
extern int ip_protocol;			/* IP protocol */

int
main(int argc, char *argv[]) {
   char arg_str[MAXLINE];	/* Args as string for syslog */
   int sockfd;			/* IP socket file descriptor */
   struct sockaddr_in sa_peer;
   struct timeval now;
   unsigned char packet_in[MAXIP];	/* Received packet */
   char namebuf[MAXLINE];
   struct hostent *hp;
   struct timeval diff;		/* Difference between two timevals */
   unsigned select_timeout;	/* Select timeout */
   unsigned long long loop_timediff;	/* Time since last packet sent in us */
   unsigned long long host_timediff; /* Time since last pkt sent to this host (us) */
   int arg;
   int arg_str_space;		/* Used to avoid buffer overruns when copying */
   struct timeval last_packet_time;	/* Time last packet was sent */
   int req_interval;		/* Requested per-packet interval */
   int cum_err=0;		/* Cumulative timing error */
   struct timeval start_time;	/* Program start time */
   struct timeval end_time;	/* Program end time */
   struct timeval elapsed_time;	/* Elapsed time as timeval */
   double elapsed_seconds;	/* Elapsed time in seconds */
   static int reset_cum_err;
   static int pass_no;
   int first_timeout=1;
   const int on = 1;		/* For setsockopt */
   int i;
/*
 *	Open syslog channel and log arguments if required.
 *	We must be careful here to avoid overflowing the arg_str buffer
 *	which could result in a buffer overflow vulnerability.  That's why
 *	we use strncat and keep track of the remaining buffer space.
 */
#ifdef SYSLOG
   openlog(scanner_name, LOG_PID, SYSLOG_FACILITY);
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
 *	Process options.
 */
   process_options(argc, argv);
/*
 *	Get program start time for statistics displayed on completion.
 */
   Gettimeofday(&start_time);
   if (debug) {print_times(); printf("main: Start\n");}
/*
 *	Call protocol-specific initialisation routine to perform any
 *	initial setup required.
 */
   initialise();
/*
 *	Create raw IP socket and set IP_HDRINCL
 */
   if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
      err_sys("socket");
   if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) != 0)
      err_sys("setsockopt");
/*
 *	Drop privileges.
 */
   if ((setuid(getuid())) < 0) {
      err_sys("setuid");
   }
/*
 *	If we're not reading from a file, then we must have some hosts
 *	given as command line arguments.
 */
   sprintf(namebuf, "%s-target.test.nta-monitor.com", scanner_name);
   hp = gethostbyname(namebuf);
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
 *	Create and initialise array of pointers to host entries.
 */
   helistptr = Malloc(num_hosts * sizeof(struct host_entry *));
   for (i=0; i<num_hosts; i++)
      helistptr[i] = &helist[i];
/*
 *	Randomise the list if required.
 */
   if (random_flag) {
      unsigned seed;
      struct timeval tv;
      int r;
      struct host_entry *temp;

      Gettimeofday(&tv);
      seed = tv.tv_usec ^ getpid();
      srandom(seed);

      for (i=num_hosts-1; i>0; i--) {
         r = random() % (i+1);     /* Random number 0<=r<i */
         temp = helistptr[i];
         helistptr[i] = helistptr[r];
         helistptr[r] = temp;
      }
   }
/*
 *	Set current host pointer (cursor) to start of list, zero
 *	last packet sent time, and set last receive time to now.
 */
   live_count = num_hosts;
   cursor = helistptr;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
/*
 *	Display initial message.
 */
   printf("Starting %s %s (%s) with %u hosts\n", scanner_name, scanner_version,
          PACKAGE_STRING, num_hosts);
/*
 *	Display the lists if verbose setting is 3 or more.
 */
   if (verbose > 2)
      dump_list();
/*
 *	Main loop: send packets to all hosts in order until a response
 *	has been received or the host has exhausted its retry limit.
 *
 *	The loop exits when all hosts have either responded or timed out.
 */
   interval *= 1000;	/* Convert from ms to us */
   reset_cum_err = 1;
   req_interval = interval;
   while (live_count) {
      if (debug) {print_times(); printf("main: Top of loop.\n");}
/*
 *	Obtain current time and calculate deltas since last packet and
 *	last packet to this host.
 */
      Gettimeofday(&now);
/*
 *	If the last packet was sent more than interval us ago, then we can
 *	potentially send a packet to the current host.
 */
      timeval_diff(&now, &last_packet_time, &diff);
      loop_timediff = 1000000*diff.tv_sec + diff.tv_usec;
      if (loop_timediff >= req_interval) {
         if (debug) {print_times(); printf("main: Can send packet now.  loop_timediff=%llu\n", loop_timediff);}
/*
 *	If the last packet to this host was sent more than the current
 *	timeout for this host us ago, then we can potentially send a packet
 *	to it.
 */
         timeval_diff(&now, &((*cursor)->last_send_time), &diff);
         host_timediff = 1000000*diff.tv_sec + diff.tv_usec;
         if (host_timediff >= (*cursor)->timeout) {
            if (reset_cum_err) {
               if (debug) {print_times(); printf("main: Reset cum_err\n");}
               cum_err = 0;
               req_interval = interval;
               reset_cum_err = 0;
            } else {
               cum_err += loop_timediff - interval;
               if (req_interval >= cum_err) {
                  req_interval = req_interval - cum_err;
               } else {
                  req_interval = 0;
               }
            }
            if (debug) {print_times(); printf("main: Can send packet to host %d now.  host_timediff=%llu, timeout=%u, req_interval=%d, cum_err=%d\n", (*cursor)->n, host_timediff, (*cursor)->timeout, req_interval, cum_err);}
            select_timeout = req_interval;
/*
 *	If we've exceeded our retry limit, then this host has timed out so
 *	remove it from the list.  Otherwise, increase the timeout by the
 *	backoff factor if this is not the first packet sent to this host
 *	and send a packet.
 */
            if (verbose && (*cursor)->num_sent > pass_no) {
               warn_msg("---\tPass %d complete", pass_no+1);
               pass_no = (*cursor)->num_sent;
            }
            if ((*cursor)->num_sent >= retry) {
               if (verbose > 1)
                  warn_msg("---\tRemoving host entry %u (%s) - Timeout", (*cursor)->n, inet_ntoa((*cursor)->addr));
               if (debug) {print_times(); printf("main: Timing out host %d.\n", (*cursor)->n);}
               remove_host(cursor);	/* Automatically calls advance_cursor() */
               if (first_timeout) {
                  timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                  host_timediff = 1000000*diff.tv_sec + diff.tv_usec;
                  while (host_timediff >= (*cursor)->timeout && live_count) {
                     if ((*cursor)->live) {
                        if (verbose > 1)
                           warn_msg("---\tRemoving host %u (%s) - Catch-Up Timeout", (*cursor)->n, inet_ntoa((*cursor)->addr));
                        remove_host(cursor);
                     } else {
                        advance_cursor();
                     }
                     timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                     host_timediff = 1000000*diff.tv_sec + diff.tv_usec;
                  }
                  first_timeout=0;
               }
               Gettimeofday(&last_packet_time);
            } else {	/* Retry limit not reached for this host */
               if ((*cursor)->num_sent)
                  (*cursor)->timeout *= backoff_factor;
               send_packet(sockfd, *cursor, ip_protocol, &last_packet_time);
               advance_cursor();
            }
         } else {	/* We can't send a packet to this host yet */
/*
 *	Note that there is no point calling advance_cursor() here because if
 *	host n is not ready to send, then host n+1 will not be ready either.
 */
            select_timeout = (*cursor)->timeout - host_timediff;
            reset_cum_err = 1;	/* Zero cumulative error */
            if (debug) {print_times(); printf("main: Can't send packet to host %d yet. host_timediff=%llu\n", (*cursor)->n, host_timediff);}
         } /* End If */
      } else {		/* We can't send a packet yet */
         select_timeout = req_interval - loop_timediff;
         if (debug) {print_times(); printf("main: Can't send packet yet.  loop_timediff=%llu\n", loop_timediff);}
      } /* End If */

      recvfrom_wto(pcap_fd, packet_in, MAXIP, (struct sockaddr *)&sa_peer,
                   select_timeout);
   } /* End While */

   printf("\n");        /* Ensure we have a blank line */

   close(sockfd);
   clean_up();

   Gettimeofday(&end_time);
   timeval_diff(&end_time, &start_time, &elapsed_time);
   elapsed_seconds = (elapsed_time.tv_sec*1000 +
                      elapsed_time.tv_usec/1000) / 1000.0;

#ifdef SYSLOG
   info_syslog("Ending: %u hosts scanned in %.3f seconds (%.2f hosts/sec). %u responded",
               num_hosts, elapsed_seconds, num_hosts/elapsed_seconds,
               responders);
#endif
   printf("Ending %s: %u hosts scanned in %.3f seconds (%.2f hosts/sec).  %u responded\n",
          scanner_name, num_hosts, elapsed_seconds, num_hosts/elapsed_seconds,
          responders);
   printf("maximum iterations=%u\n", max_iter);
   if (debug) {print_times(); printf("main: End\n");}
   return 0;
}

/*
 *	add_host -- Add a new host to the list.
 *
 *	Inputs:
 *
 *	name = The Name or IP address of the host.
 *	timeout = The initial host timeout in ms.
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is called before the helistptr array is created, so
 *	we use the helist array directly.
 */
void
add_host(char *name, unsigned timeout) {
   struct hostent *hp;
   struct host_entry *he;
   struct timeval now;
/*
 * Return immediately if the local add_host function replaces this generic one.
 */
   if (local_add_host(name, timeout))
      return;

   if ((hp = gethostbyname(name)) == NULL)
      err_sys("gethostbyname");

   num_hosts++;

   if (helist)
      helist=Realloc(helist, num_hosts * sizeof(struct host_entry));
   else
      helist=Malloc(sizeof(struct host_entry));

   he = helist + (num_hosts-1);	/* Would array notation be better? */

   Gettimeofday(&now);

   he->n = num_hosts;
   memcpy(&(he->addr), hp->h_addr_list[0], sizeof(struct in_addr));
   he->live = 1;
   he->timeout = timeout * 1000;	/* Convert from ms to us */
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;
}

/*
 * 	remove_host -- Remove the specified host from the list
 *
 *	inputs:
 *
 *	he = Pointer to host entry to remove.
 *
 *	If the host being removed is the one pointed to by the cursor, this
 *	function updates cursor so that it points to the next entry.
 */
void
remove_host(struct host_entry **he) {
   if ((*he)->live) {
      (*he)->live = 0;
      live_count--;
      if (he == cursor)
         advance_cursor();
      if (debug) {print_times(); printf("remove_host: live_count now %d\n", live_count);}
   } else {
      if (verbose > 1)
         warn_msg("***\tremove_host called on non-live host entry: SHOULDN'T HAPPEN");
   }
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 *
 *	Inputs:
 *
 *	None.
 *
 *	Does nothing if there are no live entries in the list.
 */
void
advance_cursor(void) {
   if (live_count) {
      do {
         if (cursor == (helistptr+(num_hosts-1)))
            cursor = helistptr;	/* Wrap round to beginning */
         else
            cursor++;
      } while (!(*cursor)->live);
   } /* End If */
   if (debug) {print_times(); printf("advance_cursor: cursor now %d\n", (*cursor)->n);}
}

/*
 *	find_host	-- Find a host in the list
 *
 *	Inputs:
 *
 *	he 	Pointer to the current position in the list.  Search runs
 *		backwards starting from this point.
 *	addr 	The source IP address that the packet came from.
 *	packet_in The received packet data.
 *	n	The length of the received packet.
 *
 *	Returns a pointer to the host entry associated with the specified IP
 *	or NULL if no match found.
 *
 *	This routine will normally find the host by IP address by comparing
 *	"addr" against "he->addr" for each entry in the list.  In this case,
 *	"packet_in" and "n" are not used.  However, it is  possible for
 *	the protocol-specific "local_find_host()" routine to override this
 *	generic routine, and the protocol specific routine may use "packet_in"
 *	and "n".
 */
struct host_entry *
find_host(struct host_entry **he, struct in_addr *addr,
          const unsigned char *packet_in, int n) {
   struct host_entry **p;
   struct host_entry *ptr;
   int found = 0;
   unsigned iterations = 0;	/* Used for debugging */
/*
 *	Return with the result from local_find_host if the local find_host
 *	function replaces this one.
 */
   if (local_find_host(&ptr, he, addr, packet_in, n)) {
      return ptr;
   }

   p = he;

   do {
      iterations++;
      if ((*p)->addr.s_addr == addr->s_addr) {
         found = 1;
      } else {
         if (p == helistptr) {
            p = helistptr + (num_hosts-1);	/* Wrap round to end */
         } else {
            p--;
         }
      }
   } while (!found && p != he);

   if (debug) {print_times(); printf("find_host: found=%d, iterations=%u\n", found, iterations);}

   if (found)
      return *p;
   else
      return NULL;
}

/*
 *	recvfrom_wto -- Receive packet with timeout
 *
 *	Inputs:
 *
 *	s	= Socket file descriptor.
 *	buf	= Buffer to receive data read from socket.
 *	len	= Size of buffer.
 *	saddr	= Socket structure.
 *	tmo	= Select timeout in us.
 *
 *	Returns number of characters received, or -1 for timeout.
 */
void
recvfrom_wto(int s, unsigned char *buf, int len, struct sockaddr *saddr,
             int tmo) {
   fd_set readset;
   struct timeval to;
   int n;

   FD_ZERO(&readset);
   FD_SET(s, &readset);
   to.tv_sec  = tmo/1000000;
   to.tv_usec = (tmo - 1000000*to.tv_sec);
   n = select(s+1, &readset, NULL, NULL, &to);
   if (debug) {print_times(); printf("recvfrom_wto: select end, tmo=%d, n=%d\n", tmo, n);}
   if (n < 0) {
      err_sys("select");
   } else if (n == 0) {
      return;	/* Timeout */
   }
   if ((pcap_dispatch(handle, -1, callback, NULL)) < 0)
      err_sys("pcap_dispatch: %s\n", pcap_geterr(handle));
}

/*
 *	timeval_diff -- Calculates the difference between two timevals
 *	and returns this difference in a third timeval.
 *
 *	Inputs:
 *
 *	a	= First timeval
 *	b	= Second timeval
 *	diff	= Difference between timevals (a - b).
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
 *
 *	Inputs:
 *
 *	None.
 */
void
dump_list(void) {
   int i;

   printf("Host List:\n\n");
   printf("Entry\tIP Address\n");
   for (i=0; i<num_hosts; i++)
      printf("%u\t%s\n", helistptr[i]->n, inet_ntoa(helistptr[i]->addr));
   printf("\nTotal of %u host entries.\n\n", num_hosts);
}

/*
 *	usage -- display usage message and exit
 *
 *	Inputs:
 *
 *	None.
 */
void
usage(void) {
   fprintf(stderr, "Usage: %s [options] [hosts...]\n", scanner_name);
   fprintf(stderr, "\n");
   fprintf(stderr, "Hosts are specified on the command line unless the --file option is specified.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Options:\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "--help or -h\t\tDisplay this usage message and exit.\n");
   fprintf(stderr, "\n--file=<fn> or -f <fn>\tRead hostnames or addresses from the specified file\n");
   fprintf(stderr, "\t\t\tinstead of from the command line. One name or IP\n");
   fprintf(stderr, "\t\t\taddress per line.  Use \"-\" for standard input.\n");
   fprintf(stderr, "\n--protocol=<p> or -p <p>\tSet IP protocol to <p>\n");
   fprintf(stderr, "\n--retry=<n> or -r <n>\tSet total number of attempts per host to <n>,\n");
   fprintf(stderr, "\t\t\tdefault=%d.\n", retry);
   fprintf(stderr, "\n--timeout=<n> or -t <n>\tSet initial per host timeout to <n> ms, default=%d.\n", timeout);
   fprintf(stderr, "\t\t\tThis timeout is for the first packet sent to each host.\n");
   fprintf(stderr, "\t\t\tsubsequent timeouts are multiplied by the backoff\n");
   fprintf(stderr, "\t\t\tfactor which is set with --backoff.\n");
   fprintf(stderr, "\n--interval=<n> or -i <n> Set minimum packet interval to <n> ms, default=%d.\n", interval);
   fprintf(stderr, "\t\t\tThis controls the outgoing bandwidth usage by limiting\n");
   fprintf(stderr, "\t\t\tthe rate at which packets can be sent.  The packet\n");
   fprintf(stderr, "\t\t\tinterval will be greater than or equal to this number.\n");
   fprintf(stderr, "\n--backoff=<b> or -b <b>\tSet timeout backoff factor to <b>, default=%.2f.\n", backoff_factor);
   fprintf(stderr, "\t\t\tThe per-host timeout is multiplied by this factor\n");
   fprintf(stderr, "\t\t\tafter each timeout.  So, if the number of retrys\n");
   fprintf(stderr, "\t\t\tis 3, the initial per-host timeout is 500ms and the\n");
   fprintf(stderr, "\t\t\tbackoff factor is 1.5, then the first timeout will be\n");
   fprintf(stderr, "\t\t\t500ms, the second 750ms and the third 1125ms.\n");
   fprintf(stderr, "\n--verbose or -v\t\tDisplay verbose progress messages.\n");
   fprintf(stderr, "\t\t\tUse more than once for greater effect:\n");
   fprintf(stderr, "\t\t\t1 - Show when hosts are removed from the list and\n");
   fprintf(stderr, "\t\t\t    when packets with invalid cookies are received.\n");
   fprintf(stderr, "\t\t\t2 - Show each packet sent and received.\n");
   fprintf(stderr, "\t\t\t3 - Display the host list before\n");
   fprintf(stderr, "\t\t\t    scanning starts.\n");
   fprintf(stderr, "\n--version or -V\t\tDisplay program version and exit.\n");
   fprintf(stderr, "\n--random or -R\t\tRandomise the host list.\n");
/* Call scanner-specific help function */
   local_help();
   fprintf(stderr, "\n");
   fprintf(stderr, "Report bugs or send suggestions to %s\n", PACKAGE_BUGREPORT);
   exit(1);
}

/*
 *	print_times -- display timing details for debugging.
 *
 *	Inputs:
 *
 *	None.
 */
void
print_times(void) {
   static struct timeval time_first;	/* When print_times() was first called */
   static struct timeval time_last;	/* When print_times() was last called */
   static int first_call=1;
   struct timeval time_now;
   struct timeval time_delta1;
   struct timeval time_delta2;

   Gettimeofday(&time_now);
   
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

/*
 * make_message -- allocate a sufficiently large string and print into it.
 *
 * Inputs:
 *
 * Format and variable number of arguments.
 *
 * Outputs:
 *
 * Pointer to the string,
 *
 * The code for this function is from the Debian Linux "woody" sprintf man
 * page.  Modified slightly to use wrapper functions for malloc and realloc.
 */
char *
make_message(const char *fmt, ...) {
   int n;
   /* Guess we need no more than 100 bytes. */
   size_t size = 100;
   char *p;
   va_list ap;
   p = Malloc (size);
   while (1) {
      /* Try to print in the allocated space. */
      va_start(ap, fmt);
      n = vsnprintf (p, size, fmt, ap);
      va_end(ap);
      /* If that worked, return the string. */
      if (n > -1 && n < size)
         return p;
      /* Else try again with more space. */
      if (n > -1)    /* glibc 2.1 */
         size = n+1; /* precisely what is needed */
      else           /* glibc 2.0 */
         size *= 2;  /* twice the old size */
      p = Realloc (p, size);
   }
}

/*
 *      printable -- Convert string to printable form using C-style escapes
 *
 *      Inputs:
 *
 *      string  Pointer to input string.
 *      size    Size of input string.  0 means that string is null-terminated.
 *
 *      Returns:
 *
 *      Pointer to the printable string.
 *
 *      Any non-printable characters are replaced by C-Style escapes, e.g.
 *      "\n" for newline.  As a result, the returned string may be longer than
 *      the one supplied.
 *
 *      This function makes two passes through the input string: one to
 *      determine the required output length, then a second to perform the
 *      conversion.
 *
 *      The pointer returned points to malloc'ed storage which should be
 *      free'ed by the caller when it's no longer needed.
 */
char *
printable(const unsigned char *string, size_t size) {
   char *result;
   char *r;
   const unsigned char *cp;
   size_t outlen;
   unsigned i;
/*
 *      If the input string is NULL, return an empty string.
 */
   if (string == NULL) {
      result = Malloc(1);
      result[0] = '\0';
      return result;
   }
/*
 *      Determine required size of output string.
 */
   if (!size)
      size = strlen((char *) string);

   outlen = size;
   cp = string;
   for (i=0; i<size; i++) {
      switch (*cp) {
         case '\b':
         case '\f':
         case '\n':
         case '\r':
         case '\t':
         case '\v':
            outlen++;
            break;
         default:
            if(!isprint(*cp))
               outlen += 3;
      }
      cp++;
   }
   outlen++;    /* One more for the ending NULL */

   result = Malloc(outlen);

   cp = string;
   r = result;
   for (i=0; i<size; i++) {
      switch (*cp) {
         case '\b':
            *r++ = '\\';
            *r++ = 'b';
            break;
         case '\f':
            *r++ = '\\';
            *r++ = 'f';
            break;
         case '\n':
            *r++ = '\\';
            *r++ = 'n';
            break;
         case '\r':
            *r++ = '\\';
            *r++ = 'r';
            break;
         case '\t':
            *r++ = '\\';
            *r++ = 't';
            break;
         case '\v':
            *r++ = '\\';
            *r++ = 'v';
            break;
         default:
            if (isprint(*cp)) {
               *r++ = *cp;      /* Printable character */
            } else {
               *r++ = '\\';
               sprintf(r, "%.3o", *cp);
               r += 3;
            }
            break;
      }
      cp++;
   }
   *r = '\0';

   return result;
}

/*
 *	process_options	--	Process options and arguments.
 *
 *	Inputs:
 *
 *	argc	Command line arg count
 *	argv	Command line args
 *
 *	Returns:
 *
 *	None.
 */
void
process_options(int argc, char *argv[]) {
   struct option long_options[] = {
      {"file", required_argument, 0, 'f'},
      {"help", no_argument, 0, 'h'},
      {"protocol", required_argument, 0, 'p'},
      {"retry", required_argument, 0, 'r'},
      {"timeout", required_argument, 0, 't'},
      {"interval", required_argument, 0, 'i'},
      {"backoff", required_argument, 0, 'b'},
      {"verbose", no_argument, 0, 'v'},
      {"version", no_argument, 0, 'V'},
      {"debug", no_argument, 0, 'd'},
      {"data", required_argument, 0, 'D'},
      {"random", no_argument, 0, 'R'},
      {0, 0, 0, 0}
   };
   const char *short_options = "f:hp:r:t:i:b:vVdD:";
   int arg;
   int options_index=0;
/*
 * Return immediately if the local process_options function replaces this
 * generic one.
 */
   if (local_process_options(argc, argv))
      return;

   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         case 'f':	/* --file */
            strncpy(filename, optarg, MAXLINE);
            filename_flag=1;
            break;
         case 'h':	/* --help */
            usage();
            break;
         case 'p':	/* --protocol */
            ip_protocol=atoi(optarg);
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
            backoff_factor=atof(optarg);
            break;
         case 'v':	/* --verbose */
            verbose++;
            break;
         case 'V':	/* --version */
            rawip_scan_version();
            exit(0);
            break;
         case 'd':	/* --debug */
            debug++;
            break;
         case 'D':	/* --data */
            local_data = Malloc(strlen(optarg)+1);
            strcpy(local_data, optarg);
            break;
         case 'R':      /* --random */
            random_flag=1;
            break;
         default:	/* Unknown option */
            usage();
            break;
      }
   }
}

/*
 *	rawip_scan_version -- display version information
 *
 *	Inputs:
 *
 *	None.
 *
 *	This displays the rawip-scan version information and also calls the
 *	protocol-specific version function to display the protocol-specfic
 *	version informattion.
 */
void
rawip_scan_version (void) {
   fprintf(stderr, "%s %s (%s)\n\n", scanner_name, scanner_version, PACKAGE_STRING);
   fprintf(stderr, "Copyright (C) 2003-2004 Roy Hills, NTA Monitor Ltd.\n");
   fprintf(stderr, "\n");
/* We use rcsid here to prevent it being optimised away */
   fprintf(stderr, "%s\n", rcsid);
/* Call scanner-specific version routine */
   local_version();
}
