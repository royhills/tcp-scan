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
 * tcp-scan -- The TCP Scanner
 *
 * Author:	Roy Hills
 * Date:	16 September 2003
 *
 * Usage:
 *    tcp-scan [options] [host...]
 *
 * Description:
 *
 * tcp-scan sends the specified TCP packet to the specified hosts
 * and displays any responses received.
 * 
 */

#include "tcp-scan.h"

static char const rcsid[] = "$Id$";   /* RCS ID for ident(1) */

/* Global variables */
int ip_protocol = DEFAULT_IP_PROTOCOL;	/* IP Protocol */
unsigned retry = DEFAULT_RETRY;		/* Number of retries */
unsigned timeout = DEFAULT_TIMEOUT;	/* Per-host timeout */
float backoff_factor = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
int snaplen = SNAPLEN;			/* Pcap snap length */
uint32_t seq_no;			/* Initial TCP sequence number */
uint32_t ack_no;			/* TCP acknowledgement number */
int seq_no_flag=0;
int ack_no_flag=0;
uint16_t source_port;			/* TCP Source Port */
int source_port_flag=0;
uint16_t window=DEFAULT_WINDOW;		/* TCP Window size */
uint16_t mss=DEFAULT_MSS;		/* TCP MSS. 0=Don't use MSS option */
int open_only=0;			/* Only show open ports? */
int wscale_flag=0;			/* Add wscale=0 TCP option? */
int sack_flag=0;			/* Add SACKOK TCP option? */
int timestamp_flag=0;			/* Add TIMESTAMP TCP option? */
int ip_ttl = DEFAULT_TTL;		/* IP TTL */
char *if_name=NULL;			/* Interface name, e.g. "eth0" */
int quiet_flag=0;			/* Don't decode the packet */
int ignore_dups=0;			/* Don't display duplicate packets */
int df_flag=DEFAULT_DF;			/* IP DF Flag */
int ip_tos=DEFAULT_TOS;			/* IP TOS Field */
int portname_flag=0;			/* Display port names */
int tcp_flags_flag=0;			/* Specify outbound TCP flags */
struct tcp_flags_struct tcp_flags;	/* Specified TCP flags */
char **portnames=NULL;
unsigned live_count;			/* Number of entries awaiting reply */

int verbose = 0;			/* Verbose level */
int debug = 0;				/* Debug flag */
char *local_data=NULL;			/* Local data from --data option */
struct host_entry *helist = NULL;	/* Array of host entries */
struct host_entry **helistptr;		/* Array of pointers to host entries */
unsigned num_hosts = 0;			/* Number of entries in the list */
unsigned max_iter;			/* Max iterations in find_host() */
pcap_t *handle;				/* pcap handle */
struct host_entry **cursor;		/* Pointer to current host entry ptr */
unsigned responders = 0;		/* Number of hosts which responded */
char filename[MAXLINE];
int filename_flag=0;
int random_flag=0;			/* Randomise the list */
int numeric_flag=0;			/* IP addresses only */
int ipv6_flag=0;			/* IPv6 */
unsigned bandwidth=DEFAULT_BANDWIDTH;	/* Bandwidth in bits per sec */
unsigned interval=0;

static uint32_t source_address;
int pcap_fd;				/* pcap File Descriptor */
static size_t ip_offset;		/* Offset to IP header in pcap pkt */
static uint16_t *port_list=NULL;
static char *ga_err_msg;		/* getaddrinfo error message */

int
main(int argc, char *argv[]) {
   int sockfd;                  /* IP socket file descriptor */
   struct sockaddr_in sa_peer;
   struct timeval now;
   unsigned char packet_in[MAXIP];      /* Received packet */
   struct timeval diff;         /* Difference between two timevals */
   unsigned select_timeout;     /* Select timeout */
   unsigned long long loop_timediff;    /* Time since last packet sent in us */
   unsigned long long host_timediff; /* Time since last pkt sent to this host (us) */
   struct timeval last_packet_time;     /* Time last packet was sent */
   int req_interval;            /* Requested per-packet interval */
   int cum_err=0;               /* Cumulative timing error */
   struct timeval start_time;   /* Program start time */
   struct timeval end_time;     /* Program end time */
   struct timeval elapsed_time; /* Elapsed time as timeval */
   double elapsed_seconds;      /* Elapsed time in seconds */
   static int reset_cum_err;
   static int pass_no;
   int first_timeout=1;
   const int on = 1;            /* For setsockopt */
   int i;
/*
 *      Process options.
 */
   process_options(argc, argv);
/*
 *      Get program start time for statistics displayed on completion.
 */
   Gettimeofday(&start_time);
   if (debug) {print_times(); printf("main: Start\n");}
/*
 *      Create raw IP socket and set IP_HDRINCL
 */
   if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
      err_sys("socket");
   if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) != 0)
      err_sys("setsockopt");
   if ((setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) != 0)
      err_sys("setsockopt");
/*
 *      Call protocol-specific initialisation routine to perform any
 *      initial setup required.
 */
   initialise();
/*
 *      Drop privileges.
 */
   if ((setuid(getuid())) < 0) {
      err_sys("setuid");
   }
/*
 *      If we're not reading from a file, then we must have some hosts
 *      given as command line arguments.
 */
   if (!filename_flag)
      if ((argc - optind) < 1)
         usage(EXIT_FAILURE);
/*
 *      Populate the list from the specified file if --file was specified, or
 *      otherwise from the remaining command line arguments.
 */
   if (filename_flag) { /* Populate list from file */
      FILE *fp;
      char line[MAXLINE];
      char *cp;

      if ((strcmp(filename, "-")) == 0) {       /* Filename "-" means stdin */
         if ((fp = fdopen(0, "r")) == NULL) {
            err_sys("fdopen");
         }
      } else {
         if ((fp = fopen(filename, "r")) == NULL) {
            err_sys("fopen");
         }
      }

      while (fgets(line, MAXLINE, fp)) {
         cp = line;
         while (!isspace(*cp) && *cp != '\0')
            cp++;
         *cp = '\0';
         add_host(line, timeout);
      }
      fclose(fp);
   } else {             /* Populate list from command line arguments */
      argv=&argv[optind];
      while (*argv) {
         add_host(*argv, timeout);
         argv++;
      }
   }
/*
 *      Check that we have at least one entry in the list.
 */
   if (!num_hosts)
      err_msg("No hosts to process.");
/*
 *      Check that the combination of specified options and arguments is
 *      valid.
 */
   if (interval && bandwidth != DEFAULT_BANDWIDTH)
      err_msg("ERROR: You cannot specify both --bandwidth and --interval.");
/*
 *      Create and initialise array of pointers to host entries.
 */
   helistptr = Malloc(num_hosts * sizeof(struct host_entry *));
   for (i=0; i<num_hosts; i++)
      helistptr[i] = &helist[i];
/*
 *      Randomise the list if required.
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
 *      Set current host pointer (cursor) to start of list, zero
 *      last packet sent time, and set last receive time to now.
 */
   live_count = num_hosts;
   cursor = helistptr;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
/*
 *      Calculate the required interval to achieve the required outgoing
 *      bandwidth unless the interval was manually specified with --interval.
 */
   if (!interval) {
      size_t packet_out_len;

      packet_out_len=send_packet(0, NULL, 1, NULL); /* Get packet data size */
      if (packet_out_len < MINIMUM_FRAME_SIZE)
         packet_out_len = MINIMUM_FRAME_SIZE;   /* Adjust to minimum size */
      packet_out_len += PACKET_OVERHEAD;        /* Add layer 2 overhead */
      interval = ((ARP_UINT64)packet_out_len * 8 * 1000000) / bandwidth;
      if (verbose) {
         warn_msg("DEBUG: Ether pkt len=%u bytes, bandwidth=%u bps, int=%u us",
                  packet_out_len, bandwidth, interval);
      }
   }
/*
 *      Display initial message.
 */
   printf("Starting %s with %u ports\n", PACKAGE_STRING, num_hosts);
/*
 *      Display the lists if verbose setting is 3 or more.
 */
   if (verbose > 2)
      dump_list();
/*
 *      Main loop: send packets to all hosts in order until a response
 *      has been received or the host has exhausted its retry limit.
 *
 *      The loop exits when all hosts have either responded or timed out.
 */
   reset_cum_err = 1;
   req_interval = interval;
   while (live_count) {
      if (debug) {print_times(); printf("main: Top of loop.\n");}
/*
 *      Obtain current time and calculate deltas since last packet and
 *      last packet to this host.
 */
      Gettimeofday(&now);
/*
 *      If the last packet was sent more than interval us ago, then we can
 *      potentially send a packet to the current host.
 */
      timeval_diff(&now, &last_packet_time, &diff);
      loop_timediff = (unsigned long long)1000000*diff.tv_sec + diff.tv_usec;
      if (loop_timediff >= req_interval) {
         if (debug) {print_times(); printf("main: Can send packet now.  loop_timediff=%llu\n", loop_timediff);}
/*
 *      If the last packet to this host was sent more than the current
 *      timeout for this host us ago, then we can potentially send a packet
 *      to it.
 */
         timeval_diff(&now, &((*cursor)->last_send_time), &diff);
         host_timediff = (unsigned long long)1000000*diff.tv_sec + diff.tv_usec;
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
 *      If we've exceeded our retry limit, then this host has timed out so
 *      remove it from the list.  Otherwise, increase the timeout by the
 *      backoff factor if this is not the first packet sent to this host
 *      and send a packet.
 */
            if (verbose && (*cursor)->num_sent > pass_no) {
               warn_msg("---\tPass %d complete", pass_no+1);
               pass_no = (*cursor)->num_sent;
            }
            if ((*cursor)->num_sent >= retry) {
               if (verbose > 1)
                  warn_msg("---\tRemoving host entry %u (%s) - Timeout", (*cursor)->n, my_ntoa((*cursor)->addr,ipv6_flag));
               if (debug) {print_times(); printf("main: Timing out host %d.\n", (*cursor)->n);}
               remove_host(cursor);     /* Automatically calls advance_cursor() */
               if (first_timeout) {
                  timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                  host_timediff = (unsigned long long)1000000*diff.tv_sec +
                                  diff.tv_usec;
                  while (host_timediff >= (*cursor)->timeout && live_count) {
                     if ((*cursor)->live) {
                        if (verbose > 1)
                           warn_msg("---\tRemoving host %u (%s) - Catch-Up Timeout", (*cursor)->n, my_ntoa((*cursor)->addr,ipv6_flag));
                        remove_host(cursor);
                     } else {
                        advance_cursor();
                     }
                     timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                     host_timediff = (unsigned long long)1000000*diff.tv_sec +
                                     diff.tv_usec;
                  }
                  first_timeout=0;
               }
               Gettimeofday(&last_packet_time);
            } else {    /* Retry limit not reached for this host */
               if ((*cursor)->num_sent)
                  (*cursor)->timeout *= backoff_factor;
               send_packet(sockfd, *cursor, ip_protocol, &last_packet_time);
               advance_cursor();
            }
         } else {       /* We can't send a packet to this host yet */
/*
 *      Note that there is no point calling advance_cursor() here because if
 *      host n is not ready to send, then host n+1 will not be ready either.
 */
            select_timeout = (*cursor)->timeout - host_timediff;
            reset_cum_err = 1;  /* Zero cumulative error */
            if (debug) {print_times(); printf("main: Can't send packet to host %d yet. host_timediff=%llu\n", (*cursor)->n, host_timediff);}
         } /* End If */
      } else {          /* We can't send a packet yet */
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

   printf("Ending %s: %u hosts scanned in %.3f seconds (%.2f hosts/sec).  %u responded\n",
          PACKAGE_STRING, num_hosts, elapsed_seconds, num_hosts/elapsed_seconds,
          responders);
   if (debug) {print_times(); printf("main: End\n");}
   return 0;
}

/*
 *	display_packet -- Check and display received packet
 *
 *	Inputs:
 *
 *	n		The length of the received packet in bytes.
 *			Note that this can be more or less than the IP packet
 *			size because of minimum frame sizes or snaplength
 *			cutoff respectively.
 *	packet_in	The received packet
 *	he		The host entry corresponding to the received packet
 *	recv_addr	IP address that the packet was received from
 *
 *      Returns:
 *
 *      None.
 *
 *      This should check the received packet and display details of what
 *      was received in the format: <IP-Address><TAB><Details>.
 */
void
display_packet(int n, const unsigned char *packet_in, struct host_entry *he,
               struct in_addr *recv_addr) {
   struct iphdr *iph;
   struct tcphdr *tcph;
   char *msg;
   char *cp;
   char *flags;
   int data_len;
   unsigned data_offset;
   char *df;
   int optlen;
/*
 *	Set msg to the IP address of the host entry, plus the address of the
 *	responder if different, and a tab.
 */
   msg = make_message("%s\t", my_ntoa(he->addr,ipv6_flag));
   if ((he->addr).v4.s_addr != recv_addr->s_addr) {	/* XXXX */
      cp = msg;
      msg = make_message("%s(%s) ", cp, inet_ntoa(*recv_addr));
      free(cp);
   }
/*
 *	Check that the packet is large enough to decode.
 *	This should never happen because the packet length should have
 *	already been checked in callback().
 */
   if (n < ip_offset + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
      printf("%s%d byte packet too short to decode\n", msg, n);
      free(msg);
      return;
   }
/*
 *      Overlay IP and TCP headers on packet buffer.
 *      ip_offset is size of layer-2 header.
 *      Note that iph.ihl is in 32-bit units.  We multiply by 4 to get bytes.
 *      iph.lhl is normally 5, but can be larger if IP options are present.
 */
   iph = (struct iphdr *) (packet_in + ip_offset);
   tcph = (struct tcphdr *) (packet_in + ip_offset + 4*(iph->ihl));
/*
 *	Add TCP port to message.
 */
   cp = msg;
   if (portname_flag) {
      char *portname = portnames[ntohs(tcph->source)];
      msg = make_message("%s%u (%s)\t", cp, ntohs(tcph->source),
                         portname?portname:"unknown");
   } else {
      msg = make_message("%s%u\t", cp, ntohs(tcph->source));
   }
   free(cp);
/*
 *	Determine type of response: SYN-ACK, RST or something else and
 *	add to message.
 */
   cp = msg;
   if (tcph->syn && tcph->ack) {	/* SYN + ACK = Open */
      msg = make_message("%sOPEN", cp);
   } else if (tcph->rst) {		/* RST = Closed */
      msg = make_message("%sCLOSED", cp);
   } else {				/* Shouldn't happen */
      msg = make_message("%sUNKNOWN", cp);
   }
   free(cp);
   if (!quiet_flag) {
/*
 *	Add DF, TCP Flags, TTL, IPIP, and IP packet length to the message.
 */
      flags = NULL;
      if (tcph->cwr) {
         if (flags) {
            cp = flags;
            flags = make_message("%s,CWR", cp);
            free(cp);
         } else {
            flags = make_message("CWR");
         }
      }
      if (tcph->ecn) {
         if (flags) {
            cp = flags;
            flags = make_message("%s,ECN", cp);
            free(cp);
         } else {
            flags = make_message("ECN");
         }
      }
      if (tcph->urg) {
         if (flags) {
            cp = flags;
            flags = make_message("%s,URG", cp);
            free(cp);
         } else {
            flags = make_message("URG");
         }
      }
      if (tcph->ack) {
         if (flags) {
            cp = flags;
            flags = make_message("%s,ACK", cp);
            free(cp);
         } else {
            flags = make_message("ACK");
         }
      }
      if (tcph->psh) {
         if (flags) {
            cp = flags;
            flags = make_message("%s,PSH", cp);
            free(cp);
         } else {
            flags = make_message("PSH");
         }
      }
      if (tcph->rst) {
         if (flags) {
            cp = flags;
            flags = make_message("%s,RST", cp);
            free(cp);
         } else {
            flags = make_message("RST");
         }
      }
      if (tcph->syn) {
         if (flags) {
            cp = flags;
            flags = make_message("%s,SYN", cp);
            free(cp);
         } else {
            flags = make_message("SYN");
         }
      }
      if (tcph->fin) {
         if (flags) {
            cp = flags;
            flags = make_message("%s,FIN", cp);
            free(cp);
         } else {
            flags = make_message("FIN");
         }
      }
      if (!flags)
         flags=make_message(""); /* Ensure flags not NULL if no TCP flags set */
      if (ntohs(iph->frag_off) & 0x4000) {	/* If DF flag set */
         df = "yes";
      } else {
         df = "no";
      }
      cp = msg;
      msg=make_message("%s\tDF=%s TOS=%u flags=%s win=%u ttl=%u id=%u ip_len=%d",
                       cp, df, iph->tos, flags, ntohs(tcph->window), iph->ttl,
                       ntohs(iph->id), ntohs(iph->tot_len));
      free(cp);
      free(flags);
/*
 *	Determine TCP options.
 */
      optlen = 4*(tcph->doff) - sizeof(struct tcphdr);
      if (optlen) {
         char *options=NULL;
         int trunc=0;
         unsigned char *optptr=(unsigned char *) (packet_in + ip_offset +
                                                  4*(iph->ihl) +
                                                  sizeof(struct tcphdr));
         uint16_t *sptr;	/* 16-bit ptr - used for MSS */
         uint32_t *lptr1;	/* 32-bit ptr - used for timestamp value */
         uint32_t *lptr2;	/* 32-bit ptr - used for timestamp value */
         unsigned char uc;
/*
 *	Check if options have been truncated.
 */
         if (n - ip_offset - sizeof(struct iphdr) - sizeof(struct tcphdr)
             < optlen) {
            if (verbose)
               warn_msg("---\tCaptured packet length %d is too short for calculated TCP options length %d.  Adjusting options length", n, optlen);
            optlen = n - ip_offset - sizeof(struct iphdr) - sizeof(struct tcphdr);
            trunc=1;
         }
         if (ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr)
             < optlen) {
            if (verbose)
               warn_msg("---\tClaimed IP packet length %d is too short for calculated TCP options length %d.  Adjusting options length", ntohs(iph->tot_len), optlen);
            optlen = ntohs(iph->tot_len) - sizeof(struct iphdr) -
                     sizeof(struct tcphdr);
            trunc=1;
         }

         while (optlen > 0) {
            switch (*optptr) {
               case TCPOPT_EOL:
                  optlen--;
                  optptr++;
                  if (options) {
                     cp = options;
                     options = make_message("%s,EOL", cp);
                     free(cp);
                  } else {
                     options = make_message("EOL");
                  }
                  break;
               case TCPOPT_NOP:
                  optlen--;
                  optptr++;
                  if (options) {
                     cp = options;
                     options = make_message("%s,NOP", cp);
                     free(cp);
                  } else {
                     options = make_message("NOP");
                  }
                  break;
               case TCPOPT_MAXSEG:
                  optlen -= 4;
                  sptr = (uint16_t *) (optptr+2);
                  optptr += 4;
                  if (options) {
                     cp = options;
                     options = make_message("%s,MSS=%u", cp, ntohs(*sptr));
                     free(cp);
                  } else {
                     options = make_message("MSS=%u", ntohs(*sptr));
                  }
                  break;
               case TCPOPT_WINDOW:
                  uc = *(optptr+2);
                  optlen -= 3;
                  optptr += 3;
                  if (options) {
                     cp = options;
                     options = make_message("%s,WSCALE=%u", cp, uc);
                     free(cp);
                  } else {
                     options = make_message("WSCALE=%u", uc);
                  }
                  break;
               case TCPOPT_SACK_PERMITTED:
                  optlen -= 2;
                  optptr += 2;
                  if (options) {
                     cp = options;
                     options = make_message("%s,SACKOK", cp);
                     free(cp);
                  } else {
                     options = make_message("SACKOK");
                  }
                  break;
               case TCPOPT_TIMESTAMP:
                  optlen -= 10;
                  lptr1 = (uint32_t *) (optptr+2);	/* TS Value */
                  lptr2 = (uint32_t *) (optptr+6);	/* TS Echo Reply */
                  optptr += 10;
                  if (options) {
                     cp = options;
                     options = make_message("%s,TIMESTAMP=%u,%u", cp,
                                            ntohl(*lptr1), ntohl(*lptr2));
                     free(cp);
                  } else {
                     options = make_message("TIMESTAMP=%u,%u", ntohl(*lptr1),
                                            ntohl(*lptr2));
                  }
                  break;
               default:
                  uc = *optptr;
                  if (options) {
                     cp = options;
                     options = make_message("%s,opt-%u", cp, uc);
                     free(cp);
                  } else {
                     options = make_message("opt-%u", uc);
                  }
                  uc = *(optptr+1);
                  optlen -= uc;
                  optptr += uc;
                  break;
            }
         }
         if (!options)
            options=make_message("");	/* Ensure options not NULL */
         cp = msg;
         if (trunc) {
            msg = make_message("%s <%s,...>", cp, options);
         } else {
            msg = make_message("%s <%s>", cp, options);
         }
         free(cp);
         free(options);
      }
/*
 *	Determine length of TCP data.  If this is non-zero, then display the
 *	data.
 */
      data_len = ntohs(iph->tot_len) - 4*(iph->ihl) - 4*(tcph->doff);
      data_offset = ip_offset + 4*(iph->ihl) + 4*(tcph->doff);
      if (data_len > 0) {
         char *data_str;

         cp = msg;
         if (n >= data_offset + data_len) {
            data_str=printable(packet_in+data_offset, data_len);
            msg = make_message("%s data_len=%d data=\"%s\"", cp, data_len,
                               data_str);
            free(data_str);
         } else {
            msg = make_message("%s data_len=%d data=(packet too short to decode)",
                               cp, data_len);
         }
         free(cp);
      }
/*
 *	If the host entry is not live, then flag this as a duplicate.
 */
      if (!he->live) {
         cp = msg;
         msg = make_message("%s (DUP: %u)", cp, he->num_recv);
         free(cp);
      }
   }	/* End if (!quiet_flag) */
/*
 *	Print the message.
 */
   printf("%s\n", msg);
   free(msg);
}

/*
 *	send_packet -- Construct and send a packet to the specified host
 *
 *	Inputs:
 *
 *	s		IP socket file descriptor
 *	he		Host entry to send to. If NULL, then no packet is sent
 *	ip_protocol	IP Protocol to use
 *	last_packet_time	Time when last packet was sent
 *
 *      Returns:
 *
 *      The size of the packet that was sent.
 *
 *      This must construct an appropriate packet and send it to the host
 *      identified by "he" using the socket "s".
 *      It must also update the "last_send_time" field for this host entry.
 */
int
send_packet(int s, struct host_entry *he, int ip_protocol,
            struct timeval *last_packet_time) {
   struct sockaddr_in sa_peer;
   char buf[MAXIP];
   int buflen;
   NET_SIZE_T sa_peer_len;
   struct iphdr *iph = (struct iphdr *) buf;
   struct tcphdr *tcph = (struct tcphdr *) (buf + sizeof(struct iphdr));
   struct pseudo_hdr {	/* For computing TCP checksum */
      uint32_t s_addr;
      uint32_t d_addr;
      uint8_t  mbz;
      uint8_t  proto;
      uint16_t len;
   };
   /* Position pseudo header just before the TCP header */
   struct pseudo_hdr *pseudo = (struct pseudo_hdr *) (buf + sizeof(struct iphdr)
   - sizeof(struct pseudo_hdr));
   unsigned char *options = (unsigned char *) (buf + sizeof(struct iphdr) +
                                              sizeof(struct tcphdr));
   unsigned char *optptr;
   size_t options_len=0;
/*
 *	Determine length of TCP options.
 *	We do this early because we need it for the packet length.
 */
   if (mss) {
      options_len += 4;
   }
   if (timestamp_flag) {
      options_len += 12;
   } else if (sack_flag) {
      options_len += 4;
   }
   if (wscale_flag) {
      options_len += 4;
   }
/*
 *	If he is NULL, just return with the packet length.
 */
   if (he == NULL)
      return sizeof(struct iphdr) + sizeof(struct tcphdr) + options_len;
/*
 *	Check that the host is live.  Complain if not.
 */
   if (!he->live) {
      warn_msg("***\tsend_packet called on non-live host entry: SHOULDN'T HAPPEN");
      return 0;
   }
/*
 *	Set up the sockaddr_in structure for the host.
 */
   memset(&sa_peer, '\0', sizeof(sa_peer));
   sa_peer.sin_family = AF_INET;
   sa_peer.sin_addr.s_addr = he->addr.v4.s_addr;
   sa_peer_len = sizeof(sa_peer);
/*
 *	Update the last send times for this host.
 *	We do this here because we can also use this value for the TCP
 *	timestamp option.
 */
   Gettimeofday(last_packet_time);
   he->last_send_time.tv_sec  = last_packet_time->tv_sec;
   he->last_send_time.tv_usec = last_packet_time->tv_usec;
   he->num_sent++;
/*
 *	Construct the pseudo header (for TCP checksum purposes).
 *	Note that this overlaps the IP header and gets overwritten later.
 */
   memset(pseudo, '\0', sizeof(struct pseudo_hdr));
   pseudo->s_addr = source_address;
   pseudo->d_addr = he->addr.v4.s_addr;
   pseudo->proto  = ip_protocol;
   pseudo->len    = htons(sizeof(struct tcphdr) + options_len);
/*
 *	Add TCP options.  We do this before the TCP header because the
 *	options must be covered by the TCP checksum calculation.
 *
 *	We put the options in the same order, and with the same padding,
 *	as Linux 2.4.24.
 */
   optptr = options;
   if (mss) {
      *optptr++ = 2;		/* Kind=2 (MSS) */
      *optptr++ = 4;		/* Len=4 Bytes */
      *optptr++ = mss / 256;	/* MSS high byte */
      *optptr++ = mss % 256;	/* MSS low byte */
   }
   if (timestamp_flag) {
      uint32_t tsval=htonl(last_packet_time->tv_sec);
      if (sack_flag) {
         *optptr++ = 4;		/* Kind=4 (SACKOK) */
         *optptr++ = 2;		/* Len=2 bytes */
      } else {
         *optptr++ = 1;		/* Kind=1 (NOP) - pad */
         *optptr++ = 1;		/* Kind=1 (NOP) - pad */
      }
      *optptr++ = 8;		/* Kind=8 (TIMESTAMP) */
      *optptr++ = 10;		/* Len=10 bytes */
      memcpy(optptr, &tsval, sizeof(tsval));	/* TS Value */
      optptr += sizeof(tsval);
      *optptr++ = 0;		/* TS Echo Reply */
      *optptr++ = 0;
      *optptr++ = 0;
      *optptr++ = 0;
   } else if (sack_flag) {
      *optptr++ = 1;		/* Kind=1 (NOP) - pad */
      *optptr++ = 1;		/* Kind=1 (NOP) - pad */
      *optptr++ = 4;		/* Kind=4 (SACKOK) */
      *optptr++ = 2;		/* Len=2 bytes */
   }
   if (wscale_flag) {
      *optptr++ = 1;		/* Kind=1 (NOP) - pad */
      *optptr++ = 3;		/* Kind=3 (WSCALE) */
      *optptr++ = 3;		/* Len=3 bytes */
      *optptr++ = 0;		/* Value=0 */
   }
/*
 *	Construct the TCP header.
 */
   memset(tcph, '\0', sizeof(struct tcphdr));
   tcph->source = htons(source_port);
   tcph->dest = htons(he->dport);
   tcph->seq = htonl(seq_no);
   tcph->doff = (sizeof(struct tcphdr) + options_len) / 4;
   if (tcp_flags_flag) {	/* Set specified TCP flags */
      if (tcp_flags.cwr)
         tcph->cwr = 1;
      if (tcp_flags.ecn)
         tcph->ecn = 1;
      if (tcp_flags.urg)
         tcph->urg = 1;
      if (tcp_flags.ack) {
         tcph->ack = 1;
         tcph->ack_seq = htonl(ack_no);
      }
      if (tcp_flags.psh)
         tcph->psh = 1;
      if (tcp_flags.rst)
         tcph->rst = 1;
      if (tcp_flags.syn)
         tcph->syn = 1;
      if (tcp_flags.fin)
         tcph->fin = 1;
   } else {			/* Default: Set SYN flag */
      tcph->syn = 1;
   }
   tcph->window = htons(window);
   tcph->check = in_cksum((uint16_t *)pseudo, sizeof(struct pseudo_hdr) +
                 sizeof(struct tcphdr) + options_len);
/*
 *	Construct the IP Header.
 *	This overwrites the now unneeded pseudo header.
 */
   memset(iph, '\0', sizeof(struct iphdr));
   iph->ihl = 5;	/* 5 * 32-bit longwords = 20 bytes */
   iph->version = 4;
   iph->tos = ip_tos;
   iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
   iph->id = 0;		/* Linux kernel fills this in */
   if (df_flag)
      iph->frag_off = htons(0x4000);
   else
      iph->frag_off = htons(0x0);
   iph->ttl = ip_ttl;
   iph->protocol = ip_protocol;
   iph->check = 0;	/* Linux kernel fills this in */
   iph->saddr = source_address;
   iph->daddr = he->addr.v4.s_addr;
/*
 *	Copy the required data into the output buffer "buf" and set "buflen"
 *	to the number of bytes in this buffer.
 */
   buflen=sizeof(struct iphdr) + sizeof(struct tcphdr) + options_len;
/*
 *	Send the packet.
 */
   if (debug) {print_times(); printf("send_packet: #%u to host entry %u (%s) tmo %d\n", he->num_sent, he->n, my_ntoa(he->addr,ipv6_flag), he->timeout);}
   if (verbose > 1)
      warn_msg("---\tSending packet #%u to host entry %u (%s) tmo %d", he->num_sent, he->n, my_ntoa(he->addr,ipv6_flag), he->timeout);
   if ((sendto(s, buf, buflen, 0, (struct sockaddr *) &sa_peer, sa_peer_len)) < 0) {
      err_sys("sendto");
   }
   return buflen;
}

/*
 *      initialise -- Protocol-specific initialisation routine.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 *      This is called once before any packets have been sent.  It can be
 *      used to perform any required initialisation.  It does not have to
 *      do anything.
 */
void
initialise(void) {
   md5_state_t context;
   struct timeval now;
   pid_t pid;
   struct utsname uname_buf;
   char str[MAXLINE];
   md5_byte_t md5_digest[16];		/* MD5 hash used as random source */
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program filter;
   char *filter_string;
   bpf_u_int32 netmask;
   bpf_u_int32 localnet;
   int datalink;
/*
 *	Create an MD5 hash of various things to use as a source of random
 *	data.
 */
   Gettimeofday(&now);
   pid=getpid();
   if ((uname(&uname_buf)) !=0 ) {
      perror("uname");
      exit(1);
   }

   sprintf(str, "%lu %lu %u %s", now.tv_usec, now.tv_sec, pid,
           uname_buf.nodename);
   md5_init(&context);
   md5_append(&context, (const md5_byte_t *)str, strlen(str));
   md5_finish(&context, md5_digest);
/*
 *	Set the sequence number, ack number and source port using the MD5 hash
 *	if they have not been set with command line options.
 *	We set the top bit of source port to make sure that it's
 *	above 32768 and therefore out of the way of reserved ports
 *	(1-1024).
 */
   if (!seq_no_flag)
      memcpy(&seq_no, md5_digest, sizeof(uint32_t));
   if (!ack_no_flag)
      memcpy(&ack_no, md5_digest+sizeof(uint32_t), sizeof(uint32_t));
   if (!source_port_flag) {
      memcpy(&source_port, md5_digest+sizeof(uint32_t)+sizeof(uint32_t),
             sizeof(uint16_t));
      source_port |= 0x8000;
   }
/*
 *	Determine source interface and associated IP address.
 *	If the interface was specified with the --interface option then use
 *	that, otherwise if the environment variable "RMIF" exists then use
 *	that, failing that default to "eth0".
 */
   if (!if_name) {
      if (!(if_name=getenv("RMIF")))
         if_name="eth0";
   }
   source_address = get_source_ip(if_name);
/*
 *	Prepare pcap
 */
   if (!(handle = pcap_open_live(if_name, snaplen, PROMISC, TO_MS, errbuf)))
      err_msg("pcap_open_live: %s\n", errbuf);
   if ((datalink=pcap_datalink(handle)) < 0)
      err_msg("pcap_datalink: %s\n", pcap_geterr(handle));
   printf("Interface: %s, datalink type: %s (%s)\n", if_name,
          pcap_datalink_val_to_name(datalink),
          pcap_datalink_val_to_description(datalink));
   switch (datalink) {
      case DLT_EN10MB:		/* Ethernet */
         ip_offset = 14;
         break;
      case DLT_LINUX_SLL:	/* PPP on Linux */
         ip_offset = 16;
         break;
      default:
         err_msg("Unsupported datalink type");
         break;
   }
   if ((pcap_fd=pcap_fileno(handle)) < 0)
      err_msg("pcap_fileno: %s\n", pcap_geterr(handle));
   if ((pcap_setnonblock(handle, 1, errbuf)) < 0)
      err_msg("pcap_setnonblock: %s\n", errbuf);
   if (pcap_lookupnet(if_name, &localnet, &netmask, errbuf) < 0)
      err_msg("pcap_lookupnet: %s\n", errbuf);
   if (tcp_flags_flag && tcp_flags.ack) {
      filter_string=make_message("tcp dst port %u and tcp[4:4] = %u",
                                 source_port, ack_no);
   } else {
      filter_string=make_message("tcp dst port %u and tcp[8:4] = %u",
                                 source_port, seq_no+1);
   }
   if ((pcap_compile(handle, &filter, filter_string, OPTIMISE, netmask)) < 0)
      err_msg("pcap_geterr: %s\n", pcap_geterr(handle));
   free(filter_string);
   if ((pcap_setfilter(handle, &filter)) < 0)
      err_msg("pcap_setfilter: %s\n", pcap_geterr(handle));
/*
 *	If we are displaying portnames, then initialise portname array.
 */
   if (portname_flag) {
      FILE *fp;
      int i;
      int n;
      char *p;
      char lbuf[MAXLINE];
      char desc[256];
      char portname[17];
      unsigned int port;
      char prot[4];

      if ((access(SERVICE_FILE, R_OK)) != 0)
         err_sys("Cannot open services file");
      if (!(fp = fopen(SERVICE_FILE, "r")))
         err_sys("Cannot open services file");
      portnames = Malloc(65536 * sizeof(char *));
      for (i=0; i<65536; i++)
         portnames[i] = NULL;
      while (fgets(lbuf, MAXLINE, fp)) {
         if (strchr("*# \t\n", lbuf[0]))
             continue;
         if (!(p = strchr (lbuf, '/')))
             continue;
         *p = ' ';
         desc[0]='\0';
         n=sscanf(lbuf, "%16s %u %3s %255[^\r\n]", portname, &port, prot,
                  desc);
         if (n >= 3 && !strcmp(prot, "tcp") && (port < 65536)) {
            portnames[port] = make_message("%s", portname);
         }
      }
   }
}

/*
 *      clean_up -- Protocol-specific Clean-Up routine.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 *      This is called once after all hosts have been processed.  It can be
 *      used to perform any tidying-up or statistics-displaying required.
 *      It does not have to do anything.
 */
void
clean_up(void) {
   struct pcap_stat stats;

   if ((pcap_stats(handle, &stats)) < 0)
      err_msg("pcap_stats: %s\n", pcap_geterr(handle));

   printf("%u packets received by filter, %u packets dropped by kernel\n",
          stats.ps_recv, stats.ps_drop);
   pcap_close(handle);
}

/*
 *	usage -- display usage message and exit
 *
 *	Inputs:
 *
 *	status	Status value to pass to exit()
 */
void
usage(int status) {
   fprintf(stderr, "Usage: tcp-scan [options] [hosts...]\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Hosts are specified on the command line unless the --file option is specified.\n");
   fprintf(stderr, "Each host uses %u bytes of memory.\n",
           sizeof(struct host_entry) + sizeof(struct host_entry *));
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
   fprintf(stderr, "\n--interval=<n> or -i <n> Set minimum packet interval to <n> ms, default=%d.\n", interval/1000);
   fprintf(stderr, "\t\t\tThis controls the outgoing bandwidth usage by limiting\n");
   fprintf(stderr, "\t\t\tthe rate at which packets can be sent.  The packet\n");
   fprintf(stderr, "\t\t\tinterval will be no smaller than this number.\n");
   fprintf(stderr, "\t\t\tThe interval specified is in milliseconds by default.\n");
   fprintf(stderr, "\t\t\tif \"u\" is appended to the value, then the interval\n");
   fprintf(stderr, "\t\t\tis in microseconds, and if \"s\" is appended, the\n");
   fprintf(stderr, "\t\t\tinterval is in seconds.\n");
   fprintf(stderr, "\t\t\tIf you want to use up to a given bandwidth, then it is\n");
   fprintf(stderr, "\t\t\teasier to use the --bandwidth option instead.\n");
   fprintf(stderr, "\n--bandwidth=<n> or -B <n> Set desired outbound bandwidth to <n>.\n");
   fprintf(stderr, "\t\t\tThe value is in bits per second by default.  If you\n");
   fprintf(stderr, "\t\t\tappend \"K\" to the value, then the units are kilobits\n");
   fprintf(stderr, "\t\t\tper sec; and if you append \"M\" to the value, the\n");
   fprintf(stderr, "\t\t\tunits are megabits per second.\n");
   fprintf(stderr, "\t\t\tThe \"K\" and \"M\" suffixes represent the decimal, not\n");
   fprintf(stderr, "\t\t\tbinary, multiples.  So 64K is 64000, not 65536.\n");
   fprintf(stderr, "\t\t\tYou cannot specify both --interval and --bandwidth\n");
   fprintf(stderr, "\t\t\tbecause they are just different ways to change the\n");
   fprintf(stderr, "\t\t\tsame parameter.\n");
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
   fprintf(stderr, "\n--numeric or -N\t\tIP addresses only, no hostnames.\n");
   fprintf(stderr, "\t\t\tWith this option, all hosts must be specified as\n");
   fprintf(stderr, "\t\t\tIP addresses.  Hostnames are not permitted.\n");
   fprintf(stderr, "\n--ipv6 or -6\t\tUse IPv6 protocol. Default is IPv4.\n");
/* scanner-specific help */
   fprintf(stderr, "\n--data=<p> or -D <p>\tSpecify TCP destination port(s).\n");
   fprintf(stderr, "\t\t\tThis option can be a single port, a list of ports\n");
   fprintf(stderr, "\t\t\tseparated by commas, or an inclusive range with the\n");
   fprintf(stderr, "\t\t\tbounds separated by \"-\".\n");
   fprintf(stderr, "\n--sport=<p> or -s <p>\tSpecify TCP source port.\n");
   fprintf(stderr, "\t\t\tThe default is a random port in the range 32678-65535.\n");
   fprintf(stderr, "\n--seq=<s> or -e <s>\tSpecify initial sequence number.\n");
   fprintf(stderr, "\t\t\tThe default initial sequence number is random.\n");
   fprintf(stderr, "\n--ack=<a> or -c <a>\tSpecify initial acknowledgement number.\n");
   fprintf(stderr, "\t\t\tThe default initial acknowledgement number is random.\n");
   fprintf(stderr, "\t\t\tThis is only applicable when the ACK flag is set in\n");
   fprintf(stderr, "\t\t\toutgoing packets.\n");
   fprintf(stderr, "\n--window=<w> or -w <w>\tSpecify the TCP window size.\n");
   fprintf(stderr, "\t\t\tThe default window size is %u.\n", DEFAULT_WINDOW);
   fprintf(stderr, "\n--openonly or -o\tOnly display open ports.\n");
   fprintf(stderr, "\t\t\tWith this option, closed ports are not displayed.\n");
   fprintf(stderr, "\n--servicefile=<s> or -S <s>\tUse service file <s> for TCP ports\n");
   fprintf(stderr, "\t\t\tIf this option is specified, then the TCP ports to\n");
   fprintf(stderr, "\t\t\tscan are read from the specified file.  The file is\n");
   fprintf(stderr, "\t\t\tsame format as used by \"strobe\".\n");
   fprintf(stderr, "\n--mss=<n> or -m <n>\tUse TCP MSS <n>.  Default is %u\n",
           DEFAULT_MSS);
   fprintf(stderr, "\t\t\tA non-zero MSS adds the MSS TCP option to the SYN packet\n");
   fprintf(stderr, "\t\t\twhich adds 4 bytes to the packet length.  If the MSS\n");
   fprintf(stderr, "\t\t\tis specified as zero, then no MSS option is added.\n");
   fprintf(stderr, "\n--wscale or -W\t\tAdd the WSCALE TCP option\n");
   fprintf(stderr, "\t\t\tThis option adds 4 bytes to the packet length.\n");
   fprintf(stderr, "\n--sack or -a\t\tAdd the SACKOK TCP option\n");
   fprintf(stderr, "\t\t\tThis option adds 4 bytes to the packet length. However\n");
   fprintf(stderr, "\t\t\tit does not increase packet size when used with the\n");
   fprintf(stderr, "\t\t\t--timestamp option.\n");
   fprintf(stderr, "\n--timestamp or -T\tAdd the TIMESTAMP TCP option\n");
   fprintf(stderr, "\t\t\tThe number of seconds since midnight 1/1/1970 is used\n");
   fprintf(stderr, "\t\t\tfor the timestamp value.\n");
   fprintf(stderr, "\t\t\tThis option adds 12 bytes to the packet length.\n");
   fprintf(stderr, "\n--snap=<s> or -n <s>\tSet the pcap snap length to <s>. Default=%d.\n", SNAPLEN);
   fprintf(stderr, "\t\t\tThis specifies the frame capture length.  This\n");
   fprintf(stderr, "\t\t\tlength includes the data-link header as well as the\n");
   fprintf(stderr, "\t\t\tIP and transport headers.  The default is normally\n");
   fprintf(stderr, "\t\t\tsufficient.\n");
   fprintf(stderr, "\n--ttl=<t> or -l <t>\tSet the IP TTL to <t>. Default=%d.\n", DEFAULT_TTL);
   fprintf(stderr, "\t\t\tYou can specify a higher value if the targets are\n");
   fprintf(stderr, "\t\t\tmany hops away, or you can specify a lower value to\n");
   fprintf(stderr, "\t\t\tlimit the scope to the local network.\n");
   fprintf(stderr, "\n--interface=<i> or -I <u> Use network interface <i>.\n");
   fprintf(stderr, "\t\t\tIf this option is not specified, the default is the\n");
   fprintf(stderr, "\t\t\tvalue of the RMIF environment variable.  If RMIF is\n");
   fprintf(stderr, "\t\t\tnot defined, then \"eth0\" is used as a last resort.\n");
   fprintf(stderr, "\n--quiet or -q\t\tDon't decode the received packet.\n");
   fprintf(stderr, "\t\t\tIf this option is specified, then only the minimum\n");
   fprintf(stderr, "\t\t\tinformation is displayed.  This can be useful if you\n");
   fprintf(stderr, "\t\t\tonly want to know if a port is open or not, or if\n");
   fprintf(stderr, "\t\t\tstrange packets confuse the decoding process\n");
   fprintf(stderr, "\n--ignoredups or -g\tDon't display duplicate packets.\n");
   fprintf(stderr, "\t\t\tBy default, duplicate packets are displayed and flagged\n");
   fprintf(stderr, "\t\t\twith \"(DUP: n)\" where n is the number of packets\n");
   fprintf(stderr, "\t\t\treceived from that host so far.\n");
   fprintf(stderr, "\n--df=<n> or -F <n>\tEnable (1) or disable (0) DF flag. Default=%d\n", DEFAULT_DF);
   fprintf(stderr, "\t\t\tSetting this option to 1 sets the DF flag in the IP\n");
   fprintf(stderr, "\t\t\theader of the outbound SYN packets.  Setting it to 0\n");
   fprintf(stderr, "\t\t\tclears the DF flag.\n");
   fprintf(stderr, "\n--tos=<n> or -O <n>\tSet IP TOS (Type of Service) to <n>. Default=%d\n", DEFAULT_TOS);
   fprintf(stderr, "\t\t\tThis sets the TOS value in the IP header for outbound\n");
   fprintf(stderr, "\t\t\tpackets.\n");
   fprintf(stderr, "\n--portname or -P\tDisplay port names as well as numbers.\n");
   fprintf(stderr, "\n--flags=<f> or -L <f>\tSpecify TCP flags to be set in outgoing packets.\n");
   fprintf(stderr, "\t\t\tThe flags should be specified as a comma-separated list\n");
   fprintf(stderr, "\t\t\tfrom the set of: CWR,ECN,URG,ACK,PSH,RST,SYN,FIN.\n");
   fprintf(stderr, "\t\t\tIf this option is not specified, the flags default\n");
   fprintf(stderr, "\t\t\tto SYN.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Report bugs or send suggestions to %s\n", PACKAGE_BUGREPORT);
   exit(status);
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
   static int first_time_through=1;
   char *cp;

   if (first_time_through) {
      if (local_data == NULL && port_list == NULL) {
         warn_msg("You must specify the TCP dest ports with either the --data option");
         err_msg("or with the --servicefile option.");
      }

      if (local_data && port_list) {
         err_msg("You cannot specify both the --data and --servicefile options.");
      }
      first_time_through=0;
   }
   if (local_data) {	/* --data option specified */
/*
 *	Determine the ports in the port spec, and add a host entry for
 *	each one.
 */
      cp = local_data;
      while (*cp != '\0') {
         unsigned port1;
         unsigned port2;
         unsigned i;
   
         port1=strtoul(cp, &cp, 10);
         if (!port1 || (port1 & 0x80000000))	/* Zero or -ve */
            err_msg("Invalid port specification: %s", local_data);
         if (*cp == ',' || *cp == '\0') {	/* Single port specification */
            add_host_port(name, timeout, port1);
         } else if (*cp == '-') {		/* Inclusive range */
            cp++;
            port2=strtoul(cp, &cp, 10);
            if (!port2 || port2 <= port1)	/* Missing end or empty range */
               err_msg("Invalid port specification: %s", local_data);
            for (i=port1; i<=port2; i++)
               add_host_port(name, timeout, i);
         } else {
            err_msg("Invalid port specification: %s", local_data);
         }
         if (*cp == ',')
            cp++;  /* Move on to next entry */
      }
   } else {	/* --servicefile option specified */
/*
 *	Add a host entry for each port in the port list.
 */
      int i=0;

      while (port_list[i])
         add_host_port(name, timeout, port_list[i++]);
   }
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
      if (*he == *cursor)
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
      printf("%u\t%s\n", helistptr[i]->n, my_ntoa(helistptr[i]->addr,ipv6_flag));
   printf("\nTotal of %u host entries.\n\n", num_hosts);
}

void
add_host_port(char *name, unsigned timeout, unsigned port) {
   ip_address *hp=NULL;
   ip_address addr;
   struct host_entry *he;
   struct timeval now;
   static int num_left=0;	/* Number of free entries left */
   int result;

   if (port < 1 || port > 65535)
      err_msg("Invalid port number: %u.  Port must be in range 1-65535", port);

   if (numeric_flag) {
      if (ipv6_flag) {
         result = inet_pton(AF_INET6, name, &(addr.v6));
      } else {
         result = inet_pton(AF_INET, name, &(addr.v4));
      }
      if (result <= 0)
         err_sys("inet_pton failed for \"%s\"", name);
   } else {
      if (ipv6_flag) {
         hp = get_host_address(name, AF_INET6, &addr, &ga_err_msg);
      } else {
         hp = get_host_address(name, AF_INET, &addr, &ga_err_msg);
      }
      if (hp == NULL)
         err_msg("get_host_address failed for \"%s\": %s", name, ga_err_msg);
   }

   if (!num_left) {	/* No entries left, allocate some more */
      if (helist)
         helist=Realloc(helist, (num_hosts * sizeof(struct host_entry)) +
                        REALLOC_COUNT*sizeof(struct host_entry));
      else
         helist=Malloc(REALLOC_COUNT*sizeof(struct host_entry));
      num_left = REALLOC_COUNT;
   }

   he = helist + num_hosts; /* Would array notation be better? */
   num_hosts++;
   num_left--;

   Gettimeofday(&now);

   he->n = num_hosts;
   if (ipv6_flag) {
      memcpy(&(he->addr.v6), &(addr.v6), sizeof(struct in6_addr));
   } else {
      memcpy(&(he->addr.v4), &(addr.v4), sizeof(struct in_addr));
   }
   he->live = 1;
   he->timeout = timeout * 1000;	/* Convert from ms to us */
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;
   he->dport=port;
}

/* Standard BSD internet checksum routine */
uint16_t in_cksum(uint16_t *ptr,int nbytes) {

   register uint32_t sum;
   uint16_t oddbyte;
   register uint16_t answer;

/*
 * Our algorithm is simple, using a 32-bit accumulator (sum),
 * we add sequential 16-bit words to it, and at the end, fold back
 * all the carry bits from the top 16 bits into the lower 16 bits.
 */

   sum = 0;
   while (nbytes > 1)  {
      sum += *ptr++;
      nbytes -= 2;
   }

/* mop up an odd byte, if necessary */
   if (nbytes == 1) {
      oddbyte = 0;            /* make sure top half is zero */
      *((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
      sum += oddbyte;
   }

/*
 * Add back carry outs from top 16 bits to low 16 bits.
 */

   sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
   sum += (sum >> 16);                     /* add carry */
   answer = ~sum;          /* ones-complement, then truncate to 16 bits */
   return(answer);
}

uint32_t get_source_ip(char *devname) {
   int sockfd;
   struct ifreq ifconfig;
   struct sockaddr_in sa;

   strcpy(ifconfig.ifr_name, devname);

/* Create UDP socket */
   if ((sockfd=socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket");
      exit(1);
   }
/* Obtain IP address for specified interface */
   if ((ioctl(sockfd, SIOCGIFADDR, &ifconfig)) != 0) {
      perror("ioctl");
      exit(1);
   }

   memcpy(&sa, &ifconfig.ifr_ifru.ifru_addr, sizeof(sa));
   return sa.sin_addr.s_addr;
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
   int found = 0;
   unsigned iterations = 0;	/* Used for debugging */
/*
 *	Return with the result from local_find_host if the local find_host
 *	function replaces this one.
 */
   struct iphdr *iph;
   struct tcphdr *tcph;
/*
 *      Don't try to match if packet is too short.
 */
   if (n < ip_offset + sizeof(struct iphdr) + sizeof(struct tcphdr))
      return NULL;
/*
 *      Overlay IP and TCP headers on packet buffer.
 *      ip_offset is size of layer-2 header.
 *      Note that iph.ihl is in 32-bit units.  We multiply by 4 to get bytes.
 *      iph.lhl is normally 5, but can be larger if IP options are present.
 */
   iph = (struct iphdr *) (packet_in + ip_offset);
   tcph = (struct tcphdr *) (packet_in + ip_offset + 4*(iph->ihl));
/*
 *      Don't try to match if host ptr is NULL.
 *      This should never happen, but we check just in case.
 */
   if (*he == NULL)
      return NULL;
/*
 *	Try to match against out host list.
 */
   p = he;
   do {
      iterations++;
      if (((*p)->addr.v4.s_addr == addr->s_addr) &&
          (ntohs(tcph->source) == (*p)->dport)) {
         found = 1;
      } else {
         if (p == helistptr) {
            p = helistptr + (num_hosts-1); /* Wrap round to end */
         } else {
            p--;
         }
      }
   } while (!found && p != he);

   if (debug) {print_times(); printf("find_host: found=%d, iterations=%u\n", found, iterations);}

   if (iterations > max_iter)
      max_iter=iterations;

   if (found)
      return *p;
   else
      return NULL;
}

/*
 * callback -- pcap callback function
 *
 * Inputs:
 *
 *	args		Special args (not used)
 *	header		pcap header structure
 *	packet_in	The captured packet
 *
 * Returns:
 *
 * None
 */
void
callback(u_char *args, const struct pcap_pkthdr *header,
         const u_char *packet_in) {
   struct iphdr *iph;
   struct tcphdr *tcph;
   int n = header->caplen;
   struct in_addr source_ip;
   struct host_entry *temp_cursor;
/*
 *      Check that the packet is large enough to decode.
 */
   if (n < ip_offset + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
      printf("%d byte packet too short to decode\n", n);
      return;
   }
/*
 *	Overlay IP and TCP headers on packet buffer.
 *	ip_offset is size of layer-2 header.
 *      Note that iph.ihl is in 32-bit units.  We multiply by 4 to get bytes.
 *      iph.lhl is normally 5, but can be larger if IP options are present.
 */
   iph = (struct iphdr *) (packet_in + ip_offset);
   tcph = (struct tcphdr *) (packet_in + ip_offset + 4*(iph->ihl));
/*
 *	Determine source IP address.
 */
   source_ip.s_addr = iph->saddr;
/*
 *	We've received a response.  Try to match up the packet by IP address
 *
 *	We should really start searching at the host before the cursor, as we
 *	know that the host to match cannot be the one at the cursor position
 *	because we call advance_cursor() after sending each packet.  However,
 *	the time saved is minimal, and it's not worth the extra complexity.
 */
   temp_cursor=find_host(cursor, &source_ip, packet_in, n);
   if (temp_cursor) {
/*
 *	We found an IP match for the packet. 
 */
      if (verbose > 1)
         warn_msg("---\tReceived packet #%u from %s",temp_cursor->num_recv ,inet_ntoa(source_ip));
/*
 *	Display the packet and increment the number of responders if we are
 *	counting all packets (open_only == 0) or if SYN and ACK are set and
 *	the entry is "live" or we are not ignoring duplicates.
 */
      temp_cursor->num_recv++;
      if ((!open_only || (tcph->syn && tcph->ack)) &&
          (temp_cursor->live || !ignore_dups)) {
         display_packet(n, packet_in, temp_cursor, &source_ip);
         responders++;
      }
      if (verbose > 1)
         warn_msg("---\tRemoving host entry %u (%s) - Received %d bytes", temp_cursor->n, inet_ntoa(source_ip), n);
      remove_host(&temp_cursor);
   } else {
/*
 *	The received packet is not from an IP address in the list
 *	Issue a message to that effect and ignore the packet.
 */
      if (verbose)
         warn_msg("---\tIgnoring %d bytes from unknown host %s", n, inet_ntoa(source_ip));
   }
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
      {"numeric", no_argument, 0, 'N'},
      {"ipv6", no_argument, 0, '6'},
      {"bandwidth", required_argument, 0, 'B'},
      {0, 0, 0, 0}
   };
   const char *short_options = "f:hp:r:t:i:b:vVdD:N6B:";
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
         char interval_str[MAXLINE];    /* --interval argument */
         size_t interval_len;   /* --interval argument length */
         char bandwidth_str[MAXLINE];   /* --bandwidth argument */
         size_t bandwidth_len;  /* --bandwidth argument length */

         case 'f':	/* --file */
            strncpy(filename, optarg, MAXLINE);
            filename_flag=1;
            break;
         case 'h':	/* --help */
            usage(EXIT_SUCCESS);
            break;
         case 'p':	/* --protocol */
            ip_protocol=Strtoul(optarg, 10);
            break;
         case 'r':	/* --retry */
            retry=Strtoul(optarg, 10);
            break;
         case 't':	/* --timeout */
            timeout=Strtoul(optarg, 10);
            break;
         case 'i':	/* --interval */
            strncpy(interval_str, optarg, MAXLINE);
            interval_len=strlen(interval_str);
            if (interval_str[interval_len-1] == 'u') {
               interval=Strtoul(interval_str, 10);
            } else if (interval_str[interval_len-1] == 's') {
               interval=1000000 * Strtoul(interval_str, 10);
            } else {
               interval=1000 * Strtoul(interval_str, 10);
            }
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
         case 'N':	/* --numeric */
            numeric_flag=1;
            break;
         case '6':      /* --ipv6 */
            ipv6_flag=1;
            break;
         case 'B':      /* --bandwidth */
            strncpy(bandwidth_str, optarg, MAXLINE);
            bandwidth_len=strlen(bandwidth_str);
            if (bandwidth_str[bandwidth_len-1] == 'M') {
               bandwidth=1000000 * Strtoul(bandwidth_str, 10);
            } else if (bandwidth_str[bandwidth_len-1] == 'K') {
               bandwidth=1000 * Strtoul(bandwidth_str, 10);
            } else {
               bandwidth=Strtoul(bandwidth_str, 10);
            }
            break;
         default:	/* Unknown option */
            usage(EXIT_FAILURE);
            break;
      }
   }
}

/*
 *	local_process_options	--	Process options and arguments.
 *
 *	Inputs:
 *
 *	argc	Command line arg count
 *	argv	Command line args
 *
 *	Returns:
 *
 *      0 (Zero) if this function doesn't need to do anything, or
 *      1 (One) if this function replaces the generic process_options function.
 *
 *      This protocol-specific process_options routine can replace the generic
 *      rawip-scan process_options routine if required.  If it is to replace the
 *      generic routine, then it must perform all of the process_options
 *	functions and return 1.  Otherwise, it must do nothing and return 0.
 */
int
local_process_options(int argc, char *argv[]) {
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
      {"sport", required_argument, 0, 's'},
      {"seq", required_argument, 0, 'e'},
      {"window", required_argument, 0, 'w'},
      {"openonly", no_argument, 0, 'o'},
      {"servicefile", required_argument, 0, 'S'},
      {"mss", required_argument, 0, 'm'},
      {"wscale", no_argument, 0, 'W'},
      {"sack", no_argument, 0, 'a'},
      {"timestamp", no_argument, 0, 'T'},
      {"snap", required_argument, 0, 'n'},
      {"ttl", required_argument, 0, 'l'},
      {"interface", required_argument, 0, 'I'},
      {"quiet", no_argument, 0, 'q'},
      {"ignoredups", no_argument, 0, 'g'},
      {"df", required_argument, 0, 'F'},
      {"tos", required_argument, 0, 'O'},
      {"random", no_argument, 0, 'R'},
      {"numeric", no_argument, 0, 'N'},
      {"portname", no_argument, 0, 'P'},
      {"flags", required_argument, 0, 'L'},
      {"ipv6", no_argument, 0, '6'},
      {"bandwidth", required_argument, 0, 'B'},
      {"ack", required_argument, 0, 'c'},
      {0, 0, 0, 0}
   };
   const char *short_options =
      "f:hp:r:t:i:b:vVdD:s:e:w:oS:m:WaTn:l:I:qgF:O:RNPL:6B:c:";
   int arg;
   int options_index=0;

   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         char *p1;
         char *p2;
         char interval_str[MAXLINE];    /* --interval argument */
         size_t interval_len;   /* --interval argument length */
         char bandwidth_str[MAXLINE];   /* --bandwidth argument */
         size_t bandwidth_len;  /* --bandwidth argument length */

         case 'f':	/* --file */
            strncpy(filename, optarg, MAXLINE);
            filename_flag=1;
            break;
         case 'h':	/* --help */
            usage(EXIT_SUCCESS);
            break;
         case 'p':	/* --protocol */
            ip_protocol=Strtoul(optarg, 10);
            break;
         case 'r':	/* --retry */
            retry=Strtoul(optarg, 10);
            break;
         case 't':	/* --timeout */
            timeout=Strtoul(optarg, 10);
            break;
         case 'i':	/* --interval */
            strncpy(interval_str, optarg, MAXLINE);
            interval_len=strlen(interval_str);
            if (interval_str[interval_len-1] == 'u') {
               interval=Strtoul(interval_str, 10);
            } else if (interval_str[interval_len-1] == 's') {
               interval=1000000 * Strtoul(interval_str, 10);
            } else {
               interval=1000 * Strtoul(interval_str, 10);
            }
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
            p1 = optarg;
            p2 = local_data;
            while (*p1 != '\0') {
               if (!isspace(*p1))
                  *p2++=*p1;
               p1++;
            }
            *p2 = '\0';
            break;
         case 's':	/* --sport */
            source_port=Strtoul(optarg, 0);
            source_port_flag=1;
            break;
         case 'e':	/* --seq */
            seq_no=Strtoul(optarg, 0);
            seq_no_flag=1;
            break;
         case 'w':	/* --window */
            window=Strtoul(optarg, 0);
            break;
         case 'o':	/* --openonly */
            open_only=1;
            break;
         case 'S':	/* --servicefile */
            create_port_list(optarg);
            break;
         case 'm':	/* --mss */
            mss=Strtoul(optarg, 0);
            break;
         case 'W':	/* --wscale */
            wscale_flag=1;
            break;
         case 'a':	/* --sack */
            sack_flag=1;
            break;
         case 'T':	/* --timestamp */
            timestamp_flag=1;
            break;
         case 'n':	/* --snap */
            snaplen=strtol(optarg, (char **)NULL, 0);
            break;
         case 'l':	/* --ttl */
            ip_ttl=strtol(optarg, (char **)NULL, 0);
            if (ip_ttl < 0 || ip_ttl > 255)
               err_msg("The --ttl option must be in the range 0 to 255.");
            break;
         case 'I':	/* --interface */
            if_name = make_message("%s", optarg);
            break;
         case 'q':	/* --quiet */
            quiet_flag=1;
            break;
         case 'g':	/* --ignoredups */
            ignore_dups=1;
            break;
         case 'F':	/* --df */
            df_flag = strtol(optarg, (char **)NULL, 0);
            if (df_flag < 0 || df_flag > 1)
               err_msg("The --df option must be 0 (DF off) or 1 (DF on).");
            break;
         case 'O':	/* --tos */
            ip_tos = strtol(optarg, (char **)NULL, 0);
            if (ip_tos < 0 || ip_tos > 255)
               err_msg("The --tos option must be in the range 0 to 255.");
            break;
         case 'R':	/* --random */
            random_flag=1;
            break;
         case 'N':	/* --numeric */
            numeric_flag=1;
            break;
         case 'P':	/* --portname */
            portname_flag=1;
            break;
         case 'L':	/* --flags */
            tcp_flags_flag=1;
            process_tcp_flags(optarg);
/* CWR,ECN,URG,ACK,PSH,RST,SYN,FIN */
            break;
         case '6':	/* --ipv6 */
            ipv6_flag=1;
            break;
         case 'B':      /* --bandwidth */
            strncpy(bandwidth_str, optarg, MAXLINE);
            bandwidth_len=strlen(bandwidth_str);
            if (bandwidth_str[bandwidth_len-1] == 'M') {
               bandwidth=1000000 * Strtoul(bandwidth_str, 10);
            } else if (bandwidth_str[bandwidth_len-1] == 'K') {
               bandwidth=1000 * Strtoul(bandwidth_str, 10);
            } else {
               bandwidth=Strtoul(bandwidth_str, 10);
            }
            break;
         case 'c':	/* --ack */
            ack_no=Strtoul(optarg, 0);
            ack_no_flag=1;
            break;
         default:	/* Unknown option */
            usage(EXIT_FAILURE);
            break;
      }
   }
   return 1;	/* Replace generic process_options() function */
}

/*
 *	rawip_scan_version -- display version information
 *
 *	Inputs:
 *
 *	None.
 *
 *	This displays the rawip-scan version information and also calls the
 *	protocol-specific version function to display the protocol-specific
 *	version information.
 */
void
rawip_scan_version (void) {
   fprintf(stderr, "%s\n\n", PACKAGE_STRING);
   fprintf(stderr, "Copyright (C) 2003-2007 Roy Hills, NTA Monitor Ltd.\n");
   fprintf(stderr, "tcp-scan comes with NO WARRANTY to the extent permitted by law.\n");
   fprintf(stderr, "You may redistribute copies of arp-scan under the terms of the GNU\n");
   fprintf(stderr, "General Public License.\n");
   fprintf(stderr, "For more information about these matters, see the file named COPYING.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "%s\n", pcap_lib_version());
/* We use rcsid here to prevent it being optimised away */
   fprintf(stderr, "%s\n", rcsid);
   error_use_rcsid();
   wrappers_use_rcsid();
   utils_use_rcsid();
}

/*
 *	create_port_list	-- Create TCP port list from services file
 *
 *	Inputs:
 *
 *	filename	The services file name
 *
 *	Outputs:
 *
 *	None.
 *
 *	This function creates the TCP port list from the specified services
 *	file.  It uses the same code as strobe for this so that the service
 *	file formats are compatible.  However, it is fussier than strobe
 *	regarding invalid names and port numbers.
 */
void
create_port_list(char *filename) {
   FILE *fh;
   char lbuf[1024];
   char desc[256];
   char portname[17];
   unsigned int port;
   char prot[4];
   int nports=0;

   if (port_list)
      err_msg("Service file has already been specified");

   prot[3]='\0';
   if ((access(filename, R_OK)) != 0)
      err_sys("fopen %s", filename);
   if (!(fh = fopen (filename, "r")))
      err_sys("fopen %s", filename);

   while (fgets (lbuf, sizeof (lbuf), fh)) {
      char *p;
      int n;

      if (strchr("*# \t\n", lbuf[0]))
          continue;
      if (!(p = strchr (lbuf, '/')))
          continue;
      *p = ' ';
      desc[0]='\0';
      n=sscanf(lbuf, "%16s %u %3s %255[^\r\n]", portname, &port, prot, desc);
      if (n < 3) {
         warn_msg("Ignoring invalid entry: %s", lbuf);
         continue;
      }
      if (strcmp (prot, "tcp")) {
         warn_msg("Ignoring non-TCP entry: %s", lbuf);
         continue;
      }
      if (port < 1 || port > 65535)
         err_msg("Invalid port number: %u.  Port must be in range 1-65535",
                 port);
      nports++;
      if (port_list) {
         port_list=Realloc(port_list, nports * sizeof(uint16_t));
      } else {
         port_list=Malloc(sizeof(uint16_t));
      }
      port_list[nports-1] = port;
   }
   if (port_list) {
      port_list=Realloc(port_list, (nports+1) * sizeof(uint16_t));
   } else {
      port_list=Malloc(sizeof(uint16_t));
   }
   port_list[nports] = 0;	/* Mark end of list with zero */
}

/*
 *	process_tcp_flags	-- Process TCP flags option
 *
 *	Inputs:
 *
 *	optarg		Pointer to the --flags option argument.
 *
 *	Outputs:
 *
 *	None.
 *
 *	This function sets "tcp_flags" to the TCP flags specified by the
 *	--flags option.  It also sets the tcp_flags_flag flag to show that
 *	the specified TCP flags should be used.
 */
void
process_tcp_flags(const char *optarg) {
   const char *cp1;
   char *cp2;
   int count;
   char flag_list[MAXLINE];

   tcp_flags_flag=1;
   count=0;
   cp1 = optarg;
   cp2 = flag_list;
   while (*cp1 != '\0') {
      if (!isspace((unsigned char)*cp1)) {
         *cp2++ = tolower((unsigned char)*cp1);
         count++;
      }
      cp1++;
   }
   *cp2 = '\0';

   if (strstr(flag_list, "cwr"))
      tcp_flags.cwr = 1;
   else
      tcp_flags.cwr = 0;
   if (strstr(flag_list, "ecn"))
      tcp_flags.ecn = 1;
   else
      tcp_flags.ecn = 0;
   if (strstr(flag_list, "urg"))
      tcp_flags.urg = 1;
   else
      tcp_flags.urg = 0;
   if (strstr(flag_list, "ack"))
      tcp_flags.ack = 1;
   else
      tcp_flags.ack = 0;
   if (strstr(flag_list, "psh"))
      tcp_flags.psh = 1;
   else
      tcp_flags.psh = 0;
   if (strstr(flag_list, "rst"))
      tcp_flags.rst = 1;
   else
      tcp_flags.rst = 0;
   if (strstr(flag_list, "syn"))
      tcp_flags.syn = 1;
   else
      tcp_flags.syn = 0;
   if (strstr(flag_list, "fin"))
      tcp_flags.fin = 1;
   else
      tcp_flags.fin = 0;
}
