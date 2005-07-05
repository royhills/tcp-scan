/*
 * The ICMP Scanner (icmp-scan) is Copyright (C) 2005 Roy Hills,
 * NTA Monitor Ltd.
 *
 * $Id$
 *
 * icmp-scan -- The ICMP Scanner
 *
 * Author:	Roy Hills
 * Date:	1 February 2005
 *
 * Usage:
 *    icmp-scan [options] [host...]
 *
 * Description:
 *
 * icmp-scan sends the specified ICMP packet to the specified hosts
 * and displays any responses received.
 * 
 */

#include "rawip-scan-engine.h"
#include "icmp-scan.h"

static char const rcsid[] = "$Id$";   /* RCS ID for ident(1) */

/* Global variables */
int ip_protocol = DEFAULT_IP_PROTOCOL;	/* IP Protocol */
unsigned retry = DEFAULT_RETRY;		/* Number of retries */
unsigned timeout = DEFAULT_TIMEOUT;	/* Per-host timeout */
float backoff_factor = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
int snaplen = SNAPLEN;			/* Pcap snap length */
int ip_ttl = DEFAULT_TTL;		/* IP TTL */
char *if_name=NULL;			/* Interface name, e.g. "eth0" */
int quiet_flag=0;			/* Don't decode the packet */
int ignore_dups=0;			/* Don't display duplicate packets */
int df_flag=DEFAULT_DF;			/* IP DF Flag */
int ip_tos=DEFAULT_TOS;			/* IP TOS Field */
uint16_t icmp_id_no;			/* ICMP Identifier */
uint16_t icmp_seq_no;			/* ICMP Sequence Number */
int icmp_packet_type = DEFAULT_ICMP_TYPE;
char const scanner_name[] = "icmp-scan";
char const scanner_version[] = "1.0";

extern int verbose;	/* Verbose level */
extern int debug;	/* Debug flag */
extern char *local_data;		/* Local data from --data option */
extern struct host_entry *helist;	/* Array of host entries */
struct host_entry **helistptr;		/* Array of pointers to host entries */
extern unsigned num_hosts;		/* Number of entries in the list */
extern unsigned max_iter;		/* Max iterations in find_host() */
extern pcap_t *handle;
extern struct host_entry **cursor;
extern unsigned responders;		/* Number of hosts which responded */
extern char filename[MAXLINE];
extern int filename_flag;
extern int random_flag;			/* Randomise the list */
extern int numeric_flag;		/* IP addreses only */
extern int ipv6_flag;			/* IPv6 */
extern unsigned bandwidth;
extern unsigned interval;

static uint32_t source_address;
extern int pcap_fd;			/* pcap File Descriptor */
static size_t ip_offset;		/* Offset to IP header in pcap pkt */
static char *ga_err_msg;		/* getaddrinfo error message */

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
   struct icmphdr *icmph;
   char *msg;
   char *cp;
   char *df;
   static const id_name_map icmp_type_map[] = {
      {0, "Echo_Reply"},
      {3, "Unreachable"},
      {4, "Source_Quench"},
      {5, "Redirect"},
      {8, "Echo_Request"},
      {9, "Router_Advertisement"},
      {10, "Router_Solicitation"},
      {11, "Time_Exceeded"},
      {12, "Parameter_Problem"},
      {13, "Timestamp_Request"},
      {14, "Timestamp_Reply"},
      {15, "Information_Request"},
      {16, "Information_Reply"},
      {17, "Address_Mask_Request"},
      {18, "Address_Mask_Reply"},
      {-1, NULL}
   };
   static const id_name_map icmp_code3_map[] = {
      {0, "Network_Unreachable"},
      {1, "Host_Unreachable"},
      {2, "Protocol_Unreachable"},
      {3, "Port_Unreachable"},
      {4, "Frag_Needed_DF_Set"},
      {5, "Source_Route_Failed"},
      {6, "Network_Unknown"},
      {7, "Host_Unknown"},
      {8, "Host_Isolated"},
      {9, "Net_Admin_Prohibited"},
      {10, "Host_Admin_Prohibited"},
      {11, "Net_Unreachable_TOS"},
      {12, "Host_Unreachable_TOS"},
      {13, "Admin_Filter"},
      {14, "Host_Precedence_Violation"},
      {15, "Precedence_Cutoff"},
      {-1, NULL}
   };
/*
 *	Set msg to the IP address of the host entry, plus the address of the
 *	responder if different, and a tab.
 */
   if (he) {
      msg = make_message("%s\t", my_ntoa(he->addr));
      if ((he->addr).v4.s_addr != recv_addr->s_addr) {
         cp = msg;
         msg = make_message("%s(%s) ", cp, inet_ntoa(*recv_addr));
         free(cp);
      }
   } else {
      msg = make_message("%s\t(*) ", inet_ntoa(*recv_addr));
   }
/*
 *	Check that the packet is large enough to decode.
 *	This should never happen because the packet length should have
 *	already been checked in callback().
 */
   if (n < ip_offset + sizeof(struct iphdr) + sizeof(struct icmphdr)) {
      printf("%s%d byte packet too short to decode\n", msg, n);
      free(msg);
      return;
   }
/*
 *      Overlay IP and ICMP headers on packet buffer.
 *      ip_offset is size of layer-2 header.
 *      Note that iph.ihl is in 32-bit units.  We multiply by 4 to get bytes.
 *      iph.lhl is normally 5, but can be larger if IP options are present.
 */
   iph = (struct iphdr *) (packet_in + ip_offset);
   icmph = (struct icmphdr *) (packet_in + ip_offset + 4*(iph->ihl));
/*
 *	Determine type of response and add to message.
 */
   cp = msg;
   if (icmph->type == 3)	/* Use seperate map for unreachable */
      msg = make_message("%s%s", cp, id_to_name(icmph->code, icmp_code3_map));
   else
      msg = make_message("%s%s", cp, id_to_name(icmph->type, icmp_type_map));
   free(cp);
   if (!quiet_flag) {
/*
 *	Add DF, TTL, IPIP, and IP packet length to the message.
 */
      if (ntohs(iph->frag_off) & 0x4000) {	/* If DF flag set */
         df = "yes";
      } else {
         df = "no";
      }
      cp = msg;
      msg=make_message("%s\tDF=%s TOS=%u ttl=%u id=%u ip_len=%d",
                       cp, df, iph->tos, iph->ttl,
                       ntohs(iph->id), ntohs(iph->tot_len));
      free(cp);
/*
 *	Add the ICMP details to the message.
 */
      switch(icmph->type) {
         case 0:
            cp = msg;
            msg = make_message("%s icmp_id=%u, icmp_seq=%u",
                               cp, ntohs(icmph->un.echo.id),
                               ntohs(icmph->un.echo.sequence));
            free(cp);
            break;
         case 14:
            cp = msg;
            msg = make_message("%s icmp_id=%u, icmp_seq=%u, timestamp=%u",
                               cp, ntohs(icmph->un.timestamp.id),
                               ntohs(icmph->un.timestamp.sequence),
                               ntohl(icmph->un.timestamp.transmit));
            free(cp);
            break;
         case 18:
            cp = msg;
            msg = make_message("%s icmp_id=%u, icmp_seq=%u, mask=%.8x",
                               cp, ntohs(icmph->un.mask.id),
                               ntohs(icmph->un.mask.sequence),
                               ntohl(icmph->un.mask.mask));
            free(cp);
            break;
         case 16:
            cp = msg;
            msg = make_message("%s icmp_id=%u, icmp_seq=%u",
                               cp, ntohs(icmph->un.info.id),
                               ntohs(icmph->un.info.sequence));
            free(cp);
            break;
      }
/*
 *	If the host entry is not live, then flag this as a duplicate.
 */
      if (he && !he->live) {
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
 *	ip_protocol	IP Protcol to use
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
   struct icmphdr *icmph = (struct icmphdr *) (buf + sizeof(struct iphdr));
   struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr));
   struct pseudo_hdr {  /* For computing TCP checksum */
      uint32_t s_addr;
      uint32_t d_addr;
      uint8_t  mbz;
      uint8_t  proto;
      uint16_t len;
   };
   /* Position pseudo header just before the UDP header */
   struct pseudo_hdr *pseudo = (struct pseudo_hdr *) (buf + sizeof(struct ip) -
   sizeof(struct pseudo_hdr));
/*
 *      If he is NULL, just return with the packet length.
 */
   if (he == NULL) {
      if (icmp_packet_type == 33)
         return sizeof(struct iphdr) + sizeof(struct udphdr);
      else
         return sizeof(struct iphdr) + sizeof(struct icmphdr);
   }
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
 */
   Gettimeofday(last_packet_time);
   he->last_send_time.tv_sec  = last_packet_time->tv_sec;
   he->last_send_time.tv_usec = last_packet_time->tv_usec;
   he->num_sent++;
/*
 *	Construct the ICMP header.
 */
   if (icmp_packet_type == 33)
      memset(udph, '\0', sizeof(struct icmphdr));
   else
      memset(icmph, '\0', sizeof(struct icmphdr));

   switch (icmp_packet_type) {
      struct timeval tvorig;
      unsigned long tsorig;

      case 8:
      case 32:	/* Proto unreach uses ICMP Echo payload */
         icmph->type = 8;
         icmph->code = 0;
         icmph->un.echo.id = htons(icmp_id_no);
         icmph->un.echo.sequence = htons(icmp_seq_no);
         break;
      case 13:
         icmph->type = 13;
         icmph->code = 0;
         icmph->un.timestamp.id = htons(icmp_id_no);
         icmph->un.timestamp.sequence = htons(icmp_seq_no);
/*
 * fill in originate timestamp: have to convert tv_sec from seconds since
 * the Epoch to milliseconds since midnight, then add in microseconds
 */
         Gettimeofday(&tvorig);
         tsorig = (tvorig.tv_sec % (24*60*60)) * 1000 + tvorig.tv_usec / 1000;
         icmph->un.timestamp.originate = htonl(tsorig);
         icmph->un.timestamp.receive = 0;
         icmph->un.timestamp.originate = 0;
         break;
      case 17:
         icmph->type = 17;
         icmph->code = 0;
         icmph->un.mask.id = htons(icmp_id_no);
         icmph->un.mask.sequence = htons(icmp_seq_no);
         icmph->un.mask.mask = 0;
         break;
      case 15:
         icmph->type = 15;
         icmph->code = 0;
         icmph->un.info.id = htons(icmp_id_no);
         icmph->un.info.sequence = htons(icmp_seq_no);
         break;
      case 33:
         memset(pseudo, '\0', sizeof(struct pseudo_hdr));
         pseudo->s_addr = source_address;
         pseudo->d_addr = he->addr.v4.s_addr;
         pseudo->proto  = ip_protocol;
         pseudo->len    = htons(sizeof(struct udphdr));
         udph->source = htons(icmp_id_no);
         udph->dest = htons(UNREACH_PORT);
         udph->len = htons(sizeof(struct udphdr));
         break;
   }

   if (icmp_packet_type == 33)
      udph->check = in_cksum((uint16_t *)pseudo, sizeof(struct pseudo_hdr) +
                             sizeof(struct udphdr));
   else
      icmph->checksum = in_cksum((uint16_t *)icmph, sizeof(struct icmphdr));
/*
 *	Construct the IP Header.
 */
   memset(iph, '\0', sizeof(struct iphdr));
   iph->ihl = 5;	/* 5 * 32-bit longwords = 20 bytes */
   iph->version = 4;
   iph->tos = ip_tos;
   if (icmp_packet_type == 33)
      iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
   else
      iph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
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
   if (icmp_packet_type == 33)
      buflen=sizeof(struct iphdr) + sizeof(struct udphdr);
   else
      buflen=sizeof(struct iphdr) + sizeof(struct icmphdr);
/*
 *	Send the packet.
 */
   if (debug) {print_times(); printf("send_packet: #%u to host entry %u (%s) tmo %d\n", he->num_sent, he->n, my_ntoa(he->addr), he->timeout);}
   if (verbose > 1)
      warn_msg("---\tSending packet #%u to host entry %u (%s) tmo %d", he->num_sent, he->n, my_ntoa(he->addr), he->timeout);
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
   ip_address local_address;		/* Used for filter string */
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
 *	Set the id and sequence number using the MD5 hash
 */
   memcpy(&icmp_id_no, md5_digest, sizeof(uint16_t));
   memcpy(&icmp_seq_no, md5_digest+sizeof(uint16_t), sizeof(uint16_t));
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
   local_address.v4.s_addr = source_address;
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
   switch (icmp_packet_type) {
      case 8:
         filter_string=make_message("icmp[0:1]=0 and dst host %s and icmp[4:2]=%u and icmp[6:2]=%u",
                                    my_ntoa(local_address), icmp_id_no,
                                    icmp_seq_no);
         if ((pcap_compile(handle,&filter,filter_string,OPTIMISE,netmask)) < 0)
            err_msg("pcap_geterr: %s\n", pcap_geterr(handle));
         warn_msg("pcap filter string: %s", filter_string);
         free(filter_string);
         break;
      case 13:
         filter_string=make_message("icmp[0:1]=14 and dst host %s and icmp[4:2]=%u and icmp[6:2]=%u",
                                    my_ntoa(local_address), icmp_id_no,
                                    icmp_seq_no);
         if ((pcap_compile(handle,&filter,filter_string,OPTIMISE,netmask)) < 0)
            err_msg("pcap_geterr: %s\n", pcap_geterr(handle));
         warn_msg("pcap filter string: %s", filter_string);
         free(filter_string);
         break;
      case 17:
         filter_string=make_message("icmp[0:1]=18 and dst host %s and icmp[4:2]=%u and icmp[6:2]=%u",
                                    my_ntoa(local_address), icmp_id_no,
                                    icmp_seq_no);
         if ((pcap_compile(handle,&filter,filter_string,OPTIMISE,netmask)) < 0)
            err_msg("pcap_geterr: %s\n", pcap_geterr(handle));
         warn_msg("pcap filter string: %s", filter_string);
         free(filter_string);
         break;
      case 15:
         filter_string=make_message("icmp[0:1]=16 and dst host %s and icmp[4:2]=%u and icmp[6:2]=%u",
                                    my_ntoa(local_address), icmp_id_no,
                                    icmp_seq_no);
         if ((pcap_compile(handle,&filter,filter_string,OPTIMISE,netmask)) < 0)
            err_msg("pcap_geterr: %s\n", pcap_geterr(handle));
         warn_msg("pcap filter string: %s", filter_string);
         free(filter_string);
         break;
      case 32:
         filter_string=make_message("icmp[0:1]=3 and icmp[1:1]=2 and dst host %s and icmp[32:2]=%u and icmp[34:2]=%u",
                                    my_ntoa(local_address), icmp_id_no,
                                    icmp_seq_no);
         if ((pcap_compile(handle,&filter,filter_string,OPTIMISE,netmask)) < 0)
            err_msg("pcap_geterr: %s\n", pcap_geterr(handle));
         warn_msg("pcap filter string: %s", filter_string);
         free(filter_string);
         ip_protocol = UNREACH_PROTO;	/* value to cause proto unreach */
         break;
      case 33:
         filter_string=make_message("icmp[0:1]=3 and icmp[1:1]=3 and dst host %s and icmp[28:2]=%u and icmp[30:2]=%u",
                                    my_ntoa(local_address), icmp_id_no,
                                    UNREACH_PORT);
         if ((pcap_compile(handle,&filter,filter_string,OPTIMISE,netmask)) < 0)
            err_msg("pcap_geterr: %s\n", pcap_geterr(handle));
         warn_msg("pcap filter string: %s", filter_string);
         free(filter_string);
         ip_protocol = 17;	/* UDP */
         break;
      default:
         err_msg("Unsupported ICMP packet type: %u", icmp_packet_type);
         break;
   }
   if ((pcap_setfilter(handle, &filter)) < 0)
      err_msg("pcap_setfilter: %s\n", pcap_geterr(handle));
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
 *      local_version -- Scanner-specific version function.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 *      This should output the scanner-specific version number to stderr.
 */
void
local_version(void) {
/* We use rcsid here to prevent it being optimised away */
   fprintf(stderr, "%s\n", rcsid);
}

/*
 *      local_help -- Scanner-specific help function.
 *
 *      Inputs:
 *
 *      None.
 *
 *      Returns:
 *
 *      None.
 *
 *      This should output the scanner-specific usage for the --data option
 *      (if any).
 */
void
local_help(void) {
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
   fprintf(stderr, "\n--icmptype=<n> or -T <n> Set ICMP type to <n>. Default=%d\n", DEFAULT_ICMP_TYPE);
   fprintf(stderr, "\t\t\tSupported values are:\n");
   fprintf(stderr, "\t\t\t 8 - Echo Request (Ping)\n");
   fprintf(stderr, "\t\t\t13 - Timestamp Request\n");
   fprintf(stderr, "\t\t\t15 - Information Request\n");
   fprintf(stderr, "\t\t\t17 - Address Mask Request\n");
   fprintf(stderr, "\t\t\t32 - Protocol Unreachable (type 3, code 2)\n");
   fprintf(stderr, "\t\t\t33 - Port Unreachable (type 3, code 3)\n");
}

/*
 *      local_add_host -- Protocol-specific add host routine.
 *
 *      Inputs:
 *
 *      name = The Name or IP address of the host.
 *      timeout = The initial host timeout in ms.
 *
 *      Returns:
 *
 *      0 (Zero) if this function doesn't need to do anything, or
 *      1 (One) if this function replaces the generic add_host function.
 *
 *	This function is called before the helistptr array is created, so
 *	we use the helist array directly.
 *
 *      This routine is called once for each specified host.
 *
 *      This protocol-specific add host routine can replace the generic
 *      rawip-scan add-host routine if required.  If it is to replace the
 *      generic routine, then it must perform all of the add_host functions
 *      and return 1.  Otherwise, it must do nothing and return 0.
 */
int
local_add_host(char *name, unsigned timeout) {
   ip_address *hp=NULL;
   ip_address addr;
   struct host_entry *he;
   struct timeval now;
   static int num_left=0;	/* Number of free entries left */
   int result;

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
   he->dport=0;				/* Not currently used */

   return 1;	/* Replace generic add_host() function */
}

/*
 *      Convert a two-digit hex string with to unsigned int.
 *      E.g. "0A" would return 10.
 *      Note that this function does no sanity checking, it's up to the
 *      caller to ensure that *cptr points to at least two hex digits.
 *      This function is a modified version of hstr_i at www.snippets.org.
 */
unsigned int hstr_i(char *cptr)
{
      unsigned int i;
      unsigned int j = 0;
      int k;

      for (k=0; k<2; k++) {
            i = *cptr++ - '0';
            if (9 < i)
                  i -= 7;
            j <<= 4;
            j |= (i & 0x0f);
      }
      return(j);
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
 *	local_find_host -- Protocol-specific find host routine.
 *
 *	Inputs:
 *
 *	ptr	Pointer to the host entry that was found, or NULL if not found
 *      he      Pointer to the current position in the list.  Search runs
 *              backwards starting from this point.
 *      addr    The source IP address that the packet came from.
 *      packet_in The received packet data.
 *      n       The length of the received packet.
 *
 *	Returns:
 *
 *	0 (Zero) if this function doesn't need to do anything, or
 *	1 (One) if this function replaces the generic add_host function.
 *
 *	This routine is called every time a packet is received.
 *
 *	This protocol-specific find host routine can replace the generic
 *	rawip-scan find-host routine if required.  If it is to replace the
 *	generic routine, then it must perform all of the find_host functions
 *	and return 1.  Otherwise, it must do nothing and return 0.
 */
int
local_find_host(struct host_entry **ptr, struct host_entry **he,
                struct in_addr *addr, const unsigned char *packet_in, int n) {
   struct iphdr *iph;
   struct icmphdr *icmph;
   struct host_entry **p;
   int found = 0;
   unsigned iterations = 0;     /* Used for debugging */
/*
 *      Don't try to match if packet is too short.
 */
   if (n < ip_offset + sizeof(struct iphdr) + sizeof(struct icmphdr)) {
      *ptr = NULL;
      return 1;
   }
/*
 *      Overlay IP and ICMP headers on packet buffer.
 *      ip_offset is size of layer-2 header.
 *      Note that iph.ihl is in 32-bit units.  We multiply by 4 to get bytes.
 *      iph.lhl is normally 5, but can be larger if IP options are present.
 */
   iph = (struct iphdr *) (packet_in + ip_offset);
   icmph = (struct icmphdr *) (packet_in + ip_offset + 4*(iph->ihl));
/*
 *      Don't try to match if host ptr is NULL.
 *      This should never happen, but we check just in case.
 */
   if (*he == NULL) {
      *ptr = NULL;
      return 1;
   }
/*
 *	Try to match against out host list.
 */
   p = he;
   do {
      iterations++;
      if (((*p)->addr.v4.s_addr == addr->s_addr)) {
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
      *ptr = *p;
   else
      *ptr = NULL;

   return 1;
}

/*
 * callback -- pcap callback function
 *
 * Inputs:
 *
 *	args		Special args (not used)
 *	header		pcap header structire
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
   struct icmphdr *icmph;
   int n = header->caplen;
   struct in_addr source_ip;
   struct host_entry *temp_cursor;
/*
 *      Check that the packet is large enough to decode.
 */
   if (n < ip_offset + sizeof(struct iphdr) + sizeof(struct icmphdr)) {
      printf("%d byte packet too short to decode\n", n);
      return;
   }
/*
 *	Overlay IP and ICMP headers on packet buffer.
 *	ip_offset is size of layer-2 header.
 *      Note that iph.ihl is in 32-bit units.  We multiply by 4 to get bytes.
 *      iph.lhl is normally 5, but can be larger if IP options are present.
 */
   iph = (struct iphdr *) (packet_in + ip_offset);
   icmph = (struct icmphdr *) (packet_in + ip_offset + 4*(iph->ihl));
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
      if (temp_cursor->live || !ignore_dups) {
         display_packet(n, packet_in, temp_cursor, &source_ip);
         responders++;
      }
      if (verbose > 1)
         warn_msg("---\tRemoving host entry %u (%s) - Received %d bytes", temp_cursor->n, inet_ntoa(source_ip), n);
      remove_host(&temp_cursor);
   } else {
/*
 *	The received packet is not from an IP address in the list
 */
      display_packet(n, packet_in, NULL, &source_ip);
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
      {"snap", required_argument, 0, 'n'},
      {"ttl", required_argument, 0, 'l'},
      {"interface", required_argument, 0, 'I'},
      {"quiet", no_argument, 0, 'q'},
      {"ignoredups", no_argument, 0, 'g'},
      {"df", required_argument, 0, 'F'},
      {"tos", required_argument, 0, 'O'},
      {"random", no_argument, 0, 'R'},
      {"numeric", no_argument, 0, 'N'},
      {"ipv6", no_argument, 0, '6'},
      {"icmptype", required_argument, 0, 'T'},
      {"bandwidth", required_argument, 0, 'B'},
      {0, 0, 0, 0}
   };
   const char *short_options =
      "f:hp:r:t:i:b:vVdD:n:l:I:qgF:O:RN:6T:B:";
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
            strncpy(interval_str, optarg, MAXLINE);
            interval_len=strlen(interval_str);
            if (interval_str[interval_len-1] == 'u') {
               interval=strtoul(interval_str, (char **)NULL, 10);
            } else {
               interval=1000 * strtoul(interval_str, (char **)NULL, 10);
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
         case '6':	/* --ipv6 */
            ipv6_flag=1;
            break;
         case 'T':	/* --icmptype */
            icmp_packet_type = strtol(optarg, (char **)NULL, 0);
            break;
         case 'B':      /* --bandwidth */
            strncpy(bandwidth_str, optarg, MAXLINE);
            bandwidth_len=strlen(bandwidth_str);
            if (bandwidth_str[bandwidth_len-1] == 'M') {
               bandwidth=1000000 * strtoul(bandwidth_str, (char **)NULL, 10);
            } else if (bandwidth_str[bandwidth_len-1] == 'K') {
               bandwidth=1000 * strtoul(bandwidth_str, (char **)NULL, 10);
            } else {
               bandwidth=strtoul(bandwidth_str, (char **)NULL, 10);
            }
            break;
         default:	/* Unknown option */
            usage();
            break;
      }
   }
   return 1;	/* Replace generic process_options() function */
}

/*
 *      id_to_name -- Return name associated with given id, or id number
 *
 *      Inputs:
 *
 *      id              The id to find in the map
 *      id_name_map     Pointer to the id-to-name map
 *
 *      Returns:
 *
 *      A pointer to the name associated with the id if an association is
 *      found in the map, otherwise the numeric id.  Returns NULL on error.
 *
 *      This function uses a sequential search through the map to find the
 *      ID and associated name.  This is OK when the map is relatively small,
 *      but could be time consuming if the map contains a large number of
 *      entries.
 */
char *id_to_name(int id, const id_name_map map[]) {
   int found = 0;
   int i = 0;

   if (map == NULL)
      return NULL;

   while (map[i].id != -1) {
      if (id == map[i].id) {
         found = 1;
         break;
      }
      i++;
   }

   if (found)
      return map[i].name;
   else
      return numstr(id);
}

/*
 *      numstr -- Convert an unsigned integer to a string
 *
 *      Inputs:
 *
 *      num     The number to convert
 *
 *      Returns:
 *
 *      Pointer to the string representation of the number.
 *
 *      I'm surprised that there is not a standard library function to do this.
 */
char *
numstr(unsigned num) {
   static char buf[21]; /* Large enough for biggest 64-bit integer */

   snprintf(buf, sizeof(buf), "%d", num);
   return buf;
}
