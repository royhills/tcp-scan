/*
 * The TCP Scanner (tcp-scan) is Copyright (C) 2003 Roy Hills,
 * NTA Monitor Ltd.
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

#include "rawip-scan-engine.h"
#include "tcp-scan.h"

static char const rcsid[] = "$Id$";   /* RCS ID for ident(1) */

/* Global variables */
int ip_protocol = DEFAULT_IP_PROTOCOL;	/* IP Protocol */
unsigned interval = DEFAULT_INTERVAL;	/* Interval between packets */
unsigned retry = DEFAULT_RETRY;		/* Number of retries */
unsigned timeout = DEFAULT_TIMEOUT;	/* Per-host timeout */
float backoff_factor = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
uint32_t seq_no;			/* Initial TCP sequence number */
uint16_t source_port;			/* TCP Source Port */
char const scanner_name[] = "tcp-scan";
char const scanner_version[] = "1.0";

extern int verbose;	/* Verbose level */
extern int debug;	/* Debug flag */
extern char *local_data;		/* Local data from --data option */
extern struct host_entry *rrlist;	/* Round-robin linked list "the list" */
extern unsigned num_hosts;		/* Number of entries in the list */
extern unsigned rejected;		/* Packets rejected because not ours */
extern unsigned max_iter;		/* Max iterations in find_host() */

/*
 *	display_packet -- Check and display received packet
 *
 *	Inputs:
 *
 *	n		The length of the received packet in bytes
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
display_packet(int n, unsigned char *packet_in, struct host_entry *he,
               struct in_addr *recv_addr) {
   struct iphdr *iph = (struct iphdr *) packet_in;
   struct tcphdr *tcph = (struct tcphdr *) (packet_in + sizeof(struct iphdr));
   char ip_str[MAXLINE];	/* IP address(es) to display at start */
   char *cp;
/*
 *	Write the IP addresses to the output string.
 */
   cp = ip_str;
   cp += sprintf(cp, "%s\t", inet_ntoa(he->addr));
   if ((he->addr).s_addr != recv_addr->s_addr)
      cp += sprintf(cp, "(%s) ", inet_ntoa(*recv_addr));
   *cp = '\0';
/*
 *	Check that the packet is large enough to decode.
 */
   if (n < sizeof(struct iphdr) + sizeof(struct tcphdr)) {
      printf("%s%d byte packet Packet too short to decode\n", ip_str, n);
      return;
   }
/*
 *	Determine type of response: SYN-ACK, RST or something else
 */
   if (tcph->syn && tcph->ack) {
      printf("%sSYN-ACK (len=%d, ttl=%u)\n", ip_str, n, iph->ttl);
   } else if (tcph->rst) {
      printf("%sRST (len=%d, ttl=%u)\n", ip_str, n, iph->ttl);
   } else {
      printf("%sUNKNOWN TCP PACKET (len=%d, ttl=%u)\n", ip_str, n, iph->ttl);
   }
}

/*
 *	send_packet -- Construct and send a packet to the specified host
 *
 *	Inputs:
 *
 *	s		IP socket file descriptor
 *	he		Host entry to send to
 *	ip_protocol	IP Protcol to use
 *	last_packet_time	Time when last packet was sent
 *
 *      Returns:
 *
 *      None.
 *
 *      This must construct an appropriate packet and send it to the host
 *      identified by "he" using the socket "s".
 *      It must also update the "last_send_time" field for this host entry.
 */
void
send_packet(int s, struct host_entry *he, int ip_protocol,
            struct timeval *last_packet_time) {
   struct sockaddr_in sa_peer;
   char buf[MAXIP];
   int buflen;
   char *if_name;
   NET_SIZE_T sa_peer_len;
   struct tcp_data *tdp;
   static int first_time_through=1;
   static uint32_t source_address;
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
   struct pseudo_hdr *pseudo = (struct pseudo_hdr *) (buf + sizeof(struct ip) -
   sizeof(struct pseudo_hdr));
/*
 *	Initialise static packet data.
 *	We can't do this in initialise() because local_data is not available
 *	in that function.
 */
   if (first_time_through) {
      if (!(if_name=getenv("RMIF")))
         if_name="eth0";
      source_address = get_source_ip(if_name);
      printf("Using interface %s\n", if_name);
      first_time_through=0;
   }
/*
 *	Check that the host is live.  Complain if not.
 */
   if (!he->live) {
      warn_msg("***\tsend_packet called on non-live host entry: SHOULDN'T HAPPEN");
      return;
   }
/*
 *	Set up the sockaddr_in structure for the host.
 */
   memset(&sa_peer, '\0', sizeof(sa_peer));
   sa_peer.sin_family = AF_INET;
   sa_peer.sin_addr.s_addr = he->addr.s_addr;
   sa_peer_len = sizeof(sa_peer);
/*
 *	Construct the pseudo header (for TCP checksum purposes).
 *	Note that this overlaps the IP header and gets overwritten later.
 */
   memset(pseudo, '\0', sizeof(struct pseudo_hdr));
   pseudo->s_addr = source_address;
   pseudo->d_addr = he->addr.s_addr;
   pseudo->proto  = ip_protocol;
   pseudo->len    = htons(sizeof(struct tcphdr));
/*
 *	Construct the TCP header.
 */
   tdp = (struct tcp_data *) he->local_host_data;
   memset(tcph, '\0', sizeof(struct tcphdr));
   tcph->source = htons(source_port);
   tcph->dest = htons(tdp->dport);
   tcph->seq = htonl(seq_no);
   tcph->doff = 5;	/* 5 * 32bit longwords */
   tcph->syn = 1;
   tcph->window = htons(5840);
   tcph->check = in_cksum((uint16_t *)pseudo, sizeof(struct pseudo_hdr) +
                 sizeof(struct tcphdr));
/*
 *	Construct the IP Header.
 *	This overwrites the now unneeded pseudo header.
 */
   memset(iph, '\0', sizeof(struct iphdr));
   iph->ihl = 5;	/* 5 * 32-bit longwords = 20 bytes */
   iph->version = 4;
   iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
   iph->id = 0;		/* Linux kernel fills this in */
   iph->ttl = 64;
   iph->protocol = ip_protocol;
   iph->check = 0;	/* Linux kernel fills this in */
   iph->saddr = source_address;
   iph->daddr = he->addr.s_addr;
/*
 *	Copy the required data into the output buffer "buf" and set "buflen"
 *	to the number of bytes in this buffer.
 */
   buflen=sizeof(struct iphdr) + sizeof(struct tcphdr);
/*
 *	Update the last send times for this host.
 */
   if ((gettimeofday(last_packet_time, NULL)) != 0) {
      err_sys("gettimeofday");
   }
   he->last_send_time.tv_sec  = last_packet_time->tv_sec;
   he->last_send_time.tv_usec = last_packet_time->tv_usec;
   he->num_sent++;
/*
 *	Send the packet.
 */
   if (debug) {print_times(); printf("send_packet: #%u to host entry %u (%s) tmo %d\n", he->num_sent, he->n, inet_ntoa(he->addr), he->timeout);}
   if (verbose > 1)
      warn_msg("---\tSending packet #%u to host entry %u (%s) tmo %d", he->num_sent, he->n, inet_ntoa(he->addr), he->timeout);
   if ((sendto(s, buf, buflen, 0, (struct sockaddr *) &sa_peer, sa_peer_len)) < 0) {
      err_sys("sendto");
   }
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
/*
 *	Create an MD5 hash of various things to use as a source of random
 *	data.
 */
   if ((gettimeofday(&now,NULL)) != 0) {
      perror("gettimeofday");
      exit(1);
   }
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
 *	Set the sequence number and source port using the MD5 hash.
 *	We set the top bit of source port to make sure that it's
 *	above 32768 and therefore out of the way of reserved ports
 *	(1-1024).
 */
   memcpy(&seq_no, md5_digest, sizeof(uint32_t));
   memcpy(&source_port, md5_digest+sizeof(uint32_t), sizeof(uint16_t));
   source_port |= 0x8000;
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
   fprintf(stderr, "\n--data=<d> or -D <d>\tSpecify packet contents in hex.\n");
   fprintf(stderr, "\t\t\tE.g. --data=deadbeef would specify the 4-byte IP\n");
   fprintf(stderr, "\t\t\tpayload: 0xde, 0xad, 0xbe, 0xef.\n");
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
 *      This routine is called once for each specified host.
 *
 *      This protocol-specific add host routine can replace the generic
 *      rawip-scan add-host routine if required.  If it is to replace the
 *      generic routine, then it must perform all of the add_host functions
 *      and return 1.  Otherwise, it must do nothing and return 0.
 */
int
local_add_host(char *name, unsigned timeout) {
   struct hostent *hp;
   struct host_entry *he;
   struct timeval now;
   struct tcp_data *tdp;
   static int first_time_through=1;
   static int tcp_port;		/* TCP destination port */

   if (first_time_through) {
      if (local_data == NULL)
         err_msg("You must specify the TCP dest port with the --data option.");
      tcp_port = atoi(local_data);
      first_time_through=0;
   }

   if ((hp = gethostbyname(name)) == NULL)
      err_sys("gethostbyname");

   if ((he = malloc(sizeof(struct host_entry))) == NULL)
      err_sys("malloc");

   if ((tdp = malloc(sizeof(struct tcp_data))) == NULL)
      err_sys("malloc");

   tdp->dport=tcp_port;

   num_hosts++;

   if ((gettimeofday(&now,NULL)) != 0)
      err_sys("gettimeofday");

   he->n = num_hosts;
   memcpy(&(he->addr), hp->h_addr_list[0], sizeof(struct in_addr));
   he->live = 1;
   he->timeout = timeout * 1000;	/* Convert from ms to us */
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;
   he->local_host_data = tdp;

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
local_find_host(struct host_entry **ptr, struct host_entry *he,
                struct in_addr *addr, unsigned char *packet_in, int n) {
   struct iphdr *iph = (struct iphdr *) packet_in;
   struct tcphdr *tcph = (struct tcphdr *) (packet_in + sizeof(struct iphdr));
   struct host_entry *p;
   int found = 0;
   struct tcp_data *tdp;
   unsigned iterations = 0;     /* Used for debugging */
/*
 *      Don't try to match if packet is too short.
 */
   if (n < sizeof(struct iphdr) + sizeof(struct tcphdr)) {
      *ptr = NULL;
      return 1;
   }
/*
 *	Don't try to match if it's not a response to one of our packets.
 */
   if ((ntohl(tcph->ack_seq)) != seq_no+1 || (ntohs(tcph->dest) != source_port)) {
      *ptr = NULL;
      rejected++;
      return 1;
   }
/*
 *      Don't try to match if host ptr is NULL.
 *      This should never happen, but we check just in case.
 */
   if (he == NULL) {
      *ptr = NULL;
      return 1;
   }

   p = he;
   do {
      iterations++;
      tdp = (struct tcp_data *) p->local_host_data;
      if ((p->addr.s_addr == addr->s_addr) &&
          (ntohs(tcph->source) == tdp->dport))
         found = 1;
      else
         p = p->prev;
   } while (!found && p != he);

   if (debug) {print_times(); printf("find_host: found=%d, iterations=%u\n", found, iterations);}

   if (iterations > max_iter)
      max_iter=iterations;

   if (found)
      *ptr = p;
   else
      *ptr = NULL;

   return 1;
}
