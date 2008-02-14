/*
 * The TCP Scanner (tcp-scan) is Copyright (C) 2003-2008 Roy Hills,
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
 * You are encouraged to send comments, improvements or suggestions to
 * me at tcp-scan@nta-monitor.com.
 *
 * $Id$
 *
 * Author: Roy Hills
 * Date: 5 April 2004
 *
 * This file contains various utility functions used by tcp-scan.
 */

#include "tcp-scan.h"

static char rcsid[] = "$Id$";	/* RCS ID for ident(1) */


/*
 *	timeval_diff -- Calculates the difference between two timevals
 *	and returns this difference in a third timeval.
 *
 *	Inputs:
 *
 *	a       = First timeval
 *	b       = Second timeval
 *	diff    = Difference between timevals (a - b).
 *
 *	Returns:
 *
 *	None.
 */
void
timeval_diff(const struct timeval *a, const struct timeval *b,
             struct timeval *diff) {
   struct timeval temp;

   temp.tv_sec = b->tv_sec;
   temp.tv_usec = b->tv_usec;

   /* Perform the carry for the later subtraction by updating b. */
   if (a->tv_usec < temp.tv_usec) {
     int nsec = (temp.tv_usec - a->tv_usec) / 1000000 + 1;
     temp.tv_usec -= 1000000 * nsec;
     temp.tv_sec += nsec;
   }
   if (a->tv_usec - temp.tv_usec > 1000000) {
     int nsec = (a->tv_usec - temp.tv_usec) / 1000000;
     temp.tv_usec += 1000000 * nsec;
     temp.tv_sec -= nsec;
   }
 
   /* Compute the time difference
      tv_usec is certainly positive. */
   diff->tv_sec = a->tv_sec - temp.tv_sec;
   diff->tv_usec = a->tv_usec - temp.tv_usec;
}

/*
 *	hstr_i -- Convert two-digit hex string to unsigned integer
 *
 *	Inputs:
 *
 *	cptr	Two-digit hex string
 *
 *	Returns:
 *
 *	Number corresponding to input hex value.
 *
 *	An input of "0A" or "0a" would return 10.
 *	Note that this function does no sanity checking, it's up to the
 *	caller to ensure that *cptr points to at least two hex digits.
 *
 *	This function is a modified version of hstr_i at www.snippets.org.
 */
unsigned int
hstr_i(const char *cptr)
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
      return j;
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
 *	print_times -- Print absolute and delta time for debugging
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is only used for debugging.  It should not be called
 *	from production code.
 */
void
print_times(void) {
   static struct timeval time_first;    /* When print_times() was first called */
   static struct timeval time_last;     /* When print_times() was last called */
   static int first_call=1;
   struct timeval time_now;
   struct timeval time_delta1;
   struct timeval time_delta2;

   Gettimeofday(&time_now);

   if (first_call) {
      first_call=0;
      time_first.tv_sec  = time_now.tv_sec;
      time_first.tv_usec = time_now.tv_usec;
      printf("%lu.%.6lu (0.000000) [0.000000]\n",
             (unsigned long)time_now.tv_sec, (unsigned long)time_now.tv_usec);
   } else {
      timeval_diff(&time_now, &time_last, &time_delta1);
      timeval_diff(&time_now, &time_first, &time_delta2);
      printf("%lu.%.6lu (%lu.%.6lu) [%lu.%.6lu]\n",
             (unsigned long)time_now.tv_sec,
             (unsigned long)time_now.tv_usec,
             (unsigned long)time_delta1.tv_sec,
             (unsigned long)time_delta1.tv_usec,
             (unsigned long)time_delta2.tv_sec,
             (unsigned long)time_delta2.tv_usec);
   }
   time_last.tv_sec  = time_now.tv_sec;
   time_last.tv_usec = time_now.tv_usec;
}

/*
 *	get_host_address -- Obtain target host IP address
 *
 *	Inputs:
 *
 *	name		The name to lookup
 *	af		The address family.  Either AF_INET or AF_INET6
 *	addr		Pointer to the IP address buffer
 *	error_msg	The error message, or NULL if no problem.
 *
 *	Returns:
 *
 *	Pointer to the IP address, or NULL if an error occurred.
 *
 *	This function is basically a wrapper for getaddrinfo().
 */
ip_address *
get_host_address(const char *name, int af, ip_address *addr, char **error_msg) {
   static char err[MAXLINE];
   static ip_address ipa;

   struct addrinfo *res;
   struct addrinfo hints;
   struct sockaddr_in sa_in;
   struct sockaddr_in6 sa_in6;
   int result;

   if (addr == NULL)	/* Use static storage if no buffer specified */
      addr = &ipa;

   memset(&hints, '\0', sizeof(hints));
   if (af == AF_INET) {
      hints.ai_family = AF_INET;
   } else if (af == AF_INET6) {
      hints.ai_family = AF_INET6;
   } else {
      err_msg("get_host_address: unknown address family: %d", af);
   }

   result = getaddrinfo(name, NULL, &hints, &res);
   if (result != 0) {	/* Error occurred */
      snprintf(err, MAXLINE, "%s", gai_strerror(result));
      *error_msg = err;
      return NULL;
   }

   if (af == AF_INET) {
      memcpy(&sa_in, res->ai_addr, sizeof(sa_in));
      memcpy(&(addr->v4), &sa_in.sin_addr, sizeof(struct in_addr));
   } else {	/* Must be AF_INET6 */
      memcpy(&sa_in6, res->ai_addr, sizeof(sa_in6));
      memcpy(&(addr->v6), &sa_in6.sin6_addr, sizeof(struct in6_addr));
   }

   freeaddrinfo(res);

   *error_msg = NULL;
   return addr;
}

/*
 *	my_ntoa -- IPv6 compatible inet_ntoa replacement
 *
 *	Inputs:
 *
 *	addr	The IP address (either IPv4 or IPv6)
 *
 *	Returns:
 *
 *	Pointer to the string representation of the IP address.
 */
const char *
my_ntoa(ip_address addr, int ipv6_flag) {
   static char ip_str[MAXLINE];
   const char *cp;

   if (ipv6_flag)
      cp = inet_ntop(AF_INET6, &addr.v6, ip_str, MAXLINE);
   else
      cp = inet_ntop(AF_INET, &addr.v4, ip_str, MAXLINE);

   return cp;
}

void utils_use_rcsid(void) {
   fprintf(stderr, "%s\n", rcsid);	/* Use rcsid to stop compiler optimising away */
}
