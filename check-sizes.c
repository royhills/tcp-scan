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
 * If this license is unacceptable to you, I may be willing to negotiate
 * alternative licenses (contact tcp-scan@nta-monitor.com).
 *
 * You are encouraged to send comments, improvements or suggestions to
 * me at tcp-scan@nta-monitor.com.
 *
 * $Id$
 *
 * check-sizes -- Check sizes of structures and types
 *
 * Author:	Roy Hills
 * Date:	30 October 2008
 *
 *      Check that the sizes of the various structs are what we expect them
 *      to be.  If they are not, then we return with a failure status.
 */

#include "tcp-scan.h"

#define EXPECTED_IP_HDR 20
#define EXPECTED_TCP_HDR 20
#define EXPECTED_PSEUDO_HDR 12

#define EXPECTED_UINT8_T 1
#define EXPECTED_UINT16_T 2
#define EXPECTED_UINT32_T 4

int
main() {
   unsigned octets_per_char;	/* Almost always 1 */
   int error=0;

   if (CHAR_BIT % 8)
      err_msg("CHAR_BIT is not a multiple of 8");

   octets_per_char = CHAR_BIT/8;

   printf("Structure\tExpect\tObserved\n\n");

   printf("iphdr\t\t%u\t%lu\t", EXPECTED_IP_HDR,
          (unsigned long) (octets_per_char * sizeof(struct iphdr)));
   if (octets_per_char * sizeof(struct iphdr) != EXPECTED_IP_HDR) {
      error++;
      printf("ERROR\n");
   } else {
      printf("ok\n");
   }

   printf("tcphdr\t\t%u\t%lu\t", EXPECTED_TCP_HDR,
          (unsigned long) (octets_per_char * sizeof(struct tcphdr)));
   if (octets_per_char * sizeof(struct tcphdr) != EXPECTED_TCP_HDR) {
      error++;
      printf("ERROR\n");
   } else {
      printf("ok\n");
   }

   printf("pseudo_hdr\t%u\t%lu\t", EXPECTED_PSEUDO_HDR,
          (unsigned long) (octets_per_char * sizeof(pseudo_hdr)));
   if (octets_per_char * sizeof(pseudo_hdr) != EXPECTED_PSEUDO_HDR) {
      error++;
      printf("ERROR\n");
   } else {
      printf("ok\n");
   }

   printf("\nType\t\tExpect\tObserved\n\n");

   printf("uint8_t\t\t%u\t%lu\t", EXPECTED_UINT8_T,
          (unsigned long) (octets_per_char * sizeof(uint8_t)));
   if (octets_per_char * sizeof(uint8_t) != EXPECTED_UINT8_T) {
      error++;
      printf("ERROR\n");
   } else {
      printf("ok\n");
   }

   printf("uint16_t\t%u\t%lu\t", EXPECTED_UINT16_T,
          (unsigned long) (octets_per_char * sizeof(uint16_t)));
   if (octets_per_char * sizeof(uint16_t) != EXPECTED_UINT16_T) {
      error++;
      printf("ERROR\n");
   } else {
      printf("ok\n");
   }

   printf("uint32_t\t%u\t%lu\t", EXPECTED_UINT32_T,
          (unsigned long) (octets_per_char * sizeof(uint32_t)));
   if (octets_per_char * sizeof(uint32_t) != EXPECTED_UINT32_T) {
      error++;
      printf("ERROR\n");
   } else {
      printf("ok\n");
   }

   if (error)
      return EXIT_FAILURE;
   else
      return EXIT_SUCCESS;
}
