#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "md5.h"

#define MAXLINE 255

int
main () {
   md5_byte_t md5_digest[16];
   md5_state_t context;
   struct timeval now;
   pid_t pid;
   char str[MAXLINE];
   char hex_str[MAXLINE];
   int i;
   char *cp;

   if ((gettimeofday(&now,NULL)) != 0) {
      perror("gettimeofday");
      exit(1);
   }
   pid=getpid();

   sprintf(str, "%lu %lu %u $Id$", now.tv_usec, now.tv_sec, pid);
   md5_init(&context);
   md5_append(&context, (const md5_byte_t *)str, strlen(str));
   md5_finish(&context, md5_digest);
   cp = hex_str;
   for (i=0; i<16; i++) {
      sprintf(cp, "%.2x",md5_digest[i]);
      cp += 2;
   }
   *cp = '\0';
   printf("%s\n", str);
   printf("%s\n", hex_str);
   return 0;
}
