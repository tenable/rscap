/*
Copyright (c) 2014 Tenable Network Security, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#include <rscap_includes.h>
#include <rscap_common.h>
#include <syslog.h>


#define MAX_LOG_FACILITIES 5

static FILE * rscap_log_facilities[MAX_LOG_FACILITIES];
static int rscap_num_log_facilities = 0;


int rscap_log_init(const char * ident)
{
 if ( ident == NULL )
 {
  errno = EINVAL;
  return -1;
 }

 openlog(ident, LOG_PID, LOG_DAEMON);
 return 0;
}

int rscap_add_log_fp(FILE * fp)
{
 if ( rscap_num_log_facilities >= MAX_LOG_FACILITIES ) return -1;
 rscap_log_facilities[rscap_num_log_facilities++] = fp;
 return 0;
}

int rscap_add_log_file(const char * path)
{
 FILE * fp;

 fp = fopen(path, "a");
 if ( fp == NULL ) 
 {
   fprintf(stderr, "Could not open %s - %s\n", path, strerror(errno));
   return -1;
 }
 return rscap_add_log_fp(fp);
}


void rscap_log(char * str, ...)
{
 va_list params;
 char entry[4096]; 
 char * tmp;
 time_t t;
 char timestr[255];
 int i;

 t = rscap_time();
 va_start(params, str);
 vsnprintf(entry, sizeof(entry), str, params);
 va_end(params);
 
 tmp = entry;
 while ( ( tmp = strchr(tmp, '\n') ) != NULL )
 	tmp[0] = ' ';
 
 rscap_ctime(t, timestr, sizeof(timestr));
 syslog(LOG_NOTICE, "%s\n", entry);
 for ( i = 0 ; i < rscap_num_log_facilities; i ++ )
 {
  fprintf(rscap_log_facilities[i], "[%s][%d] %s\n", timestr, rscap_getpid(), entry);
  fflush(rscap_log_facilities[i]);
 }
}
