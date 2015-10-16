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

#include "scapremedy_process.h"


static void dir_missing(const char * name)
{
 fprintf(stderr, "Could not open directory %s -- please fix your installation\n", name);
 exit(1);
}

int main(int argc, char ** argv)
{
 char * directories[] = { RSCAP_REMEDY_QUEUE_DIR, RSCAP_REMEDY_RUNNING_DIR, NULL };
 int i;
 struct rscap_hash * cfg;
 struct rscap_signature_cfg * sig_cfg;
 const char * v;


 rscap_log_init("scapassess");
 cfg = rscap_config_load(RSCAP_CONFIG_FILE);
 if ( cfg == NULL )
 {
  fprintf(stderr, "Could not load %s - %s\n", RSCAP_CONFIG_FILE, strerror(errno));
  exit(1);
 }

 sig_cfg = rscap_signature_init(cfg);
 if ( sig_cfg == NULL )
 {
  fprintf(stderr, "Could not load the signature verification context\n"); 
  exit(1);
 }


 for ( i = 0 ; directories[i] != NULL ; i ++ )
	 if ( rscap_file_readable(directories[i]) < 0 )  dir_missing(directories[i]);
 

 scapremedy_process_init();
 scapremedy_job_cleaner(cfg);

 
 v = rscap_config_get(cfg, "LogFile");
 if ( v != NULL ) rscap_add_log_file(v);

 v = rscap_config_get(cfg, "Debug");
 if ( v != NULL && strcmp(v, "yes") == 0 ) rscap_add_log_fp(stderr);

 rscap_log("scapremedy v%s starting up\n", RSCAP_VERSION);

 for( ;; ) 
 {
  struct rscap_stack * stack = rscap_dir_contents(RSCAP_REMEDY_QUEUE_DIR);
  if ( stack != NULL )
  {
   char * entry;
   while ( ( entry = rscap_stack_pop(stack) ) != NULL ) 
	{
		while ( scapremedy_job_count() > 0 ) sleep(1); 
		/* 	
 		 *  Should be a directory. Directory should contain:
 		 * - The zip file to process
 		 * - The name of the profile to process 
 		 */
		scapremedy_process_entry(sig_cfg, RSCAP_REMEDY_QUEUE_DIR, entry);
		rscap_free(entry);
	}
   rscap_stack_free(stack);
  }
  rscap_sleep(5);
 }
 return 0;
}
