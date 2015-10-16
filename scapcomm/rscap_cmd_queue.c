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

#include "rscap_cmd.h"



struct rscap_cmd * rscapcmd_queue_list()
{
 struct rscap_stack * waiting = rscap_dir_contents(RSCAP_QUEUE_DIR);
 struct rscap_stack * running = rscap_dir_contents(RSCAP_RUNNING_DIR);
 struct rscap_stack * ret;
 char * str;

 ret = rscap_stack_init(0);
 rscap_stack_add_column(ret);
 rscap_stack_set_column_name(ret, 0, "uuid");
 rscap_stack_set_column_name(ret, 1, "status");

 while (  ( str = rscap_stack_pop(waiting) ) != NULL ) 
 {
  rscap_stack_push_index(ret, str, 0);
  rscap_stack_push_index(ret, "WAITING", 1);
  rscap_free(str);
 }
 rscap_stack_free(waiting);

 while (  ( str = rscap_stack_pop(running) ) != NULL ) 
 {
  rscap_stack_push_index(ret, str, 0);
  rscap_stack_push_index(ret, "RUNNING", 1);
  rscap_free(str);
 }

 rscap_stack_free(running);
 return rscap_mk_stack_cmd_res(RSCAP_CMD_STATUS_OK, ret);
}

struct rscap_cmd * rscapcmd_queue_add(const char * fname, const char ** profiles)
{
 char uuid[64];
 char * fpath = NULL;
 char * t1 = NULL, *t2 = NULL;
 FILE * fp;
 int i;
 struct rscap_stack * stack;


 if ( fname == NULL || strchr(fname, '/') != NULL || strstr(fname, "..") != NULL  || profiles == NULL ) goto err;

 rscap_uuid(uuid, sizeof(uuid));
 fpath = rscap_mk_path(RSCAP_STAGING_DIR, uuid, NULL);
 mkdir(fpath, 0770);

 t1 = rscap_mk_path(RSCAP_DB_DIR, fname, NULL);
 t2 = rscap_mk_path(fpath, "xccdf.tgz", NULL);
 
 if ( rscap_copy_file(t1, t2) < 0 ) {
	fprintf(stderr, "copy %s to %s failed\n", t1, t2);
	goto err;
 }
 rscap_free(t1); t1 = NULL;
 rscap_free(t2); t2 = NULL;

 t1 = rscap_mk_path(fpath, "fname", NULL); /* Original archive name */
 rscap_write_file_contents(t1, fname, strlen(fname));
 rscap_free(t1); t1 = NULL;

 t1 = rscap_mk_path(fpath, "profile", NULL);
 fp = fopen(t1, "w");
 rscap_free(t1); t1 = NULL;
 if ( fp == NULL ) {
	fprintf(stderr, "Open %s failed\n", t1);
	goto err;
 }
 for ( i = 0 ; profiles[i] != NULL ; i ++ )
 {
  fprintf(fp, "%s\n", profiles[i]);
 }
 fclose(fp);

 t1 = rscap_mk_path(RSCAP_STAGING_DIR, uuid, NULL);
 t2 = rscap_mk_path(RSCAP_QUEUE_DIR, uuid, NULL);
 if ( rename(t1, t2) < 0 ) {
	fprintf(stderr, "rename %s %s failed- %s\n", t1, t2, strerror(errno));
	goto err;
 }
 rscap_free(t1);
 rscap_free(t2);
 rscap_free(fpath);
  
 stack = rscap_stack_init(0);
 rscap_stack_set_column_name(stack, 0, "uuid");
 rscap_stack_push(stack, uuid);
 
 return rscap_mk_stack_cmd_res(RSCAP_CMD_STATUS_OK, stack);

err:
 if ( t1 != NULL ) rscap_free(t1);
 if ( t2 != NULL ) rscap_free(t2);
 if ( fpath != NULL )
 {
  rscap_recursive_rmdir(fpath);
  rscap_free(fpath);
 }
 return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Starting the job failed");
}

struct rscap_cmd * rscapcmd_queue_remove(const char * uuid)
{
 char * fpath;

 if ( uuid == NULL || rscap_validate_uuid(uuid) < 0 ) return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");

 fpath = rscap_mk_path(RSCAP_QUEUE_DIR, uuid, NULL);
 if ( rscap_recursive_rmdir(fpath) < 0 )
 {
   rscap_free(fpath);
   fpath = rscap_mk_path(RSCAP_RUNNING_DIR, uuid, NULL);
   if ( rscap_recursive_rmdir(fpath) < 0 )
   {
	rscap_free(fpath);
	return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Job not found");	
   }
 }
 rscap_free(fpath);
 return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_OK, "Job successfully deleted");	
}
