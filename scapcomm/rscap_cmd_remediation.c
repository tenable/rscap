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



struct rscap_cmd * rscapcmd_remediation_delete(const char * fname)
{
 char * fpath;

 if ( fname == NULL || strchr(fname, '/') != NULL || strstr(fname, "..") != NULL ) return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");
 fpath = rscap_mk_path(RSCAP_REMEDY_DB_DIR, fname, NULL);
 if ( rscap_recursive_rmdir(fpath) < 0 )
 {
	char msg[1024];
	rscap_free(fpath);
	snprintf(msg, sizeof(msg), "Could not delete %s - %s\n", fname, strerror(errno));
	return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, msg);
 }
 rscap_free(fpath);
 return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_OK, "File successfully deleted");
}



struct rscap_cmd * rscapcmd_remediation_queue_add(const char * fname)
{
 char uuid[64];
 char * fpath = NULL;
 char * t1 = NULL, *t2 = NULL;
 struct rscap_stack * stack;


 if ( fname == NULL || strchr(fname, '/') != NULL || strstr(fname, "..") != NULL ) goto err;

 rscap_uuid(uuid, sizeof(uuid));
 fpath = rscap_mk_path(RSCAP_STAGING_DIR, uuid, NULL);
 mkdir(fpath, 0770);

 t1 = rscap_mk_path(RSCAP_REMEDY_DB_DIR, fname, NULL);
 t2 = rscap_mk_path(fpath, "remediation.tgz", NULL);
 
 if ( rscap_copy_file(t1, t2) < 0 ) {
        fprintf(stderr, "copy %s to %s failed\n", t1, t2);
        goto err;
 }
 rscap_free(t1); t1 = NULL;
 rscap_free(t2); t2 = NULL;


 t1 = rscap_mk_path(RSCAP_STAGING_DIR, uuid, NULL);
 t2 = rscap_mk_path(RSCAP_REMEDY_QUEUE_DIR, uuid, NULL);
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


struct rscap_cmd * rscapcmd_remediation_list()
{
 struct rscap_stack * list = rscap_dir_contents(RSCAP_REMEDY_DB_DIR);
 struct rscap_stack * ret;
 char * str;
 char sha[64];

 ret = rscap_stack_init(0);
 rscap_stack_add_column(ret);
 rscap_stack_set_column_name(ret, 0, "fname");
 rscap_stack_set_column_name(ret, 1, "sha-1");

 while (  ( str = rscap_stack_pop(list) ) != NULL ) 
 {
  if ( rscap_sha1(RSCAP_REMEDY_DB_DIR, str, sha, sizeof(sha)) < 0 ) continue;
  rscap_stack_push_index(ret, str, 0);
  rscap_stack_push_index(ret, sha, 1);
  rscap_free(str);
 }
 rscap_stack_free(list);

 return rscap_mk_stack_cmd_res(RSCAP_CMD_STATUS_OK, ret);
}


struct rscap_cmd * rscapcmd_remediation_queue_list()
{
 struct rscap_stack * waiting = rscap_dir_contents(RSCAP_REMEDY_QUEUE_DIR);
 struct rscap_stack * running = rscap_dir_contents(RSCAP_REMEDY_RUNNING_DIR);
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


struct rscap_cmd * rscapcmd_remediation_queue_remove(const char * uuid)
{
 char * fpath;

 if ( uuid == NULL || rscap_validate_uuid(uuid) < 0 ) return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");

 fpath = rscap_mk_path(RSCAP_REMEDY_QUEUE_DIR, uuid, NULL);
 if ( rscap_recursive_rmdir(fpath) < 0 )
 {
   rscap_free(fpath);
   return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Job not found");
 }
 rscap_free(fpath);
 return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_OK, "Job successfully deleted");
}


struct rscap_cmd * rscapcmd_remediation_results_list()
{
 struct rscap_stack * list = rscap_dir_contents(RSCAP_REMEDY_RESULTS_DIR);
 struct rscap_stack * ret;
 char * str;

 ret = rscap_stack_init(0);
 rscap_stack_add_column(ret); /* Timestamp */

 rscap_stack_set_column_name(ret, 0, "uuid");
 rscap_stack_set_column_name(ret, 1, "timestamp");

 while (  ( str = rscap_stack_pop(list) ) != NULL ) 
 {
  char * path = rscap_mk_path(RSCAP_REMEDY_RESULTS_DIR, str, NULL);
  struct stat st;

  if ( stat(path, &st) == 0 && access(path, X_OK|R_OK) == 0 )
  {
   char timestamp[32];

   rscap_stack_push_index(ret, str, 0);
   rscap_ctime(st.st_mtime, timestamp, sizeof(timestamp));
   rscap_stack_push_index(ret, timestamp, 1);
  }
  rscap_free(path);
  rscap_free(str);
 }
 rscap_stack_free(list);

 return rscap_mk_stack_cmd_res(RSCAP_CMD_STATUS_OK, ret);
}

struct rscap_cmd * rscapcmd_remediation_results_delete(const char * uuid)
{
 char * fpath;

 if ( uuid == NULL || rscap_validate_uuid(uuid) < 0 ) return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");

 fpath = rscap_mk_path(RSCAP_REMEDY_RESULTS_DIR, uuid, NULL);
 if ( rscap_recursive_rmdir(fpath) < 0 )
 {
   rscap_free(fpath);
  return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Results not found");
 }
 rscap_free(fpath);
 return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_OK, "Results successfully deleted");
}


struct rscap_cmd * rscapcmd_remediation_results_download(const char * uuid)
{
 char * fpath;
 struct stat st;

 if ( uuid == NULL || rscap_validate_uuid(uuid) < 0 ) return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");

 fpath = rscap_mk_path(RSCAP_REMEDY_RESULTS_DIR, uuid, "results.out", NULL);
 if ( stat(fpath, &st) < 0 )
 {
   rscap_free(fpath);
   return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "No result file");
 }

 return rscap_mk_file_cmd_res(RSCAP_CMD_STATUS_OK, fpath);
}
