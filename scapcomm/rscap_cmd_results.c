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



struct rscap_cmd * rscapcmd_results_list()
{
 struct rscap_stack * list = rscap_dir_contents(RSCAP_RESULTS_DIR);
 struct rscap_stack * ret;
 char * str;

 ret = rscap_stack_init(0);
 rscap_stack_add_column(ret); /* Timestamp */
 rscap_stack_add_column(ret); /* Filename */
 rscap_stack_add_column(ret); /* SHA1 */
 rscap_stack_add_column(ret); /* Profiles */

 rscap_stack_set_column_name(ret, 0, "uuid");
 rscap_stack_set_column_name(ret, 1, "timestamp");
 rscap_stack_set_column_name(ret, 2, "filename");
 rscap_stack_set_column_name(ret, 3, "sha-1");
 rscap_stack_set_column_name(ret, 4, "profiles");

 while (  ( str = rscap_stack_pop(list) ) != NULL ) 
 {
  char * path = rscap_mk_path(RSCAP_RESULTS_DIR, str, NULL);
  struct stat st;

  if ( stat(path, &st) == 0 && access(path, X_OK|R_OK) == 0 )
  {
   char timestamp[32];
   char sha[64];
   char *fname;
   char *buf = NULL;
   size_t buf_sz;

   rscap_stack_push_index(ret, str, 0);
   rscap_ctime(st.st_mtime, timestamp, sizeof(timestamp));
   rscap_stack_push_index(ret, timestamp, 1);
   fname = rscap_mk_path(RSCAP_RESULTS_DIR, str, "fname", NULL);
   rscap_read_file_contents(fname, &buf, &buf_sz);
   rscap_free(fname);
   if ( buf != NULL )
   {
    rscap_chomp(buf);
    rscap_stack_push_index(ret, buf, 2);
    rscap_free(buf);
   }
   else rscap_stack_push_index(ret, "???", 2);

   fname = rscap_mk_path(RSCAP_RESULTS_DIR, str, NULL);
   if ( rscap_sha1(fname, "xccdf.tgz", sha, sizeof(sha)) < 0 )
   	rscap_stack_push_index(ret, "???", 3);
   else
	rscap_stack_push_index(ret, sha, 3);
   rscap_free(fname);

   fname = rscap_mk_path(RSCAP_RESULTS_DIR, str, "profile", NULL);
   buf = NULL;
   rscap_read_file_contents(fname, &buf, &buf_sz);
   rscap_free(fname);
   if ( buf != NULL ) 
   {
     rscap_stack_push_index(ret, buf, 4);
     rscap_free(buf);
   }
   else
     rscap_stack_push_index(ret,"???", 4);
  }
  rscap_free(path);
  rscap_free(str);
 }
 rscap_stack_free(list);

 return rscap_mk_stack_cmd_res(RSCAP_CMD_STATUS_OK, ret);
}


struct rscap_cmd * rscapcmd_results_delete(const char * uuid)
{
 char * fpath;

 if ( uuid == NULL || rscap_validate_uuid(uuid) < 0 ) return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");

 fpath = rscap_mk_path(RSCAP_RESULTS_DIR, uuid, NULL);
 if ( rscap_recursive_rmdir(fpath) < 0 )
 {
   rscap_free(fpath);
  return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Results not found");
 }
 rscap_free(fpath);
 return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_OK, "Results successfully deleted");
}

struct rscap_cmd * rscapcmd_results_download(const char * uuid)
{
 char * fpath;
 char xccdf_file[1024];
 struct stat st;
 struct rscap_cmd * ret;

 if ( uuid == NULL || rscap_validate_uuid(uuid) < 0 ) return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");

 fpath = rscap_mk_path(RSCAP_RESULTS_DIR, uuid, "xccdf.tgz", NULL);
 if ( rscap_tar_find_xccdf_file(fpath, xccdf_file, sizeof(xccdf_file)) < 0 )
 {
   rscap_free(fpath);
   return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "No XCCDF file in archive");
 }

 strlcat(xccdf_file, ".results", sizeof(xccdf_file));
 rscap_free(fpath);
 fpath = rscap_mk_path(RSCAP_RESULTS_DIR, uuid, xccdf_file, NULL);
 if ( stat(fpath, &st) < 0 )
 { 
   rscap_free(fpath);
   return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "No XCCDF result file");
 }

 
 ret = rscap_mk_file_cmd_res(RSCAP_CMD_STATUS_OK, fpath);
 rscap_free(fpath);
 return ret;
}
