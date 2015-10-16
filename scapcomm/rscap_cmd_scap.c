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
#include <expat.h>
#include <openssl/rand.h>




struct rscap_cmd * rscapcmd_scap_list()
{
 struct rscap_stack * list = rscap_dir_contents(RSCAP_DB_DIR);
 struct rscap_stack * ret;
 char * str;
 char sha[64];

 ret = rscap_stack_init(0);
 rscap_stack_add_column(ret);
 rscap_stack_set_column_name(ret, 0, "fname");
 rscap_stack_set_column_name(ret, 1, "sha-1");

 while (  ( str = rscap_stack_pop(list) ) != NULL ) 
 {
  if ( rscap_sha1(RSCAP_DB_DIR, str, sha, sizeof(sha)) < 0 ) continue;
  rscap_stack_push_index(ret, str, 0);
  rscap_stack_push_index(ret, sha, 1);
  rscap_free(str);
 }
 rscap_stack_free(list);

 return rscap_mk_stack_cmd_res(RSCAP_CMD_STATUS_OK, ret);
}


struct rscap_cmd * rscapcmd_scap_delete(const char * fname)
{
 char * fpath;

 if ( fname == NULL || strchr(fname, '/') != NULL || strstr(fname, "..") != NULL ) return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");
 fpath = rscap_mk_path(RSCAP_DB_DIR, fname, NULL);
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

static void _xccdf_handler_start(void * arg, const XML_Char* name, const XML_Char ** atts)
{
 struct rscap_stack * stack = (struct rscap_stack*)arg;
 if ( strcmp(name, "Profile") == 0 )
 {
   int i;
   if ( atts != NULL ) 
     for ( i = 0 ; atts[i] != NULL; i += 2 )
     {
 	if ( strcmp(atts[i], "id") == 0 )
		rscap_stack_push(stack, atts[i+1]);
     }
 }
}

struct rscap_cmd * rscap_cmd_scap_profile_list(const char * fname)
{
 char * fpath;
 char xccdf_file[1024];
 char * xml;
 size_t xml_sz;
 XML_Parser xmlParser;
 struct rscap_stack * stack;

 if ( fname == NULL || strchr(fname,'/') != NULL || strstr(fname, "..") != NULL) return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");

 fpath = rscap_mk_path(RSCAP_DB_DIR, fname, NULL);

 if ( rscap_tar_find_xccdf_file(fpath, xccdf_file, sizeof(xccdf_file)) < 0 )
 {
   rscap_free(fpath);
   return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "No XCCDF file in archive");
 }

 if ( rscap_tar_get_file(fpath, xccdf_file, &xml, &xml_sz) < 0 )
 { 
   rscap_free(fpath);
   return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid archive");
 }
 
 stack = rscap_stack_init(0);
 rscap_stack_set_column_name(stack, 0, "profile");
 xmlParser = XML_ParserCreate(NULL);
 XML_SetUserData(xmlParser, (void*)stack);
 XML_SetElementHandler(xmlParser, _xccdf_handler_start, NULL);
 XML_Parse(xmlParser, xml, xml_sz, 1);
 XML_ParserFree(xmlParser);
 rscap_free(fpath);
 if ( xml != NULL ) rscap_free(xml);
 return rscap_mk_stack_cmd_res(RSCAP_CMD_STATUS_OK, stack);
}


struct rscap_cmd * rscapcmd_cert_replace(struct rscap_hash * hash, const char * fname)
{
 char * cbuf, *kbuf;
 size_t cbuf_sz, kbuf_sz;
 char * fpath;

 const char *kpath, *cpath;

 fpath = rscap_mk_path(RSCAP_STAGING_DIR, fname, NULL);
 if ( rscap_tar_get_file(fpath, "cert", &cbuf, &cbuf_sz) < 0 )
 {
  rscap_free(fpath);
  return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid archive");
 }

 if ( rscap_tar_get_file(fpath, "key", &kbuf, &kbuf_sz) < 0 )
 {
  rscap_free(fpath);
  rscap_free(cbuf);
  return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid archive");
 }
 
   
 kpath = rscap_config_get(hash, "SSLCertificateKeyFile");
 rscap_write_file_contents(kpath, kbuf, kbuf_sz);
 cpath = rscap_config_get(hash, "SSLCertificateFile");
 rscap_write_file_contents(cpath, cbuf, cbuf_sz);
 
 rscap_free(fpath);
 rscap_free(cbuf);
 rscap_free(kbuf);
 return rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_OK, "Successfully replaced the certificate and key");
}
