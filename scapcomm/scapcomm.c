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
#include <openssl/ssl.h>

#include "rscap_cmd.h"
#include "rscap_cmd_queue.h"
#include "rscap_cmd_scap.h"
#include "rscap_cmd_results.h"
#include "rscap_cmd_remediation.h"
#include "rscap_base64.h"


#include <evhtp.h>


typedef char*(*rscapcmd_output_func_t)(struct rscap_cmd*);

static rscapcmd_output_func_t rscap_output_func = rscapcmd2xmlbuf;
static char * rscap_output_content_type = "text/xml";



static struct rscap_hash * g_users = NULL;

static void dir_missing(const char * name)
{
 fprintf(stderr, "Could not open directory %s -- please fix your installation\n", name);
}


static void rscap_cb_free(const void * arg, size_t arglen, void *a )
{
 rscap_free((void*)arg);
}


typedef struct rscap_cmd*(*q_func_t)(void);

static void cb_list(evhtp_request_t * req, void * a )
{
 q_func_t func = (q_func_t)a;
 struct rscap_cmd * res;
 char * buf;

 res = func();
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}

static void cb_scap_profile_list(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * fname;

 fname = evhtp_kv_find(req->uri->query, "scapfile");
 res = rscap_cmd_scap_profile_list(fname);
 rscap_log("Listing profiles in %s\n", fname);
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}
 
static void cb_version(evhtp_request_t * req, void * a)
{
 struct rscap_stack * res = NULL;
 struct rscap_cmd   * cmd;
 char * buf;

 rscap_log("Version request\n");
 res = rscap_stack_init(0);
 rscap_stack_set_column_name(res, 0, "version");
 rscap_stack_push(res, RSCAP_VERSION);
 cmd = rscap_mk_stack_cmd_res(RSCAP_CMD_STATUS_OK, res);
 buf = rscap_output_func(cmd);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(cmd);
}
 
static void cb_remediation_delete(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * fname;

 fname = evhtp_kv_find(req->uri->query, "remediationfile");
 rscap_log("Deleting %s\n", fname);
 res = rscapcmd_remediation_delete(fname);
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}


static void cb_scap_delete(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * fname;

 fname = evhtp_kv_find(req->uri->query, "scapfile");
 rscap_log("Deleting %s\n", fname);
 res = rscapcmd_scap_delete(fname);
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}

static void cb_scap_queue_add(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * fname;
 const char * profile;
 char ** profiles = NULL;
 int cnt = 0;

 fname = evhtp_kv_find(req->uri->query, "scapfile");
 if ( fname == NULL || strchr(fname,'/') != NULL || strstr(fname, "..") != NULL )
  res = rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");
 else
 {
  profile = evhtp_kv_find(req->uri->query, "profile");
  if ( profile == NULL )
   res = rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid profile name");
  else
  { 
   rscap_log("Executing %s in %s\n", profile, fname);
   if ( profile != NULL )
   {
    const char * p = profile;
    while ( p != NULL ) 
   {
   cnt ++;
   p = strchr(p + 1, ',');
   }
   profiles = rscap_zalloc(sizeof(char*) * ( cnt + 1 ));
   p = profile;
   cnt = 0;
   while ( p != NULL ) 
   {
    char * q;

    q = strchr(p + 1, ',');
    if ( q != NULL )  
    {
     profiles[cnt] = rscap_zalloc( q - p + 1);
     memcpy(profiles[cnt], p, q - p);
    }
   else
    {
     profiles[cnt] = rscap_zalloc(strlen(p) + 1);
     memcpy(profiles[cnt], p, strlen(p));
    }
    p = q;
    if ( p != NULL ) p ++;
   }
  }
  res = rscapcmd_queue_add(fname, (const char**)profiles);
  if ( profiles != NULL )
  {
   for ( cnt = 0 ; profiles[cnt] != NULL ; cnt ++ ) rscap_free(profiles[cnt]);
   rscap_free(profiles);
  }
 }
 }
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}

static void cb_remediation_queue_add(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * fname;

 fname = evhtp_kv_find(req->uri->query, "remediationfile");
 res = rscapcmd_remediation_queue_add(fname);
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}
 

static void cb_scap_queue_remove(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * uuid;


 uuid = evhtp_kv_find(req->uri->query, "uuid");
 if ( uuid == NULL || strstr(uuid, "..") != NULL || strstr(uuid, "/" ) != NULL )
  res = rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");
 else
 {
  rscap_log("Removing %s from the queue", uuid);
  res = rscapcmd_queue_remove(uuid);
 }
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}

static void cb_remediation_queue_remove(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * uuid;


 uuid = evhtp_kv_find(req->uri->query, "uuid");
 rscap_log("Removing %s from the queue", uuid);
 res = rscapcmd_remediation_queue_remove(uuid);
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}

static void cb_results_download(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * uuid;


 uuid = evhtp_kv_find(req->uri->query, "uuid");
 if ( uuid == NULL || strstr(uuid, "..") != NULL || strstr(uuid, "/") != NULL )
 {
  res = rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");
  buf = rscap_output_func(res);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
  evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 }
 else
 {
 rscap_log("Downloading results for %s", uuid);
 res = rscapcmd_results_download(uuid);
 if ( res->type != RSCAP_CMD_TYPE_FILE )
 {
  buf = rscap_output_func(res);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
  evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 }
 else
 {
  struct stat st;
  int fd;

  if ( stat(rscap_cmd_fpath(res), &st) < 0 || ( fd = open(rscap_cmd_fpath(res), O_RDONLY) ) < 0 )
  {
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
  evbuffer_add_printf(req->buffer_out, "An unknown error happened when processing %s", rscap_cmd_fpath(res));
  }
  else
  {
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
  evbuffer_add_file(req->buffer_out, fd, 0, st.st_size);
  }
 }
 }
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}

static void cb_remediation_results_download(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * uuid;


 uuid = evhtp_kv_find(req->uri->query, "uuid");
 rscap_log("Downloading results for %s", uuid);
 res = rscapcmd_remediation_results_download(uuid);
 if ( res->type != RSCAP_CMD_TYPE_FILE )
 {
  buf = rscap_output_func(res);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
  evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 }
 else
 {
  struct stat st;
  int fd;

  if ( stat(rscap_cmd_fpath(res), &st) < 0 || ( fd = open(rscap_cmd_fpath(res), O_RDONLY) ) < 0 )
  {
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
  evbuffer_add_printf(req->buffer_out, "An unknown error happened when processing %s", rscap_cmd_fpath(res));
  }
  else
  {
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
  evbuffer_add_file(req->buffer_out, fd, 0, st.st_size);
  }
 }
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}

static void cb_results_delete(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * uuid;


 uuid = evhtp_kv_find(req->uri->query, "uuid");
 rscap_log("Delete results for %s\n", uuid);
 res = rscapcmd_results_delete(uuid);
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}

static void cb_remediation_results_delete(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * uuid;


 uuid = evhtp_kv_find(req->uri->query, "uuid");
 rscap_log("Delete results for %s\n", uuid);
 res = rscapcmd_remediation_results_delete(uuid);
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}


static void cb_test(evhtp_request_t * req, void * a)
{
 struct stat st;
 int fd;
 char * path;

 path = rscap_mk_path(RSCAP_HTML_ROOT, "index.html", NULL);

 if ( stat(path, &st) < 0 || ( fd = open(path, O_RDONLY) ) < 0 )
 {
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
  evbuffer_add_printf(req->buffer_out, "An unknown error happened when processing %s", "index.html");
 }
 else
 {
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
  evbuffer_add_file(req->buffer_out, fd, 0, st.st_size);
 }
 rscap_free(path);
 evhtp_send_reply(req, EVHTP_RES_OK);
}

static evhtp_res _cb_upload_fini(evhtp_request_t * req, void * a, const char * destdir)
{
 char * b = NULL;
 size_t sz;
 const char * content_type;
 char * p = NULL, *q, *r, *s;
 char * boundary;
 char * filename, *fname = NULL;
 char * fullpath = NULL;
 struct rscap_hash * hash;
 int err = 0;
 struct rscap_signature_cfg * sig_cfg = (struct rscap_signature_cfg*)a;


 content_type = evhtp_kv_find(req->headers_in, "content-type");
 if ( content_type == NULL ) goto err;

 p = rscap_strdup(content_type);
 boundary = strstr(p, "boundary=");
 if ( boundary == NULL ) goto err;

 boundary += strlen("boundary=");

 
 sz = evbuffer_get_length(req->buffer_in);
 b = rscap_zalloc( sz + 1);
 evbuffer_copyout(req->buffer_in, b, sz);

 q = memmem(b, sz, boundary, strlen(boundary));
 if ( q == NULL ) goto err;


 r = strchr(q, '\n');
 if ( r == NULL ) goto err; // End of line
 filename = strstr(r, "filename=\"");
 if ( filename == NULL ) { printf("No filename in %s\n", r); goto err; }
 filename += strlen("filename=\"");
 s = strchr(filename, '"');
 if ( s == NULL ) { printf("No ending quote in %s\n", filename); goto err; }
 s[0] = '\0';
 fname = rscap_strdup(filename);
 rscap_log("Uploaded %s\n", filename);
 s[0] = '"';

 r = strchr(r + 1, '\n');
 if ( r == NULL ) goto err; // Content-Disposition: form-data; name="file"; filename="a.c"

 r = strchr(r + 1, '\n');
 if ( r == NULL ) goto err; // Content-Type
 r = strchr(r + 1, '\n');
 if ( r == NULL ) goto err; // end of line
 if ( r[1] == '\r' ) r += 2;
 else r += 1;

 q = memmem(r, sz - ( r - b ),  boundary, strlen(boundary));
 if ( q == NULL ) goto err;
 q -= 2;
 if ( q[0] != '-' ) goto err;
 q -= 2;
 q[0] = '\0';

 if ( strchr(fname, '/') == NULL && strstr(fname, "..") == NULL )
 {
  char * path = rscap_mk_path(destdir, fname, NULL);
  int fd;

  rscap_unlink(path);
  fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0600);
  if ( fd > 0 )
  {
   write(fd, r, q - r);
   close(fd);
  }
  rscap_free(path);
 }


 rscap_free(p); p = NULL;
 rscap_free(b); b = NULL;


 /*
  * Check the signature
  */
 
 if ( sig_cfg != NULL )
 {
  hash = rscap_load_signatures(sig_cfg, destdir, fname);
  if ( hash == NULL )
  {
   char * path = rscap_mk_path(destdir, fname, NULL);

   rscap_unlink(path);
   rscap_free(path);
   rscap_log("Attempt to upload %s with an invalid signature", fname);
   goto err;
  }
  else
  {
   char * path = rscap_mk_path(destdir, fname, NULL);
   if ( rscap_untar(path, "./", hash, 1) != 0 ) 
   { 
    rscap_log("Attempt to upload %s with an invalid signature", fname);
    rscap_hash_free(hash);
    rscap_free(path);
    goto err;
   }
   rscap_free(path);
   rscap_hash_free(hash);
  }
 }


 /* Is it a real xccdf tgz file? */
 
 fullpath = rscap_mk_path(destdir, fname, NULL);
 if ( rscap_tar_check_header(fullpath) < 0 )
 {
   rscap_unlink(fullpath);
   rscap_free(fullpath);
   rscap_log("Attempt to upload %s which is an invalid archive", fname);
   goto err;
 }
 rscap_free(fullpath);


 
 rscap_free(fname);
 if ( err == 0 ) evbuffer_add_printf(req->buffer_out, "Successfully uploaded the file");
 evhtp_send_reply(req, EVHTP_RES_OK);
 
 
 return EVHTP_RES_OK;

err:
 if ( p != NULL ) rscap_free(p);
 if ( fname != NULL ) rscap_free(fname);
 if ( b != NULL ) rscap_free(b);
 evbuffer_add_printf(req->buffer_out, "An unknown error happened when processing %s", "index.html");
 evhtp_send_reply(req, EVHTP_RES_BADREQ);
 return EVHTP_RES_BADREQ;
}

static evhtp_res cb_scap_upload_fini(evhtp_request_t * req, void * a)
{
  return _cb_upload_fini(req, a, RSCAP_DB_DIR);
}

static void cb_scap_upload(evhtp_request_t * req, void * a)
{
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evhtp_set_hook(&req->conn->hooks, evhtp_hook_on_request_fini, cb_scap_upload_fini, a);
 evbuffer_add_printf(req->buffer_out, "Successfully uploaded the file");
 evhtp_send_reply(req, EVHTP_RES_OK);
}

static evhtp_res cb_scap_cert_upload_fini(evhtp_request_t * req, void * a)
{
  return _cb_upload_fini(req, a, RSCAP_STAGING_DIR);
}

static void cb_scap_cert_upload(evhtp_request_t * req, void * a)
{
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evhtp_set_hook(&req->conn->hooks, evhtp_hook_on_request_fini, cb_scap_cert_upload_fini, a);
 evbuffer_add_printf(req->buffer_out, "Successfully uploaded the file");
 evhtp_send_reply(req, EVHTP_RES_OK);
}

static void cb_scap_cert_replace(evhtp_request_t * req, void * a)
{
 struct rscap_cmd * res = NULL;
 char * buf;
 const char * fname;

 fname = evhtp_kv_find(req->uri->query, "certfile");
 if ( fname == NULL || strchr(fname,'/') != NULL || strstr(fname, "..") != NULL )
  res = rscap_mk_cmd_status_res(RSCAP_CMD_STATUS_FAIL, "Invalid file name");
 else
 {
  res = rscapcmd_cert_replace((struct rscap_hash*)a, fname);
 }
 buf = rscap_output_func(res);
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evbuffer_add_reference(req->buffer_out, buf, strlen(buf), rscap_cb_free, buf);
 evhtp_send_reply(req, EVHTP_RES_OK);
 rscap_cmd_res_free(res);
}

static evhtp_res cb_remediation_upload_fini(evhtp_request_t * req, void * a)
{
  return _cb_upload_fini(req, a, RSCAP_REMEDY_DB_DIR);
}

static void cb_remediation_upload(evhtp_request_t * req, void * a)
{
 evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", rscap_output_content_type, 0, 0));
 evhtp_set_hook(&req->conn->hooks, evhtp_hook_on_request_fini, cb_remediation_upload_fini, a);
 evbuffer_add_printf(req->buffer_out, "Successfully uploaded the file");
 evhtp_send_reply(req, EVHTP_RES_OK);
}



static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
 X509 * cert;
 int depth;
 char fullName[4096];
 STACK_OF(X509) *chain = NULL;
 int i, n;


 if ( preverify_ok == 0 ) 
 {
  rscap_log("Auth:Denied connection attempt (invalid or no certificate) (%d)\n", X509_STORE_CTX_get_error(ctx));
  return 0;
 }

 if (X509_STORE_CTX_get_error(ctx) != 0 )
 {
  depth = X509_STORE_CTX_get_error_depth(ctx);
  if ( depth != 0 ) 
  {
   rscap_log("Auth: Error depth:%d\n", depth);
   return 0;
  }
 }


 chain = sk_X509_dup(X509_STORE_CTX_get_chain(ctx));
 n = sk_X509_num(chain);
 for ( i = 0; i < n ; i ++ )
  cert = sk_X509_pop(chain);
 
 if ( rscap_full_dname(cert, fullName, sizeof(fullName)) == NULL ) goto err;

 sk_X509_free(chain);

 if ( rscap_hash_get_value(g_users, fullName) != NULL ) 
	{
	  rscap_log("Auth:Authorized %s\n", fullName);
	  return preverify_ok;
	}
 rscap_log("Auth:Denied %s\n", fullName);
 return 0;

err:
 if ( chain != NULL ) sk_X509_free(chain);
  rscap_log("Auth:Denied connection attempt (invalid or no certificate - %s)\n", fullName);
  return 0;
}


static void rscap_drop_privileges(struct rscap_hash * cfg)
{
 const char * user;
 const char * group;
 int uid = -1;
 int gid = -1;

 user = rscap_config_get(cfg, "ScapComm.RunAsUser");
 if ( user == NULL )
 {
  fprintf(stderr, "'ScapComm.RunAsUser' not set to a username in the configuration file -- aborting\n");
  exit(1);
 }

 group = rscap_config_get(cfg, "ScapComm.RunAsGroup");
 uid = rscap_uid_byname(user);
 if ( uid < 0 ) 
 {
   fprintf(stderr, "'ScapComm.RunAsUser' is set to non-existant user '%s' -- aborting\n", user);
   exit(1);
 }
 
 if ( group != NULL )
 {
  gid = rscap_gid_byname(group);
  if ( gid < 0 )
  { 
   fprintf(stderr, "'ScapComm.RunAsGroup' is set to non-existant group '%s' -- aborting\n", user);
   exit(1);
  }
 }
 else
  gid = rscap_gid_byname(user);

 setegid(gid);
 seteuid(uid);
 setgid(gid);
 setuid(uid);
}

static int validate_user(struct rscap_hash * users, const char * u, const char * p)
{
 const char * v; 
 char buf[1024];
 char hash[1024];
 char buf1[1024];
 char * ptr;
 int ret;

 v = rscap_config_get(users, u);
 if ( v == NULL )
 {
	rscap_log("Invalid auth attempt for inexistant user '%s'\n", u);
	return -1;
 }
 strlcpy(buf, v, sizeof(buf));
 ptr = strchr(buf, ':');
 if ( ptr == NULL ) 
 {
	rscap_log("Invalid entry in UsersDB for user '%s'\n", u);
	return -1;
 }
 ptr[0] = '\0';
 ptr ++;
 strlcpy(hash, ptr, sizeof(hash));
 strlcat(buf, p, sizeof(buf));
 strlcat(buf, "\n", sizeof(buf));
 rscap_sha1_buf(buf, strlen(buf), buf1, sizeof(buf1));
 if ( strcmp(hash, buf1) == 0 ) ret = 0;
 else ret = -1;
 
 bzero(buf, sizeof(buf));
 bzero(buf1, sizeof(buf1));

 if ( ret == 0 ) rscap_log("Password authentication succeeded for user %s\n", u);
 else rscap_log("Password authentication failed for user %s\n", u);

 return ret;
}

static evhtp_res cb_req(evhtp_request_t * req,  evhtp_headers_t * hdrs, void * arg)
{
 evhtp_kv_t * auth;
 struct rscap_hash * users = (struct rscap_hash*)arg;
 
 if ( users == NULL ) 
  return EVHTP_RES_OK;

 auth = evhtp_kvs_find_kv(hdrs, "Authorization");
 
 if ( auth == NULL || strncmp(auth->val, "Basic ", strlen("Basic ")) != 0 ) 
 {
  evhtp_kv_t * head;

err:
  head = evhtp_kv_new("WWW-Authenticate",  "Basic realm=\"rscap\"", 0, 0);
  evhtp_headers_add_header(req->headers_out, head);
  evhtp_send_reply(req, EVHTP_RES_UNAUTH);
  return EVHTP_RES_UNAUTH;
 }
 else
 { 
  char * pw = auth->val + strlen("Basic ");
  char * decoded;
  char * u, *p;
  rscap_base64_decode(pw, &decoded);
  u = decoded;
  p = strchr(u, ':');
  if ( p == NULL ) 
  {
    rscap_free(decoded);
    goto err;
  }
  p[0] = '\0'; p++;
  if ( validate_user(users, u, p) != 0 ) goto err; 
  return EVHTP_RES_OK;
 }
}


static evhtp_res cb_accept(evhtp_connection_t * conn, void * arg)
{
 evhtp_set_hook(&conn->hooks, evhtp_hook_on_headers, cb_req, arg);
 return EVHTP_RES_OK;
}



#if (OPENSSL_VERSION_NUMBER < 0x00904000)
#define rscap_PEM_read_bio_X509(b) PEM_read_bio_X509(b, NULL, NULL)
#else
#define rscap_PEM_read_bio_X509(b) PEM_read_bio_X509(b, NULL, NULL, NULL)
#endif

int SSL_CTX_use_certificate_chain(SSL_CTX *ctx, const char *file)
{
  BIO *bio;
  X509 *x509;

  if ((bio = BIO_new(BIO_s_file_internal())) == NULL) return -1;
  if (BIO_read_filename(bio, file) <= 0) goto err;
  while ((x509 = rscap_PEM_read_bio_X509(bio)) != NULL) 
  {
    if ( SSL_CTX_add_extra_chain_cert(ctx, x509) == 0 )
        {
	    fprintf(stderr, "SSL_CTX_add_extra_chain_cert failed\n");
            X509_free(x509);
            goto err;
        }
  }

   BIO_free(bio);
   return 1;
err:
   BIO_free(bio);
   return -1;
}



int SSL_add_CRL(SSL_CTX * ctx, const char * crl_path)
{
 X509_STORE *x509_store = SSL_CTX_get_cert_store(ctx);
 X509_LOOKUP *lookup;
 X509_VERIFY_PARAM *param; 

 lookup = X509_STORE_add_lookup (x509_store, X509_LOOKUP_file () );
 if ( X509_load_crl_file (lookup, crl_path, X509_FILETYPE_PEM) != 1 )
 {
   fprintf(stderr, "Could not load CRL file %s\n", crl_path);
   exit(1);
 }

 /* Enable CRL checking */
 param = X509_VERIFY_PARAM_new();
 X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
 SSL_CTX_set1_param(ctx, param);
 X509_VERIFY_PARAM_free(param);

 return 0;
}



int main(int argc, char ** argv)
{
 char * directories[] = { RSCAP_QUEUE_DIR, RSCAP_RUNNING_DIR, RSCAP_RESULTS_DIR, RSCAP_DB_DIR, RSCAP_UPLOAD_DIR, RSCAP_STAGING_DIR, RSCAP_REMEDY_QUEUE_DIR, RSCAP_REMEDY_RUNNING_DIR, RSCAP_REMEDY_DB_DIR, RSCAP_REMEDY_RESULTS_DIR, NULL };
 int i;
 evbase_t * evbase = event_base_new();
 evhtp_t  * htp    = evhtp_new(evbase, NULL);
 evhtp_ssl_cfg_t htp_ssl;
 struct rscap_hash * cfg;
 struct rscap_hash * users = NULL;
 int listen_port = 8080;
 const char * listen_address = "0.0.0.0";
 const char * v;
 int idx;
 struct rscap_signature_cfg * sig_cfg = NULL;
 int err;


 rscap_log_init("scapcomm");

 cfg = rscap_config_load(RSCAP_CONFIG_FILE);
 if ( cfg == NULL ) 
 {
  fprintf(stderr, "Could not load the configuration file, exiting\n");
  exit(1);
 }

 v = rscap_config_get(cfg, "Port");
 if ( v != NULL ) 
 {
  listen_port = atoi(v);
  if ( listen_port <= 0 || listen_port > 65535 )
  {
    fprintf(stderr, "Error in the configuration - '%s' is an invalid port number\n", v);
    exit(1);
  }
 }

 v = rscap_config_get(cfg, "ListenAddress");
 if ( v != NULL ) listen_address = v;

 
 
 v = rscap_config_get(cfg, "AuthorizedUsers");
 if ( v == NULL )
 {
   fprintf(stderr, "Error -- missing AuthorizedUsers entry in the configuration file\n");
   exit(1);
 }
 g_users = rscap_users_load(v);
 if ( g_users == NULL ) 
 {
   fprintf(stderr, "Error -- wrong AuthorizedUsers entry in the configuration file -- could not read %s\n", v);
   exit(1);
 }

 
 v = rscap_config_get(cfg, "PasswordAuth");
 if ( v != NULL && strcmp(v, "yes") == 0 )
 {
  v = rscap_config_get(cfg, "UsersDB");
  if ( v != NULL ) 
  {
    users = rscap_config_load(v);
    if ( users == NULL )
    {
	fprintf(stderr, "Error -- could not load %s\n", v);
 	exit(1);
    }
  }
 }
 
 SSL_library_init();
 SSL_load_error_strings();

 for ( i = 0, err = 0 ; directories[i] != NULL ; i ++ )
         if ( rscap_file_readable(directories[i]) < 0 )  
	  {
		dir_missing(directories[i]);
		err++;
	  }

 if ( err != 0 ) exit(1);
 
 bzero(&htp_ssl, sizeof(htp_ssl));

 v = rscap_config_get(cfg, "DisableSSL");
 if ( v == NULL || strcmp(v, "yes") != 0 )
 {
  v = rscap_config_get(cfg, "SSLCertificateFile");
  if ( v != NULL ) htp_ssl.pemfile = (char*)v;
  
  v = rscap_config_get(cfg, "SSLCertificateKeyFile");
  if ( v != NULL ) htp_ssl.privfile = (char*)v;

  v = rscap_config_get(cfg, "SSLCACertificateFile");
  if ( v != NULL ) htp_ssl.cafile = (char*)v;

  v = rscap_config_get(cfg, "SSLCipherSuite");
  if ( v != NULL ) htp_ssl.ciphers = (char*)v;

  v = rscap_config_get(cfg, "DebugOnly_DisableAuthentication");
  if ( v == NULL || strcmp(v, "yes") != 0 )
	{
	   v = rscap_config_get(cfg, "PasswordAuth");
	   if ( v == NULL || strcmp(v, "yes") != 0 )
		   htp_ssl.verify_peer = SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	   else
		{
		   htp_ssl.verify_peer = SSL_VERIFY_NONE;
		}

	    htp_ssl.x509_verify_cb   = verify_callback;
	}
  else
  {
    rscap_log("*** WARNING! DebugOnly_DisableAuthentication is set -- NO AUTHENTICATION IS IN PLACE\n");
    fprintf(stderr, "*** WARNING! DebugOnly_DisableAuthentication is set -- NO AUTHENTICATION IS IN PLACE\n");
  }

  v = rscap_config_get(cfg, "SSLVerifyDepth");
  if ( v != NULL && atoi(v) != 0 ) htp_ssl.verify_depth = atoi(v) + 1; 

  if ( evhtp_ssl_init(htp, &htp_ssl) != 0 )
  {
   fprintf(stderr, "SSL init failed\n");
   exit(1);
  }
 }


 v = rscap_config_get(cfg, "LogFile");
 if ( v != NULL ) rscap_add_log_file(v);

 v = rscap_config_get(cfg, "Debug");
 if ( v != NULL && strcmp(v, "yes") == 0 ) rscap_add_log_fp(stderr);

 v = rscap_config_get(cfg, "OutputMode");
 if ( v != NULL ) 
 {
   if ( strcmp(v, "html") == 0 ) {
	rscap_output_func = rscapcmd2buf;
	rscap_output_content_type = "text/html";
	}
   else if ( strcmp(v, "xml") == 0 ) {
	rscap_output_func = rscapcmd2xmlbuf;
	rscap_output_content_type = "text/xml";
	}
 }

 v = rscap_config_get(cfg, "CheckArchivesSignatures");
 if ( v == NULL || strcmp(v, "no") != 0 )
  sig_cfg = rscap_signature_init(cfg);
 else
  sig_cfg = NULL;


 idx = SSL_get_ex_new_index(0, "Config", NULL, NULL, NULL);
  

 rscap_log("scapcomm v%s starting up\n", RSCAP_VERSION);


 evhtp_set_post_accept_cb(htp, cb_accept, users);


 evhtp_set_cb(htp, "/scap/list", cb_list, (void*)rscapcmd_scap_list);
 evhtp_set_cb(htp, "/scap/profile/list", cb_scap_profile_list, NULL);
 evhtp_set_cb(htp, "/scap/upload", cb_scap_upload, (void*)sig_cfg);
 evhtp_set_cb(htp, "/scap/delete", cb_scap_delete, NULL);
 evhtp_set_cb(htp, "/scap/queue", cb_list, (void*)rscapcmd_queue_list);
 evhtp_set_cb(htp, "/scap/queue/add", cb_scap_queue_add, NULL);
 evhtp_set_cb(htp, "/scap/queue/remove", cb_scap_queue_remove, NULL);
 evhtp_set_cb(htp, "/scap/results/list", cb_list, (void*)rscapcmd_results_list);
 evhtp_set_cb(htp, "/scap/results/delete", cb_results_delete, NULL);
 evhtp_set_cb(htp, "/scap/results/download", cb_results_download, NULL);
 evhtp_set_cb(htp, "/scap/version", cb_version, NULL);

#if 0
 evhtp_set_cb(htp, "/scap/cert_upload", cb_scap_cert_upload, (void*)sig_cfg);
 evhtp_set_cb(htp, "/scap/cert_replace", cb_scap_cert_replace, (void*)cfg);
#endif

 evhtp_set_cb(htp, "/remediation/upload", cb_remediation_upload, (void*)sig_cfg);
 evhtp_set_cb(htp, "/remediation/list", cb_list, (void*)rscapcmd_remediation_list);
 evhtp_set_cb(htp, "/remediation/delete", cb_remediation_delete, NULL);
 evhtp_set_cb(htp, "/remediation/queue/add", cb_remediation_queue_add, NULL);
 evhtp_set_cb(htp, "/remediation/queue/remove", cb_remediation_queue_remove, NULL);
 evhtp_set_cb(htp, "/remediation/queue", cb_list, (void*)rscapcmd_remediation_queue_list);
 evhtp_set_cb(htp, "/remediation/results/list", cb_list, (void*)rscapcmd_remediation_results_list);
 evhtp_set_cb(htp, "/remediation/results/delete", cb_remediation_results_delete, NULL);
 evhtp_set_cb(htp, "/remediation/results/download", cb_remediation_results_download, NULL);


 if ( rscap_output_func == rscapcmd2buf ) 
 	evhtp_set_cb(htp, "/", cb_test, NULL);

 evhtp_bind_socket(htp, "0.0.0.0", listen_port, 1024);

 if ( htp->ssl_ctx != NULL )
 {
  if ( (v = rscap_config_get(cfg, "SSLCRL")) != NULL ) 
	{
	  SSL_add_CRL(htp->ssl_ctx, v);
	}

  if ( (v = rscap_config_get(cfg, "SSLCertificateChainFile")) != NULL )
	{
	 SSL_CTX_use_certificate_chain(htp->ssl_ctx, v);
	}
 }

 if ( geteuid() == 0 ) rscap_drop_privileges(cfg);
 event_base_loop(evbase, 0);
 return 0;


 return 0;
}

