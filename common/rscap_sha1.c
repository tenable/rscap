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
#include <openssl/sha.h>


int rscap_sha1_buf(const char * buffer, size_t buffer_size, char * sig, size_t sig_sz)
{
 SHA_CTX ctx;
 unsigned char sha[SHA_DIGEST_LENGTH];
 int i;

 if ( buffer == NULL || sig == NULL ) return -1;
 bzero(sha, sizeof(sha));
 bzero(sig, sig_sz);

 SHA1_Init(&ctx);
 SHA1_Update(&ctx, buffer, buffer_size);
 SHA1_Final(sha, &ctx);
 
 sig[0] = '\0';

 for ( i = 0 ; i < SHA_DIGEST_LENGTH ; i ++ )
 {
  char tmp[3];
  snprintf(tmp, sizeof(tmp), "%02x", sha[i]);
  strlcat(sig, tmp, sig_sz);
 }

 return 0;
}


int rscap_sha1(const char * dir, const char * fname, char * buf, size_t buf_sz)
{
 SHA_CTX ctx;
 int fd;
 char *fpath;
 struct stat st;
 size_t rd;
 unsigned char sha[SHA_DIGEST_LENGTH];
 int i;

 fpath = rscap_mk_path(dir, fname, NULL);
 fd = open(fpath, O_RDONLY);
 rscap_free(fpath);
 if ( fd < 0 ) return -1;
 if ( fstat(fd, &st) < 0 ) 
 {
  close(fd);
  return -1; /* ? */
 }


 SHA1_Init(&ctx);

 for ( rd = 0 ; rd != st.st_size ;  )
 {
  char buf[16384];
  int n = read(fd, buf, sizeof(buf));

  if ( n <= 0 ) break;
  SHA1_Update(&ctx, buf, n);
  rd += n;
 }
 

 close(fd);
 bzero(sha, sizeof(sha));
 SHA1_Final(sha, &ctx);
 bzero(buf, buf_sz);

 for ( i = 0 ; i < SHA_DIGEST_LENGTH ; i ++ )
 {
  char tmp[3];
  snprintf(tmp, sizeof(tmp), "%02x", sha[i]);
  strlcat(buf, tmp, buf_sz);
 }

 return 0;
}

