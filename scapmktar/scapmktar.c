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

#define BLOCKSIZE 512



struct tar_header
{
        char name[100];
        char mode[8];
        char uid[8];
        char gid[8];
        char size[12];
        char mtime[12];
        char chksum[8];
        char typeflag;
        char linkname[100];
        char magic[6];
        char version[2];
        char uname[32];
        char gname[32];
        char devmajor[8];
        char devminor[8];
        char prefix[155];

};

union tar_buffer
{
        char               buffer[BLOCKSIZE];
        struct tar_header  header;
};

int dec2base8(unsigned int n, char * str, size_t sz)
{
 char tmp[128];
 int i, j;

 memset(str, '0', sz - 1);
 str[sz - 1] = '\0';
 tmp[0] = '\0';
 while ( n != 0 )
 {
  unsigned int t = n % 8; 
  char s[8];
  snprintf(s, sizeof(s), "%d", t);
  strlcat(tmp, s, sizeof(tmp));
  n = n / 8;
 }

 for ( i = strlen(tmp) - 1, j = strlen(str) - strlen(tmp); i >= 0 ; i --, j ++ )
 {
  if ( j >= sz - 1) break;
  str[j] = tmp[i];
 }
 str[j] = '\0';
 return 0;
}

void mktarbuffer(union tar_buffer * buffer, const char * fname, size_t fsize, time_t mtime)
{
  long cksum;
  int j;

  bzero(buffer, sizeof(*buffer));
  strlcpy(buffer->header.name, fname, sizeof(buffer->header.name));
  strlcpy(buffer->header.mode, "0000644", sizeof(buffer->header.mode));
  strlcpy(buffer->header.uid, "0000000", sizeof(buffer->header.uid));
  strlcpy(buffer->header.gid, "0000000", sizeof(buffer->header.gid));
  dec2base8(fsize, buffer->header.size, sizeof(buffer->header.size));
  dec2base8(mtime, buffer->header.mtime, sizeof(buffer->header.mtime));
  buffer->header.typeflag = '\0';
  buffer->header.linkname[0] = '0';
  strlcpy(buffer->header.magic, "ustar  ", sizeof(buffer->header.magic) + sizeof(buffer->header.version));
  
  strlcpy(buffer->header.uname, "root", sizeof(buffer->header.uname));
  strlcpy(buffer->header.gname, "root", sizeof(buffer->header.gname));
  memset(buffer->header.chksum, ' ', sizeof(buffer->header.chksum));


  cksum = 0;
  for ( j = 0 ; j < sizeof(buffer->header) ; j ++ )
  {
   unsigned char c = buffer->buffer[j];
   cksum += c;
  }
  snprintf(buffer->header.chksum, sizeof(buffer->header.chksum), "%06o", (unsigned)(cksum & 07777777));
}




int main(int argc, char ** argv)
{
 int i;
 gzFile fd;
 union tar_buffer buffer;
 struct rscap_string rstr;
 int pad;
 struct stat st;
 char * signed_buf;
 struct rscap_hash * cfg;
 const char * certfile, *keyfile;


 cfg = rscap_config_load(RSCAP_CONFIG_FILE);
 if ( cfg == NULL )
 {
  fprintf(stderr, "Could not load the configuration file - %s\n", strerror(errno));
  exit(1);
 }
 certfile = rscap_config_get(cfg, "SigningSSLCertificateFile");
 keyfile = rscap_config_get(cfg, "SigningSSLCertificateKeyFile");
 if ( certfile == NULL || keyfile == NULL )
 {
  fprintf(stderr, "No SigningSSLCertificateFile nor SSLCertificateKeyFile specified in %s\n", RSCAP_CONFIG_FILE);
  exit(1);
 }


rscap_add_log_fp(stderr);
 rscap_string_init(&rstr);
 if ( argc < 3 )
 {
  fprintf(stderr, "Usage: %s <archive> <file1> <file2> ...\n", argv[0]);
  exit(1);
 }


 if ( stat(argv[1], &st) == 0 )
 {
  fprintf(stderr, "%s already exists\n", argv[1]);
  exit(1);
 }

 fd = gzopen(argv[1], "wb");
 if ( fd == NULL )
 {
  fprintf(stderr, "Could not open %s - %s\n", argv[1], strerror(errno));
 }

 for ( i = 2 ; argv[i] != NULL ; i ++ )
 {
  char sha[256];
  int fd2, j;

  if ( stat(argv[i], &st) != 0 ) continue;
  if( rscap_sha1("./", argv[i], sha, sizeof(sha)) == 0 )
	{
	 rscap_string_cat(&rstr, argv[i]);
	 rscap_string_cat(&rstr, ":");
	 rscap_string_cat(&rstr, sha);
	 rscap_string_cat(&rstr, "\n");
	}
  else 
	continue;

   
  mktarbuffer(&buffer, argv[i], st.st_size, st.st_mtime);

  gzwrite(fd, &buffer.header, sizeof(buffer.buffer));

  fd2 = open(argv[i], O_RDONLY);
  if ( fd2 < 0 ) break;
  for ( j = 0 ; j < st.st_size; )
  { 
   int sz;
   bzero(&buffer.buffer, sizeof(buffer.buffer));
   sz = st.st_size - j;
   if ( sz > BLOCKSIZE ) sz = BLOCKSIZE;
   read(fd2, &buffer.buffer, sz);
   gzwrite(fd, &buffer.buffer, BLOCKSIZE);
   j += sz;
  }
  printf("%s\n", argv[i]);
  close(fd2);
 }



 signed_buf = rscap_buffer_sign(certfile, keyfile, rscap_string_cstring(&rstr), strlen(rscap_string_cstring(&rstr)));
 if ( signed_buf == NULL ) 
 {
  fprintf(stderr, "Could not sign the archive\n");
  exit(1);
 }
 mktarbuffer(&buffer, "+SIGNATURE", strlen(signed_buf), time(NULL));
 gzwrite(fd, &buffer.header, sizeof(buffer.buffer));
 gzwrite(fd, signed_buf, strlen(signed_buf));
 pad = BLOCKSIZE - (strlen(signed_buf) % BLOCKSIZE);
 for ( i = 0 ; i < pad ; i ++ ) gzwrite(fd, "\x00", 1);
 bzero(buffer.buffer, sizeof(buffer.buffer));
 gzwrite(fd, buffer.buffer, sizeof(buffer.buffer));
 
 gzclose(fd);
 rscap_free(signed_buf);

   

 return 0;
}
