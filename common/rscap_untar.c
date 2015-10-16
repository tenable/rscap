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


int rscap_untar(const char * archive, const char * destdir, struct rscap_hash * signatures, int verifyOnly)
{
 gzFile fd;
 union tar_buffer buffer;
 size_t sz = 0, pad = 0, bufsz = 0;
 char * fname;
 int recover;
 char * buf = NULL;
 int n = 0;
 
 
 if ( archive == NULL || destdir == NULL ) return -1;

 if ( verifyOnly != 0 && signatures == 0 ) return -1;


 fd = gzopen(archive, "rb");
 if ( fd == NULL ) return -1;

 for ( ;; )
 {
  recover = 0;
  if ( gzread(fd, &buffer, sizeof(buffer)) != sizeof(buffer) )
  {
    rscap_log("%s is an invalid gzip archive", archive);
    break;
  }


  buffer.header.name[sizeof(buffer.header.name) - 1] = '\0';
  if ( buffer.header.name[0] == '\0' ) break;
  if ( buffer.header.name[0] == '/' ||
       buffer.header.name[0] == ':' ||
       strstr(buffer.header.name, "..") != NULL ) 
   {
     rscap_log("%s contains an invalid entry name (%s)", archive, buffer.header.name[0]);
     break;
   }

  if ( memcmp(buffer.header.magic, "ustar", 5) != 0 ) 
  { 
    rscap_log("%s is an invalid gzip archive", archive);
    break;
  }

   sz = strtol(buffer.header.size, NULL, 8);
   if ( sz % BLOCKSIZE )
	pad = sz + ( BLOCKSIZE - ( sz % BLOCKSIZE ) );
   else
	pad = sz;

   fname = rscap_mk_path(destdir, buffer.header.name, NULL);
   if ( strcmp(buffer.header.name, "+SIGNATURE") == 0 ) 
   {
    recover = 1;
   }
   if ( recover == 0 && verifyOnly == 0 && rscap_unlink(fname) < 0 && errno != ENOENT )
   {
    rscap_log("Error while processing %s - %s could not be deleted (%s). Skipping.\n", archive, fname, rscap_strerror());
    recover = 1;
   }
   
  if ( bufsz < pad ) 
   {
     bufsz = pad;
     buf = rscap_realloc(buf, bufsz + 1);
     buf[bufsz] = '\0';
   }

   for ( n = 0 ; n < pad ; ) 
   {
    int e;
    e = gzread(fd, buf + n, pad - n );
    if ( e < 0 && errno == EINTR ) continue;
    else if ( e < 0 ) break;
    else if ( e == 0 ) {
	goto bailout;
	}
    n += e;
   }

   if ( recover ) 
   {
	rscap_free(fname);
	continue;
   }
    
  if ( signatures != NULL )
  {
   char sig[1024];
   const char * v;

   v = rscap_hash_get_value(signatures, buffer.header.name);
   rscap_sha1_buf(buf, sz, sig, sizeof(sig));
   if ( v == NULL || strcmp(sig, v) != 0 )  
   {
 	gzclose(fd);
	if ( buf != NULL )rscap_free(buf);
	return -1;
   }
  } 

  if ( verifyOnly == 0 && rscap_write_file_contents(fname, buf, sz) < 0 )
  {
	rscap_log("Error while processing %s - could not write to %s - %s\n", archive, fname, rscap_strerror());
  }

   rscap_free(fname);
 }
bailout:
 gzclose(fd);
 if ( buf != NULL ) rscap_free(buf);
 return 0;
}



int rscap_tar_find_xccdf_file(const char * archive, char * out_fname, size_t out_fname_sz)
{
 gzFile fd;
 union tar_buffer buffer;
 size_t sz = 0, pad = 0, bufsz = 0;
 char * fname;
 int recover;
 char * buf = NULL;
 int n = 0;
 int ret = -1;
 
 
 if ( archive == NULL ) return -1;

 fd = gzopen(archive, "rb");
 if ( fd == NULL ) return -1;

 for ( ;; )
 {
  recover = 0;
  if ( gzread(fd, &buffer, sizeof(buffer)) != sizeof(buffer) )
  {
    rscap_log("%s is an invalid gzip archive", archive);
    break;
  }


  buffer.header.name[sizeof(buffer.header.name) - 1] = '\0';
  if ( buffer.header.name[0] == '\0' ) break;
  if ( buffer.header.name[0] == '/' ||
       buffer.header.name[0] == ':' ||
       strstr(buffer.header.name, "..") != NULL ) 
   {
     rscap_log("%s contains an invalid entry name (%s)", archive, buffer.header.name[0]);
     break;
   }

  if ( memcmp(buffer.header.magic, "ustar", 5) != 0 ) 
  { 
    rscap_log("%s is an invalid gzip archive", archive);
    break;
  }

   sz = strtol(buffer.header.size, NULL, 8);
   if ( sz % BLOCKSIZE )
	pad = sz + ( BLOCKSIZE - ( sz % BLOCKSIZE ) );
   else
	pad = sz;

   fname = buffer.header.name;
   
  if ( bufsz < pad ) 
   {
     bufsz = pad;
     buf = rscap_realloc(buf, bufsz + 1);
     buf[bufsz] = '\0';
   }

   for ( n = 0 ; n < pad ; ) 
   {
    int e;
    e = gzread(fd, buf + n, pad - n );
    if ( e < 0 && errno == EINTR ) continue;
    else if ( e < 0 ) break;
    else if ( e == 0 ) goto bailout;
    n += e;
   }

   if ( recover ) 
   {
	continue;
   }

    
   if ( strstr(buf, "<Benchmark xmlns=\"http://checklists.nist.gov/xccdf/") != NULL )
   {
     strlcpy(out_fname, fname, out_fname_sz);
     ret = 0;
     break;
   }

 }
bailout:
 gzclose(fd);
 if ( buf != NULL ) rscap_free(buf);
 return ret;
}

int rscap_tar_get_file(const char * archive, const char * search_fname, char ** out_buf, size_t * out_buf_sz )
{
 gzFile fd;
 union tar_buffer buffer;
 size_t sz = 0, pad = 0, bufsz = 0;
 char * fname;
 int recover;
 char * buf = NULL;
 int n = 0;
 int ret = -1;
 
 
 if ( archive == NULL ) return -1;

 fd = gzopen(archive, "rb");
 if ( fd == NULL ) return -1;

 for ( ;; )
 {
  recover = 0;
  if ( gzread(fd, &buffer, sizeof(buffer)) != sizeof(buffer) )
  {
    rscap_log("%s is an invalid gzip archive", archive);
    break;
  }


  buffer.header.name[sizeof(buffer.header.name) - 1] = '\0';
  if ( buffer.header.name[0] == '\0' ) break;
  if ( buffer.header.name[0] == '/' ||
       buffer.header.name[0] == ':' ||
       strstr(buffer.header.name, "..") != NULL ) 
   {
     rscap_log("%s contains an invalid entry name (%s)", archive, buffer.header.name[0]);
     break;
   }

  if ( memcmp(buffer.header.magic, "ustar", 5) != 0 ) 
  { 
    rscap_log("%s is an invalid gzip archive", archive);
    break;
  }

   sz = strtol(buffer.header.size, NULL, 8);
   if ( sz % BLOCKSIZE )
	pad = sz + ( BLOCKSIZE - ( sz % BLOCKSIZE ) );
   else
	pad = sz;

   fname = buffer.header.name;
   
  if ( bufsz < pad ) 
   {
     bufsz = pad;
     buf = rscap_realloc(buf, bufsz + 1);
     buf[bufsz] = '\0';
   }

   for ( n = 0 ; n < pad ; ) 
   {
    int e;
    e = gzread(fd, buf + n, pad - n );
    if ( e < 0 && errno == EINTR ) continue;
    else if ( e < 0 ) break;
    else if ( e == 0 ) goto bailout;
    n += e;
   }


   if ( strcmp(fname, search_fname) == 0 )
   { 
    *out_buf = buf;
    *out_buf_sz = sz;
    ret = 0;
    break;
   }

   if ( recover ) 
   {
	continue;
   }
    

 }
bailout:
 gzclose(fd);
 if ( ret != 0 && buf != NULL ) 
 {	
	rscap_free(buf);
	*out_buf = NULL;
 }
 return ret;
}

int rscap_tar_check_header(const char * archive)
{
 gzFile fd;
 union tar_buffer buffer;
 
 
 if ( archive == NULL ) return -1;

 fd = gzopen(archive, "rb");
 if ( fd == NULL ) return -1;
 if ( gzread(fd, &buffer, sizeof(buffer)) != sizeof(buffer) )
 {
   rscap_log("%s is an invalid gzip archive", archive);
   goto err;
 }

 buffer.header.name[sizeof(buffer.header.name) - 1] = '\0';
 if ( buffer.header.name[0] == '\0' ) goto err;
 if ( buffer.header.name[0] == '/' ||
      buffer.header.name[0] == ':' ||
      strstr(buffer.header.name, "..") != NULL ) 
   {
     rscap_log("%s contains an invalid entry name (%s)", archive, buffer.header.name[0]);
     goto err;
   }

 if ( memcmp(buffer.header.magic, "ustar", 5) != 0 ) 
 { 
   rscap_log("%s is an invalid gzip archive", archive);
   goto err;
 }

 gzclose(fd);
 return 0;

err:
 gzclose(fd);
 return -1;
}
 
