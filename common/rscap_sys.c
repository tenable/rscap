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

#include <pwd.h>
#include <grp.h>
#include <openssl/rand.h>

void rscap_sleep(int s)
{
 sleep(s);
}

time_t rscap_time()
{
 return time(NULL);
}

int rscap_ctime(time_t t, char * str, size_t str_sz)
{
 if ( str_sz < 26 ) return -1;
 ctime_r(&t, str);
 if ( str[0] != '\0' && str[strlen(str) - 1] == '\n' )
	str[strlen(str) - 1] = '\0';

 return 0;
}

pid_t rscap_getpid()
{
 return getpid();
}

const char * rscap_strerror()
{
 return strerror(errno);
}

char * rscap_chomp(char * in)
{
 int len;
 if ( in == NULL ) return NULL;
 len = strlen(in);
 while ( len > 0 && ( in[len - 1] == '\r' || in[len - 1] == '\n' ) ) 
 {
    in[len - 1] = '\0';
    len --;
 }
 return in;
}

int rscap_validate_uuid(const char * uuid)
{
 /* TBD! */
 return 0;
}

int rscap_uuid(char * buf, int buf_sz )
{
 unsigned char uuid[16];
 int i, j;

 if ( buf_sz < 37 ) return -1;

 bzero(uuid, sizeof(uuid));
 RAND_bytes(uuid, 16);
 

 for ( i = 0, j = 0 ; i < 16; i ++ )
 {
  char tmp[3];
  snprintf(tmp, sizeof(tmp), "%02x", uuid[i]);
  if ( j + 2 >= buf_sz ) return -1;
  buf[j++] = tmp[0];
  buf[j++] = tmp[1];
  if ( (j + 1 >= buf_sz) ) return -1;
  if ( ( j == 8 || j == 13 || j == 18 || j == 23 ) )
        buf[j++] = '-';

 }

 buf[j] = '\0';
 return 0; 
}


int rscap_uid_byname(const char * username)
{
  struct passwd pw;
  struct passwd *res = NULL;
  char buf[4096];


  if ( getpwnam_r(username, &pw, buf, sizeof(buf), &res) != 0 ) return -1;
  if ( res == NULL ) return -1;
  return res->pw_uid;
}

int rscap_gid_byname(const char * groupname)
{
 struct group gr;
 struct group * res = NULL;
 char buf[4096];
  struct passwd pw;
  struct passwd *res_pw = NULL;

 if ( getgrnam_r(groupname, &gr, buf, sizeof(buf), &res) == 0 && res != NULL )
	return res->gr_gid;

  if ( getpwnam_r(groupname, &pw, buf, sizeof(buf), &res_pw) != 0 ) return -1;
  if ( res_pw == NULL ) return -1;
  return res_pw->pw_gid;
} 
