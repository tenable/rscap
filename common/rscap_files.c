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


int rscap_file_readable(const char * path)
{
 return access(path, R_OK);
}

int rscap_mkdir(const char * path, int mode)
{
 return mkdir(path, mode);
}

int rscap_rename_dir(const char * src, const char * dst)
{
 struct rscap_stack * files;
 char * entry;

 if ( src == NULL || dst == NULL ) return -1;

 if (rscap_mkdir(dst, 0770) < 0 ) return -1;

 files = rscap_dir_contents(src);
 if ( files == NULL ) return -1;

 while ( ( entry = rscap_stack_pop(files) ) != NULL )
 {
  char * srcpath = rscap_mk_path(src, entry, NULL);
  char * dstpath = rscap_mk_path(dst, entry, NULL);

  if ( rscap_rename(srcpath, dstpath) < 0 )
	rscap_log("Renaming %s to %s failed -- %s\n", srcpath, dstpath, rscap_strerror());

  rscap_free(srcpath);
  rscap_free(dstpath);
  rscap_free(entry);
 }

 rscap_rmdir(src);
 rscap_stack_free(files);
 return 0;
}


int rscap_rmdir(const char * path)
{
 return rmdir(path);
}

struct rscap_stack * rscap_dir_contents(const char * path)
{
 DIR * dir;
 struct dirent entry, *result;
 struct rscap_stack * stack;

 if ( path == NULL ) return NULL;
 dir = opendir(path);
 if ( dir == NULL ) return NULL;

 stack = rscap_stack_init(0);
 while ( readdir_r(dir, &entry, &result) == 0 )
 {
  if ( result == NULL ) break;
  if ( result->d_name == NULL ) continue;
  if ( result->d_name[0] == '.' ) continue;
  rscap_stack_push(stack, result->d_name);
 }
 closedir(dir);
 return stack;
}

char * rscap_mk_path(const char * dir, ...)
{
 va_list params;
 size_t sz, used_sz;
 char * ret;
 char * str;

 if ( dir == NULL ) return NULL;
 if ( ADD_U_OVERFLOW(strlen(dir), 4096) ) abort(); 

 sz = strlen(dir) + 4096;
 used_sz = strlen(dir) + 1;
 ret = rscap_alloc(sz);
 ret[0] = '\0';
 strlcat(ret, dir, sz);

 va_start(params, dir);
 for ( ;; )
 {
  str = va_arg(params, char *);
  if ( str  == NULL ) break;
  if ( ADD_U_OVERFLOW(strlen(str), 1 ) ) abort();
  if ( ADD_U_OVERFLOW(used_sz, (strlen(str)+1) ) ) abort();
  used_sz += strlen(str) + 1;
  if ( used_sz + 1 >= sz ) 
  {
    if ( ADD_U_OVERFLOW(sz, 4096) ) abort();
    sz += 4096;
    ret = rscap_realloc(ret, sz);
  }
  strlcat(ret, "/", sz);
  strlcat(ret, str, sz);
 }
 return rscap_realloc(ret, strlen(ret) + 1);
}


int rscap_rename(const char * src, const char * dst)
{
 return rename(src, dst);
}

int rscap_chown_dir(const char * path, const char * user, const char * group)
{
 DIR * dp;
 struct dirent *de, *dr = NULL;
 int uid, gid;

 uid = rscap_uid_byname(user);
 gid = rscap_gid_byname(group);

 if ( uid < 0 || gid < 0 ) return -1;

 if ( ( dp = opendir(path) ) == NULL ) 
 {
  int perr = errno;
  if ( chown(path, uid, gid) == 0 ) return 0;
  errno = perr;
  return -1;
 }

 de = rscap_alloc(sizeof(struct dirent) + 4096 + 1);
 while ( readdir_r(dp, de, &dr) == 0 && dr != NULL && dr->d_name != NULL )
 {
  char * fpath;
  if ( strcmp(dr->d_name, ".") == 0  || strcmp(dr->d_name, "..") == 0 ) continue;
  fpath = rscap_mk_path(path, dr->d_name, NULL);
  if ( chown(fpath, uid, gid) < 0 ) break;
  if ( dr->d_type == DT_DIR ) rscap_chown_dir(fpath, user, group);
  rscap_free(fpath);
  dr = NULL;
 }
 closedir(dp);
 chown(path, uid, gid);
 rscap_free(de);
 return 0;
}

int rscap_recursive_rmdir(const char * path)
{
 DIR * dp;
 struct dirent *de, *dr = NULL;

 if ( ( dp = opendir(path) ) == NULL ) 
 {
  int perr = errno;
  if ( unlink(path) == 0 ) return 0;
  errno = perr;
  return -1;
 }

 de = rscap_alloc(sizeof(struct dirent) + 4096 + 1);
 while ( readdir_r(dp, de, &dr) == 0 && dr != NULL && dr->d_name != NULL )
 {
  char * fpath;
  if ( strcmp(dr->d_name, ".") == 0  || strcmp(dr->d_name, "..") == 0 ) continue;
  fpath = rscap_mk_path(path, dr->d_name, NULL);
  if ( unlink(fpath) < 0 ) rscap_recursive_rmdir(fpath);
  rscap_free(fpath);
  dr = NULL;
 }
 closedir(dp);
 rmdir(path);
 rscap_free(de);
 return 0;
}


int rscap_unlink(const char * path)
{
 return unlink(path);
}

int rscap_write_file_contents(const char * path, const char * contents, size_t sz )
{
 int fd;
 size_t n;
 int s_errno;

 rscap_unlink(path);
 fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0600);
 if ( fd < 0 ) return -1;
 for ( n = 0 ; n < sz ; )
 {
   int e = write(fd, contents + n, sz - n );
   if ( e < 0 && errno == EINTR ) continue;
   else if ( e < 0 ) break;
   else if ( e == 0 ) break;
   n += e;
 }

 close(fd);
 if ( n != sz )
 {
  s_errno = errno;
  rscap_unlink(path);
  errno = s_errno;
  return -1;
 }
 return 0;
}

int rscap_read_file_contents(const char * path, char ** contents, size_t * sz )
{
 int fd;
 struct stat st;
 char * buf;
 size_t bufsz;
 size_t n;

 if ( contents == NULL || sz == NULL ) return -1;
 
 *contents = NULL;
 *sz = 0;

 if ( stat(path, &st) < 0 ) return -1;

 fd = open(path, O_RDONLY);
 if ( fd < 0 ) return -1;

 bufsz = st.st_size;
 buf = rscap_alloc(bufsz + 1);
 for ( n = 0 ; n < bufsz ; )
 {
  int e = read(fd, buf + n, bufsz - n );
  if ( e < 0 && errno == EINTR ) continue;
  if ( e <= 0 ) break;
  n += e;
 }

 close(fd);

 if ( n != bufsz )
 { 
   rscap_free(buf);
   return -1;
 }

 buf[bufsz] = '\0';
 *sz = bufsz;
 *contents = buf; 
 return 0;
}


int rscap_copy_file(const char * src, const char * dst)
{
 int fd_src, fd_dst;
 struct stat st;
 char buf[16384];
 size_t totsz = 0;

 fd_src = open(src, O_RDONLY);
 if ( fd_src < 0 ) return -1;

 fd_dst = open(dst, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0600);
 if ( fd_dst < 0 )
 {
  close(fd_src);
  return -1;
 }

 fstat(fd_src, &st);
 while ( totsz != st.st_size )
 {
 int n = read(fd_src, buf, sizeof(buf));
 if ( n <= 0 ) break;
 write(fd_dst, buf, n);
 totsz += n;
 }

 close(fd_src);
 close(fd_dst);
 return totsz == st.st_size ? 0 : -1;
}
