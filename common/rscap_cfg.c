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


struct rscap_hash * rscap_config_load(const char * path)
{
 FILE * fp;
 char line[4096];
 struct rscap_hash * ret;
 int line_num = 0;
 char * err_txt = NULL;

 if ( path == NULL )
 {
  return NULL;
 }
 
 fp = fopen(path, "r");
 if ( fp == NULL ) return NULL;

 ret = rscap_hash_init(0);
 
 line[sizeof(line) - 1] = '\0';
 while ( fgets(line, sizeof(line), fp) != NULL )
 {
   char * p, * q, *s;
   line_num++;
   while ( line[0] != '\0' && (line[strlen(line) - 1] == '\r' || line[strlen(line) - 1] == '\n' ) ) line[strlen(line) - 1] = '\0';
   p = line;
   while ( isspace(p[0]) ) p++;
   if ( p[0] == '#' || p[0] == '\0' ) continue;
   q = strchr(p, '=');
   if (q == NULL) 
	{
	 err_txt = "Expected '=' in the line";
	 goto parse_err;
	}

  s = q - 1;
  while (isspace(s[0])) s --;
  s[1] = '\0';
  q ++;
  while (isspace(q[0])) q ++;
  if ( p[0] == '\0' ) 
  {
	 err_txt = "No option name";
	 goto parse_err;
  }
  if ( q[0] == '\0' ) 
  {
	 err_txt = "No option value";
	 goto parse_err;
  }
  /* Todo: verify key? */
  rscap_hash_add_value(ret, p, q);
 }

 fclose(fp);
 return ret;

 
parse_err:
 fclose(fp);
 fprintf(stderr, "Parse error in %s, line %d:\n%s\nLine: %s\n", path, line_num, err_txt, line);
 rscap_hash_free(ret);
 return NULL;
}

const char * rscap_config_get(const struct rscap_hash * config, const char * key)
{
 return rscap_hash_get_value(config, key);
}


struct rscap_hash * rscap_users_load(const char * path)
{
 FILE * fp;
 char line[4096];
 struct rscap_hash * ret;

 if ( path == NULL ) return NULL;
 fp = fopen(path, "r");
 if ( fp == NULL ) return NULL;

 ret = rscap_hash_init(0);
 line[sizeof(line) - 1] = '\0';
 while ( fgets(line, sizeof(line) - 1, fp) != NULL )
 {
  while ( line[0] != '\0' && ( line[strlen(line) - 1] == '\n' || line[strlen(line) - 1] == '\r' ) ) line[strlen(line) - 1] = '\0';
  if ( line[0] != '\0' ) 
		rscap_hash_add_value(ret, line, "OK");

 }
 fclose(fp);
 return ret;
}
