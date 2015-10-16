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



void rscap_string_init(struct rscap_string * str)
{
 if ( str == NULL )
 {
  errno = EINVAL;
  return;
 }
 str->buf = NULL;
 str->buf_sz = str->buf_len = 0;
}


void rscap_string_cat(struct rscap_string * str, const char * data)
{
 return rscap_string_ncat(str, data, strlen(data));
}

void rscap_string_ncat(struct rscap_string * str, const char * data, int data_len)
{

 if ( str == NULL || data == NULL )
 {
  errno = EINVAL;
  return;
 }

 if ( str->buf_len + data_len >= str->buf_sz )
 {
   str->buf_sz += data_len + 1024; /* XX */
   str->buf = rscap_realloc(str->buf, str->buf_sz);
   str->buf[str->buf_len] = '\0';
 }
 memcpy(str->buf + str->buf_len, data, data_len);
 str->buf_len += data_len;
 str->buf[str->buf_len] = '\0';
}

void rscap_string_free(struct rscap_string * str)
{
 if ( str == NULL ) return;
 if ( str->buf != NULL ) rscap_free(str->buf);
 bzero(str, sizeof(*str));
}

char * rscap_string_cstring(struct rscap_string * str)
{
 if ( str == NULL ) return NULL;
 return str->buf;
}

void rscap_string_cat_escape(struct rscap_string * str, const char * data)
{
 rscap_string_cat(str, data);
}

static const char base64_code[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static  int base64_value[256];
static unsigned char inalphabet[256];

void rscap_base64_init()
{
  int   i;
  static int initialized = 0;

  if ( initialized ) return;
  initialized = 1;

  if (base64_value[(int)base64_code[1]] != 1)
    {
      for (i = 0; i < 256; i++)
        base64_value[i] = -1;

      for (i = 0; i < 64; i++)
        base64_value[(int) base64_code[i]] = i;
      base64_value['='] = 0;
    }

  bzero(inalphabet, sizeof(inalphabet));
  for (i = (sizeof base64_code) - 1; i >= 0 ; i --)
      {
        inalphabet[(int) base64_code[i]] = 1;
      }
}

/* adopted from http://ftp.sunet.se/pub2/gnu/vm/base64-encode.c with adjustments */
char * rscap_base64_encode(const char *decoded_str, size_t decoded_len, char * result, size_t result_sz)
{
    int bits = 0;
    int char_count = 0;
    int out_cnt = 0;
    int c;
    int i;

    rscap_base64_init();
    
    if ( decoded_str == NULL )
        return NULL;

    if ( result == NULL || result_sz == 0 )
    {
        return NULL;
    }


    for (i = 0; i < decoded_len && out_cnt < result_sz - 5; i ++)
      {
        c = (unsigned char) decoded_str[i];
        bits += c;
        char_count++;
        if (char_count == 3) {
            result[out_cnt++] = base64_code[bits >> 18];
            result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
            result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
            result[out_cnt++] = base64_code[bits & 0x3f];
            bits = 0;
            char_count = 0;
        } else {
            bits <<= 8;
        }
    }
    if (char_count != 0) {
        bits <<= 16 - (8 * char_count);
        result[out_cnt++] = base64_code[bits >> 18];
        result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
        if (char_count == 1) {
            result[out_cnt++] = '=';
            result[out_cnt++] = '=';
        } else {
            result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
            result[out_cnt++] = '=';
        }
    }
    result[out_cnt] = '\0';     /* terminate */
    return result;
}


