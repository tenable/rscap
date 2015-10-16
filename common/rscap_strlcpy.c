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

#ifndef HAVE_STRLCAT

size_t strlcat(char * dst, const char* src, size_t dst_max_len)
{
  size_t src_len, dst_len, i;

  if ( dst == NULL || src == NULL ) return 0;

  src_len = strlen(src);
  dst_len = strlen(dst);
 
 if ( dst_len + src_len >= dst_max_len ) 
        src_len = dst_max_len - dst_len - 1;

 
 for ( i = 0 ; i < src_len ; i ++ )
   dst[dst_len + i] = src[i];

 dst[dst_len+src_len] = '\0';
 return dst_len + src_len; 
}

#endif
#ifndef HAVE_STRLCPY 
size_t strlcpy(char * dst, const char * src, size_t len)
{
 strncpy(dst, src, len);
 dst[len - 1] = '\0';
 return strlen(src);
}
#endif
#ifndef HAVE_STRCASECMP
int strcasecamp(const char * s1, const char * s2 )
{
 while (*s1 && *s2 )
 {
  if ( tolower(*s1) != tolower(*s2) )
        return *s1 - *s2;

  s1++;
  s2++;
 }
 if ( *s1 != *s2 )
        return *s1 == '\0' ? *s1 : *s2;

 return 0;
}
#endif
