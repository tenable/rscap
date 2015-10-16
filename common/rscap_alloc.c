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

#define MAGICCOOKIE 0xc00feebe

struct rscap_buffer_header {
	size_t size; /* Not including the header */
	int cookie;
};

void * rscap_alloc(size_t sz)
{
 char * ret;
 struct rscap_buffer_header * header;

 if ( ADD_U_OVERFLOW(sz, sizeof(struct rscap_buffer_header) ) ) abort();

 ret = malloc(sz + sizeof(struct rscap_buffer_header));
 if ( ret == NULL ) abort();
 header = (struct rscap_buffer_header*)ret;
 header->size = sz;
 header->cookie = MAGICCOOKIE;
 ret += sizeof(struct rscap_buffer_header);
 return ret;
}

void * rscap_zalloc(size_t sz)
{
 void * ret = rscap_alloc(sz);
 if ( ret == NULL ) return NULL;
 memset(ret, '\0', sz);
 return ret;
}


char * rscap_strndup(const char * str, size_t len)
{
 char * ret;

 if ( ADD_U_OVERFLOW(len, 1) ) abort();
 ret = rscap_alloc(len + 1);
 memcpy(ret, str, len);
 ret[len] = '\0';
 return ret;
}

char * rscap_strdup(const char * str)
{
  return rscap_strndup(str, strlen(str));
}

void * rscap_realloc(void * ptr, size_t sz)
{
 char * buf = (char *)ptr;
 struct rscap_buffer_header * header;

 if ( ptr == NULL ) return rscap_alloc(sz);
 buf -= sizeof(struct rscap_buffer_header);
 header = (struct rscap_buffer_header*)buf;
 if ( header->cookie != MAGICCOOKIE ) abort();
 if ( ADD_U_OVERFLOW(sz, sizeof(struct rscap_buffer_header)) ) abort();
 buf = realloc(buf, sz + sizeof(struct rscap_buffer_header));
 header = (struct rscap_buffer_header*)buf;
 header->size = sz;
 buf += sizeof(struct rscap_buffer_header);
 return buf;
}

void rscap_free(void * ptr)
{
 char * buf = (char*)ptr;
 struct rscap_buffer_header * header;

 if ( ptr == NULL ) abort();

 buf -= sizeof(struct rscap_buffer_header);
 header = (struct rscap_buffer_header *)buf;
 if ( header->cookie != MAGICCOOKIE ) abort();
 free(header);
}
