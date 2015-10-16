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


static unsigned int mkhash(const char * nm, size_t len, unsigned int max)
{
 unsigned int h = 0;
 size_t i;
 unsigned char * name = (unsigned char*)nm;

 for ( i = 0 ; i < len ; i ++ )
 {
        h += name[i];
        h +=  ( h << 10 );
        h ^=  ( h>> 6 );
 }

 h += ( h << 3 );
 h ^= ( h >> 11 );
 h += ( h >> 15 );

 return h % max;
}




struct rscap_hash * rscap_hash_init(int sz)
{
 struct rscap_hash * ret;

 ret = rscap_zalloc(sizeof(*ret));
 if ( sz == 0 ) sz = 67;
 ret->key_sz = sz;
 ret->entries = rscap_zalloc(ret->key_sz * sizeof(struct rscap_hash_entry*));
 return ret;
}

void rscap_hash_free(struct rscap_hash * h )
{
 int i;
 if ( h == NULL ) return;
 for ( i = 0 ; i < h->key_sz ; i ++ )
 {
   struct rscap_hash_entry * entry, * nxt;
   entry = h->entries[i];
   while ( entry != NULL )
   {
	nxt = entry->next;
	rscap_free(entry->key);
	rscap_free(entry->value);
	rscap_free(entry);
	entry = nxt;
   }
 }
 rscap_free(h->entries);
 rscap_free(h);
}


int rscap_hash_add_value(struct rscap_hash * h, const char * key , const char * value )
{
 unsigned int idx;
 struct rscap_hash_entry * entry;

 if ( h == NULL || key == NULL || value == NULL ) return -1;

 idx  = mkhash(key, strlen(key), h->key_sz);
 entry = rscap_zalloc(sizeof(*entry));
 entry->key = rscap_strdup(key);
 entry->value = rscap_strdup(value);
 entry->next = h->entries[idx];
 h->entries[idx] = entry;
 return 0;
}
	

const char * rscap_hash_get_value(const struct rscap_hash * h, const char * key)
{
 unsigned int idx;
 struct rscap_hash_entry * entry;

 if ( h == NULL || key == NULL || h->entries == NULL ) return NULL;

 idx = mkhash(key, strlen(key), h->key_sz);
 entry = h->entries[idx];
 while ( entry != NULL )
 {
  if ( strcmp(entry->key, key) == 0 ) return entry->value;
  entry = entry->next;
 }
 return NULL;
}
  

