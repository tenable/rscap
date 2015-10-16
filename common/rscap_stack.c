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


struct rscap_stack * rscap_stack_init(int type)
{
 struct rscap_stack * ret;

 ret = rscap_alloc(sizeof(*ret));
 if ( ret == NULL ) return NULL;
 ret->type = type;
 ret->stack = NULL;
 ret->columns = NULL;
 ret->n_col = 0;
 ret->col_name = NULL;
 return ret;
}

void rscap_stack_add_column(struct rscap_stack * stack)
{
 assert ( stack->stack == NULL );
 if ( stack->n_col == 0 )
 {
  stack->n_col = 2;
  stack->columns = rscap_zalloc(sizeof(struct rscap_stack*) * stack->n_col);
  stack->columns[0] = stack;
  stack->columns[1] = rscap_stack_init(stack->type);
  return;
 }

 stack->n_col ++;
 stack->columns = rscap_realloc(stack->columns, sizeof(struct rscap_stack*) * stack->n_col);
 stack->columns[stack->n_col-1] = rscap_stack_init(stack->type);
}

void rscap_stack_set_column_name(struct rscap_stack * stack, int idx, const char * col_name)
{
 if ( stack == NULL );

 if ( idx == 0 && stack->n_col == 0 )
 {
  stack->n_col = 1;
  stack->columns = rscap_zalloc(sizeof(struct rscap_stack*));
  stack->columns[0] = stack;
 }

 if ( idx >= stack->n_col || idx < 0 )  return;

 if ( stack->columns[idx]->col_name != NULL )
	rscap_free(stack->columns[idx]->col_name);

  stack->columns[idx]->col_name = rscap_strdup(col_name);
}

const char * rscap_stack_get_column_name(struct rscap_stack * stack, int idx)
{
 if ( stack == NULL || idx >= stack->n_col || idx < 0 )  return NULL;
 return stack->columns[idx]->col_name;
}

int rscap_stack_push_index(struct rscap_stack * stack, const char * str, int column)
{
 if ( column >= stack->n_col ) abort();

 return rscap_stack_push(stack->columns[column], str);
}


char * rscap_stack_pop_index(struct rscap_stack * stack, int column)
{
 if ( column >= stack->n_col ) abort();

 return rscap_stack_pop(stack->columns[column]);
}


void rscap_stack_free(struct rscap_stack * stack)
{
 int i;

 if ( stack == NULL ) return;
 if ( stack->col_name != NULL ) rscap_free(stack->col_name);
 while ( stack->stack != NULL )
 {
   struct rscap_stack_content * nxt = stack->stack->next;

   rscap_free(stack->stack->item);
   rscap_free(stack->stack);
   stack->stack = nxt;
 }
 for ( i = 1 ; i < stack->n_col ; i ++ )
	rscap_stack_free(stack->columns[i]);

 if ( stack->columns != NULL ) rscap_free(stack->columns);
 rscap_free(stack);
}

int rscap_stack_push(struct rscap_stack * stack, const char * str)
{
 struct rscap_stack_content * item;

 if ( stack == NULL || str == NULL ) return -1;

 item = rscap_zalloc(sizeof(*item));
 item->item = rscap_strdup(str);
 item->next = stack->stack;
 stack->stack = item;
 return 0;
}

char * rscap_stack_pop(struct rscap_stack * stack)
{
 struct rscap_stack_content * ret;
 char * str;
 if ( stack == NULL ) return NULL;
 if ( stack->stack == NULL ) return NULL;
 ret = stack->stack;
 stack->stack = ret->next;
 str = ret->item;
 rscap_free(ret);
 return str;
}


int rscap_stack_pending(struct rscap_stack * stack)
{
 if ( stack == NULL ) return 0;
 if ( stack->stack == NULL ) return 0;
 if ( stack->stack != NULL ) return 1;
 return 0;
}

struct rscap_stack * rscap_lines2stack(const char * txt)
{
 struct rscap_stack * ret;
 char * tmp = NULL;
 const char  *p, *q;
 size_t tmp_sz = 0;

 if ( txt == NULL ) return NULL;
 ret = rscap_stack_init(0);
 p = txt;
 q = strchr(p, '\n');
 while ( q != NULL )
 {
  size_t len = (size_t)(q - p);

  if ( len >= tmp_sz ) 
  {
 	tmp_sz = len + 1;
	tmp = rscap_realloc(tmp, tmp_sz);
  }

  memcpy(tmp, p, len);
  tmp[len] = '\0';
  if ( len > 0 && tmp[len-1] == '\r' ) tmp[len-1] = '\0';
  rscap_stack_push(ret, tmp);
  p = q + 1;
  q = strchr(p, '\n');
 }

 if ( tmp != NULL ) rscap_free(tmp);

 if ( p != NULL && strlen(p) > 0 ) rscap_stack_push(ret, p);
 return ret;
}
