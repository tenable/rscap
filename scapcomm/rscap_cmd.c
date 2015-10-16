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

#include "rscap_cmd.h"


void rscap_cmd_res_dump(struct rscap_cmd * cmd)
{
 char * status;
 char * str;
 switch (  cmd->status )
 {
  case RSCAP_CMD_STATUS_FAIL: 
	status = "FAIL";
	break;
  case RSCAP_CMD_STATUS_OK: 
	status = "OK";
	break;
  default:
	status = "UNKNOWN";
	break;
 }
 printf("Status: %s\n", status);

 switch( cmd->type )
 {
  case RSCAP_CMD_TYPE_FILE:
	printf(" file://%s\n", cmd->res.msg);
	break;
  case RSCAP_CMD_TYPE_STATUS:
	printf(" %s\n", cmd->res.msg);
	break;
  case RSCAP_CMD_TYPE_STACK:
	if ( cmd->res.stack->n_col == 0 )
	{
	while ( ( str = rscap_stack_pop(cmd->res.stack) ) != NULL )
		{
			printf(" %s\n", str);
			rscap_free(str);
		}
	}
	else
	{
	 int i;

	while ( ( str = rscap_stack_pop_index(cmd->res.stack, 0) ) != NULL )
 	{
		printf(" %s", str);
		rscap_free(str);
		for ( i = 1; i < cmd->res.stack->n_col ; i ++ ) 
		{
			char * p = rscap_stack_pop_index(cmd->res.stack, i);
			printf("|%s", p);
			rscap_free(p);
		}
		printf("\n");
	}
	
	}
	break;
 }
}



struct rscap_cmd * rscap_mk_stack_cmd_res(int status, struct rscap_stack * stack)
{
 struct rscap_cmd * ret;

 ret = rscap_zalloc(sizeof(*ret));
 ret->status = status;
 ret->type = RSCAP_CMD_TYPE_STACK;
 ret->res.stack = stack;
 return ret;
}

struct rscap_cmd * rscap_mk_cmd_status_res(int status, const char * msg)
{
 struct rscap_cmd * ret;

 ret = rscap_zalloc(sizeof(*ret));
 ret->status = status;
 ret->type = RSCAP_CMD_TYPE_STATUS;
 ret->res.msg = rscap_strdup(msg);
 return ret;
}

struct rscap_cmd * rscap_mk_file_cmd_res(int status, const char * path)
{
 struct rscap_cmd * ret;

 ret = rscap_zalloc(sizeof(*ret));
 ret->status = status;
 ret->type = RSCAP_CMD_TYPE_FILE;
 ret->res.msg = rscap_strdup(path);
 return ret;
}

void rscap_cmd_res_free(struct rscap_cmd * res)
{
 switch( res->type )
 {
  case RSCAP_CMD_TYPE_FILE:
  case RSCAP_CMD_TYPE_STATUS:
	rscap_free(res->res.msg);
	break;
  case RSCAP_CMD_TYPE_STACK:
	rscap_stack_free(res->res.stack);
	break;
  default:
	abort();
 }

 rscap_free(res);
}


char * rscapcmd2buf(struct rscap_cmd * res)
{
 struct rscap_string str;
 char * cstr;

 rscap_string_init(&str);

 if ( res->status == RSCAP_CMD_STATUS_OK ) rscap_string_cat(&str, "STATUS: OK<br>\n");
 else if ( res->status == RSCAP_CMD_STATUS_FAIL ) rscap_string_cat(&str, "STATUS: FAIL<br>\n");
 else rscap_string_cat(&str, "STATUS: UNKNOWN<br>\n");

 switch( res->type )
 {
  case RSCAP_CMD_TYPE_FILE:
	rscap_string_cat(&str, "file://\n");
	rscap_string_cat(&str, res->res.msg);
	rscap_string_cat(&str, "<br>\n");
	break;
  case RSCAP_CMD_TYPE_STATUS:
	rscap_string_cat(&str, res->res.msg);
	rscap_string_cat(&str, "<br>\n");
	break;
  case RSCAP_CMD_TYPE_STACK:
	if ( res->res.stack->n_col == 0 )
	{
	while ( ( cstr = rscap_stack_pop(res->res.stack) ) != NULL )
		{
		rscap_string_cat(&str, cstr);
		rscap_free(cstr);
		rscap_string_cat(&str, "<br>\n");
		}
	}
	else
	{
	 int i;

	rscap_string_cat(&str, "<center><table border=1>");
	rscap_string_cat(&str, "<tr>");
	if ( res->res.stack->columns != NULL )
	 for ( i = 0 ; i < res->res.stack->n_col ; i ++ )
	 {
		rscap_string_cat(&str, "<td>");
		rscap_string_cat(&str, res->res.stack->columns[i]->col_name);
		rscap_string_cat(&str, "</td>");
	 }
	rscap_string_cat(&str, "</tr>");
	

	 
	while ( ( cstr = rscap_stack_pop_index(res->res.stack, 0) ) != NULL )
 	{
		rscap_string_cat(&str, "<tr><td>");
		rscap_string_cat(&str, cstr);
		rscap_free(cstr);
		rscap_string_cat(&str, "</td>");
		for ( i = 1; i < res->res.stack->n_col ; i ++ ) {
				cstr = rscap_stack_pop_index(res->res.stack, i);
				rscap_string_cat(&str, "<td>");
				if ( cstr != NULL ) rscap_string_cat(&str, cstr);
				rscap_string_cat(&str, "</td>");
				if ( cstr != NULL ) rscap_free(cstr);
				}
		rscap_string_cat(&str, "</tr>\n");
	}
	rscap_string_cat(&str, "</table></center>");
	
	}
	break;
 }
 return rscap_string_cstring(&str);
}

char * rscapcmd2xmlbuf(struct rscap_cmd * res)
{
 struct rscap_string str;

 rscap_string_init(&str);
 rscap_string_cat(&str, "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n");
 rscap_string_cat(&str, "<rscap_reply>\n");
 rscap_string_cat(&str, "<cmd_status>");
 if ( res->status == RSCAP_CMD_STATUS_OK ) rscap_string_cat(&str, "OK");
 else if ( res->status == RSCAP_CMD_STATUS_FAIL ) rscap_string_cat(&str, "FAIL");
 else rscap_string_cat(&str, "UNKNOWN");
 rscap_string_cat(&str, "</cmd_status>\n");

 switch( res->type )
 {
  case RSCAP_CMD_TYPE_FILE:
	rscap_string_cat(&str, "<file>");
	rscap_string_cat(&str, "file://");
	rscap_string_cat_escape(&str, res->res.msg);
	rscap_string_cat(&str, "</file>\n");
	break;
  case RSCAP_CMD_TYPE_STATUS:
	rscap_string_cat(&str, "<msg>");
	rscap_string_cat_escape(&str, res->res.msg);
	rscap_string_cat(&str, "</msg>\n");
	break;
  case RSCAP_CMD_TYPE_STACK:
	if ( res->res.stack->n_col == 0 ) abort();
	else
	{
	 int i;
	while ( rscap_stack_pending(res->res.stack ) != 0 )
  	{
         rscap_string_cat(&str, "<result>\n");
	 for ( i = 0 ; i < res->res.stack->n_col ; i ++ )
	 {
		char * cstr;
		rscap_string_cat(&str, "<");
		rscap_string_cat_escape(&str, res->res.stack->columns[i]->col_name);
		rscap_string_cat(&str, ">");
		cstr = rscap_stack_pop_index(res->res.stack, i);
		rscap_string_cat_escape(&str, cstr);
		rscap_free(cstr);
		rscap_string_cat(&str, "</");
		rscap_string_cat_escape(&str, res->res.stack->columns[i]->col_name);
		rscap_string_cat(&str, ">");
	 }
	rscap_string_cat(&str, "\n");
        rscap_string_cat(&str, "</result>\n");
 	}
	}
	break;
 }
 rscap_string_cat(&str, "</rscap_reply>");
 return rscap_string_cstring(&str);
}

const char * rscap_cmd_fpath(struct rscap_cmd * res)
{
 if ( res->type != RSCAP_CMD_TYPE_FILE ) return NULL;
 return res->res.msg;
}
