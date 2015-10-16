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


#define RSCAP_CMD_TYPE_STACK 1
#define RSCAP_CMD_TYPE_STATUS 2
#define RSCAP_CMD_TYPE_FILE  3


#define RSCAP_CMD_STATUS_OK 0
#define RSCAP_CMD_STATUS_FAIL 1


struct rscap_cmd {
	int status;
	int type;
	union {
	  struct rscap_stack * stack;
  	  char * msg;
	} res;
};

struct rscap_cmd * rscap_mk_stack_cmd_res(int status, struct rscap_stack * stack);
struct rscap_cmd * rscap_mk_cmd_status_res(int status, const char * msg);
struct rscap_cmd * rscap_mk_file_cmd_res(int status, const char * path);
void rscap_cmd_res_free(struct rscap_cmd * res);
void rscap_cmd_res_dump(struct rscap_cmd * cmd);
char * rscapcmd2buf(struct rscap_cmd * res);
char * rscapcmd2xmlbuf(struct rscap_cmd * res);
const char * rscap_cmd_fpath(struct rscap_cmd * res);
