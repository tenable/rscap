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


struct rscap_stack_content {
	char * item;
	struct rscap_stack_content * next;
};
	
struct rscap_stack {
	int type;
	char * col_name;
	struct rscap_stack_content * stack;
	struct rscap_stack ** columns;
	int n_col;
};


struct rscap_stack * rscap_stack_init(int type);
void rscap_stack_free(struct rscap_stack * stack);
int rscap_stack_push(struct rscap_stack * stack, const char * str);
char * rscap_stack_pop(struct rscap_stack * stack);
struct rscap_stack * rscap_lines2stack(const char * txt);

void rscap_stack_add_column(struct rscap_stack * stack);
void rscap_stack_set_column_name(struct rscap_stack * , int, const char *);
const char *rscap_stack_get_column_name(struct rscap_stack * , int);
int rscap_stack_push_index(struct rscap_stack * stack, const char * str, int column);
char * rscap_stack_pop_index(struct rscap_stack * stack, int column);
int rscap_stack_pending(struct rscap_stack * stack);


