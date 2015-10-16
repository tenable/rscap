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


#define SCAP_TASK_SUCCESS 1
#define SCAP_TASK_ERROR   2
#define SCAP_TASK_INTR	  3


struct scap_task {
	char * path;
	char * dir;
	int    task_id;
	pid_t  fork_pid;
	int    fork_exit_status; /* 0 = success, 1 = error, 2 = interrupted */
	struct scap_task * next;
	pthread_mutex_t mx;
	pthread_t thread;
	int finished;
	struct rscap_signature_cfg * sig_cfg;
	const char * cmd;
};


struct scap_tasks {
	struct scap_task  * tasks;
	int	task_id_counter;
	pthread_mutex_t mx;
};

int scapassess_process_entry(const char * cmd, struct rscap_signature_cfg * sig_cfg, const char * directory, const char * path);
void scapassess_process_init();
int scapassess_job_count();
void scapassess_job_cleaner(struct rscap_hash * cfg);
