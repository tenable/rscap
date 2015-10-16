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

#include "scapremedy_process.h"


int scapremedy_exec(const char * dir, const char *remediation_file)
{
 pid_t pid;

 

 pid = fork();
 if ( pid == 0 )
 {
#define MAX_ARGV 1024
   int fd = open("/dev/null", O_RDONLY);
   int fd2;
   int i;
   struct rscap_hash * hash;
   const char * cmd;
   const char * argv_list[MAX_ARGV];
   char argv[32];

   chdir(dir);
   fd2 = open("results.out", O_CREAT|O_TRUNC|O_WRONLY, 0660);

   close(0); 
   dup2(fd, 0);
   dup2(fd2, 1);
   dup2(fd2, 2);
   
   for ( i = 3; i < 1024 ; i ++ ) close(i);

   hash = rscap_config_load(remediation_file);
   if ( hash == NULL ) 
   {
	fprintf(stderr, "Could not parse %s\n", remediation_file);
	exit(1);
   }
   cmd = rscap_config_get(hash, "Command");
   if ( cmd == NULL )
   {
	fprintf(stderr, "Missing Command= in %s\n", remediation_file);
 	exit(1);
   }
   argv_list[0] = cmd;
   for ( i = 0 ; i < MAX_ARGV - 1 ; i ++ )
   {
    snprintf(argv, sizeof(argv), "Arg%d", i);
    argv_list[i] = rscap_config_get(hash, argv);
    if ( argv_list[i] == NULL ) break;
   }

   rscap_hash_free(hash);
   for ( i = 0 ; argv_list[i] != NULL ; i ++ )
	printf("arg%d=%s\n", i, argv_list[i]);

   execv(cmd, (char* const*)argv_list);
   perror("execv()");
   _exit(1);
 }
 return pid;
}

static int _scapremedy_exec_script(struct rscap_signature_cfg * sig_cfg, const char * dir, const char * path, struct scap_task * task)
{
 char * remediation_tar_archive;
 char * remediation_file;
 struct rscap_hash * hash;

 rscap_log("Should eval dir=%s path=%s\n", dir, path);
 
 remediation_tar_archive = rscap_mk_path(dir, "remediation.tgz", NULL);

 hash = rscap_load_signatures(sig_cfg, dir, "remediation.tgz");
 if ( hash == NULL )
 {
   rscap_log("Invalid archive for job %s (No/Invalid signature)\n", path);
   rscap_free(remediation_tar_archive);
   goto err;
 }
 

 if ( rscap_untar(remediation_tar_archive, dir, hash, 0) != 0 )
 {
   rscap_log("Invalid archive for job %s (bad signature)\n", path);
   rscap_hash_free(hash);
   rscap_free(remediation_tar_archive);
   goto err;
 }
 rscap_free(remediation_tar_archive);
 rscap_hash_free(hash);

 remediation_file = rscap_mk_path(dir, "command", NULL);

 if ( rscap_file_readable(remediation_file) < 0 )
 {
  rscap_log("Invalid archive for job %s (%s not included)\n", path, remediation_file);
  rscap_free(remediation_file);
  goto err;
 }
 

 pthread_mutex_lock(&task->mx);
 task->fork_pid = scapremedy_exec(dir, remediation_file); 
 pthread_mutex_unlock(&task->mx);
 if ( task->fork_pid > 0)
 {
  for ( ;; )
  {
   int e;
   errno = 0;
   e = waitpid(task->fork_pid, NULL, 0);
   if ( e >= 0 ) break;
   if ( e < 0 && errno != EINTR ) break;
  }
 }

 
 pthread_mutex_lock(&task->mx);
 if ( task->finished == 0 ) task->finished = SCAP_TASK_SUCCESS;
 pthread_mutex_unlock(&task->mx);
  
 rscap_free(remediation_file);
 return 0;
err:
 pthread_mutex_lock(&task->mx);
 task->finished = SCAP_TASK_ERROR;
 pthread_mutex_unlock(&task->mx);
 return -1;
}

static void * _scapremedy_exec_script_bootstrap(void * arg)
{
 struct scap_task * task = (struct scap_task*) arg;
 _scapremedy_exec_script(task->sig_cfg, task->path, task->dir, task);
 return NULL;
}

int scapremedy_exec_script(struct scap_task * task)
{
 pthread_mutex_lock(&task->mx);
 pthread_create(&task->thread, NULL, _scapremedy_exec_script_bootstrap, task);  
 pthread_mutex_unlock(&task->mx);
 return 0;
}

