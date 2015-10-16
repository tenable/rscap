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

#include "scapassess_process.h"


/* 
 * This function should eventually be re-done entirely to invoke the OpenSCAP
 * library directly, instead of an executable
 */
int scapassess_exec(const char * cmd, const char * dir, const char *profile, const char *xccdf_file)
{
 pid_t pid;

 pid = fork();
 if ( pid == 0 )
 {
   int fd = open("/dev/null", O_RDONLY);
   int i;
   const char * args[32];
   char results[1024];


   strlcpy(results, xccdf_file, sizeof(results));
   strlcat(results, ".results", sizeof(results));

   close(0); 
   dup2(fd, 0);
   dup2(fd, 1);
   dup2(fd, 2);
   
   for ( i = 3; i < 1024 ; i ++ ) close(i);
   args[0] = cmd;
   args[1] = "xccdf";
   args[2] = "eval";
/*  args[3] = "--fetch-remote-resources"; */
   args[3] = "--profile";
   args[4] = profile;
   args[5] = "--results";
   args[6] = results;
   args[7] = xccdf_file;
   args[8] = NULL;
   execvp(cmd, (char * const *)args);
   _exit(1);
 }
 return pid;
}

static int _scapassess_eval_xccdf(struct rscap_signature_cfg * sig_cfg, const char * dir, const char * path, struct scap_task * task)
{
 char * profile;
 char * xccdf_tar_archive;
 char * xccdf_file;
 char xccdf_fname[1024];
 char * buf;
 size_t bufsz;
 struct rscap_hash * hash = NULL;

 rscap_log("Should eval dir=%s path=%s\n", dir, path);
 
 xccdf_tar_archive = rscap_mk_path(dir, "xccdf.tgz", NULL);

 if ( sig_cfg != NULL ) 
 {
  hash = rscap_load_signatures(sig_cfg, dir, "xccdf.tgz");
  if ( hash == NULL )
  {
    rscap_log("Invalid archive for job %s (No/Invalid signature)\n", path);
    rscap_free(xccdf_tar_archive);
    goto err;
  }
 }
 
 if ( rscap_tar_find_xccdf_file(xccdf_tar_archive, xccdf_fname, sizeof(xccdf_fname) ) < 0 ) 
 {
   rscap_log("Invalid archive for job %s (Could not find SCAP data to use)\n", path);
   if ( hash != NULL ) rscap_hash_free(hash);
   rscap_free(xccdf_tar_archive);
   goto err;
 }

 if ( rscap_untar(xccdf_tar_archive, dir, hash, 0) != 0 )
 {
   rscap_log("Invalid archive for job %s (bad signature)\n", path);
   if ( hash != NULL ) rscap_hash_free(hash);
   rscap_free(xccdf_tar_archive);
   goto err;
 }
 rscap_free(xccdf_tar_archive);
 if ( hash != NULL ) rscap_hash_free(hash);

 xccdf_file = rscap_mk_path(dir, xccdf_fname, NULL);

 if ( rscap_file_readable(xccdf_file) < 0 )
 {
  rscap_log("Invalid archive for job %s (%s not included)\n", path, xccdf_file);
  rscap_free(xccdf_file);
  goto err;
 }
 

 profile = rscap_mk_path(dir, "profile", NULL);
 if ( rscap_read_file_contents(profile, &buf, &bufsz) < 0 )
 {
  rscap_log("Failed to read %s - %s\n", profile, rscap_strerror());
  rscap_free(profile);
  rscap_free(xccdf_file);
  goto err;
 }
 else
 {
  struct rscap_stack * profiles = rscap_lines2stack(buf);

  rscap_free(profile);
  rscap_free(buf);
  while ( ( profile = rscap_stack_pop(profiles) ) != NULL  )
  {
    rscap_log("EXEC %s on %s\n", profile, xccdf_file);

    if ( rscap_file_readable(xccdf_file) < 0 ) 
    {
     /* The job was deleted by scapcomm */
     rscap_log("%s does not exist any more -- interrupting task %d\n", task->task_id);
     pthread_mutex_lock(&task->mx);
     task->finished = SCAP_TASK_INTR;
     pthread_mutex_unlock(&task->mx);
    }


    pthread_mutex_lock(&task->mx);
    if ( task->finished != 0 ) 
    {
	rscap_log("Task %d was requested to be interrupted\n", task->task_id);
	task->finished = SCAP_TASK_INTR;
	pthread_mutex_unlock(&task->mx);
    	rscap_free(profile);
	break;
    }

    task->fork_pid = scapassess_exec(task->cmd, dir, profile, xccdf_file); 
    pthread_mutex_unlock(&task->mx);
    if ( task->fork_pid > 0)
    {
 	while ( waitpid(task->fork_pid, NULL, WNOHANG) <= 0 )
 	{
    	  if ( rscap_file_readable(xccdf_file) < 0 ) 
	  {
		kill(task->fork_pid, SIGTERM);
		while ( waitpid(task->fork_pid, NULL, 0) < 0 && errno == EINTR ) errno = 0;


     		pthread_mutex_lock(&task->mx);
     		task->finished = SCAP_TASK_INTR;
     		pthread_mutex_unlock(&task->mx);
		break;
	  }
	  else usleep(500000);
	}
    }
    rscap_free(profile);
  }
 
  rscap_stack_free(profiles);
 }



 if ( sig_cfg != NULL && sig_cfg->do_sign )
  {
   char results[1024];
   int do_sign = 0;;

   pthread_mutex_lock(&task->mx);
   if ( task->finished == 0 ) do_sign = 1;
   pthread_mutex_unlock(&task->mx);
     
   if ( do_sign )
   {
    strlcpy(results, xccdf_file, sizeof(results));
    strlcat(results, ".results", sizeof(results));
    rscap_log("Signing %s\n", results);
    rscap_xml_sign(sig_cfg->signing_cert, sig_cfg->signing_key, results);
   }
  }
	 	

 
 pthread_mutex_lock(&task->mx);
 if ( task->finished == 0 ) task->finished = SCAP_TASK_SUCCESS;
 pthread_mutex_unlock(&task->mx);
  
 rscap_free(xccdf_file);
 return 0;
err:
 pthread_mutex_lock(&task->mx);
 task->finished = SCAP_TASK_ERROR;
 pthread_mutex_unlock(&task->mx);
 return -1;
}

static void * _scapassess_eval_xccdf_bootstrap(void * arg)
{
 struct scap_task * task = (struct scap_task*) arg;
 _scapassess_eval_xccdf(task->sig_cfg, task->path, task->dir, task);
 return NULL;
}

int scapassess_eval_xccdf(struct scap_task * task)
{
 pthread_mutex_lock(&task->mx);
 pthread_create(&task->thread, NULL, _scapassess_eval_xccdf_bootstrap, task);  
 pthread_mutex_unlock(&task->mx);
 return 0;
}

