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
#include "scapremedy_exec_script.h"



static struct scap_tasks * scap_tasks = NULL;

void scapremedy_process_init()
{
 assert ( scap_tasks == NULL );
 scap_tasks = rscap_alloc(sizeof ( *scap_tasks ));
 scap_tasks->tasks = NULL;
 scap_tasks->task_id_counter = 1;
 pthread_mutex_init(&scap_tasks->mx, NULL);
}


struct scap_task * scap_task_new(const char * path, const char * dir)
{
 struct scap_task * ret = rscap_zalloc(sizeof(*ret));
 
 pthread_mutex_lock(&scap_tasks->mx);
 ret->path = rscap_strdup(path);
 ret->dir  = rscap_strdup(dir);

 ret->task_id   = scap_tasks->task_id_counter++;
 ret->next 	= scap_tasks->tasks;
 pthread_mutex_init(&ret->mx, NULL);
 scap_tasks->tasks = ret;
 pthread_mutex_unlock(&scap_tasks->mx);
 return ret;
}

static void * _scapremedy_job_cleaner(void * arg)
{
 struct rscap_hash * cfg = (struct rscap_hash*)arg;
 const char * user, * group;

 user = rscap_config_get(cfg, "ScapComm.RunAsUser");
 group = rscap_config_get(cfg, "ScapComm.RunAsGroup");
 if ( group == NULL ) group = user;

 for ( ;; ) 
 {
  struct scap_task * task;
  struct scap_task * prev = NULL;
  sleep(15);
  pthread_mutex_lock(&scap_tasks->mx);
  task = scap_tasks->tasks;
  while ( task != NULL )
  {
    pthread_mutex_lock(&task->mx);
    if ( task->finished != 0 )
    {
	char * qpath;
	void * unused;
	struct scap_task * next;

	/* Cleanup task */
	pthread_join(task->thread, &unused);
 	qpath = rscap_mk_path(RSCAP_REMEDY_RESULTS_DIR, task->dir, NULL);
	if ( rscap_rename_dir(task->path, qpath) < 0 )
 	{
   	 rscap_log("Could not rename %s to %s -- %s\n", task->path, qpath, rscap_strerror());
   	 rscap_recursive_rmdir(task->path);
	}
   	if ( rscap_chown_dir(qpath, user, group) < 0 )
   	{
   	 rscap_log("Could not chown %s to %s:%s - %s\n", qpath, user, group, rscap_strerror());
   	 rscap_recursive_rmdir(qpath);
	}
	rscap_free(task->path);
	rscap_free(task->dir);
	if ( prev != NULL ) prev->next = task->next;
	else scap_tasks->tasks = task->next;
	pthread_mutex_unlock(&task->mx);
	pthread_mutex_destroy(&task->mx);
	next = task->next;
	rscap_free(task);
	task = next;
    }
    else {
	pthread_mutex_unlock(&task->mx);
	task = task->next;
	}
  }
  pthread_mutex_unlock(&scap_tasks->mx);
 }  
 return NULL;
}

void scapremedy_job_cleaner(struct rscap_hash * cfg)
{
 pthread_t thr;
 void * arg = (void*)cfg;

 pthread_create(&thr, NULL, _scapremedy_job_cleaner, arg);
 pthread_detach(thr);
}

int scapremedy_job_count()
{
  struct scap_task * task;
  int cnt = 0;
  pthread_mutex_lock(&scap_tasks->mx);
  task = scap_tasks->tasks;
  while (task != NULL)
  {
   cnt ++;
   task = task->next;
  }
  pthread_mutex_unlock(&scap_tasks->mx);
  return cnt;
}


int scapremedy_process_entry(struct rscap_signature_cfg * sig_cfg, const char * directory, const char * path)
{
 char * qpath = NULL;
 char * rpath = NULL;
 char * entry = NULL;
 struct scap_task * task;

 if ( directory == NULL || path == NULL ) return -1;

 rscap_log("Received new job -- %s\n", path);


 /* Rename the entry */
 qpath = rscap_mk_path(directory, path, NULL);
 rpath = rscap_mk_path(RSCAP_REMEDY_RUNNING_DIR, path, NULL);

 if ( rscap_rename_dir(qpath, rpath) < 0 ) 
 {
  rscap_log("Could not rename %s to %s -- %s\n", qpath, rpath, rscap_strerror());
  goto err;
 }

 entry = rscap_mk_path(RSCAP_REMEDY_RUNNING_DIR, path, "remediation.tgz", NULL);
 if ( rscap_file_readable(entry) ) 
 {
  rscap_log("%s is an invalid remediation job (%s does not exist) -- deleting it", path, entry);
  rscap_recursive_rmdir(rpath);
  goto err;
 }

 rscap_free(entry);
 entry = NULL;

 task = scap_task_new(rpath, path);
 task->sig_cfg = sig_cfg;

 /* Exec the task */
 scapremedy_exec_script(task);
 
 if ( qpath != NULL ) rscap_free(qpath);
 if ( rpath != NULL ) rscap_free(rpath);
 return 0;

err:
 if ( qpath != NULL ) rscap_free(qpath);
 if ( rpath != NULL ) rscap_free(rpath);
 if ( entry != NULL ) rscap_free(entry);
 return -1;
}

