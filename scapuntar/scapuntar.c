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
#include <openssl/ssl.h>



int main(int argc, char ** argv)
{
 struct rscap_hash * cfg;
 struct rscap_hash * sigs;
 struct rscap_signature_cfg * sig_cfg;
 int e;


 cfg = rscap_config_load(RSCAP_CONFIG_FILE);
 if ( cfg == NULL )
 {
  fprintf(stderr, "Could not load the configuration file - %s\n", strerror(errno));
  exit(1);
 }
 
 sig_cfg = rscap_signature_init(cfg);
 if ( sig_cfg == NULL )
 {
  fprintf(stderr, "Could not load the signature verification context\n"); 
  exit(1);
 }


 
 rscap_add_log_fp(stderr);
 if ( argc < 2 )
 {
  fprintf(stderr, "Usage: %s <archive>\n", argv[0]);
  exit(1);
 }

 sigs = rscap_load_signatures(sig_cfg, "./", argv[1]);
 if ( sigs == NULL )
 {
  fprintf(stderr, "Could not verify the signature of the archive\n"); 
  exit(1);
 }

 e = rscap_untar(argv[1], ".",  sigs, 1);
 if ( e != 0 ) 
 {
  fprintf(stderr, "Invalid or mis-signed tar archive\n");
  exit(1);
 }

 e = rscap_untar(argv[1], ".",  sigs, 0);
 if ( e != 0 )
 {
  fprintf(stderr, "Failed to untar the archive\n");
  exit(1);
 }
 printf("Success\n");

 return 0;

}
