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


struct rscap_signature_cfg {
	void * m_store;	
        struct rscap_hash * authorized_signers;
	STACK_OF(X509) * chain;

	int do_sign;
	const char * signing_cert;
	const char * signing_key;
};

struct rscap_signature_cfg *  rscap_signature_init(struct rscap_hash * config);
int rscap_check_signature(const char * tmpdir, const char * fname);
struct rscap_hash * rscap_load_signatures(struct rscap_signature_cfg * cfg, const char * tmpdir, const char * fname);
char * rscap_buffer_sign(const char * cert, const char * key, const char * buffer, size_t buffer_size );
int rscap_verify_signed_message(struct rscap_signature_cfg * cfg, const char * message, struct rscap_signature_cfg * sigcfg);

char * rscap_full_dname(void * cert, char * fullName, size_t fullName_sz);
int rscap_xml_sign(const char * cert, const char * key, const char * xml_path);
