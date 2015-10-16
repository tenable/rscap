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

#define BEGIN_CERT "-----BEGIN CERTIFICATE-----"
#define END_CERT   "-----END CERTIFICATE-----"
#define BEGIN_SIG  "-----BEGIN SIGNATURE-----"
#define END_SIG    "-----END SIGNATURE-----"
#define BEGIN_MSG  "-----BEGIN MESSAGE-----"
#define END_MSG    "-----END MESSAGE-----"


char * rscap_full_dname(void * certificate, char * fullName, size_t fullName_sz)
{
 X509 * cert = (X509*)certificate;
 char cn[1024];

 fullName[0]  = '\0';

 if ( X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_countryName, cn, sizeof(cn)) >= 0 ) 
 {
 strlcat(fullName, "C=", fullName_sz);
 strlcat(fullName, cn, fullName_sz);
 }

 if ( X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_localityName, cn, sizeof(cn)) >= 0 ) 
 {
 if ( fullName[0] != '\0' ) strlcat(fullName, ", ", fullName_sz);
 strlcat(fullName, "L=", fullName_sz);
 strlcat(fullName, cn, fullName_sz);
 }

 if ( X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_stateOrProvinceName, cn, sizeof(cn)) >= 0 ) 
 {
 if ( fullName[0] != '\0' ) strlcat(fullName, ", ", fullName_sz);
 strlcat(fullName, "S=", fullName_sz);
 strlcat(fullName, cn, fullName_sz);
 }


 if ( X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_organizationName, cn, sizeof(cn)) >= 0 ) 
 {
 if ( fullName[0] != '\0' ) strlcat(fullName, ", ", fullName_sz);
 strlcat(fullName, "O=", fullName_sz);
 strlcat(fullName, cn, fullName_sz);
 }

 if ( X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_organizationalUnitName, cn, sizeof(cn)) >= 0 ) 
 { 
 if ( fullName[0] != '\0' ) strlcat(fullName, ", ", fullName_sz);
 strlcat(fullName, "OU=", fullName_sz);
 strlcat(fullName, cn, fullName_sz);
 }

 if ( X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof(cn)) >= 0 ) 
 {
 if ( fullName[0] != '\0' ) strlcat(fullName, ", ", fullName_sz);
 strlcat(fullName, "CN=", fullName_sz);
 strlcat(fullName, cn, fullName_sz);
 }

 return fullName[0] == '\0' ? NULL : fullName;
}

struct rscap_signature_cfg *  rscap_signature_init(struct rscap_hash * config)
{
 struct rscap_signature_cfg * ret;
 X509_LOOKUP * m_lookup;
 X509_STORE  * m_store;
 const char * ca;
 const char * chain;
 struct rscap_hash * authorized_signers;
 const char * str;

 if ( config == NULL ) return NULL;
 ca = rscap_config_get(config, "SSLCACertificateFile");
 if ( ca == NULL ) return NULL;
 if ( (authorized_signers = rscap_users_load(rscap_config_get(config, "AuthorizedXCCDFSigners"))) == NULL ) return NULL;


 ret = rscap_zalloc(sizeof(*ret));
 ret->authorized_signers = authorized_signers;
 ret->chain = NULL;

 m_store = X509_STORE_new();
 OpenSSL_add_all_algorithms();

 m_lookup = X509_STORE_add_lookup(m_store, X509_LOOKUP_file());
 X509_STORE_load_locations(m_store, ca, NULL);

 chain  = rscap_config_get(config, "SSLCertificateChainFile");

#if (OPENSSL_VERSION_NUMBER < 0x00904000)
#define rscap_PEM_read_bio_X509(b) PEM_read_bio_X509(b, NULL, NULL)
#else
#define rscap_PEM_read_bio_X509(b) PEM_read_bio_X509(b, NULL, NULL, NULL)
#endif

 if ( chain != NULL )
 { 
  BIO *bio;
  X509 *cert;


  if ((bio = BIO_new(BIO_s_file_internal())) == NULL) return NULL;
  if (BIO_read_filename(bio, chain ) > 0) 
  {
   ret->chain = sk_X509_new_null();
   while ((cert = rscap_PEM_read_bio_X509(bio)) != NULL) 
   {
    sk_X509_push(ret->chain, cert); 
   }
#if 0
  BIO_free(bio);
  if ((bio = BIO_new(BIO_s_file_internal())) == NULL) return NULL;
  if (BIO_read_filename(bio, ca) > 0) 
  {
   while ((cert = rscap_PEM_read_bio_X509(bio)) != NULL) 
   {
    sk_X509_push(ret->chain, cert); 
   }
  }
#endif
  }
  BIO_free(bio);
 }

 X509_LOOKUP_load_file(m_lookup, ca, X509_FILETYPE_PEM);
 X509_STORE_add_lookup(m_store,X509_LOOKUP_hash_dir());
 ret->m_store = (void*)m_store;

 str = rscap_config_get(config, "SignArchives");
 if ( str != NULL && strcmp(str, "yes") == 0 )
 { 
  ret->signing_cert = rscap_config_get(config, "SigningSSLCertificateFile");
  ret->signing_key = rscap_config_get(config, "SigningSSLCertificateKeyFile");
  if ( ret->signing_key != NULL && ret->signing_cert != NULL ) ret->do_sign = 1;
   
 }

 
 return ret;
}







static char * extract_item(const char * message, const char * start_label, const char * end_label, int keep)
{
 char * p, *q;
 char * ret;

 p = strstr(message, start_label);
 if ( p == NULL ) goto err;
 if ( keep == 0 )
 {
  p += strlen(start_label);
  while ( p[0] == '\n' || p[0] == '\r' ) p ++;
 }
 q = strstr(p, end_label);
 if ( q == NULL ) goto err;
 if ( keep == 0 )
 {
  q --;
 // while ( q[0] == '\n' || q[0] == '\r' ) q --;
 }
 else q += strlen(end_label) - 1;

 if ( q < p ) goto err;
 ret = rscap_zalloc( (q - p) + 2);
 memcpy(ret, p, (q - p) + 1);
 ret[q - p + 1] = '\0';
 return ret;
err:
 return NULL;
}




struct rscap_hash * rscap_load_signatures(struct rscap_signature_cfg * cfg, const char * tmpdir, const char * fname)
{
 char *path;
 char * sigbuf = NULL;
 size_t sigbuf_sz = 0;
 char *b = NULL, * p, * q, *s;
 struct rscap_hash * ret = NULL; 
 int e;

 path = rscap_mk_path( tmpdir, fname, NULL);
 e = rscap_tar_get_file(path, "+SIGNATURE", &sigbuf, &sigbuf_sz);
 rscap_free(path);
 if ( e < 0 || sigbuf == NULL ) return NULL;
 
 if ( rscap_verify_signed_message(cfg, sigbuf, NULL) != 0 ) 
 {
  rscap_log("Invalid signature in %s/%s", tmpdir, fname);
  return NULL;
 }
 

 b = p = extract_item(sigbuf, BEGIN_MSG, END_MSG, 0);
 if ( p == NULL ) return NULL;
 q = strchr(p, '\n');
 if ( q == NULL ) goto err;
 ret = rscap_hash_init(0);
 while ( q != NULL )
 {
  q[0] = '\0';
  s = strchr(p, ':'); 
  if ( s == NULL ) goto err;
  s[0] = '\0';
  s ++;
  rscap_hash_add_value(ret, p, s);
  p = q + 1;
  if ( p[0] == '\0' ) break;
  q = strchr(p, '\n');
  if ( q == NULL ) goto err;
 } 
 

 rscap_free(b);
 rscap_free(sigbuf);
 return ret;
 

err:
 if ( b != NULL ) rscap_free(b);
 if ( sigbuf != NULL ) rscap_free(sigbuf);
 if ( ret != NULL ) rscap_hash_free(ret);
 return NULL;
}

static char * _rscap_buffer_sign(const char * cert, const char * key, const char * buffer, size_t buffer_size, int xml )
{
  RSA * rsa;
  FILE * fp;
  unsigned int len;
  unsigned char * result = NULL;
  unsigned char md[SHA_DIGEST_LENGTH+1];
  struct rscap_string str;
  char * tmp;
  size_t tmp_sz;
  int i;
  char * b64_buf;
  size_t b64_sz;
  const char * p;

  if ( xml )
  {
  p = strstr(buffer, "?>");
  if ( p != NULL ) { p += 2; while (*p == '\n' || *p == '\r' ) p++; }
  else p = buffer;

   buffer = p;
   buffer_size = strlen(buffer);
  }

  fp = fopen(key, "r"); 
  if ( fp == NULL ) return NULL;

  rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  if ( rsa == NULL ) return NULL;
  len = RSA_size(rsa);
  result = rscap_zalloc(len);

  SHA1((unsigned char*)buffer, buffer_size, md);

  RSA_sign(NID_sha1, md, SHA_DIGEST_LENGTH, result, &len, rsa);
  RSA_free(rsa);

  rscap_string_init(&str);
  rscap_read_file_contents(cert, &tmp, &tmp_sz);
  if ( xml )
  {
   int n;
   int f;

   rscap_string_cat(&str, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
   rscap_string_cat(&str, "<Root xmlns=\"urn:envelope\">\n");
   rscap_string_cat(&str, "<Value>");
   rscap_string_cat(&str, buffer);
   rscap_string_cat(&str, "</Value>\n");
   rscap_string_cat(&str, "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n");
   rscap_string_cat(&str, "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n");
   rscap_string_cat(&str, "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n");
   rscap_string_cat(&str, "<ds:Reference>");
   rscap_string_cat(&str, "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></ds:Transforms>\n");
   rscap_string_cat(&str, "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n");
   rscap_string_cat(&str, "<ds:DigestValue>");
   b64_sz = SHA_DIGEST_LENGTH * 4;
   b64_buf = rscap_alloc(b64_sz + 1);
   rscap_base64_encode((const char*)md, SHA_DIGEST_LENGTH, b64_buf, b64_sz);
   rscap_string_cat(&str, b64_buf);
   rscap_free(b64_buf);
   rscap_string_cat(&str, "</ds:DigestValue>\n");
   rscap_string_cat(&str, "</ds:Reference>\n");
   rscap_string_cat(&str, "</ds:SignedInfo>\n");
   rscap_string_cat(&str, "<ds:SignatureValue>");
   b64_sz = len * 4;
   b64_buf    = rscap_alloc(b64_sz + 1);
   rscap_base64_encode((const char*)result, len, b64_buf, b64_sz);
   rscap_string_cat(&str, b64_buf);
   rscap_free(b64_buf);
   rscap_string_cat(&str, "</ds:SignatureValue>\n");
   rscap_string_cat(&str, "<ds:KeyInfo>\n");
   rscap_string_cat(&str, "<ds:X509Data>\n");
   rscap_string_cat(&str, "<ds:X509Certificate>");
   for ( i = 0, f = 0, n = strlen(tmp) ; i < n ; i ++ )
   {
     if ( tmp[i] == '\n' && f == 0 ) f = 1;
     if ( tmp[i] == '\n' || tmp[i] == '\r' ) continue;
     if ( i > 0 && tmp[i - 1] == '\n' && tmp[i] == '-' && tmp[i+1] == '-' ) break;
     if ( f ) rscap_string_ncat(&str, tmp + i, 1);
   }
   rscap_string_cat(&str, "</ds:X509Certificate>");
   rscap_string_cat(&str, "</ds:X509Data>\n");
   rscap_string_cat(&str, "</ds:KeyInfo>\n");
   rscap_string_cat(&str, "</ds:Signature>\n");
   rscap_string_cat(&str, "</Root>\n");
  }
  else
  {
  rscap_string_cat(&str, tmp);
  rscap_string_cat(&str, BEGIN_MSG);
  rscap_string_cat(&str, "\n");
  rscap_string_cat(&str, buffer);
  rscap_string_cat(&str, END_MSG);
  rscap_string_cat(&str, "\n");
    
  rscap_string_cat(&str, BEGIN_SIG);
  rscap_string_cat(&str, "\n");




   for ( i = 0 ; i < len ; i ++ )
   {
    char tmp[3];
    snprintf(tmp, sizeof(tmp), "%.2x", result[i]); 
    rscap_string_cat(&str, tmp);
   }
  
   rscap_string_cat(&str, "\n");
   rscap_string_cat(&str, END_SIG);
   rscap_string_cat(&str, "\n");
  }

  if ( result != NULL ) rscap_free(result);
  rscap_free(tmp);
  return rscap_string_cstring(&str);
}

char * rscap_buffer_sign(const char * cert, const char * key, const char * buffer, size_t buffer_size)
{
 return _rscap_buffer_sign(cert, key, buffer, buffer_size, 0);
}

int rscap_xml_sign(const char * cert, const char * key, const char * xml_path)
{
 char * xml1 = NULL, *xml2 = NULL;
 size_t xml1_sz;
 int ret = -1;

 rscap_read_file_contents(xml_path, &xml1, &xml1_sz);
 if ( xml1 != NULL )
 { 
   xml2 = _rscap_buffer_sign(cert, key, xml1, xml1_sz, 1);
   if ( xml2 ) 
   {
    rscap_write_file_contents(xml_path, xml2, strlen(xml2));
    rscap_free(xml2);
    ret = 0;
   }
  rscap_free(xml1);
 }
 return ret;
}



static int recognized_certificate(struct rscap_signature_cfg * cfg, X509 * x509)
{
 X509_STORE_CTX * store_ctx;
 X509_STORE * m_store;
 char fullName[1024];

 if ( cfg == NULL ) return -1;
 if ( cfg->authorized_signers == NULL ) return -1;
 if ( x509 == NULL ) return -1;

 m_store = (X509_STORE*)cfg->m_store;
 if ( m_store == NULL ) return -1;

 store_ctx = X509_STORE_CTX_new();
 if ( store_ctx == NULL ) return -1;

 X509_STORE_CTX_init(store_ctx, m_store, x509, cfg->chain);
 X509_STORE_CTX_set_flags(store_ctx, 0x4000);
 if ( rscap_full_dname((void*)x509, fullName, sizeof(fullName)) == NULL ) 
 {
  X509_STORE_CTX_free(store_ctx);
  return -1;
 }

 if ( X509_verify_cert(store_ctx) != 1 )
 {
  X509_STORE_CTX_free(store_ctx);
  return -1;
 }

 X509_STORE_CTX_free(store_ctx);
 if ( rscap_full_dname((void*)x509, fullName, sizeof(fullName)) == NULL ) return -1;
 if ( rscap_hash_get_value(cfg->authorized_signers, fullName) == NULL ) return -1;

 

 return 0;

}


int rscap_verify_signed_message(struct rscap_signature_cfg * cfg, const char * message, struct rscap_signature_cfg * sigcfg)
{
 RSA * rsa = NULL;
 BIO *bufio = NULL;
 X509 * x509 = NULL;
 EVP_PKEY * pkey = NULL;
 unsigned char md[SHA_DIGEST_LENGTH+1];
 unsigned char bin_sig[8192];
 int bin_sz = 0;
 int i;
 int res = -1;
 char * cert, * msg, * sig;
 

 cert = msg = sig = NULL;

 cert = extract_item(message, BEGIN_CERT, END_CERT, 1);
 sig = extract_item(message, BEGIN_SIG, END_SIG, 0);
 msg = extract_item(message, BEGIN_MSG, END_MSG, 0);
 if ( cert == NULL || sig == NULL || msg == NULL ) goto ret;
 while ( sig[0] != '\0' && sig[strlen(sig) - 1] == '\n' )  sig[strlen(sig) - 1] = '\0';
 
 
 bufio = BIO_new_mem_buf((void*)cert, strlen(cert));
 if ( bufio == NULL ) goto ret;
 x509 = NULL;
 if ( PEM_read_bio_X509(bufio, &x509, 0, NULL) == NULL ) goto ret;
 if ( recognized_certificate(cfg, x509) != 0 ) goto ret;
 pkey = X509_get_pubkey(x509);
 if ( pkey == NULL) goto ret;
 rsa = EVP_PKEY_get1_RSA(pkey);
 
 BIO_free(bufio);
 bufio = NULL;

 SHA1((unsigned char*)msg, strlen(msg), md);

 for ( i = 0 ; i < strlen(sig) ; i += 2 )
 {
  char t[3];
  strlcpy(t, sig + i, sizeof(t));
  bin_sig[bin_sz] = (unsigned char)strtoul(t, NULL, 16);
  bin_sz ++;
  if ( bin_sz >= sizeof(bin_sig) ) goto ret;
 }

 res = RSA_verify(NID_sha1, md, SHA_DIGEST_LENGTH, bin_sig, bin_sz, rsa);
 RSA_free(rsa);

ret:
 if ( cert != NULL ) rscap_free(cert);
 if ( msg != NULL ) rscap_free(msg);
 if ( sig != NULL ) rscap_free(sig);
 if ( rsa != NULL ) RSA_free(rsa);
 if ( x509 != NULL ) X509_free(x509);

 
 if ( res == 1 ) return 0;
 else return -1;
}



