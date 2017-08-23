#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>

#include <hybris/common/binding.h>

HYBRIS_LIBRARY_INITIALIZE(libvoip, "libVOIP_ENGINE_API.so");

typedef struct pj_str
{
  /** Buffer pointer, which is by convention NOT null terminated. */
  char       *ptr;

  /** The length of the string. */
  size_t  slen;
} pj_str_t;



typedef struct pjsip_cred_info_struct
{
  pj_str_t    realm;/**< Realm. Use "*" to make a credential that
		            can be used to authenticate against any
			    challenges.    */
  pj_str_t scheme;/**< Scheme (e.g. "digest").    */
  pj_str_t username;/**< User name.    */
  int     unk;
  int data_type;/**< Type of data (0 for plaintext passwd). */
  pj_str_t data;/**< The data, which can be a plaintext 
		  password or a hashed digest.    */
} pjsip_cred_info;


HYBRIS_IMPLEMENT_VOID_FUNCTION9(libvoip, pjsip_auth_create_digest, pj_str_t *, pj_str_t *, pj_str_t *, pj_str_t *, pj_str_t *, pj_str_t *, pj_str_t *, pjsip_cred_info *, pj_str_t *);



const char *nonce = "00000000000000000000000000000000";
const char *nc = "00000001";
const char *cnonce = "00000000000000000000000000000000";

const char *qop = "auth";
const char *method = "REGISTER";
const char *uri = "sip:orange-multimedia.fr";
const char *realm = "orange-multimedia.fr";
const char *username = "doe@orange-multimedia.fr";

void set_str(pj_str_t *to, const char *string, size_t size)
{
	to->ptr = (char *)string;
	to->slen = size;
}

void hex2str(unsigned char *dest, const unsigned char *src, int src_length)
{
  int i;
  for(i = 0; i < src_length; i++) {
    sprintf((char *)(dest+i*2), "%02x", src[i]);
  }
  dest[i*2] = 0;
}

int main()
{
	pj_str_t result, pnonce, pnc, pcnonce, pqop, puri, prealm, pmethod;
	int i;
	int ch;
	printf("starting!\n");
	pjsip_cred_info cred;
	cred.realm.ptr = (char *)"orange-multimedia.fr";	
	cred.realm.slen = strlen("orange-multimedia.fr") ;
	cred.scheme.ptr = (char *)"Digest";
	cred.scheme.slen = strlen("Digest");
	cred.username.ptr = (char *)"blabla@orange-multimedia.fr";
	cred.username.slen = strlen("doe@orange-multimedia.fr");
	cred.data.ptr = (char *)"1234567890123456789012345678901234567890abcdefabcdefabcdefabdefabcdefabcdefabcdefabcdefabcdefabc";
	cred.data.slen = strlen("1234567890123456789012345678901234567890abcdefabcdefabcdefabdefabcdefabcdefabcdefabcdefabcdefabc");
	cred.unk = 1;
	cred.data_type = 2; /* PJSIP_CRED_DATA_DIGEST */
	result.ptr = (char *)malloc(33);
	result.slen = 33;
	set_str(&pnonce, nonce,strlen(nonce));
	set_str(&pnc, nc, strlen(nc));
	set_str(&pcnonce, cnonce,strlen(cnonce));
	set_str(&pqop, qop, strlen(qop));
	set_str(&puri, uri, strlen(uri));
	set_str(&prealm, realm, strlen(realm));
	set_str(&pmethod, method, strlen(method));


	printf("calling\n");
	pjsip_auth_create_digest(&result, &pnonce, &pnc, &pcnonce, &pqop, &puri, &prealm, &cred, &pmethod);
	printf("done!\n");
	char final[33];
	memcpy(final, result.ptr, 32);
	final[32] = 0;
	printf("\ndigest final:%s\n", final);
	
	return 0;
}
