#include "alloc.h"
#include "auth.h"
#include "openssl/hmac.h"
/* the debug module for authentiation */

debug_module_t mod_hmac_openssl = {
  0,                  /* debugging is off by default */
  "hmac sha-1 openssl"        /* printable name for module   */
};

typedef HMAC_CTX openssl_hmac_ctx_t;

extern auth_type_t hmac_openssl;

err_status_t
openssl_hmac_alloc(auth_t **a, int key_len, int out_len) {
  uint8_t *pointer;

  /*
   * check key length - note that we don't support keys larger
   * than 20 bytes yet
   */
  if (key_len > 20)
    return err_status_bad_param;

  /* check output length - should be less than 20 bytes */
  if (out_len > 20)
    return err_status_bad_param;

  /* allocate memory for auth and hmac_ctx_t structures */
  pointer = (uint8_t*)crypto_alloc(sizeof(openssl_hmac_ctx_t) + sizeof(auth_t));
  if (pointer == NULL)
    return err_status_alloc_fail;

  /* set pointers */
  *a = (auth_t *)pointer;
  (*a)->type = &hmac_openssl;
  (*a)->state = pointer + sizeof(auth_t);  
  (*a)->out_len = out_len;
  (*a)->key_len = key_len;
  (*a)->prefix_len = 0;

  /* increment global count of all hmac uses */
  hmac_openssl.ref_count++;

  return err_status_ok;
}

err_status_t
openssl_hmac_dealloc(auth_t *a) {
  // Cleanup hmac context.
  HMAC_CTX_cleanup((openssl_hmac_ctx_t*) a->state);
  /* zeroize entire state*/
  octet_string_set_to_zero((uint8_t *)a, 
			   sizeof(openssl_hmac_ctx_t) + sizeof(auth_t));

  /* free memory */
  crypto_free(a);
  
  /* decrement global count of all hmac uses */
  hmac_openssl.ref_count--;

  return err_status_ok;
}

err_status_t
openssl_hmac_init(openssl_hmac_ctx_t *state, const uint8_t *key, int key_len) {
  /*
   * check key length - note that we don't support keys larger
   * than 20 bytes yet
   */
  if (key_len > 20)              
    return err_status_bad_param;
  
  HMAC_CTX_init(state);
  HMAC_Init(state, key, key_len, EVP_sha1());

  return err_status_ok;
}

err_status_t
openssl_hmac_start(openssl_hmac_ctx_t *state) {
  // Use NULL key and md, to ensure that we just reuse
  // for better performance.
  HMAC_Init(state, NULL, 0, NULL);
  return err_status_ok;
}

err_status_t
openssl_hmac_update(openssl_hmac_ctx_t *state, const uint8_t *message, int msg_octets) {
  return (HMAC_Update(state, message, msg_octets))
      ? err_status_ok : err_status_fail;
}

err_status_t
openssl_hmac_compute(openssl_hmac_ctx_t *state, const void *message,
	     int msg_octets, int tag_len, uint8_t *result) {
  int i;
  uint8_t new_result[20];
  unsigned int size = sizeof(new_result);

  /* check tag length, return error if we can't provide the value expected */
  if (tag_len > 20)
    return err_status_bad_param;
  
  if (openssl_hmac_update(state, (const uint8_t*)message, msg_octets))
    return err_status_fail;
  
  if (!HMAC_Final(state, new_result, &size))
    return err_status_fail;
  
  for (i=0; i < tag_len; i++)    
    result[i] = ((uint8_t *)new_result)[i];  
  return err_status_ok;
}


/* begin test case 0 */

uint8_t
openssl_hmac_test_case_0_key[20] = {
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 
  0x0b, 0x0b, 0x0b, 0x0b
};

uint8_t 
openssl_hmac_test_case_0_data[8] = {
  0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65   /* "Hi There" */
};

uint8_t
openssl_hmac_test_case_0_tag[20] = {
  0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 
  0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 
  0xf1, 0x46, 0xbe, 0x00
};

auth_test_case_t
openssl_hmac_test_case_0 = {
  20,                                /* octets in key            */
  openssl_hmac_test_case_0_key,      /* key                      */
  8,                                 /* octets in data           */ 
  openssl_hmac_test_case_0_data,     /* data                     */
  20,                                /* octets in tag            */
  openssl_hmac_test_case_0_tag,      /* tag                      */
  NULL                               /* pointer to next testcase */
};

/* end test case 0 */

char openssl_hmac_description[] = "hmac sha-1 authentication function";

/*
 * auth_type_t hmac is the hmac metaobject
 */

auth_type_t
hmac_openssl  = {
  (auth_alloc_func)      openssl_hmac_alloc,
  (auth_dealloc_func)    openssl_hmac_dealloc,
  (auth_init_func)       openssl_hmac_init,
  (auth_compute_func)    openssl_hmac_compute,
  (auth_update_func)     openssl_hmac_update,
  (auth_start_func)      openssl_hmac_start,
  (char *)               openssl_hmac_description,
  (int)                  0,  /* instance count */
  (auth_test_case_t *)  &openssl_hmac_test_case_0,
  (debug_module_t *)    &mod_hmac_openssl,
  HMAC_SHA1
};
