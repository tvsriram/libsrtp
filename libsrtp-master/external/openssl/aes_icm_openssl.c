#include "aes_icm_openssl.h"
#include "alloc.h"

extern cipher_type_t aes_icm_openssl;

debug_module_t mod_aes_icm_openssl = {
  0,                         /* debugging is off by default */
  "aes icm openssl"          /* printable module name       */
};

err_status_t
openssl_aes_icm_alloc(cipher_t **c, int key_len, int forIsmacryp) {
  uint8_t *pointer;
  int tmp;

  debug_print(mod_aes_icm_openssl,
              "allocating cipher with key length %d", key_len);

  if (!(forIsmacryp && key_len > 16 && key_len < 30) &&
      key_len != 30 && key_len != 38 && key_len != 46)
    return err_status_bad_param;

  /* allocate memory a cipher of type aes_icm */
  tmp = (sizeof(openssl_aes_icm_ctx_t) + sizeof(cipher_t));
  pointer = (uint8_t*)crypto_alloc(tmp);
  if (pointer == NULL)
    return err_status_alloc_fail;

  /* set pointers */
  *c = (cipher_t *)pointer;
  (*c)->type = &aes_icm_openssl;
  (*c)->state = pointer + sizeof(cipher_t);

  /* increment ref_count */
  aes_icm_openssl.ref_count++;

  /* set key size        */
  (*c)->key_len = key_len;

  return err_status_ok;
}

err_status_t
openssl_aes_icm_dealloc(cipher_t *c) {

  /* zeroize entire state*/
  octet_string_set_to_zero(
    (uint8_t *)c, sizeof(openssl_aes_icm_ctx_t) + sizeof(cipher_t));

  /* free memory */
  crypto_free(c);

  /* decrement ref_count */
  aes_icm_openssl.ref_count--;

  return err_status_ok;
}


/*
 * openssl_aes_icm_context_init(...) initializes the openssl_aes_icm_context
 * using the value in key[].
 *
 * the key is the secret key
 *
 * the salt is unpredictable (but not necessarily secret) data which
 * randomizes the starting point in the keystream
 */

err_status_t
openssl_aes_icm_context_init(openssl_aes_icm_ctx_t *c,const uint8_t *key,
                             int key_len) {
  int base_key_len;

  if (key_len > 16 && key_len < 30) /* Ismacryp */
    base_key_len = 16;
  else if (key_len == 30 || key_len == 38 || key_len == 46)
    base_key_len = key_len - 14;
  else
    return err_status_bad_param;

  if (AES_set_encrypt_key(key, base_key_len * 8, &c->key) < 0) {
    return err_status_fail;
  }
  memset(c->offset, 0, AES_BLOCK_SIZE);
  memset(c->iv, 0, AES_BLOCK_SIZE);
  memset(c->ucount, 0, AES_BLOCK_SIZE);
  c->num = 0;
  /* This assumes the salt is at key + 16, and for 14 octets*/
  memcpy(c->iv, key + base_key_len, AES_BLOCK_SIZE - 2);
  memcpy(c->offset, key + base_key_len, AES_BLOCK_SIZE - 2);
  return err_status_ok;
}

/*
 * openssl_aes_icm_set_iv(c, iv) sets the counter value to the exor of iv with
 * the offset
 */

err_status_t
openssl_aes_icm_set_iv(openssl_aes_icm_ctx_t *c, void *iv) {
  v128_t *nonce = (v128_t *) iv;

  debug_print(mod_aes_icm_openssl,
      "setting iv: %s", v128_hex_string(nonce));

  v128_xor((v128_t*) &c->iv, (v128_t*) &c->offset, nonce);
  c->num = 0;

  return err_status_ok;
}

/*
 * aes ctr mode encrypt and decrypt.
 */
err_status_t
openssl_aes_icm_encrypt(openssl_aes_icm_ctx_t *c,
                        unsigned char *buf, unsigned int *enc_len) {
  // Openssl doesnt have an inplace AES encrypt.
  // This has the chance to fragment memory if used with
  // multiple sizes. We do expect that the packets will be
  // uniformly sized buckets when we protect them with srtp/srtcp.
  unsigned char* old_buf = (uint8_t*)crypto_alloc(*enc_len);
  memcpy(old_buf, buf, *enc_len);
  AES_ctr128_encrypt(old_buf, buf, *enc_len,
                     &c->key, c->iv, c->ucount, &c->num);
  crypto_free(old_buf);
  return err_status_ok;
}

err_status_t
openssl_aes_icm_output(openssl_aes_icm_ctx_t *c, uint8_t *buffer,
                       int num_octets_to_output) {
  unsigned int len = num_octets_to_output;

  /* zeroize the buffer */
  octet_string_set_to_zero(buffer, num_octets_to_output);

  /* exor keystream into buffer */
  return openssl_aes_icm_encrypt(c, buffer, &len);
}

char
openssl_aes_icm_description[] = "aes integer counter mode openssl";

uint8_t openssl_aes_icm_test_case_0_key[30] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
};

uint8_t openssl_aes_icm_test_case_0_nonce[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t openssl_aes_icm_test_case_0_plaintext[32] =  {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

uint8_t openssl_aes_icm_test_case_0_ciphertext[32] = {
  0xe0, 0x3e, 0xad, 0x09, 0x35, 0xc9, 0x5e, 0x80,
  0xe1, 0x66, 0xb1, 0x6d, 0xd9, 0x2b, 0x4e, 0xb4,
  0xd2, 0x35, 0x13, 0x16, 0x2b, 0x02, 0xd0, 0xf7,
  0x2a, 0x43, 0xa2, 0xfe, 0x4a, 0x5f, 0x97, 0xab
};

cipher_test_case_t openssl_aes_icm_test_case_0 = {
  30,                                    /* octets in key            */
  openssl_aes_icm_test_case_0_key,       /* key                      */
  openssl_aes_icm_test_case_0_nonce,     /* packet index             */
  32,                                    /* octets in plaintext      */
  openssl_aes_icm_test_case_0_plaintext, /* plaintext                */
  32,                                    /* octets in ciphertext     */
  openssl_aes_icm_test_case_0_ciphertext,/* ciphertext               */
  NULL                                   /* pointer to next testcase */
};

uint8_t openssl_aes_icm_test_case_1_key[46] = {
  0x57, 0xf8, 0x2f, 0xe3, 0x61, 0x3f, 0xd1, 0x70,
  0xa8, 0x5e, 0xc9, 0x3c, 0x40, 0xb1, 0xf0, 0x92,
  0x2e, 0xc4, 0xcb, 0x0d, 0xc0, 0x25, 0xb5, 0x82,
  0x72, 0x14, 0x7c, 0xc4, 0x38, 0x94, 0x4a, 0x98,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
};

uint8_t openssl_aes_icm_test_case_1_nonce[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t openssl_aes_icm_test_case_1_plaintext[32] =  {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};

uint8_t openssl_aes_icm_test_case_1_ciphertext[32] = {
  0x92, 0xbd, 0xd2, 0x8a, 0x93, 0xc3, 0xf5, 0x25,
  0x11, 0xc6, 0x77, 0xd0, 0x8b, 0x55, 0x15, 0xa4,
  0x9d, 0xa7, 0x1b, 0x23, 0x78, 0xa8, 0x54, 0xf6,
  0x70, 0x50, 0x75, 0x6d, 0xed, 0x16, 0x5b, 0xac
};

cipher_test_case_t openssl_aes_icm_test_case_1 = {
  46,                                    /* octets in key            */
  openssl_aes_icm_test_case_1_key,               /* key                      */
  openssl_aes_icm_test_case_1_nonce,             /* packet index             */
  32,                                    /* octets in plaintext      */
  openssl_aes_icm_test_case_1_plaintext,         /* plaintext                */
  32,                                    /* octets in ciphertext     */
  openssl_aes_icm_test_case_1_ciphertext,        /* ciphertext               */
  &openssl_aes_icm_test_case_0                   /* pointer to next testcase */
};

cipher_type_t aes_icm_openssl = {
  (cipher_alloc_func_t)          openssl_aes_icm_alloc,
  (cipher_dealloc_func_t)        openssl_aes_icm_dealloc,
  (cipher_init_func_t)           openssl_aes_icm_context_init,
  (cipher_encrypt_func_t)        openssl_aes_icm_encrypt,
  (cipher_decrypt_func_t)        openssl_aes_icm_encrypt,
  (cipher_set_iv_func_t)         openssl_aes_icm_set_iv,
  (char *)                       openssl_aes_icm_description,
  (int)                          0,   /* instance count */
  (cipher_test_case_t *)         &openssl_aes_icm_test_case_1,
  (debug_module_t *)             &mod_aes_icm_openssl,
  (cipher_type_id_t)             AES_ICM
};

