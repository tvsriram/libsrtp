#ifndef AES_ICM_OPENSSL_H
#define AES_ICM_OPENSSL_H

#include "cipher.h"
#include "openssl/aes.h"

typedef struct {
  AES_KEY  key;                         /* AES key used                */
  unsigned char offset[AES_BLOCK_SIZE]; /* initial offset              */
  unsigned char iv[AES_BLOCK_SIZE];     /* ivec for AES CTR mode       */
  unsigned char ucount[AES_BLOCK_SIZE]; /* the keystream buffer        */
  unsigned int num;                     /* the # used in keystream buf */
} openssl_aes_icm_ctx_t;


err_status_t
openssl_aes_icm_context_init(openssl_aes_icm_ctx_t *c,
                             const unsigned char *key,
                             int key_len);

err_status_t
openssl_aes_icm_set_iv(openssl_aes_icm_ctx_t *c, void *iv);

err_status_t
openssl_aes_icm_encrypt(openssl_aes_icm_ctx_t *c,
                        unsigned char *buf, unsigned int *bytes_to_encr);

err_status_t
openssl_aes_icm_output(openssl_aes_icm_ctx_t *c,
                       unsigned char *buf, int bytes_to_output);

err_status_t
openssl_aes_icm_dealloc(cipher_t *c);

err_status_t
openssl_aes_icm_alloc(cipher_t **c,
                      int key_len,
                      int forIsmacryp);

#endif /* AES_ICM__OPENSSL_H */

