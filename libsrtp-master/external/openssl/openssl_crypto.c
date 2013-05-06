#include "config.h"
#include "crypto_kernel.h"

err_status_t
openssl_crypto_init() {
#if SRTP_OPENSSL
  extern auth_type_t hmac_openssl;
  extern cipher_type_t aes_icm_openssl;
  err_status_t status = crypto_kernel_replace_auth_type(
      &hmac_openssl, HMAC_SHA1);
  if (status) {
    printf("error replacing auth %d\n", status);
    return status;
  }
  
  status = crypto_kernel_replace_cipher_type(&aes_icm_openssl, AES_ICM);             
  if (status) {
    printf("error replacing cipher type %d\n", status);
  }
  return status;
#else
  return -1;
#endif
}
