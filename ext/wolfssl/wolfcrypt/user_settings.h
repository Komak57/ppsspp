#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* Tell wolfSSL to use this file instead of options.h */
#define WOLFSSL_USER_SETTINGS

/* X.509 and cert handling */
#define WOLFSSL_CERTS
//#define WOLFSSL_X509

/* For OpenSSL-like APIs (wolfSSL_get_verify_result, etc.) */
#define OPENSSL_EXTRA

/* Debugging (optional) */
#define WOLFSSL_DEBUG

/* Don’t disable MD5/SHA — required for TLS < 1.2 */
/* So: no #define NO_MD5, no #define NO_SHA */

#endif /* USER_SETTINGS_H */
