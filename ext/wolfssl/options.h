/* options.h.in
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


/* default blank options for autoconf */

#ifdef WOLFSSL_NO_OPTIONS_H
/* options.h inhibited by configuration */
#elif !defined(WOLFSSL_OPTIONS_H)
#define WOLFSSL_OPTIONS_H


/* Enable legacy TLS */
#define WOLFSSL_OLD_TLS
#define WOLFSSL_ALLOW_SSLV3
#define WOLFSSL_ALLOW_OLD_VERSIONS
#define WC_NO_HARDEN
#define WOLFSSL_ENCRYPT_THEN_MAC

/* Enable DES3 cipher support */
#define WOLFSSL_DES3

/* Enable other features as needed */
#define HAVE_AESGCM
#define WOLFSSL_TLS13
#define WC_RSA_PSS
#define WOLFSSL_RC4
#define HAVE_ARC4
#define HAVE_MD5   


#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif


#endif /* WOLFSSL_OPTIONS_H */
