#pragma once
#define WOLFSSL_LIB
//#define WOLFSSL_PERF

#define USE_WOLFSSL_IO
#define HAVE_AESGCM
#define WOLFSSL_TLS13
#define HAVE_HKDF
#define HAVE_FFDHE_4096
#define WC_RSA_PSS
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_SEND_HRR_COOKIE
#define WOLFSSL_DTLS_CID

/* Enables blinding mode, to prevent timing attacks */
#define WC_RSA_BLINDING
#define NO_MULTIBYTE_PRINT

#define HAVE_CRL
#define HAVE_CRL_MONITOR

#if defined(WOLFSSL_LIB)
    /* The lib */
    #define OPENSSL_EXTRA
    #define WOLFSSL_RIPEMD
    #define NO_PSK
    #define HAVE_EXTENDED_MASTER
    #define WOLFSSL_SNIFFER
    #define HAVE_SECURE_RENEGOTIATION

    #define HAVE_AESGCM
    #define WOLFSSL_AESGCM_STREAM
    #define WOLFSSL_SHA384
    #define WOLFSSL_SHA512

	#define HAVE_SNI
    #define HAVE_SUPPORTED_CURVES
    #define HAVE_TLS_EXTENSIONS

    #define HAVE_ECC
    #define ECC_SHAMIR
    #define ECC_TIMING_RESISTANT

    #define WOLFSSL_SP_X86_64
    #define SP_INT_BITS  4096

    /* Optional Performance Speedups */
    #if defined(WOLFSSL_PERF)
        /* AESNI on x64 */
        #ifdef _WIN64
            #define HAVE_INTEL_RDSEED
            #define WOLFSSL_AESNI
            #define HAVE_INTEL_AVX1
            #if 0
                #define HAVE_INTEL_AVX2
            #endif

            #define USE_INTEL_CHACHA_SPEEDUP
            #define USE_INTEL_POLY1305_SPEEDUP
        #endif

        /* Single Precision Support for RSA/DH 1024/2048/3072 and
            * ECC P-256/P-384 */
        #define WOLFSSL_SP
        #define WOLFSSL_HAVE_SP_ECC
        #define WOLFSSL_HAVE_SP_DH
        #define WOLFSSL_HAVE_SP_RSA

        #ifdef _WIN64
            /* Old versions of MASM compiler do not recognize newer
                * instructions. */
            #if 0
                #define NO_AVX2_SUPPORT
                #define NO_MOVBE_SUPPORT
            #endif
            #define WOLFSSL_SP_ASM
            #define WOLFSSL_SP_X86_64_ASM
        #endif
    #endif
#endif
