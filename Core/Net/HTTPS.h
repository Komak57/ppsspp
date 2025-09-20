#pragma once
#include <unordered_map>
#include <string>
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include <mbedtls/timing.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

const int legacy_ciphersuites_array[] = {
MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,  // DES-CBC3-SHA
MBEDTLS_TLS_RSA_WITH_RC4_128_SHA,       // RC4-SHA
MBEDTLS_TLS_RSA_WITH_RC4_128_MD5,       // RC4-MD5
0                                       // terminator (required)
};

class HTTPS_Config {
public:
	bool enabled = false;
	mbedtls_ssl_context sslCtx;
	mbedtls_net_context netCtx;

	mbedtls_ssl_config sslConfig;
	mbedtls_ctr_drbg_context ctrDrbg;
	mbedtls_entropy_context entropy;
	mbedtls_x509_crt caCert;
	// For UDP retransmissions
	mbedtls_timing_delay_context timerCtx;
	//mbedtls_ssl_session session;
};

class HTTPS {
public:
	int InitializeSSL(std::string certPEM = "");
	void ResetSSL();

	bool GetOption(int id) {
		auto it = this->httpsOptions.find(id);
		if (it == this->httpsOptions.end())
			return false;
		return it->second;
	}
public:
	HTTPS_Config tls;

	std::unordered_map<int, bool> httpsOptions;

	int useCookie = 0;
	int useKeepAlive = 0;
	int useCache = 0;
	int useAuth = 0;
	int useRedirect = 0;
};
