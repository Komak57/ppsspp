#include "Core/Net/HTTPS.h"
#include "Common/Log.h"
#include "Core/HLE/HLE.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int HTTPS::InitializeSSL(std::string certPEM) {
	WARN_LOG(Log::sceNet, "UNTESTED InitializeSSL()");
	if (tls.enabled)
		return hleLogError(Log::sceNet, -1, "Already Initialized");

	// wolfSSL requires global init once in your program
	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		return hleLogError(Log::sceNet, -1, "wolfSSL_Init failed");
	}

	// Create and initialize CTX (equivalent to mbedtls_ssl_config)
	tls.sslConfig = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!tls.sslConfig) {
		wolfSSL_Cleanup();
		return hleLogError(Log::sceNet, -1, "Failed to create wolfSSL_CTX");
	}

	// Optional: debugging
	wolfSSL_Debugging_ON();

	// RNG (equivalent to mbedtls_ctr_drbg + entropy)
	if (wc_InitRng(&tls.rng) != 0) {
		wolfSSL_CTX_free(tls.sslConfig);
		wolfSSL_Cleanup();
		return hleLogError(Log::sceNet, -1, "Failed to init RNG");
	}

	// Load CA certificate (if provided)
	if (certPEM.size() == 0) {
		WARN_LOG(Log::sceNet, "InitializeSSL: No cert provided.");
	}
	else {
		int ret = wolfSSL_CTX_load_verify_buffer(
			tls.sslConfig,
			reinterpret_cast<const unsigned char*>(certPEM.c_str()),
			static_cast<long>(certPEM.size()),
			WOLFSSL_FILETYPE_PEM
		);
		if (ret != SSL_SUCCESS) {
			wc_FreeRng(&tls.rng);
			wolfSSL_CTX_free(tls.sslConfig);
			wolfSSL_Cleanup();
			return hleLogError(Log::sceNet, -1, "Failed to parse cert: %d", ret);
		}
	}

	// Authentication mode
	if (useAuth) {
		wolfSSL_CTX_set_verify(tls.sslConfig, SSL_VERIFY_PEER, NULL);
	}
	else {
		wolfSSL_CTX_set_verify(tls.sslConfig, SSL_VERIFY_NONE, NULL);
	}

	// Limit TLS version (disable TLS 1.3 on older wolfSSL)
	wolfSSL_CTX_set_options(tls.sslConfig, WOLFSSL_OP_NO_TLSv1_3);

	// Allocate SSL object (per-connection)
	tls.sslCtx = wolfSSL_new(tls.sslConfig);
	if (!tls.sslCtx) {
		// cleanup
		wc_FreeRng(&tls.rng);
		wolfSSL_CTX_free(tls.sslConfig);
		wolfSSL_Cleanup();
		return hleLogError(Log::sceNet, -1, "Failed to create wolfSSL object");
	}

	tls.enabled = true;
	return 0;
}



void HTTPS::ResetSSL() {
	if (tls.sslCtx) {
		wolfSSL_free(tls.sslCtx);
		tls.sslCtx = nullptr;
	}
	if (tls.sslConfig) {
		wolfSSL_CTX_free(tls.sslConfig);
		tls.sslConfig = nullptr;
	}
	if (tls.sockfd >= 0) {
		close(tls.sockfd);  // or ::closesocket() on Windows
		tls.sockfd = -1;
	}
	wc_FreeRng(&tls.rng);  // cleanup RNG

	tls.enabled = false;
}


void HTTPS::ResetSession() {
	if (tls.sslCtx) {
		wolfSSL_free(tls.sslCtx);
		tls.sslCtx = wolfSSL_new(tls.sslConfig);
	}
	tls.enabled = false;
}

