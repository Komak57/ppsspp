#include "Common/Net/HTTPS.h"
#include "Common/Log.h"

int HTTPS::InitializeSSL(std::string certPEM) {
	WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::InitializeSSL()");
	this->useAuth = useAuth;

	wolfSSL_Debugging_ON();  // Optional: turn off for release
#ifdef DEBUG
	wolfSSL_SetLoggingCb(wolfssl_debug);
#endif
	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		ERROR_LOG(Log::sceNet, "wolfSSL_Init failed");
		return -1;
	}

	tls.ctx = wolfSSL_CTX_new(wolfTLS_client_method());
	if (!tls.ctx) {
		ERROR_LOG(Log::sceNet, "wolfSSL_CTX_new failed");
		return -1;
	}

	// Force specific ciphers in the handshake process
	//const char* cipher_list = "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256";
	//wolfSSL_CTX_set_cipher_list(ctx_, cipher_list);

	// Optional: TLS version range
	wolfSSL_CTX_SetMinVersion(tls.ctx, WOLFSSL_TLSV1);

	if (useAuth)
		wolfSSL_CTX_set_verify(tls.ctx, SSL_VERIFY_PEER, NULL);
	else
		wolfSSL_CTX_set_verify(tls.ctx, SSL_VERIFY_NONE, NULL);

	int ret;
	if (!certPEM.empty()) {
		ret = wolfSSL_CTX_load_verify_buffer(tls.ctx, (const unsigned char*)certPEM.c_str(), (long)certPEM.length(), SSL_FILETYPE_PEM);
		if (ret != WOLFSSL_SUCCESS) {
			ERROR_LOG(Log::sceNet, "Failed to load PEM certificate");
			return ret;
		}
	}
	else {
		/*ret = LoadStoreCert();
		if (ret < 0)
			return ret;*/
	}

	tls.ssl = wolfSSL_new(tls.ctx);
	if (!tls.ssl) {
		ERROR_LOG(Log::sceNet, "Could not generate SSL from Context");
		return -1;
	}

	tls.enabled = true;
	return 0;
}

void HTTPS::ResetSSL() {
	tls.enabled = false;
}
