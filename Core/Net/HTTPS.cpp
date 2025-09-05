#include "Core/Net/HTTPS.h"
#include "Common/Log.h"
#include <Core\HLE\HLE.h>

int HTTPS::InitializeSSL(std::string certPEM) {
	WARN_LOG(Log::sceNet, "UNTESTED InitializeSSL()");
	//this->useAuth = useAuth;
	if (tls.enabled)
		return hleLogError(Log::sceNet, -1, "Already Initialized");

	mbedtls_net_init(&tls.netCtx);
	mbedtls_ssl_init(&tls.sslCtx);
	mbedtls_ssl_config_init(&tls.sslConfig);
	mbedtls_ctr_drbg_init(&tls.ctrDrbg);
	mbedtls_entropy_init(&tls.entropy);
	mbedtls_debug_set_threshold(4);

	if (mbedtls_ctr_drbg_seed(&tls.ctrDrbg, mbedtls_entropy_func, &tls.entropy, NULL, 0) != 0) {
		return hleLogError(Log::sceNet, -1, "Failed to seed RNG");
	}

	// MPO Doesn't provide a cert here
	if (certPEM.size() == 0)
		WARN_LOG(Log::sceNet, "InitializeSSL: No cert provided.");
	// Initialize CA certificate store
	// Note: certPEM MUST be pointing to a valid certificate, or it will cause a strlen crash
	// PSP2i has it at 0x08e73a04
	if (certPEM.size() > 0) {
		mbedtls_x509_crt_init(&tls.caCert);
		int ret = mbedtls_x509_crt_parse(&tls.caCert, (const unsigned char*)certPEM.c_str(), certPEM.size() + 1);
		if (ret < 0) {
			return hleLogError(Log::sceNet, -1, "Failed to parse cert: -0x%04x", -ret);
		}
	}

	// Setup SSL config
	if (mbedtls_ssl_config_defaults(&tls.sslConfig,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		return hleLogError(Log::sceNet, -1, "Failed to set SSL config defaults");
	}

	/* OPTIONAL is not optimal for security,
	 * but makes interop easier in this simplified example */
	if (useAuth)
		mbedtls_ssl_conf_authmode(&tls.sslConfig, MBEDTLS_SSL_VERIFY_OPTIONAL);
	else
		mbedtls_ssl_conf_authmode(&tls.sslConfig, MBEDTLS_SSL_VERIFY_NONE);
	if (certPEM.size() > 0)
		mbedtls_ssl_conf_ca_chain(&tls.sslConfig, &tls.caCert, NULL);
	mbedtls_ssl_conf_rng(&tls.sslConfig, mbedtls_ctr_drbg_random, &tls.ctrDrbg);
	mbedtls_ssl_conf_dbg(&tls.sslConfig, ssl_debug, NULL);

	// Check compiled Ciphers
	/*const int* ciphers = mbedtls_ssl_list_ciphersuites();
	int cipherCount = 0;
	for (const int* c = ciphers; *c != 0; ++c)
		++cipherCount;
	INFO_LOG(Log::sceNet, "sceHttpsInit: Parsing %i ciphers", cipherCount);
	for (int i = 0; i < cipherCount; i++) {
		INFO_LOG(Log::sceNet, "sceHttpsInit: ciphers[%i] = 0x%04x = %s", i, ciphers[i], mbedtls_ssl_get_ciphersuite_name(ciphers[i]));
	}*/

	// Enable Legacy Cipher
	//mbedtls_ssl_conf_ciphersuites(&tls.sslConfig, legacy_ciphersuites_array); // optional if you’ve recompiled with weak cipher support
	// Limit to TLS 1.0 - TLS 1.2 to match Hardware Limitations
	mbedtls_ssl_conf_min_version(&tls.sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
	mbedtls_ssl_conf_max_version(&tls.sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);

	tls.enabled = true;
	return 0;
}

void HTTPS::ResetSSL() {
	mbedtls_ssl_session_reset(&tls.sslCtx);
	mbedtls_ssl_config_free(&tls.sslConfig);

	mbedtls_ssl_free(&tls.sslCtx);
	mbedtls_net_free(&tls.netCtx);
	tls.enabled = false;
}
