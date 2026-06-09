#include "Core/Net/HTTPS.h"
#include "Common/Log.h"
#include "Core/HLE/HLE.h"
#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#elif defined(__APPLE__)
#include <Security/Security.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

int HTTPS::LoadDefaultCerts() {
	int certsLoaded = 0;
#if defined(_WIN32)
	HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG, L"ROOT");
	if (store) {
		PCCERT_CONTEXT ctx = NULL;
		while ((ctx = CertEnumCertificatesInStore(store, ctx))) {
			if (ctx->pbCertEncoded && ctx->cbCertEncoded > 0) {
				// MbedTLS natively handles the ASN1/DER encoding from the Windows store
				int ret = mbedtls_x509_crt_parse_der(&tls.caCert, ctx->pbCertEncoded, ctx->cbCertEncoded);
				if (ret == 0) certsLoaded++;
				else {
					WARN_LOG(Log::sceNet, "InitializeSSL: Failed to load a CA cert: -0x%04x", -ret);
				}
			}
		}
		CertFreeCertificateContext(ctx);
		CertCloseStore(store, 0);
	}
#elif defined(__linux__)
	const char* linux_cert_paths[] = {
		"/etc/ssl/certs/ca-certificates.crt",               // Debian/Ubuntu
		"/etc/pki/tls/certs/ca-bundle.crt",                 // Fedora/RHEL/CentOS
		"/etc/ssl/ca-bundle.pem",                           // OpenSUSE
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" // Newer Fedora
	};
	for (const char* path : linux_cert_paths) {
		if (access(path, R_OK) == 0) {
			// MbedTLS parses the entire bundle file at once
			int ret = mbedtls_x509_crt_parse_file(&tls.caCert, path);
			if (ret == 0) {
				certsLoaded++;
				break; 
			} else {
				WARN_LOG(Log::sceNet, "InitializeSSL: Error loading CA certificate from file: -0x%04x", -ret);
			}
		}
	}
	if (certsLoaded == 0) {
		ERROR_LOG(Log::sceNet, "InitializeSSL: No trusted CA certs found on Linux");
	}
#elif defined(__APPLE__)
	CFArrayRef certs = NULL;
	OSStatus status = SecTrustCopyAnchorCertificates(&certs);
	if (status == errSecSuccess && certs) {
		for (CFIndex i = 0; i < CFArrayGetCount(certs); ++i) {
			SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
			CFDataRef data = SecCertificateCopyData(cert);
			if (data) {
				int ret = mbedtls_x509_crt_parse_der(&tls.caCert, CFDataGetBytePtr(data), CFDataGetLength(data));
				if (ret == 0) certsLoaded++;
				else {
					WARN_LOG(Log::sceNet, "InitializeSSL: Failed to load an Apple CA cert: -0x%04x", -ret);
				}
				CFRelease(data);
			}
		}
		CFRelease(certs);
	}
#endif
	INFO_LOG(Log::sceNet, "InitializeSSL: Loaded %d OS default certificates", certsLoaded);
	return certsLoaded;
}

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
	mbedtls_x509_crt_init(&tls.caCert);
	if (certPEM.size() == 0) {
		if (useDefaultCerts)
			LoadDefaultCerts();
		else
			WARN_LOG(Log::sceNet, "InitializeSSL: No cert provided.");
	} else {
		// Initialize CA certificate store
		// Note: certPEM MUST be pointing to a valid certificate, or it will cause a strlen crash
		// PSP2i has it at 0x08e73a04
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
