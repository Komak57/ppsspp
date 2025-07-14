#ifndef HTTPS_NOT_AVAILABLE

#include <cstring>

#include "Common/Net/HTTPRequest.h"
#include "Common/Net/SSLRequest.h"
#include "Common/Thread/ThreadUtil.h"
#include "Common/StringUtils.h"
#include "Common/Log.h"
#if defined(_WIN32)
#pragma comment(lib, "Crypt32.lib")
#include <windows.h>
#include <wincrypt.h>
#endif

//#include "ext/naett/naett.h"

namespace http {
	struct URLParts {
		std::string scheme;
		std::string host;
		std::string path;
		std::string port;
	};

	static URLParts SplitURL(const std::string& fullUrl) {
		URLParts parts;

		size_t scheme_end = fullUrl.find("://");
		if (scheme_end != std::string::npos) {
			parts.scheme = fullUrl.substr(0, scheme_end);
			scheme_end += 3;
		}
		else {
			scheme_end = 0;
			parts.scheme = "http";
		}

		size_t path_start = fullUrl.find('/', scheme_end);
		if (path_start == std::string::npos)
			path_start = fullUrl.length();

		std::string hostPort = fullUrl.substr(scheme_end, path_start - scheme_end);
		size_t colon = hostPort.find(':');
		if (colon != std::string::npos) {
			parts.host = hostPort.substr(0, colon);
			parts.port = hostPort.substr(colon + 1);
		}
		else {
			parts.host = hostPort;
			parts.port = (parts.scheme == "https") ? "443" : "80";
		}

		parts.path = fullUrl.substr(path_start);
		if (parts.path.empty())
			parts.path = "/";

		return parts;
	}

	HTTPSRequest::HTTPSRequest(RequestMethod method, std::string_view url, std::string_view postData, std::string_view postMime, const Path& outfile, RequestFlags flags, std::string_view name)
		: Request(method, url, name, &cancelled_, flags), method_(method), postData_(postData), postMime_(postMime) {
		outfile_ = outfile;
		// Pull trusted cert from device

#if defined(_WIN32)
		HCERTSTORE store = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			0,
			NULL,
			CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
			L"ROOT");

		PCCERT_CONTEXT ctx = NULL;
		mbedtls_x509_crt_init(&caCert);

		while ((ctx = CertEnumCertificatesInStore(store, ctx))) {
			mbedtls_x509_crt_parse_der(&caCert,
				ctx->pbCertEncoded,
				ctx->cbCertEncoded);
		}

		CertFreeCertificateContext(ctx);
		CertCloseStore(store, 0);
#elif defined(__linux__)
		// FIXME: untested
		mbedtls_x509_crt_init(&caCert);
		mbedtls_x509_crt_parse_file(&caCert,
			"/etc/ssl/certs/ca-certificates.crt");
#elif defined(__APPLE__)
		// FIXME: untested
		SecTrustRef trust;
		OSStatus status = SecTrustCopyAnchorCertificates(&trust);
		CFArrayRef certs = SecTrustCopyAnchorCertificates(&trust);

		mbedtls_x509_crt_init(&caCert);
		for (size_t i = 0; i < CFArrayGetCount(certs); ++i) {
			SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
			CFDataRef data = SecCertificateCopyData(cert);
			mbedtls_x509_crt_parse_der(&caCert,
				CFDataGetBytePtr(data),
				CFDataGetLength(data));
			CFRelease(data);
		}
		SecTrustSetAnchorCertificates(trust, NULL);
		CFRelease(certs);
#endif
		// Then attach to mbedTLS:
		mbedtls_ssl_conf_ca_chain(&sslConfig, &caCert, NULL);
	}

	HTTPSRequest::~HTTPSRequest() {
		HTTPSRequest::Join();
	}

	// Note: This is a Blocking action
	void HTTPSRequest::Start() {
		URLParts urlParts = SplitURL(url_);
		// Setup TLS
		mbedtls_ssl_init(&sslCtx);
		mbedtls_ssl_setup(&sslCtx, &sslConfig);
		mbedtls_ssl_set_hostname(&sslCtx, urlParts.host.c_str());

		// Setup TCP connection
		mbedtls_net_init(&netCtx);
		int ret = mbedtls_net_connect(&netCtx, url_.c_str(), "443", MBEDTLS_NET_PROTO_TCP);
		if (ret != 0) {
			ERROR_LOG(Log::IO, "TLS connect failed: %d", ret);
			failed_ = true;
			progress_.Update(0, 0, true);
			return;
		}

		mbedtls_ssl_set_bio(&sslCtx, &netCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

		// Handshake
		while ((ret = mbedtls_ssl_handshake(&sslCtx)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				ERROR_LOG(Log::IO, "TLS handshake failed: -0x%x", -ret);
				failed_ = true;
				progress_.Update(0, 0, true);
				return;
			}
		}

		// Construct HTTP request
		char requestBuf[2048];
		int offset = 0;

		offset += snprintf(requestBuf + offset, sizeof(requestBuf) - offset,
			"%s %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept: %s\r\n",
			method_ == RequestMethod::POST ? "POST" : "GET",
			urlParts.path.c_str(),
			urlParts.host.c_str(),
			userAgent_.c_str(),
			acceptMime_);

		if (method_ == RequestMethod::POST && !postData_.empty()) {
			offset += snprintf(requestBuf + offset, sizeof(requestBuf) - offset,
				"Content-Type: %s\r\n"
				"Content-Length: %zu\r\n",
				postMime_.c_str(),
				postData_.size());
		}

		offset += snprintf(requestBuf + offset, sizeof(requestBuf) - offset, "Connection: close\r\n\r\n");

		std::string requestStr = requestBuf;
		const unsigned char* buf = (const unsigned char*)requestBuf;
		size_t len = requestStr.size();

		// Send HTTP request
		size_t written = 0;
		while (written < len) {
			ret = mbedtls_ssl_write(&sslCtx, buf + written, len - written);
			if (ret < 0) {
				ERROR_LOG(Log::IO, "TLS write failed: %d", ret);
				failed_ = true;
				progress_.Update(0, 0, true);
				return;
			}
			written += ret;
		}
		progress_.Update(written, written, false);
	}

	void HTTPSRequest::Join() {
		if (!completed_) {
			WARN_LOG(Log::IO, "HTTPSRequest::Join - Not completed yet");
			return;
		}

		mbedtls_ssl_close_notify(&sslCtx);
		mbedtls_net_free(&netCtx);
		mbedtls_ssl_free(&sslCtx);
	}

	bool HTTPSRequest::Done() {
		if (completed_) return true;

		unsigned char responseBuf[4096];
		std::string responseData;
		int total = 0;
		int ret = 0;

		do {
			ret = mbedtls_ssl_read(&sslCtx, responseBuf, sizeof(responseBuf));
			if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
				continue;
			else if (ret <= 0)
				break;

			responseData.append((char*)responseBuf, ret);
			total += ret;
			progress_.Update(total, total, false);
		} while (true);

		// Parse headers (you can improve this later)
		size_t headerEnd = responseData.find("\r\n\r\n");
		if (headerEnd == std::string::npos) {
			ERROR_LOG(Log::IO, "HTTP response malformed");
			failed_ = true;
			progress_.Update(0, 0, true);
			return true;
		}

		std::string headers = responseData.substr(0, headerEnd);
		std::string body = responseData.substr(headerEnd + 4);
		buffer_.Append(body.size());
		memcpy(buffer_.Append(0), body.data(), body.size());

		// Very naive status code extraction
		size_t statusStart = headers.find(" ");
		if (statusStart != std::string::npos)
			resultCode_ = std::stoi(headers.substr(statusStart + 1));

		completed_ = true;
		progress_.Update(total, total, true);

		if (resultCode_ != 200) {
			ERROR_LOG(Log::IO, "Request failed: %d", resultCode_);
			failed_ = true;
		}

		return true;
	}

}  // namespace http

#endif  // HTTPS_NOT_AVAILABLE
