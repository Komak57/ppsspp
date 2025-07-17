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
#if defined(__linux__)
#include <unistd.h> // For access()
#endif
#include <Common\File\FileDescriptor.h>

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

	void HTTPSRequest::ThrowError(const char* fmt, ...) {
		char buffer[1024];  // Adjust size if needed
		va_list args;
		va_start(args, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, args);
		va_end(args);

		ERROR_LOG(Log::sceNet, "%s", buffer);
		failed_ = true;
		progress_.Update(0, 0, true);
	}

	HTTPSRequest::HTTPSRequest(RequestMethod method, std::string_view url, std::string_view postData, std::string_view postMime, const Path& outfile, RequestFlags flags, std::string_view name)
		: Request(method, url, name, &cancelled_, flags), method_(method), postData_(postData), postMime_(postMime) {
		outfile_ = outfile;
	}

	HTTPSRequest::~HTTPSRequest() {
		HTTPSRequest::Join();
	}

	int HTTPSRequest::LoadStoreCert() {
		_dbg_assert_msg_(ctx_, "LoadStoreCert called before WOLFSSL_CTX initialized!");
#if defined(_WIN32)
		// We can also use CERT_SYSTEM_STORE_CURRENT_USER / CERT_SYSTEM_STORE_LOCAL_MACHINE if needed
		HCERTSTORE store = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			0,
			NULL,
			CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
			L"ROOT");

		PCCERT_CONTEXT ctx = NULL;
		int idx = 0;

		// Cert Type: SSL_FILETYPE_ASN1, SSL_FILETYPE_PEM, SSL_FILETYPE_DEFAULT
		while ((ctx = CertEnumCertificatesInStore(store, ctx))) {
			idx++;
			//INFO_LOG(Log::sceNet, "Cert %d: len = %d", idx++, ctx->cbCertEncoded);
			_dbg_assert_(ctx->pbCertEncoded != nullptr);
			_dbg_assert_(ctx->cbCertEncoded > 0);
			// Try ASN1
			if (wolfSSL_CTX_load_verify_buffer(ctx_, ctx->pbCertEncoded, ctx->cbCertEncoded, SSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
				int err = wolfSSL_get_error(nullptr, 0);
				char errBuf[80];
				wolfSSL_ERR_error_string(err, errBuf);
				DEBUG_LOG(Log::sceNet, "Failed to load CA cert #%i (%s)", idx, errBuf);
			}
		}

		CertFreeCertificateContext(ctx);
		CertCloseStore(store, 0);
#elif defined(__linux__)
		// FIXME: untested
		const char* linux_cert_paths[] = {
			"/etc/ssl/certs/ca-certificates.crt",               // Debian/Ubuntu
			"/etc/pki/tls/certs/ca-bundle.crt",                 // Fedora/RHEL/CentOS
			"/etc/ssl/ca-bundle.pem",                           // OpenSUSE
			"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" // Newer Fedora
		};
		bool found = false;
		for (const char* path : linux_cert_paths) {
			if (access(path, R_OK) == 0) {
				int ret = wolfSSL_CTX_load_verify_locations(ctx_, path, NULL);
				if (ret != SSL_SUCCESS) {
					// Not a valid certificate
					DEBUG_LOG(Log::sceNet, "LoadStoreCert - Error loading CA certificate from file: %d (%s)", ret, wolfSSL_ERR_reason_error_string(wolfSSL_get_error(NULL, ret)));
					continue;
				}
				found = true;
				break;
			}
		}
		if (!found) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: No trusted CA certs found on Linux");
			return -1;
		}
#elif defined(__APPLE__)
		// FIXME: untested
		SecTrustRef trust;
		OSStatus status = SecTrustCopyAnchorCertificates(&trust);
		CFArrayRef certs = SecTrustCopyAnchorCertificates(&trust);

		for (size_t i = 0; i < CFArrayGetCount(certs); ++i) {
			SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
			CFDataRef data = SecCertificateCopyData(cert);

			if (wolfSSL_CTX_load_verify_buffer(ctx_, CFDataGetBytePtr(data), CFDataGetLength(data), SSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
				int err = wolfSSL_get_error(nullptr, 0);
				char errBuf[80];
				wolfSSL_ERR_error_string(err, errBuf);
				WARN_LOG(Log::sceNet, "Failed to load CA cert #%i (%s)", idx, errBuf);
			}
			CFRelease(data);
		}
		SecTrustSetAnchorCertificates(trust, NULL);
		CFRelease(certs);
#endif
		return 0;
	}

	int HTTPSRequest::InitializeSSL(CertType certtype, std::string target) {
		WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::InitializeSSL()");

		wolfSSL_Debugging_ON();  // Optional: turn off for release
#ifdef DEBUG
		wolfSSL_SetLoggingCb(wolfssl_debug);
#endif
		if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
			ERROR_LOG(Log::sceNet, "wolfSSL_Init failed");
			return -1;
		}

		ctx_ = wolfSSL_CTX_new(wolfTLS_client_method());
		if (!ctx_) {
			ERROR_LOG(Log::sceNet, "wolfSSL_CTX_new failed");
			return -1;
		}

		// Force specific ciphers in the handshake process
		//const char* cipher_list = "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256";
		//wolfSSL_CTX_set_cipher_list(ctx_, cipher_list);

		// Optional: TLS version range
		wolfSSL_CTX_SetMinVersion(ctx_, WOLFSSL_TLSV1_2);
		wolfSSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, NULL);

		int ret;
		switch (certtype) {
		case CertType::Store:
			ret = LoadStoreCert();
			if (ret < 0)
				return ret;
			break;
		case CertType::File:
			ret = wolfSSL_CTX_load_verify_locations(ctx_, target.c_str(), NULL);
			if (ret != SSL_SUCCESS) {
				ERROR_LOG(Log::sceNet, "Error loading CA certificate from file: %d (%s)", ret, wolfSSL_ERR_reason_error_string(wolfSSL_get_error(NULL, ret)));
				return ret;
			}
			break;
		case CertType::PEM:
			ret = wolfSSL_CTX_load_verify_buffer(ctx_, (const unsigned char*)target.c_str(), (long)target.size(), SSL_FILETYPE_PEM);
			if (ret != WOLFSSL_SUCCESS) {
				ERROR_LOG(Log::sceNet, "Failed to load PEM certificate");
				return ret;
			}
			break;
		}

		ssl_ = wolfSSL_new(ctx_);
		if (!ssl_) {
			ERROR_LOG(Log::sceNet, "Could not generate SSL from Context");
			return -1;
		}

		return 0;
	}


	// Note: This is a Blocking action
	void HTTPSRequest::Start() {
		URLParts urlParts = SplitURL(url_);
		// Setup TLS
		int ret = InitializeSSL(CertType::Store);
		if (ret < 0) {
			ThrowError("TLS init failed: %d", ret);
			return;
		}
		wolfSSL_UseSNI(ssl_, WOLFSSL_SNI_HOST_NAME, urlParts.host.c_str(), (unsigned short)urlParts.host.length());

		struct addrinfo hints = {}, * res = nullptr;
		hints.ai_family = AF_INET;       // Use AF_UNSPEC to support IPv4+IPv6
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		int status = getaddrinfo(urlParts.host.c_str(), urlParts.port.c_str(), &hints, &res);
		if (status != 0 || res == nullptr) {
			ThrowError("Unable to get Address Info for socket: %d", gai_strerror(status));
			return;
		}
		// Create TCP socket
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0) {
			ThrowError("Could not create Socket: %d", sockfd);
			freeaddrinfo(res);
			return;
		}

		wolfSSL_set_fd(ssl_, sockfd);

		// wolfSSL_connect does not connect the socket, so we need to do it ourselves
		if (connect(sockfd, res->ai_addr, (int)res->ai_addrlen) < 0) {
#ifdef _WIN32
			ThrowError("Connection Failed: %d", WSAGetLastError());
#else
			ThrowError("Connection Failed");
#endif
			freeaddrinfo(res);
#ifdef _WIN32
			closesocket(sockfd);
#else
			close(sockfd);
#endif
			return;
		}
		// FIXME: Insecure
		//wolfSSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, NULL);

		// Debugging stuff
		INFO_LOG(Log::sceNet, "SNI: %s", urlParts.host.c_str()); // Reports 4 (TLS1_3)
		INFO_LOG(Log::sceNet, "SSL Version: %i", wolfSSL_GetVersion(ssl_)); // Reports 4 (TLS1_3)
		int i = 0;
		const char* cipher;
		while ((cipher = wolfSSL_get_cipher_list(i++)) != NULL)
			DEBUG_LOG(Log::sceNet, "Supported cipher: %s", cipher);
		INFO_LOG(Log::sceNet, "%i Supported Ciphers", i);

		// Then initiate handshake
		if (wolfSSL_connect(ssl_) != WOLFSSL_SUCCESS) {
			if (wolfSSL_is_init_finished(ssl_)) {
				ThrowError("Connection failed (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl_, 0)));
			}
			else {
				const char* cipher = wolfSSL_get_cipher(ssl_);
				if (cipher == "NONE")	// Reports (NONE) when handshake failed
					ThrowError("TLS handshake failed / Unable to agree on a cipher (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl_, 0)));
				else
					ThrowError("TLS handshake failed / Using Cipher %s (%s)", cipher, wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl_, 0)));
			}

			return;
		}
		// Set NonBlocking
		fd_util::SetNonBlocking(sockfd, true);

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
			ret = wolfSSL_write(ssl_, buf + written, (int)(len - written));
			if (ret <= 0) {
				int err = wolfSSL_get_error(ssl_, ret);
				switch (err) {
				case WOLFSSL_ERROR_WANT_WRITE:
					continue;
				default:
					ThrowError("TLS write failed: %d (wolfSSL_get_error: %d)", ret, err);
					return;
				}
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

		if (ssl_) {
			wolfSSL_free(ssl_);
			ssl_ = nullptr;
		}
		if (ctx_) {
			wolfSSL_CTX_free(ctx_);
			ctx_ = nullptr;
		}
		wolfSSL_Cleanup();
	}

	// TODO: Move this to the requesting service
	// DeChunk Helper
	static bool DeChunk(Buffer* inbuffer, Buffer* outbuffer, int contentLength) {
		_dbg_assert_(outbuffer->empty());
		int dechunkedBytes = 0;
		while (true) {
			std::string line;
			inbuffer->TakeLineCRLF(&line);
			if (!line.size())
				return false;
			unsigned int chunkSize = 0;
			if (sscanf(line.c_str(), "%x", &chunkSize) != 1) {
				return false;
			}
			if (chunkSize) {
				std::string data;
				inbuffer->Take(chunkSize, &data);
				outbuffer->Append(data);
			}
			else {
				// a zero size chunk should mean the end.
				inbuffer->clear();
				return true;
			}
			dechunkedBytes += chunkSize;
			inbuffer->Skip(2);
		}
		// Unreachable
		return true;
	}

	bool HTTPSRequest::Done() {
		if (completed_) return true;

		unsigned char responseBuf[4096];
		std::string responseData;
		int total = 0;
		int ret = 0;

		// Read until there's nothing left to grab
		do {
			if (IsCancelled()) {
				resultCode_ = -1000;
				return false;
			}

			ret = wolfSSL_read(ssl_, responseBuf, sizeof(responseBuf));
			if (ret <= 0) {
				int err = wolfSSL_get_error(ssl_, ret);
				switch (err) {
				case WOLFSSL_ERROR_WANT_READ:
					continue; // non-blocking compliant
				case WOLFSSL_ERROR_ZERO_RETURN:
					NOTICE_LOG(Log::sceNet, "TLS connection closed by peer.");
					break;
				default:
					WARN_LOG(Log::IO, "Read End - %d", err);
					ThrowError("Read End - %d", err);
					return false;
				}
				break; // Clean break from loop
			}
			if (ret > sizeof(responseBuf)) {
				ThrowError("Read returned more data than available in the buffer");
				return false;
			}
			responseData.append((char*)responseBuf, ret);
			total += ret;
			progress_.Update(responseData.size(), total, false);
		} while (true);

		// Strip headers
		size_t headerEnd = responseData.find("\r\n\r\n");
		std::string headers = responseData.substr(0, headerEnd+4);

		std::vector<std::string> responseHeaders = {};
		// Split headers into organized lines
		size_t start = 0;
		size_t end;
		while ((end = headers.find("\r\n", start)) != std::string::npos) {
			std::string line = headers.substr(start, end - start);
			if (line != "")
				responseHeaders.push_back(line);
			start = end + 2;  // Skip past the \r\n
		}
		// take first line
		std::string line = responseHeaders.front();

		// Find HTTP Code
		size_t code_pos = line.find(' ');
		if (code_pos != line.npos) {
			code_pos = line.find_first_not_of(' ', code_pos);
		}

		if (code_pos != line.npos) {
			resultCode_ = atoi(&line[code_pos]);
		}
		else {
			ThrowError("Could not parse HTTP status code: '%s'", line.c_str());
			return false;
		}

		// buffer body data for external handling
		std::string body = responseData.substr(headerEnd + 4);
		Buffer bodybuf;
		void* dst = bodybuf.Append(body.size());
		memcpy(dst, body.data(), body.size());

		for (std::string line : responseHeaders) {
			if (startsWithNoCase(line, "Transfer-Encoding:")) {
				// De-Chunk data
				if (line.find("chunked") != std::string::npos) {
					if (!DeChunk(&bodybuf, &buffer_, body.length())) {
						ThrowError("Bad chunked data, couldn't read chunk size");
						return false;
					}
				}
			}
		}
		//// Parse headers (you can improve this later)
		//size_t headerEnd = responseData.find("\r\n\r\n");
		//if (headerEnd == std::string::npos) {
		//	ERROR_LOG(Log::IO, "HTTP response malformed");
		//	failed_ = true;
		//	progress_.Update(0, 0, true);
		//	return true;
		//}

		//std::string headers = responseData.substr(0, headerEnd);
		//std::string body = responseData.substr(headerEnd + 4);
		//buffer_.Append(body.size());
		//memcpy(buffer_.Append(0), body.data(), body.size());

		//// Very naive status code extraction
		//size_t statusStart = headers.find(" ");
		//if (statusStart != std::string::npos)
		//	resultCode_ = std::stoi(headers.substr(statusStart + 1));

		completed_ = true;
		progress_.Update(total, total, true);

		if (resultCode_ != 200) {
			ThrowError("Request failed: %d", resultCode_);
			failed_ = true;
		}

		return true;
	}

}  // namespace http

#endif  // HTTPS_NOT_AVAILABLE
