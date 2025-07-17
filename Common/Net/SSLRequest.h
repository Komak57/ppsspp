#pragma once

#include <thread>
#include <string_view>

#include "Common/Net/HTTPRequest.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/error-ssl.h>

#ifndef HTTPS_NOT_AVAILABLE

namespace http {
	enum CertType {
		Store,
		File,
		PEM
	};
	// Really an asynchronous request.
	class HTTPSRequest : public Request {
	public:
		HTTPSRequest(RequestMethod method, std::string_view url, std::string_view postData, std::string_view postMime, const Path& outfile, RequestFlags flags = RequestFlags::ProgressBar | RequestFlags::ProgressBarDelayed, std::string_view name = "");
		~HTTPSRequest();

		// Initilizes the SSL libraries and sets the certificate.
		// CertType::Store - will pull from a Trusted CA
		// CertType::File - loads a file at path 'target'
		// CertType::PEM - lads a PEM directly from 'target'
		int InitializeSSL(CertType certtype, std::string target = "");
		// Compatibility Enabled way to obtain trusted certs from the device
		int LoadStoreCert();

		void Start() override;
		void Join() override;

		// Also acts as a Poll.
		bool Done() override;
		bool Failed() const override { return failed_; }

	private:
		RequestMethod method_;
		std::string postData_;
		std::string postMime_;
		bool completed_ = false;
		bool failed_ = false;

		WOLFSSL_CTX *ctx_ = nullptr;
		WOLFSSL *ssl_ = nullptr;
		int sockfd = 0;
		void ThrowError(const char* fmt, ...);
	};

}  // namespace http

#endif  // HTTPS_NOT_AVAILABLE
