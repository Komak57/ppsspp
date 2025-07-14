#pragma once

#include <thread>
#include <string_view>

#include "Common/Net/HTTPRequest.h"
#include <mbedtls\entropy.h>
#include <mbedtls\ctr_drbg.h>

#ifndef HTTPS_NOT_AVAILABLE

namespace http {

	// Really an asynchronous request.
	class HTTPSRequest : public Request {
	public:
		HTTPSRequest(RequestMethod method, std::string_view url, std::string_view postData, std::string_view postMime, const Path& outfile, RequestFlags flags = RequestFlags::ProgressBar | RequestFlags::ProgressBarDelayed, std::string_view name = "");
		~HTTPSRequest();

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

		// mbedTLS state
		mbedtls_ssl_context sslCtx;
		mbedtls_net_context netCtx;

		mbedtls_ssl_config sslConfig;
		mbedtls_ctr_drbg_context ctrDrbg;
		mbedtls_entropy_context entropy;
		mbedtls_x509_crt caCert;

	};

}  // namespace http

#endif  // HTTPS_NOT_AVAILABLE
