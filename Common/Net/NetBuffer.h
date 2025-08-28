#pragma once

#include <cstdint>
#include <functional>
#include <mbedtls/ssl.h>

#include "Common/Buffer.h"
#include <mbedtls/net_sockets.h>

namespace net {

class RequestProgress {
public:
	explicit RequestProgress(bool *c) : cancelled(c) {}

	void Update(int64_t downloaded, int64_t totalBytes, bool done);

	float progress = 0.0f;
	float kBps = 0.0f;
	bool *cancelled = nullptr;
	std::function<void(int64_t, int64_t, bool)> callback;
};

class Buffer : public ::Buffer {
public:
	bool FlushSocket(uintptr_t sock, double timeout, bool* cancelled = nullptr);
	bool FlushSocket(mbedtls_ssl_context *sslCtx, mbedtls_net_context *netCtx, double timeout, bool* cancelled = nullptr);
	
	int ReadAllWithProgress(int fd, int knownSize, RequestProgress *progress, bool useSSL, mbedtls_ssl_context* sslCtx);

	// < 0: error
	// >= 0: number of bytes read
	int Read(int fd, size_t sz, bool useSSL, mbedtls_ssl_context* sslCtx);
	int ReadHTML(int fd, bool useSSL, mbedtls_ssl_context* sslCtx);
};

}
