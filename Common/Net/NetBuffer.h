#pragma once

#include <cstdint>
#include <functional>
#include <mbedtls/ssl.h>

#include "Common/Buffer.h"
#include <mbedtls/net_sockets.h>

namespace net {

class RequestProgress {
public:
	explicit RequestProgress(bool *c) : cancelled(c) {
		bytes_read = 0;
	}

	void Update(int64_t downloaded, int64_t totalBytes, bool done);

	float progress = 0.0f;
	float kBps = 0.0f;
	int64_t bytes_read = 0;
	bool *cancelled = nullptr;
	std::function<void(int64_t, int64_t, bool)> callback;
};

class Buffer : public ::Buffer {
public:
	bool FlushSocket(uintptr_t sock, double timeout, bool* cancelled = nullptr);
	
	int ReadAllWithProgress(int fd, int knownSize, RequestProgress *progress);

	// < 0: error
	// >= 0: number of bytes read
	int Read(int fd, size_t sz);
};

}
