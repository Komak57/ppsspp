#include "ppsspp_config.h"

#include <algorithm>
#include <cstring>
#include "Common/Net/SocketCompat.h"

#if _MSC_VER
#pragma warning(disable:4267)
#endif

#include "Common/File/FileDescriptor.h"
#include "Common/Log.h"
#include "Common/Net/NetBuffer.h"
#include "Common/TimeUtil.h"

namespace net {

void RequestProgress::Update(int64_t downloaded, int64_t totalBytes, bool done) {
	if (totalBytes) {
		progress = (double)downloaded / (double)totalBytes;
	} else {
		progress = 0.01f;
	}

	if (callback) {
		callback(downloaded, totalBytes, done);
	}
}

bool Buffer::FlushSocket(uintptr_t sock, double timeout, bool* cancelled) {
	static constexpr float CANCEL_INTERVAL = 0.25f;

	data_.iterate_blocks([&](const char* data, size_t size) {
		for (size_t pos = 0, end = size; pos < end; ) {
			bool ready = false;
			double endTimeout = time_now_d() + timeout;
			while (!ready) {
				if (cancelled && *cancelled)
					return false;
				ready = fd_util::WaitUntilReady(sock, CANCEL_INTERVAL, true);
				if (!ready && time_now_d() > endTimeout) {
					ERROR_LOG(Log::IO, "FlushSocket timed out");
					return false;
				}
			}
			int sent = send(sock, &data[pos], end - pos, MSG_NOSIGNAL);
			// TODO: Do we need some retry logic here, instead of just giving up?
			if (sent < 0) {
				ERROR_LOG(Log::IO, "FlushSocket failed to send: %d", errno);
				return false;
			}
			pos += sent;
		}
		return true;
	});

	data_.clear();
	return true;
}
bool Buffer::FlushSocket(mbedtls_ssl_context *sslCtx, mbedtls_net_context* netCtx, double timeout, bool* cancelled) {
	static constexpr float CANCEL_INTERVAL = 0.25f;

	data_.iterate_blocks([&](const char* data, size_t size) {
		for (size_t pos = 0, end = size; pos < end; ) {
			bool ready = false;
			double endTimeout = time_now_d() + timeout;
			while (!ready) {
				if (cancelled && *cancelled)
					return false;
				ready = fd_util::WaitUntilReady(netCtx->fd, CANCEL_INTERVAL, true);
				if (!ready && time_now_d() > endTimeout) {
					ERROR_LOG(Log::IO, "FlushSocket timed out");
					return false;
				}
			}
			int sent = mbedtls_ssl_write(sslCtx, (const unsigned char*)data + pos, end - pos);
			//int sent = send(sock, &data[pos], end - pos, MSG_NOSIGNAL);
			// TODO: Do we need some retry logic here, instead of just giving up?
			if (sent <= 0) {
				switch (sent) {
				case MBEDTLS_ERR_NET_CONN_RESET:
				case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
					ERROR_LOG(Log::sceNet, "SSL write failed: Client closed connection");
					return false;
				default:
					ERROR_LOG(Log::sceNet, "SSL write failed: -0x%04x", -sent);
					return false;
				}
			}
			pos += sent;
		}
		return true;
	});

	data_.clear();
	return true;
}

bool Buffer::ReadAllWithProgress(int fd, int knownSize, RequestProgress *progress, bool useSSL, mbedtls_ssl_context* sslCtx) {
	static constexpr float CANCEL_INTERVAL = 0.25f;
	std::vector<char> buf;
	// We're non-blocking and reading from an OS buffer, so try to read as much as we can at a time.
	if (knownSize >= 65536 * 16) {
		buf.resize(65536);
	} else if (knownSize >= 1024 * 16) {
		buf.resize(knownSize / 16);
	} else {
		buf.resize(1024);
	}

	double st = time_now_d();
	int total = 0;
	while (true) {
		bool ready = false;

		// If we might need to cancel, check on a timer for it to be ready.
		// After this, we'll block on reading so we do this while first if we have a cancel pointer.
		while (!ready && progress && progress->cancelled) {
			if (*progress->cancelled)
				return false;
			ready = fd_util::WaitUntilReady(fd, CANCEL_INTERVAL, false);
		}
		int retval;
		if (useSSL) {
			retval = mbedtls_ssl_read(sslCtx, reinterpret_cast<unsigned char*>(&buf[0]), (int)buf.size());
		}
		else {
			retval = recv(fd, &buf[0], buf.size(), MSG_NOSIGNAL);
		}
		if (retval == 0) {
			return true;
		} else if (retval < 0) {
			if (useSSL) {
				switch (retval) {
				case MBEDTLS_ERR_NET_CONN_RESET:
				case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
					WARN_LOG(Log::sceNet, "ReadAllWithProgress - SSL read failed: Client closed connection gracefully");
					return true;
				default:
					ERROR_LOG(Log::sceNet, "ReadAllWithProgress - SSL read failed: -0x%04x", -retval);
					return false;
				}
			}
			else {
				if (socket_errno != EWOULDBLOCK) {
					ERROR_LOG(Log::IO, "ReadAllWithProgress - Error reading from buffer: %i", retval);
					return false;
				}
			}

			// Just try again on a would block error, not a real error.
			continue;
		}
		char *p = Append((size_t)retval);
		memcpy(p, &buf[0], retval);
		total += retval;
		if (progress) {
			progress->Update(total, knownSize, false);
			progress->kBps = (float)(total / (time_now_d() - st)) / 1024.0f;
		}
	}
	return true;
}

//int Buffer::Read(int fd, size_t sz) {
//	char buf[4096];
//	int retval;
//	size_t received = 0;
//	while ((retval = recv(fd, buf, std::min(sz, sizeof(buf)), MSG_NOSIGNAL)) > 0) {
//		if (retval < 0) {
//			return retval;
//		}
//		char *p = Append((size_t)retval);
//		memcpy(p, buf, retval);
//		sz -= retval;
//		received += retval;
//		if (sz == 0)
//			return 0;
//	}
//	return (int)received;
//}
int Buffer::Read(int fd, size_t sz, bool useSSL, mbedtls_ssl_context* sslCtx) {
	char buf[4096];
	int retval = 0;
	size_t received = 0;

	while (sz > 0) {
		int toRead = (int)std::min(sz, sizeof(buf));
		if (useSSL) {
			retval = mbedtls_ssl_read(sslCtx, (unsigned char*)buf, toRead);
			if (retval == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				WARN_LOG(Log::HTTP, "mbedtls_ssl_read Connection closed gracefully");
				return 0;
			}
			if (retval == MBEDTLS_ERR_SSL_TIMEOUT) {
				ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned TIMOUT");
				return -1;
			}
			if (retval == MBEDTLS_ERR_SSL_WANT_WRITE) {
				ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned WANT_WRITE");
				break;
			}
			if (retval == MBEDTLS_ERR_SSL_WANT_READ) {
				ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned WANT_READ");
				continue;
			}
			if (retval < 0) {
				ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned %i", retval);
				return -1;
			}
			char* p = Append((size_t)retval);
			memcpy(p, buf, retval);
			sz -= retval;
			received += retval;

		}
		else {
			retval = recv(fd, buf, toRead, MSG_NOSIGNAL);

			if (retval < 0)
				break;

			char* p = Append((size_t)retval);
			memcpy(p, buf, retval);
			sz -= retval;
			received += retval;
		}
	}

	return (int)received > 0 ? (int)received : retval;  // Return -1 or 0 for error, else bytes read
}

}  // namespace
