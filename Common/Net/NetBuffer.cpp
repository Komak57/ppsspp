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
	bytes_read += downloaded;
	if (totalBytes) {
		progress = (double)bytes_read / (double)totalBytes;
	} else {
		progress = 0.01f;
	}

	if (callback) {
		callback(bytes_read, totalBytes, done);
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
				ERROR_LOG(Log::IO, "FlushSocket failed to send: errno=%d", errno);
				return false;
			}
			pos += sent;
		}
		return true;
	});

	data_.clear();
	return true;
}

bool Buffer::FlushSocket(HTTPS_Config* tls, double timeout, bool* cancelled) {
	static constexpr float CANCEL_INTERVAL = 0.25f;

	bool ready = true;
	data_.iterate_blocks([&](const char* data, size_t size) {
		for (size_t pos = 0, end = size; pos < end; ) {
			double endTimeout = time_now_d() + timeout;
			// Check cancelation flag
			if (*cancelled)
				return false;
			while (!ready) {
				// Wait a moment for data to be ready
				ready = fd_util::WaitUntilReady(wolfSSL_get_fd(tls->ssl), CANCEL_INTERVAL, true);
				// Check cancelation flag each loop
				if (*cancelled)
					return false;
				// Check for Timeout
				if (time_now_d() > endTimeout) {
					ERROR_LOG(Log::sceNet, "FlushSocket: Client timed out");
					return false;
				}
			}
			int sent = wolfSSL_write(tls->ssl, data + pos, (int)(end - pos));
			//int sent = send(sock, &data[pos], end - pos, MSG_NOSIGNAL);
			// TODO: Do we need some retry logic here, instead of just giving up?
			if (sent <= 0) {
				int err = wolfSSL_get_error(tls->ssl, sent);
				switch (err) {
				case WOLFSSL_ERROR_ZERO_RETURN:
					ERROR_LOG(Log::sceNet, "FlushSocket: Client closed connection gracefully");
					return true;
				case WOLFSSL_ERROR_WANT_WRITE:
					ready = false;
					continue;
				default:
					ERROR_LOG(Log::sceNet, "SSL write failed: -0x%04x", -err);
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

int Buffer::ReadAllWithProgress(int fd, int knownSize, RequestProgress *progress, bool useSSL, HTTPS_Config* tls) {
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
	bool ready = true;
	while (true) {
		if (*progress->cancelled)
			return false;
		while (!ready) {
			ready = fd_util::WaitUntilReady(wolfSSL_get_fd(tls->ssl), CANCEL_INTERVAL, true);
			if (*progress->cancelled)
				return false;
		}
		// FIXME: Can stall without a timeout?
		// If we might need to cancel, check on a timer for it to be ready.
		int retval;
		if (useSSL) {
			retval = wolfSSL_read(tls->ssl, reinterpret_cast<unsigned char*>(&buf[0]), (int)buf.size());
		}
		else {
			retval = recv(fd, &buf[0], buf.size(), MSG_NOSIGNAL);
		}
		if (retval == 0) {
			return true;
		} else if (retval < 0) {
			if (useSSL) {
				int err = wolfSSL_get_error(tls->ssl, retval);
				switch (err) {
				case WOLFSSL_ERROR_ZERO_RETURN:
					WARN_LOG(Log::HTTP, "ReadAllWithProgress - Client closed connection gracefully");
					return total;
				case WOLFSSL_ERROR_WANT_READ:
					ready = false;
					break;
				default:
					ERROR_LOG(Log::HTTP, "ReadAllWithProgress Failed: -0x%04x", -err);
					return err;
				}
			}
			else {
				if (socket_errno != EWOULDBLOCK) {
					ERROR_LOG(Log::IO, "ReadAllWithProgress - Error reading from buffer: %i", retval);
					return retval;
				}
			}

			// Just try again on a would block error, not a real error.
			continue;
		}
		char *p = Append((size_t)retval);
		memcpy(p, &buf[0], retval);
		total += retval;
		if (progress) {
			progress->Update(total - progress->bytes_read, knownSize, false);
			progress->kBps = (float)(total / (time_now_d() - st)) / 1024.0f;
		}
	}
	return total;
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

int Buffer::Read(int fd, size_t sz, bool useSSL, HTTPS_Config* tls) {
	static constexpr float CANCEL_INTERVAL = 0.25f;
	//char buf[4096];
	char* buf = new char[sz];
	int retval = 0;
	size_t received = 0;

	while (sz > 0) {
		int toRead = (int)std::min(sz, sizeof(buf));
		if (useSSL) {
			DEBUG_LOG(Log::sceNet, "WolfSSL reading %i bytes", toRead);
			retval = wolfSSL_read(tls->ssl, (unsigned char*)buf, toRead);
			int ready = 0;
			if (retval < 0) {
				int err = wolfSSL_get_error(tls->ssl, retval);
				switch (err) {
				case WOLFSSL_ERROR_ZERO_RETURN:
					WARN_LOG(Log::sceNet, "Read - Client closed connection gracefully");
					return (int)received > 0 ? (int)received : err;
				case WOLFSSL_ERROR_WANT_WRITE:
					ERROR_LOG(Log::sceNet, "WolfSSL returned WANT_WRITE");
					return err;
				case WOLFSSL_ERROR_WANT_READ:
					DEBUG_LOG(Log::sceNet, "WolfSSL returned WANT_READ");
					while (!ready)
						ready = fd_util::WaitUntilReady(fd, CANCEL_INTERVAL, false);
					// Read some more!
					continue;
				default:
					ERROR_LOG(Log::sceNet, "Read Failed: -0x%04x", -err);
					return err;
				}
			}

		}
		else {
			retval = recv(fd, buf, toRead, MSG_NOSIGNAL);

			if (retval < 0)
				break;
		}
		char* p = Append((size_t)retval);
		memcpy(p, buf, retval);
		sz -= retval;
		received += retval;
	}

	return (int)received > 0 ? (int)received : retval;  // Return -1 or 0 for error, else bytes read
}
enum ReadState {
	Headers,
	Body,
	Complete
};

int Buffer::ReadHTML(int fd, bool useSSL, HTTPS_Config* tls) {
	static constexpr float CANCEL_INTERVAL = 0.25f;
	char buf[4096];
	// Adjustable read size
	size_t toRead = 256;
	int retval = 0;
	size_t received = 0;
	ReadState state = ReadState::Headers;
	std::vector<std::string> responseHeaders = {};
	int code = 404;
	int content_length = 0;

	while (state != ReadState::Complete) {
		if (useSSL) {
			DEBUG_LOG(Log::HTTP, "WolfSSL reading %i bytes", toRead);
			retval = wolfSSL_read(tls->ssl, (unsigned char*)buf, toRead);
			//int ready = 0;
			if (retval < 0) {
				switch (retval) {
				case WOLFSSL_ERROR_ZERO_RETURN:
					WARN_LOG(Log::HTTP, "Read - Client closed connection gracefully");
					return (int)received > 0 ? (int)received : retval;
				case WOLFSSL_ERROR_WANT_WRITE:
					ERROR_LOG(Log::HTTP, "WolfSSL returned WANT_WRITE");
					return retval;
				case WOLFSSL_ERROR_WANT_READ:
					DEBUG_LOG(Log::HTTP, "WolfSSL returned WANT_READ");
					/*while (!ready)
						ready = fd_util::WaitUntilReady(fd, CANCEL_INTERVAL, false);*/
					// Read some more!
					continue;
				default:
					ERROR_LOG(Log::HTTP, "Read Failed: -0x%04x", -retval);
					return retval;
				}
			}

		}
		else {
			DEBUG_LOG(Log::HTTP, "socket reading %i bytes", toRead);
			retval = recv(fd, buf, toRead, MSG_NOSIGNAL);

			if (retval < 0)
				break;
		}
		char* p = Append((size_t)retval);
		memcpy(p, buf, retval);
		received += retval;

		if (state == ReadState::Headers) {
			// Check for header marker
			int i = Contains("\r\n\r\n");
			// Still no header eof? Try again!
			if (i < 0) {
				DEBUG_LOG(Log::HTTP, "Headers not yet found in %i bytes (%s)", received, std::string(buf).substr(0, received).c_str());
				continue;
			}

			std::string header;
			Take(i + 4, &header);
			// Reset received
			received = size();

			// Split lines into responseHeaders
			size_t start = 0;
			size_t end;
			std::string clen = "Content-Length:";
			while ((end = header.find("\r\n", start)) != std::string::npos) {
				std::string line = header.substr(start, end - start);
				if (line != "") {
					// First header?
					if (responseHeaders.size() == 0) {
						// Find HTTP Code
						size_t code_pos = line.find(' ');
						if (code_pos != line.npos) {
							code_pos = line.find_first_not_of(' ', code_pos);
						}

						if (code_pos != line.npos) {
							code = atoi(&line[code_pos]);
						}
						else {
							ERROR_LOG(Log::HTTP, "Could not parse HTTP status code: '%s'", line.c_str());
							return -1;
						}
					}
					else {
						// Find Content Length
						if (line.size() < clen.size())
							return false;
						if (strncasecmp(line.data(), clen.data(), clen.size()) == 0) {
							size_t size_pos = line.find_first_of(' ');
							if (size_pos != line.npos) {
								size_pos = line.find_first_not_of(' ', size_pos);
							}
							if (size_pos != line.npos) {
								// Resize to read remaining length
								content_length = atoi(&line[size_pos]);
								toRead = content_length - size();
							}
						}
					}
					responseHeaders.push_back(line);
				}
				start = end + 2;  // Skip past the \r\n
			}
			state = ReadState::Body;
		}
		if (state == ReadState::Body) {
			// Should always be true
			if (received == content_length)
				state = ReadState::Complete;
		}
	}

	return code;  // Return HTML Status Code or Error Code
}


}  // namespace
