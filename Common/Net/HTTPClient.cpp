#include <cmath>
#include <cstdio>
#include <cstdlib>

#include "Common/Net/HTTPClient.h"

#include "Common/TimeUtil.h"
#include "Common/StringUtils.h"
#include "Common/System/OSD.h"

#include "Common/Net/HTTPS.h"
#include "Common/Net/SocketCompat.h"
#include "Common/Net/Resolve.h"
#include "Common/Net/URL.h"

#include "Common/File/FileDescriptor.h"
#include "Common/SysError.h"
#include "Common/Thread/ThreadUtil.h"
#include "Common/Data/Encoding/Compression.h"
#include "Common/Net/NetBuffer.h"
#include "Common/Log.h"
#include <Core/HLE/sceHttp.h>

namespace net {

Connection::~Connection() {
		Disconnect();
	//if (resolved_ != nullptr)
		//DNSResolveFree(resolved_);
}

// For whatever crazy reason, htons isn't available on android x86 on the build server. so here we go.

// TODO: Fix for big-endian
inline unsigned short myhtons(unsigned short x) {
	return (x >> 8) | (x << 8);
}

bool Connection::Resolve(const char *host, int port, DNSType type) {
	if ((intptr_t)sock_ != -1) {
		ERROR_LOG(Log::IO, "Resolve: Already have a socket");
		lastError = SCE_HTTP_ERROR_ALREADY_INITED;
		return false;
	}
	if (!host || port < 1 || port > 65535) {
		ERROR_LOG(Log::IO, "Resolve: Invalid host or port (%d)", port);
		lastError = SCE_HTTP_ERROR_NETWORK;
		return false;
	}

	host_ = host;
	port_ = port;

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", port);

	std::string processedHostname(host);

	if (customResolve_) {
		processedHostname = customResolve_(host);
	}
	
	std::string err;
	if (!net::DNSResolve(processedHostname.c_str(), port_str, &resolved_, err, type)) {
		WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (%s)", host, err.c_str(), DNSTypeAsString(type));
		// Zero port so that future calls fail.
		port_ = 0;
		lastError = SCE_HTTP_ERROR_PARSE_HTTP_NOT_FOUND;
		return false;
	}

	return true;
}

bool Connection::Connect(int maxTries, double timeout, bool *cancelConnect) {
	NOTICE_LOG(Log::sceNet, "Connection::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
	if (port_ <= 0) {
		ERROR_LOG(Log::IO, "Bad port");
		lastError = SCE_HTTP_ERROR_NETWORK;
		return false;
	}
	sock_ = -1;

	for (int tries = maxTries; tries > 0; --tries) {
		std::vector<uintptr_t> sockets;
		fd_set fds;
		int maxfd = 1;
		FD_ZERO(&fds);
		for (addrinfo *possible = resolved_; possible != nullptr; possible = possible->ai_next) {
			if (possible->ai_family != AF_INET && possible->ai_family != AF_INET6)
				continue;

			int sock = socket(possible->ai_family, SOCK_STREAM, IPPROTO_TCP);
			if ((intptr_t)sock == -1) {
				ERROR_LOG(Log::IO, "Bad socket");
				continue;
			}
			// Windows sockets aren't limited by socket number, just by count, so checking FD_SETSIZE there is wrong.
#if !PPSSPP_PLATFORM(WINDOWS)
			if (sock >= FD_SETSIZE) {
				ERROR_LOG(Log::IO, "Socket doesn't fit in FD_SET: %d   We probably have a leak.", sock);
				closesocket(sock);
				continue;
			}
#endif
			fd_util::SetNonBlocking(sock, true);

			// Start trying to connect (async with timeout.)
			errno = 0;
			if (connect(sock, possible->ai_addr, (int)possible->ai_addrlen) < 0) {
				int errorCode = socket_errno;
				std::string errorString = GetStringErrorMsg(errorCode);
				bool unreachable = errorCode == ENETUNREACH;
				bool inProgress = errorCode == EINPROGRESS || errorCode == EWOULDBLOCK;
				if (!inProgress) {
					char addrStr[128]{};
					FormatAddr(addrStr, sizeof(addrStr), possible);
					if (!unreachable) {
						ERROR_LOG(Log::HTTP, "connect(%d) call to %s failed (%d: %s)", sock, addrStr, errorCode, errorString.c_str());
					} else {
						INFO_LOG(Log::HTTP, "connect(%d): Ignoring unreachable resolved address %s", sock, addrStr);
					}
					closesocket(sock);
					continue;
				}
			}
			sockets.push_back(sock);
			FD_SET(sock, &fds);
			if (maxfd < sock + 1) {
				maxfd = sock + 1;
			}
		}

		int selectResult = 0;
		long timeoutHalfSeconds = floor(2 * timeout);
		while (timeoutHalfSeconds >= 0 && selectResult == 0) {
			struct timeval tv{};
			tv.tv_sec = 0;
			if (timeoutHalfSeconds > 0) {
				// Wait up to 0.5 seconds between cancel checks.
				tv.tv_usec = 500000;
			} else {
				// Wait the remaining <= 0.5 seconds.  Possibly 0, but that's okay.
				tv.tv_usec = (timeout - floor(2 * timeout) / 2) * 1000000.0;
			}
			--timeoutHalfSeconds;

			selectResult = select(maxfd, nullptr, &fds, nullptr, &tv);
			if (cancelConnect && *cancelConnect) {
				WARN_LOG(Log::HTTP, "connect: cancelled (1): %s:%d", host_.c_str(), port_);
				break;
			}
		}
		if (selectResult > 0) {
			// Something connected.  Pick the first one that did (if multiple.)
			for (int sock : sockets) {
				if ((intptr_t)sock_ == -1 && FD_ISSET(sock, &fds)) {
					sock_ = sock;
				} else {
					closesocket(sock);
				}
			}

			// Great, now we're good to go.
			return true;
		} else {
			// Fail. Close all the sockets.
			for (int sock : sockets) {
				closesocket(sock);
			}
		}

		if (cancelConnect && *cancelConnect) {
			WARN_LOG(Log::HTTP, "connect: cancelled (2): %s:%d", host_.c_str(), port_);
			break;
		}

		sleep_ms(1, "connect");
	}

	lastError = SCE_HTTP_ERROR_PARSE_HTTP_NOT_FOUND;
	// Nothing connected, unfortunately.
	return false;
	}

void Connection::Disconnect() {
	}

}	// net

namespace http {

// TODO: do something sane here
constexpr const char *DEFAULT_USERAGENT = "PPSSPP";
constexpr const char *HTTP_VERSION = "1.1";

Client::Client(net::ResolveFunc func) : Connection(func) {
	userAgent_ = DEFAULT_USERAGENT;
	httpVersion_ = HTTP_VERSION;
	// TODO: Initialize SSH
}

Client::~Client() {
	DEBUG_LOG(Log::HTTP, "~Client()");
	Disconnect();
}

// Ignores line folding (deprecated), but respects field combining.
// Don't use for Set-Cookie, which is a special header per RFC 7230.
bool GetHeaderValue(const std::vector<std::string> &responseHeaders, const std::string &header, std::string *value) {
	std::string search = header + ":";
	bool found = false;

	value->clear();
	for (const std::string &line : responseHeaders) {
		auto stripped = StripSpaces(line);
		if (startsWithNoCase(stripped, search)) {
			size_t value_pos = search.length();
			size_t after_white = stripped.find_first_not_of(" \t", value_pos);
			if (after_white != stripped.npos)
				value_pos = after_white;

			if (!found)
				*value = stripped.substr(value_pos);
			else
				*value += "," + stripped.substr(value_pos);
			found = true;
		}
	}

	return found;
}

static bool DeChunk(Buffer *inbuffer, Buffer *outbuffer, int contentLength) {
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
		} else {
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

int Client::GET(const RequestParams &req, Buffer *output, std::vector<std::string> &responseHeaders, net::RequestProgress *progress) {
	const char *otherHeaders =
		"Accept-Encoding: gzip\r\n";
	int err = SendRequest("GET", req, otherHeaders, progress);
	if (err < 0) {
		return err;
	}
	/* TODO:
	   - Await for response
	   - Read data until header marker '\r\n\r\n'
	   - Pull headers from buffer, leaving data
	   - Check for response-code
	   - Check for content-length
	   - Check remaining data against content-length
	   - Read data until content-length obtained
	*/

	net::Buffer readbuf;
	int code = ReadResponseHeaders(&readbuf, responseHeaders, progress);
	if (code < 0) {
		ERROR_LOG(Log::HTTP, "Failed to read HTTP Headers");
		return code;
	}

	err = ReadResponseEntity(&readbuf, responseHeaders, output, progress);
	if (err < 0) {
		ERROR_LOG(Log::HTTP, "Failed to read HTTP Entity");
		return err;
	}
	return code;
}

int Client::GET(const RequestParams &req, Buffer *output, net::RequestProgress *progress) {
	std::vector<std::string> responseHeaders;
	int code = GET(req, output, responseHeaders, progress);
	return code;
}

int Client::POST(const RequestParams &req, std::string_view data, std::string_view mime, Buffer *output, net::RequestProgress *progress) {
	char otherHeaders[2048];
	if (mime.empty()) {
		snprintf(otherHeaders, sizeof(otherHeaders), "Content-Length: %lld\r\n", (long long)data.size());
	} else {
		snprintf(otherHeaders, sizeof(otherHeaders), "Content-Length: %lld\r\nContent-Type: %.*s\r\n", (long long)data.size(), (int)mime.size(), mime.data());
	}

	int err = SendRequestWithData("POST", req, data, otherHeaders, progress);
	if (err < 0) {
		return err;
	}

	net::Buffer readbuf;
	std::vector<std::string> responseHeaders;
	int code = ReadResponseHeaders(&readbuf, responseHeaders, progress);
	if (code < 0) {
		ERROR_LOG(Log::HTTP, "Failed to read HTTP headers");
		return code;
	}

	err = ReadResponseEntity(&readbuf, responseHeaders, output, progress);
	if (err < 0) {
		ERROR_LOG(Log::HTTP, "Failed to read HTTP Entity");
		return err;
	}
	return code;
}

int Client::POST(const RequestParams &req, std::string_view data, Buffer *output, net::RequestProgress *progress) {
	return POST(req, data, "", output, progress);
}

int Client::SendRequest(const char *method, const RequestParams &req, const char *otherHeaders, net::RequestProgress *progress) {
	return SendRequestWithData(method, req, "", otherHeaders, progress);
}

int Client::SendRequestWithData(const char *method, const RequestParams &req, std::string_view data, const char *otherHeaders, net::RequestProgress *progress) {
	DEBUG_LOG(Log::HTTP, "SendRequestWithData()");
	progress->Update(0, 0, false);

	net::Buffer buffer;
	const char *tpl =
		"%s %s HTTP/%s\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Accept: %s\r\n"
		"Connection: close\r\n"
		"%s"
		"\r\n";

	buffer.Printf(tpl,
		method, req.resource.c_str(), HTTP_VERSION,
		host_.c_str(),
		userAgent_.c_str(),
		req.acceptMime,
		otherHeaders ? otherHeaders : "");

	buffer.Append(data);
	if (tls.enabled) {
		bool flushed = buffer.FlushSocket(&tls, dataTimeout_, progress->cancelled);
		if (!flushed) {
			return -1;  // TODO error code.
		}
	}
	else {
		bool flushed = buffer.FlushSocket(sock(), dataTimeout_, progress->cancelled);
		if (!flushed) {
			return -1;  // TODO error code.
		}
	}
	return 0;
}

int Client::ReadResponse(net::Buffer* readbuf, net::RequestProgress* progress) {
	DEBUG_LOG(Log::HTTP, "ReadResponse()");
	// maps the socket for HTTPS or HTTP
	int fd = sock();

	// Snarf all the data we can into RAM. A little unsafe but hey.
	static constexpr float CANCEL_INTERVAL = 0.25f;
	int ready = 0;
	double endTimeout = time_now_d() + dataTimeout_;
begin:
	while (ready == 0) {
		if (progress->cancelled && *progress->cancelled)
			return SCE_HTTP_ERROR_ABORTED;
		// Check for silent fails
		if (fd < 0) {
			ERROR_LOG(Log::HTTP, "HTTP Connection lost");
			return SCE_HTTP_DEFAULT_CONNECT_TIMEOUT;
		}
		ready = fd_util::WaitUntilReady(fd, CANCEL_INTERVAL, false);
		if (ready < 0) {
			ERROR_LOG(Log::HTTP, "HTTP WaitUntilReady Failed");
			return SCE_HTTP_DEFAULT_RECV_TIMEOUT;
		}
		if (!ready && time_now_d() > endTimeout) {
			ERROR_LOG(Log::HTTP, "HTTP headers timed out");
			return SCE_HTTP_DEFAULT_RECV_TIMEOUT;
		}
	};
	// Read small chunk
	int ret;
	if ((ret = readbuf->ReadHTML(fd, tls.enabled, (tls.enabled ? &tls : nullptr))) < 0) {
		ERROR_LOG(Log::HTTP, "Failed to read Response -0x%04x", -ret);
		return SCE_HTTP_ERROR_UNKNOWN;
	}

	return ret;
}

int Client::ReadResponseHeaders(net::Buffer *readbuf, std::vector<std::string> &responseHeaders, net::RequestProgress *progress, std::string *statusLine) {
	DEBUG_LOG(Log::HTTP, "ReadResponseHeaders()");
	// maps the socket for HTTPS or HTTP
	int fd = sock();
	static constexpr float CANCEL_INTERVAL = 0.25f;
	// Adjustable read size
	size_t toRead = 64;
	int code = 404;
	int content_length = 0;
	int eoh;
	while (true) {
		int retval = readbuf->Read(fd, toRead, tls.enabled, &tls);
		if (*progress->cancelled)
			return SCE_HTTP_ERROR_ABORTED;
		if (retval < 0)
			return retval;
		// Check for header marker
		eoh = readbuf->Contains("\r\n\r\n");
		// Still no header eof? Try again!
		if (eoh >= 0)
			break;
		DEBUG_LOG(Log::HTTP, "Headers not yet found in %i bytes", readbuf->size());
	}

	std::string header;
	readbuf->Take(eoh + 4, &header);

	// Split lines into responseHeaders
	size_t start = 0;
	size_t end;
	while ((end = header.find("\r\n", start)) != std::string::npos) {
		std::string line = header.substr(start, end - start);
		DEBUG_LOG(Log::HTTP, "HEADER: %s", line.c_str());
		responseHeaders.push_back(line);
		start = end + 2;  // Skip past the \r\n
	}

	return 0;  // Return HTML Status Code or Error Code
}

int Client::ReadPartialResponseEntity(net::Buffer* readbuf, int chunkSize, int contentLength, net::RequestProgress* progress) {
	DEBUG_LOG(Log::HTTP, "ReadPartialResponseEntity()");
	_dbg_assert_(progress->cancelled);

	if (contentLength < 0) {
		WARN_LOG(Log::HTTP, "Negative Content Length %d", contentLength);
		// Just sanity checking...
		contentLength = 0;
	}

	// Minimize calls to readbuf->size() for performance
	int readbufLength = readbuf->size();
	int remainingLength = contentLength - progress->bytes_read;
	progress->Update(0, contentLength, (remainingLength == 0));
	int pack = std::min(remainingLength, chunkSize);
	int obtained = 0;
	// Only read if we're expecting more data
	if (remainingLength > 0) {
		INFO_LOG(Log::sceNet, "ReadResponseEntity - Reading %i bytes of the %i bytes remaining", pack, remainingLength);
		int ret;
		if ((ret = readbuf->Read(sock(), pack, tls.enabled, (tls.enabled ? &tls : nullptr))) < 0)
			return ret;
		obtained = ret;
	}
	progress->Update(obtained, contentLength, (readbufLength == contentLength));
	return 0;
}

int Client::ReadPartialResponseEntity(net::Buffer* readbuf, int chunkSize, int contentLength, net::Buffer* output, net::RequestProgress* progress) {
	DEBUG_LOG(Log::HTTP, "ReadResponseEntity()");
	_dbg_assert_(progress->cancelled);

	if (contentLength < 0) {
		WARN_LOG(Log::HTTP, "Negative Content Length %d", contentLength);
		// Just sanity checking...
		contentLength = 0;
	}
	
	// Minimize calls to readbuf->size() for performance
	int readbufLength = readbuf->size();
	int remainingLength = contentLength - progress->bytes_read;
	progress->Update(0, contentLength, (remainingLength == 0));
	int pack = std::min(remainingLength, chunkSize);
	// Only read if we're expecting more data
	if (remainingLength > 0) {
		INFO_LOG(Log::sceNet, "ReadResponseEntity - %i/%i bytes remaining", remainingLength, contentLength);
		int ret;
		if ((ret = readbuf->ReadAllWithProgress(sock(), pack, progress, tls.enabled, (tls.enabled ? &tls : nullptr))) < 0)
			return ret;
	}

	// Pull out the chunk requested, or everything available, including 0 if required
	int available = readbuf->size();
	int consume = std::min(chunkSize, available);
	if (consume > 0) {
		std::string data;
		readbuf->Take(consume, &data);
		output->Append(data);
	}

	progress->Update(consume, contentLength, (progress->bytes_read + consume == contentLength));
	return 0;
}

int Client::ReadResponseEntity(net::Buffer* readbuf, int contentLength, net::RequestProgress* progress) {
	DEBUG_LOG(Log::HTTP, "ReadResponseEntity()");
	_dbg_assert_(progress->cancelled);

	if (contentLength < 0) {
		WARN_LOG(Log::HTTP, "Negative content length %d", contentLength);
		// Just sanity checking...
		contentLength = 0;
	}
	// Minimize calls to readbuf->size() for performance
	int readbufLength = readbuf->size();
	int remainingLength = contentLength - readbufLength;
	progress->Update(readbufLength - progress->bytes_read, contentLength, (remainingLength == 0));
	// Only read if we're expecting more data
	if (remainingLength > 0) {
		INFO_LOG(Log::sceNet, "ReadResponseEntity - %i/%i bytes remaining", remainingLength, contentLength);
		int ret;
		if ((ret = readbuf->ReadAllWithProgress(sock(), remainingLength, progress, tls.enabled, (tls.enabled ? &tls : nullptr))) < 0)
			return -1;
	}

	progress->Update(contentLength - progress->bytes_read, contentLength, true);
	return 0;
}

int Client::ReadResponseEntity(net::Buffer *readbuf, const std::vector<std::string> &responseHeaders, Buffer *output, net::RequestProgress *progress) {
	DEBUG_LOG(Log::HTTP, "ReadResponseEntity()");
	_dbg_assert_(progress->cancelled);

	bool gzip = false;
	bool chunked = false;
	int contentLength = 0;
	for (std::string line : responseHeaders) {
		if (startsWithNoCase(line, "Content-Length:")) {
			size_t size_pos = line.find_first_of(' ');
			if (size_pos != line.npos) {
				size_pos = line.find_first_not_of(' ', size_pos);
			}
			if (size_pos != line.npos) {
				contentLength = atoi(&line[size_pos]);
				chunked = false;
			}
		} else if (startsWithNoCase(line, "Content-Encoding:")) {
			// TODO: Case folding...
			if (line.find("gzip") != std::string::npos) {
				gzip = true;
			}
		} else if (startsWithNoCase(line, "Transfer-Encoding:")) {
			// TODO: Case folding...
			if (line.find("chunked") != std::string::npos) {
				chunked = true;
			}
		}
	}

	if (contentLength < 0) {
		WARN_LOG(Log::HTTP, "Negative content length %d", contentLength);
		// Just sanity checking...
		contentLength = 0;
	}
	// Minimize calls to readbuf->size() for performance
	int readbufLength = readbuf->size();
	int remainingLength = contentLength - readbufLength;
	progress->Update(readbufLength - progress->bytes_read, contentLength, (remainingLength == 0));
	// Only read if we're expecting more data
	if (remainingLength > 0) {
		INFO_LOG(Log::sceNet, "ReadResponseEntity - %i/%i bytes remaining", remainingLength, contentLength);
		int ret;
		if ((ret = readbuf->ReadAllWithProgress(sock(), remainingLength, progress, tls.enabled, (tls.enabled ? &tls : nullptr))) < 0)
			return -1;
	}
	// output now contains the rest of the reply. Dechunk it.
	if (!output->IsVoid()) {
		if (chunked) {
			if (!DeChunk(readbuf, output, contentLength)) {
				ERROR_LOG(Log::HTTP, "Bad chunked data, couldn't read chunk size");
				progress->Update(0, 0, true);
				return -1;
			}
		} else {
			output->Append(*readbuf);
		}

		// If it's gzipped, we decompress it and put it back in the buffer.
		if (gzip) {
			std::string compressed, decompressed;
			output->TakeAll(&compressed);
			bool result = decompress_string(compressed, &decompressed);
			if (!result) {
				ERROR_LOG(Log::HTTP, "Error decompressing using zlib");
				progress->Update(0, 0, true);
				return -1;
			}
			output->Append(decompressed);
		}
	}

	progress->Update(contentLength - progress->bytes_read, contentLength, true);
	return 0;
}

HTTPRequest::HTTPRequest(RequestMethod method, std::string_view url, std::string_view postData, std::string_view postMime, const Path &outfile, RequestFlags flags, net::ResolveFunc customResolve, std::string_view name)
	: Request(method, url, name, &cancelled_, flags), postData_(postData), postMime_(postMime), customResolve_(customResolve) {
	outfile_ = outfile;
}

HTTPRequest::~HTTPRequest() {
	g_OSD.RemoveProgressBar(url_, !failed_, 0.5f);

	if (thread_.joinable()) {
		_dbg_assert_msg_(false, "Download destructed without join");
	}
}

void HTTPRequest::Start() {
	thread_ = std::thread([this] { Do(); });
}

void HTTPRequest::Join() {
	if (!thread_.joinable()) {
		ERROR_LOG(Log::HTTP, "Already joined thread!");
		_dbg_assert_(false);
	}
	thread_.join();
}

void HTTPRequest::SetFailed(int code) {
	failed_ = true;
	progress_.Update(0, 0, true);
	completed_ = true;
}

int HTTPRequest::Perform(const std::string &url) {
	Url fileUrl(url);
	if (!fileUrl.Valid()) {
		return -1;
	}

	http::Client client(customResolve_);
	if (!userAgent_.empty()) {
		client.SetUserAgent(userAgent_);
	}

	if (!client.Resolve(fileUrl.Host().c_str(), fileUrl.Port())) {
		ERROR_LOG(Log::HTTP, "Failed resolving %s", url.c_str());
		return -1;
	}

	if (cancelled_) {
		return -1;
	}

	if (!client.Connect(2, 20.0, &cancelled_)) {
		ERROR_LOG(Log::HTTP, "Failed connecting to server or cancelled (=%d).", cancelled_);
		return -1;
	}

	if (cancelled_) {
		return -1;
	}

	RequestParams req(fileUrl.Resource(), acceptMime_);
	if (method_ == RequestMethod::GET) {
		return client.GET(req, &buffer_, responseHeaders_, &progress_);
	} else {
		return client.POST(req, postData_, postMime_, &buffer_, &progress_);
	}
}

std::string HTTPRequest::RedirectLocation(const std::string &baseUrl) const {
	std::string redirectUrl;
	if (GetHeaderValue(responseHeaders_, "Location", &redirectUrl)) {
		Url url(baseUrl);
		url = url.Relative(redirectUrl);
		redirectUrl = url.ToString();
	}
	return redirectUrl;
}

void HTTPRequest::Do() {
	SetCurrentThreadName("HTTPDownload::Do");

	AndroidJNIThreadContext jniContext;
	resultCode_ = 0;

	std::string downloadURL = url_;
	while (resultCode_ == 0) {
		// This is where the new request is performed.
		int resultCode = Perform(downloadURL);
		if (resultCode == -1) {
			SetFailed(resultCode);
			return;
		}

		if (resultCode == 301 || resultCode == 302 || resultCode == 303 || resultCode == 307 || resultCode == 308) {
			std::string redirectURL = RedirectLocation(downloadURL);
			if (redirectURL.empty()) {
				ERROR_LOG(Log::HTTP, "Could not find Location header for redirect");
				resultCode_ = resultCode;
			} else if (redirectURL == downloadURL || redirectURL == url_) {
				// Simple loop detected, bail out.
				resultCode_ = resultCode;
			}

			// Perform the next GET.
			if (resultCode_ == 0) {
				INFO_LOG(Log::HTTP, "Download of %s redirected to %s", downloadURL.c_str(), redirectURL.c_str());
				buffer_.clear();
				responseHeaders_.clear();
			}
			downloadURL = redirectURL;
			continue;
		}

		if (resultCode == 200) {
			INFO_LOG(Log::HTTP, "Completed requesting %s (storing result to %s)", url_.c_str(), outfile_.empty() ? "memory" : outfile_.c_str());
			bool clear = !(flags_ & RequestFlags::KeepInMemory);
			if (!outfile_.empty() && !buffer_.FlushToFile(outfile_, clear)) {
				ERROR_LOG(Log::HTTP, "Failed writing download to '%s'", outfile_.c_str());
			}
		} else {
			ERROR_LOG(Log::HTTP, "Error requesting '%s' (storing result to '%s'): %i", url_.c_str(), outfile_.empty() ? "memory" : outfile_.c_str(), resultCode);
		}
		resultCode_ = resultCode;
	}

	// Set this last to ensure no race conditions when checking Done. Users must always check
	// Done before looking at the result code.
	completed_ = true;
}

}  // namespace http
