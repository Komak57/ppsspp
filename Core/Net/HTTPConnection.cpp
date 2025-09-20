#include "HTTPConnection.h"
#include <Log.h>
#include <iterator>
#include <StringUtils.h>
#include <numeric>
#include <chrono>
#include <thread>
#include <sstream>
#include<future>

#include "Core/HLE/HLE.h"
#include "Core/Core.h"
#include "Core/HLE/sceKernel.h"
#include"Core/HLE/sceKernelThread.h"
#include "Core/MemMap.h"
#include "Core/HLE/sceKernelMemory.h"
#include "Core/Debugger/MemBlockInfo.h"
#include "Common/Net/URL.h"
#include "Common/File/FileDescriptor.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int doneload = 0;
test testsesh;
mbedtls_ssl_session test::savedsesh= { 0 };

HTTPTemplate::HTTPTemplate(const char* userAgent, int httpVer, int autoProxyConf) {
	this->userAgent = userAgent ? userAgent : "";
	this->httpVer = (SceHttpVersion)httpVer;
	this->autoProxyConf = (SceHttpProxyMode)autoProxyConf;
}
HTTPTemplate::~HTTPTemplate() {
	WARN_LOG(Log::sceNet, "HTTPTemplate::~HTTPTemplate()");
}

int HTTPTemplate::addRequestHeader(const char* name, const char* value, u32 mode) {
	// Note: std::map doesn't support key duplication, will need std::multimap to support SCE_HTTP_HEADER_ADD mode
	//if (mode != SCE_HTTP_HEADER_OVERWRITE)
	//	return SCE_HTTP_ERROR_NOT_SUPPORTED; // FIXME: PSP might not support mode other than SCE_HTTP_HEADER_OVERWRITE (0)
	// Handle User-Agent separately, since PSP Browser seems to add "User-Agent" header manually
	if (mode == SCE_HTTP_HEADER_OVERWRITE) {
		std::string s = name;
		std::transform(s.begin(), s.end(), s.begin(), [](const unsigned char i) { return std::tolower(i); });
		if (s == "user-agent")
			setUserAgent(value);
	}

	requestHeaders[name] = value;
	return 0;
}

int HTTPTemplate::removeRequestHeader(const char* name) {
	requestHeaders.erase(name);
	return 0;
}
int HTTPTemplate::setCert(std::string certificate) {
	if (certificate.size() == 0)
		return -1;
	certPEM = certificate;
	return 0;
}

HTTPConnection::HTTPConnection(int templateID, const char* hostString, const char* scheme, u32 port, int enableKeepalive) {
	// Copy base data as initial base value for this
	HTTPTemplate::operator=(*httpObjects.find(templateID)->second.get());

	// Initialize
	this->templateID = templateID;
	this->hostString = hostString;
	this->scheme = scheme;
	this->port = port;
	this->enableKeepalive = enableKeepalive;
	if (strcmp(scheme, "https") == 0) {
		this->tls = HTTPS_Config2();
		Resolve(hostString, port, net::DNSType::IPV4);
		InitializeSSL();
		wolfSSL_CTX_set_cipher_list(tls.sslConfig, "DES-CBC3-SHA:RC4-MD5:RC4-SHA");
	}
}

HTTPConnection::~HTTPConnection() {
	WARN_LOG(Log::sceNet, "HTTPConnection::~HTTPConnection(templateID: %i)", this->templateID);
	// NOTE: Do not clean up and free SSL resources here. The entire parent collapses on destruction.
	// Instead, clean up these in sceHttpDeleteConnection
}

void HTTPConnection::Disconnect() {
	if (tls.enabled) {
	}
}

bool HTTPConnection::Resolve(const char* host, int port, net::DNSType type) {
	if (!host || port < 1 || port > 65535) {
		ERROR_LOG(Log::IO, "Resolve: Invalid host or port (%d)", port);
		lastError = SCE_HTTP_ERROR_NETWORK;
		return false;
	}

	this->host = host;
	this->port = port;

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", port);

	std::string processedHostname(host);

	std::string err;
	if (!net::DNSResolve(processedHostname.c_str(), port_str, &resolved_, err, type)) {
		WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (%s)", host, err.c_str(), DNSTypeAsString(type));
		// Zero port so that future calls fail.
		port = 0;
		lastError = SCE_HTTP_ERROR_PARSE_HTTP_NOT_FOUND;
		return false;
	}

	return true;
}

bool HTTPConnection::Connect(int maxTries, double timeout, bool* cancelConnect) {
	if (tls.enabled)
		return SSLConnect(maxTries, timeout, cancelConnect);
	WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
	_dbg_assert_(!tls.enabled);
	return hleLogError(Log::sceNet, false, "HTTP Not Supported Yet");
}

//bool HTTPConnection::handshake_async(int maxTries, double timeout, bool* cancelConnect) {
//	auto start_time = std::chrono::high_resolution_clock::now();
//	auto end_time = std::chrono::high_resolution_clock::now();
//	long long duration_ms = 0;
//	int ret;
//	NOTICE_LOG(Log::sceNet, "SSLConnect - Performing the SSL/TLS handshake...");
//	start_time = std::chrono::high_resolution_clock::now();
//	while ((ret = mbedtls_ssl_handshake(&tls.sslCtx)) != 0) {
//		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
//			char errbuf[128];
//			mbedtls_strerror(ret, errbuf, sizeof(errbuf));
//			ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_handshake ERROR -0x%x: %s", (unsigned int)-ret, errbuf);
//			//goto retry;
//			return false;
//		}
//		std::this_thread::sleep_for(std::chrono::seconds(1));
//	}
//	end_time = std::chrono::high_resolution_clock::now();
//	duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
//	if (duration_ms > 100)
//		ERROR_LOG(Log::sceNet, "SSLConnect - Handshake took %dms", duration_ms);
//	else if (duration_ms > 60)
//		WARN_LOG(Log::sceNet, "SSLConnect - Handshake took %dms", duration_ms);
//	else
//		NOTICE_LOG(Log::sceNet, "SSLConnect - Handshake took %dms", duration_ms);
//	return true;
//}

std::future<int> connection_result_future;

bool HTTPConnection::SSLConnect(int maxTries, double timeout, bool* cancelConnect) {
	WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::SSLConnect(%i, %f, %p)", maxTries, timeout, cancelConnect);

	if (port <= 0) {
		ERROR_LOG(Log::IO, "SSLConnect - Bad port");
		lastError = SCE_HTTP_ERROR_NETWORK;
		return false;
	}

	for (int tries = maxTries; tries > 0; --tries) {
		for (addrinfo* possible = resolved_; possible != nullptr; possible = possible->ai_next) {
			if (possible->ai_family != AF_INET && possible->ai_family != AF_INET6)
				continue;

			char addrStr[128]{};
			FormatAddr(addrStr, sizeof(addrStr), possible);
			if (strncmp(addrStr, "0.0.0.0", 8) == 0) {
				ERROR_LOG(Log::sceNet, "SSLConnect - Cannot connect to loopback.");
				return false;
			}

			char portStr[8]{};
			snprintf(portStr, sizeof(portStr), "%d", port);

			// 1. Connect TCP socket
			int sockfd = socket(possible->ai_family, possible->ai_socktype, possible->ai_protocol);
			if (sockfd < 0) {
				ERROR_LOG(Log::sceNet, "SSLConnect - socket() failed");
				continue;
			}

			if (connect(sockfd, possible->ai_addr, possible->ai_addrlen) < 0) {
				ERROR_LOG(Log::sceNet, "SSLConnect - connect() failed");
				close(sockfd);
				continue;
			}

			// Set nonblocking if needed
			fd_util::SetNonBlocking(sockfd, true);

			// 2. Create SSL object
			tls.sslCtx = wolfSSL_new(tls.sslConfig);
			if (!tls.sslCtx) {
				ERROR_LOG(Log::sceNet, "SSLConnect - wolfSSL_new() failed");
				close(sockfd);
				continue;
			}

			wolfSSL_set_fd(tls.sslCtx, sockfd);

			// 3. Hostname verification (SNI)
			if (wolfSSL_check_domain_name(tls.sslCtx, host.c_str()) != SSL_SUCCESS) {
				WARN_LOG(Log::sceNet, "SSLConnect - could not set SNI/hostname");
			}
#ifdef WOLFSSL_DES3
			printf("DES3 enabled in this build\n");
#else
			printf("DES3 NOT enabled\n");
#endif

#ifdef WOLFSSL_RC4
			printf("RC4 is enabled in this build\n");
#else
			printf("RC4 is NOT enabled\n");
#endif

#ifdef WOLFSSL_ENCRYPT_THEN_MAC
			printf("eh");
#else
			printf("he");
#endif

			wolfSSL_CTX_SetMinVersion(tls.sslConfig, WOLFSSL_TLSV1);
			INFO_LOG(Log::sceNet, "Ciphers: \n %i", wolfSSL_get_ciphers);
			
			// Force legacy cipher suites
			char* legacyCipherstest = "DES-CBC3-SHA:RC4-SHA:RC4-MD5";
			char test = wolfSSL_get_ciphers(legacyCipherstest, strlen(legacyCipherstest));
			const char* legacyCiphers = "DES-CBC3-SHA";
			if (wolfSSL_CTX_set_cipher_list(tls.sslConfig, legacyCiphers) != WOLFSSL_SUCCESS) {
				return hleLogError(Log::sceNet, -1, "Failed to set legacy cipher list");
			}

			// 4. Resume session if available
			if (tls.session) {
				if (wolfSSL_set_session(tls.sslCtx, tls.session) != SSL_SUCCESS) {
					WARN_LOG(Log::sceNet, "SSLConnect - Failed to resume session, continuing");
				}
			}

			

			// 5. TLS Handshake
			NOTICE_LOG(Log::sceNet, "SSLConnect - Performing the SSL/TLS handshake...");
			auto start_time = std::chrono::high_resolution_clock::now();

			int ret;
			while ((ret = wolfSSL_connect(tls.sslCtx)) != SSL_SUCCESS) {
				int err = wolfSSL_get_error(tls.sslCtx, ret);
				if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
					ERROR_LOG(Log::sceNet, "SSLConnect - wolfSSL_connect failed: %d", err);
					wolfSSL_free(tls.sslCtx);
					tls.sslCtx = nullptr;
					close(sockfd);
					goto retry;
				}
				// yield thread if needed
				SceUID thread = __KernelGetCurThread();
				if (!KernelIsThreadWaiting(thread)) {
					__KernelResumeThreadFromWait(thread, 0);
				}
			}

			auto end_time = std::chrono::high_resolution_clock::now();
			long long duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
			if (duration_ms > 100)
				ERROR_LOG(Log::sceNet, "SSLConnect - Handshake took %lldms", duration_ms);
			else if (duration_ms > 60)
				WARN_LOG(Log::sceNet, "SSLConnect - Handshake took %lldms", duration_ms);
			else
				NOTICE_LOG(Log::sceNet, "SSLConnect - Handshake took %lldms", duration_ms);

			// 6. Verify certificate
			if (GetOption(28)) {
				const WOLFSSL_X509* cert = wolfSSL_get_peer_certificate(tls.sslCtx);
				if (cert != nullptr) {
					// Peer certificate exists
					INFO_LOG(Log::sceNet, "SSLConnect - Peer certificate received");
				}
				else {
					WARN_LOG(Log::sceNet, "SSLConnect - No peer certificate received");
				}
			}


			// 7. Save session
			tls.session = wolfSSL_get_session(tls.sslCtx);

			INFO_LOG(Log::sceNet, "SSLConnect - Connection Successful");
			connected = true;
			doneload = 1;
			return true;

		retry:
			INFO_LOG(Log::sceNet, "SSLConnect - Connection Failed, retrying");
			ResetSSL();
			continue;
		}
	}

	lastError = SCE_HTTP_ERROR_PARSE_HTTP_NOT_FOUND;
	return false;
}


HTTPRequest::HTTPRequest(int connectionID, int method, const char* url, u64 contentLength) : progress(&cancelled) {
	// Copy base data as initial base value for this
	// Since dynamic_cast/dynamic_pointer_cast/typeid requires RTTI to be enabled (ie. /GR instead of /GR- on msvc, enabled by default on most compilers), so we can only use static_cast here
	HTTPConnection::operator=(static_cast<HTTPConnection&>(*httpObjects.find(connectionID)->second.get()));

	// Initialize
	this->connectionID = connectionID;
	this->method = method;
	this->contentLength = contentLength;

	if (tls.enabled) {
		NOTICE_LOG(Log::HTTP, "HTTPRequest::HTTPRequest() - Re-Enabling TLS Session");
		//this->tls.session = test::savedsesh;
		wolfSSL_set_session(this->tls.sslCtx, this->tls.session);
	}

	// Note: LittleBigPlanet onlu passed the path (ie. /LITTLEBIGPLANETPSP_XML/login?) during sceHttpCreateRequest without the host domain, thus will need to be construced into a valid URI using the data from sceHttpCreateConnection upon validating/parsing the URL.
	if (startsWithNoCase(url, "/")) {
		this->fullURL = scheme + "://" + hostString + ":" + std::to_string(port) + url;
	}
	// Simulate connected
	ErrorCode = SCE_HTTP_OKAY;
}

HTTPRequest::~HTTPRequest() {
	WARN_LOG(Log::HTTP, "HTTPRequest::~HTTPRequest(connectionID: %i)", this->connectionID);
	abortRequest();
	if (Memory::IsValidAddress(headerAddr_))
		userMemory.Free(headerAddr_);
}

int HTTPRequest::getResponseContentLength() {
	// Split lines into responseHeaders
	static const std::string clen = "Content-Length:";
	static const std::string tenc = "Transfer-Encoding:";
	// Process additional conditions
	for (const std::string& line : responseHeaders) {
		if (line != "") {
			// Find Content Length
			if (line.size() > clen.size() && strncasecmp(line.data(), clen.data(), clen.size()) == 0) {
				size_t size_pos = line.find_first_of(' ');
				if (size_pos != line.npos) {
					size_pos = line.find_first_not_of(' ', size_pos);
				}
				if (size_pos != line.npos) {
					// Resize to read remaining length
					this->contentLength = atoi(&line[size_pos]);
				}
			}
			else if (line.size() > tenc.size() && strncasecmp(line.data(), tenc.data(), tenc.size()) == 0) {
				std::string value = line.substr(tenc.size());
				std::transform(value.begin(), value.end(), value.begin(), ::tolower);
				if (value.find("chunked") != std::string::npos) {
					WARN_LOG(Log::HTTP, "HTTP Response is chunked");
				}
			}
		}
	}
	// Reset Progress to indicate how much data is in the buffer
	progress = core::RequestProgress(&cancelled);
	progress.Update(readbuf.size(), contentLength, false);
	return this->contentLength;
}

int HTTPRequest::abortRequest() {
	// FIXME: Will sceHttpAbortRequest returns an error if the request was not sent yet?
	//if (progress_.progress == 0.0f)
		//return SCE_HTTP_ERROR_BEFORE_SEND;
	return 0;
}

int HTTPRequest::getStatusCode() {
	// Find HTTP Code
	{
		std::string line = responseHeaders[0];

		size_t code_pos = line.find(' ');
		if (code_pos != line.npos) {
			code_pos = line.find_first_not_of(' ', code_pos);
		}

		if (code_pos != line.npos) {
			this->responseCode_ = atoi(&line[code_pos]);
		}
		else {
			ERROR_LOG(Log::HTTP, "Could not parse HTTP status code: '%s'", line.c_str());
			this->responseCode_ = -1;
		}
	}
	return responseCode_;
}

int HTTPRequest::getAllResponseHeaders(u32 headerAddrPtr, u32 headerSizePtr) {
	// FIXME: Will sceHttpGetAllHeader returns an error if the request was not sent yet?
	//if (progress_.progress == 0.0f)
	//	return SCE_HTTP_ERROR_BEFORE_SEND;
	const char* const delim = "\r\n";
	std::ostringstream imploded;
	std::copy(responseHeaders.begin(), responseHeaders.end(), std::ostream_iterator<std::string>(imploded, delim));
	const std::string& s = httpLine_ + delim + imploded.str();
	u32 sz = (u32)s.size();

	auto headerAddr = PSPPointer<u32>::Create(headerAddrPtr);
	auto headerSize = PSPPointer<u32>::Create(headerSizePtr);
	// Resize internal header buffer (should probably be part of network memory pool?)
	// FIXME: Do we still need to provides a valid address for the game even when header size is 0 ?
	if (headerSize_ != sz && sz > 0) {
		if (Memory::IsValidAddress(headerAddr_)) {
			userMemory.Free(headerAddr_);
		}
		headerAddr_ = userMemory.Alloc(sz, false, "sceHttp response headers");
		headerSize_ = sz;
	}

	u8* header = Memory::GetPointerWrite(headerAddr_);
	DEBUG_LOG(Log::HTTP, "headerAddr: %08x => %08x", headerAddr.IsValid() ? *headerAddr : 0, headerAddr_);
	DEBUG_LOG(Log::HTTP, "headerSize: %d => %d", headerSize.IsValid() ? *headerSize : 0, sz);
	if (!header && sz > 0) {
		ERROR_LOG(Log::HTTP, "Failed to allocate internal header buffer.");
		//*headerSize = 0;
		//*headerAddr = 0;
		return SCE_HTTP_ERROR_OUT_OF_MEMORY; // SCE_HTTP_ERROR_TOO_LARGE_RESPONSE_HEADER
	}

	if (sz > 0) {
		memcpy(header, s.c_str(), sz);
		NotifyMemInfo(MemBlockFlags::WRITE, headerAddr_, sz, "HttpGetAllHeader");
	}

	// Set the output
	if (headerSize.IsValid()) {
		*headerSize = sz;
		headerSize.NotifyWrite("HttpGetAllHeader");
	}

	if (headerAddr.IsValid()) {
		*headerAddr = headerAddr_;
		headerAddr.NotifyWrite("HttpGetAllHeader");
	}

	DEBUG_LOG(Log::HTTP, "Headers: %s", s.c_str());
	return 0;
}

int HTTPRequest::readData(u32 destDataPtr, u32 size) {
	// Minimize calls to readbuf->size() for performance
	size_t readbufLength = readbuf.size();
	u32 remainingLength = contentLength - progress.bytes_read;
	progress.Update(0, contentLength, (remainingLength == 0));
	int pack = std::min(remainingLength, size);
	int obtained = 0;
	// Only read if we're expecting more data
	if (remainingLength > 0) {
		INFO_LOG(Log::sceNet, "ReadResponseEntity - Reading %i bytes of the %i bytes remaining", pack, remainingLength);
		int ret;
		if (tls.enabled)
			ret = readbuf.Read(tls.sockfd, sizeof(pack), &tls);
		else
			ret = readbuf.Read(fd, pack, nullptr);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Unable to read HTTP response entity: %d", ret);
		}
		obtained = ret;
	}
	progress.Update(obtained, contentLength, (remainingLength == 0));

	//entity_.TakeAll(&responseContent_);
	if (cancelled) {
		return SCE_HTTP_ERROR_ABORTED;
	}

	u32 sz = std::min(size, (u32)readbuf.size());
	if (sz > 0) {
		std::string entity;
		readbuf.Take(sz, &entity);

		DEBUG_LOG(Log::HTTP, "Buffer has %d bytes, writing %d bytes", entity.length(), sz);
		Memory::MemcpyUnchecked(destDataPtr, entity.c_str(), sz);
		NotifyMemInfo(MemBlockFlags::WRITE, destDataPtr, sz, "HttpReadData");
		entity.erase(0, sz);
	}
	return sz;
}

std::map<u32, std::shared_ptr<HTTPConnection>> conn;

int HTTPRequest::sendRequest(u32 postDataPtr, u32 postDataSize) {
	//auto request_ptr = std::static_pointer_cast<HTTPConnection>(httpObjects.find(templateID)->second);
	//std::future<bool> async_result = std::async(std::launch::async, [&]() {
	//	return request_ptr->SSLConnect();
	//	if (async_result.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
	//	}
	//	
	//	});

	SSLConnect();
	while (!connected) {

	}
	//std::thread worker([&]() {return SSLConnect(); });
	//worker.detach();

	// FIXME: Probably doesn't adhere to the new requestHeaders format
	if (postDataSize > 0)
		requestHeaders["Content-Length"] = std::to_string(postDataSize);
	const std::string delimiter = "\r\n";
	const std::string extraHeaders = std::accumulate(requestHeaders.begin(), requestHeaders.end(), std::string(),
		[delimiter](const std::string& s, const std::pair<const std::string, std::string>& p) {
			return s + p.first + ": " + p.second + delimiter;
		});

	Url fileUrl(this->fullURL);
	if (!fileUrl.Valid()) {
		ErrorCode = SCE_HTTP_ERROR_INVALID_URL;
		return ErrorCode;
	}

	// Send the Request
	std::string methodstr = "GET";
	switch (method) {
	case PSP_HTTP_METHOD_POST:
		methodstr = "POST";
		break;
	case PSP_HTTP_METHOD_HEAD:
		methodstr = "HEAD";
		break;
	default:
		break;
	}

	progress = core::RequestProgress(&cancelled);
	//RequestParams req(fileUrl.Resource(), "*/*");
	const char* postData = Memory::GetCharPointer(postDataPtr);
	if (postDataSize > 0)
		NotifyMemInfo(MemBlockFlags::READ, postDataPtr, postDataSize, "HttpSendRequest");

	//int err = client.SendRequestWithData(methodstr.c_str(), req, std::string(postData ? postData : "", postData ? postDataSize : 0), extraHeaders.c_str(), &progress_);
	progress.Update(0, 0, false);

	const char* tpl =
		"%s %s HTTP/%s\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Accept: %s\r\n"
		"Connection: close\r\n"
		"%s"
		"\r\n";

	const char* mime = "*/*";
	const char* extra = !extraHeaders.empty() ? extraHeaders.c_str() : "";

	readbuf.Printf(tpl,
		methodstr.c_str(), fileUrl.Resource().c_str(), HTTP_VERSION,
		host.c_str(),
		userAgent.c_str(),
		mime,
		extra);
	std::string data = std::string(postData ? postData : "", postData ? postDataSize : 0);
	readbuf.Append(data);
	if (tls.enabled) {
		bool flushed = readbuf.FlushSocketSSL(&tls, dataTimeout_, progress.cancelled);
		if (!flushed) {
			return -1;  // TODO error code.
		}
	}
	else {
		bool flushed = readbuf.FlushSocket(fd, dataTimeout_, progress.cancelled);
		if (!flushed) {
			return -1;  // TODO error code.
		}
	}

	if (cancelled) {
		ErrorCode = SCE_HTTP_ERROR_ABORTED;
		return ErrorCode;
	}

	//responseCode_ = client.ReadResponseHeaders(&this->buffer_, responseHeaders_, &this->progress_, &httpLine_);
	static constexpr float CANCEL_INTERVAL = 0.25f;
	// Adjustable read size
	size_t toRead = 64;
	int code = 404;
	int content_length = 0;
	int eoh;
	while (true) {
		int retval = readbuf.Read(tls.sockfd, toRead, &tls);
		if (cancelled)
			return SCE_HTTP_ERROR_ABORTED;
		if (retval < 0)
			return retval;
		// Check for header marker
		eoh = readbuf.Contains("\r\n\r\n");
		// Still no header eof? Try again!
		if (eoh >= 0)
			break;
		DEBUG_LOG(Log::HTTP, "Headers not yet found in %i bytes", readbuf.size());
	}

	std::string header;
	readbuf.Take(eoh + 4, &header);

	// Split lines into responseHeaders
	size_t start = 0;
	size_t end;
	while ((end = header.find("\r\n", start)) != std::string::npos) {
		std::string line = header.substr(start, end - start);
		DEBUG_LOG(Log::HTTP, "HEADER: %s", line.c_str());
		responseHeaders.push_back(line);
		start = end + 2;  // Skip past the \r\n
	}

	return ErrorCode;
}
