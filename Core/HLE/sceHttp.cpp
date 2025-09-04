// Copyright (c) 2012- PPSSPP Project.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0 or later versions.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License 2.0 for more details.

// A copy of the GPL 2.0 should have been included with the program.
// If not, see http://www.gnu.org/licenses/

// Official git repository and contact information can be found at
// https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.

#include <sstream>
#include <iterator>
#include <numeric>
#include <mutex>
#include <algorithm>
#include <cctype> // for std::tolower

#include "Core/Core.h"
#include "Core/HLE/HLE.h"
#include "Core/HLE/FunctionWrappers.h"
#include "Core/HLE/sceKernelMemory.h"
#include "Core/HLE/sceHttp.h"
#include "Core/HLE/sceNet.h"
#include "Core/Debugger/MemBlockInfo.h"
#include "Common/StringUtils.h"
#include "Common/LogReporting.h"
#include "Common/Net/URL.h"
#include "Common/Net/HTTPClient.h"
#include <Common/File/FileDescriptor.h>
#include <SysError.h>

static std::map<u32, std::shared_ptr<HTTPTemplate>> httpObjects;
static std::mutex httpLock;

bool httpInited = false;
bool httpsInited = false;
bool httpCacheInited = false;

u32 NextObjectID() {
	if (httpObjects.empty())
		return 0;
	return httpObjects.rbegin()->first + 1;
}

HTTPTemplate bufferTemplate;
//static SSL_CTX* pspSslCtx = nullptr;

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

	requestHeaders_[name] = value;
	return 0;
}

int HTTPTemplate::removeRequestHeader(const char* name) {
	requestHeaders_.erase(name);
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
		this->tls = HTTPS_Config();
		Resolve(hostString, port, net::DNSType::IPV4);
		InitializeSSL();
		SSLConnect();
	}
}

HTTPConnection::~HTTPConnection() {
	WARN_LOG(Log::sceNet, "HTTPConnection::~HTTPConnection(templateID: %i)", this->templateID);
	// NOTE: Do not clean up and free SSL resources here. The entire parent collapses on destruction.
	// Instead, clean up these in sceHttpDeleteConnection
}

void HTTPConnection::Disconnect() {
	if (tls.enabled) {
		ResetSSL();
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
	if (tlsEnabled)
		return SSLConnect(maxTries, timeout, cancelConnect);
	WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
	_dbg_assert_(!tlsEnabled);
	return hleLogError(Log::sceNet, false, "HTTP Not Supported Yet");
}

bool HTTPConnection::SSLConnect(int maxTries, double timeout, bool* cancelConnect) {
	WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::SSLConnect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
	if (port <= 0) {
		ERROR_LOG(Log::IO, "SSLConnect - Bad port");
		lastError = SCE_HTTP_ERROR_NETWORK;
		return false;
	}
	// This will only occur if we pass the tls pointer correctly
	// Currently doesn't function as desired.
	if (tls.connected) {
		mbedtls_ssl_session_reset(&tls.sslCtx);
		mbedtls_ssl_config_free(&tls.sslConfig);

		mbedtls_ssl_free(&tls.sslCtx);
		mbedtls_net_free(&tls.netCtx);

		mbedtls_ssl_set_session(&tls.sslCtx, &tls.session);
		tls.connected = false;
	}


	for (int tries = maxTries; tries > 0; --tries) {
		mbedtls_ssl_setup(&tls.sslCtx, &tls.sslConfig);
		for (addrinfo* possible = resolved_; possible != nullptr; possible = possible->ai_next) {
			if (possible->ai_family != AF_INET && possible->ai_family != AF_INET6)
				continue;

			int ret;
			/*
			 * 1. Start the connection
			 */
			char addrStr[128]{};
			memset(addrStr, 0, 128);
			FormatAddr(addrStr, sizeof(addrStr), possible);
			if (strncmp(addrStr, "0.0.0.0", 8) == 0) {
				ERROR_LOG(Log::sceNet, "SSLConnect - Cannot connect to loopback.");
				return false;
			}
			char portStr[8]{};
			memset(portStr, 0, 8);
			memcpy(portStr, std::to_string(port).c_str(), std::to_string(port).length());
			if ((ret = mbedtls_net_connect(&tls.netCtx, addrStr, portStr, MBEDTLS_NET_PROTO_TCP)) != 0) {
				ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_net_connect(netCtx, %s, %s, PROTO_TCP) call to %s failed with -0x%04x)", addrStr, portStr, (unsigned int)-ret);
				goto retry;
			}
			// Set NonBlocking
			fd_util::SetNonBlocking(tls.netCtx.fd, true);
			/*
			 * 2. Setup stuff
			 */
			if ((ret = mbedtls_ssl_setup(&tls.sslCtx, &tls.sslConfig)) != 0) {
				ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_setup returned 0x%04x", ret);
				goto retry;
			}

			//if ((ret = mbedtls_ssl_set_hostname(&sslCtx, possible->ai_addr->sa_data)) != 0) {
			if ((ret = mbedtls_ssl_set_hostname(&tls.sslCtx, host.c_str())) != 0) {
				char errbuf[128];
				mbedtls_strerror(ret, errbuf, sizeof(errbuf));
				ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_set_hostname returned -0x%04x (%s)", (unsigned int)-ret, errbuf);
				goto retry;
			}

			mbedtls_ssl_set_bio(&tls.sslCtx, &tls.netCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

			/*
			 * 4. Handshake
			 */
			NOTICE_LOG(Log::sceNet, "SSLConnect - Performing the SSL/TLS handshake...");
			auto start_time = std::chrono::high_resolution_clock::now();
			while ((ret = mbedtls_ssl_handshake(&tls.sslCtx)) != 0) {
				if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_handshake ERROR -0x%x: %s", (unsigned int)-ret, errbuf);
					goto retry;
				}
			}
			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
			if (duration_ms > 100)
				ERROR_LOG(Log::sceNet, "SSLConnect - Handshake took %dms", duration_ms);
			else if (duration_ms > 60)
				WARN_LOG(Log::sceNet, "SSLConnect - Handshake took %dms", duration_ms);
			else
				NOTICE_LOG(Log::sceNet, "SSLConnect - Handshake took %dms", duration_ms);
			// Fake latency
			std::this_thread::sleep_for(std::chrono::milliseconds(60 - duration_ms));
			/*
			 * 5. Verify the server certificate
			 */
			 // HTTPS Option 28 may relate to disabling this check
			if (GetOption(28)) {
				NOTICE_LOG(Log::sceNet, "SSLConnect - Verifying peer X.509 certificate...");

				/* In real life, we probably want to bail out when ret != 0 */
				u32 flags;
				if ((flags = mbedtls_ssl_get_verify_result(&tls.sslCtx)) != 0) {
					char vrfy_buf[512];

					mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_get_verify_result failed: %s", vrfy_buf);
					goto retry;
				}
			}
			INFO_LOG(Log::sceNet, "SSLConnect - Connection Successful");
			tls.connected = true;
			// Save session for recycle
			mbedtls_ssl_get_session(&tls.sslCtx, &tls.session);
			return true;
		retry:
			INFO_LOG(Log::sceNet, "SSLConnect - Connection Failed, retrying");
			mbedtls_ssl_session_reset(&tls.sslCtx);
			mbedtls_ssl_config_free(&tls.sslConfig);

			mbedtls_ssl_free(&tls.sslCtx);
			mbedtls_net_free(&tls.netCtx);

			continue;
		}
	}
	lastError = SCE_HTTP_ERROR_PARSE_HTTP_NOT_FOUND;
	return false;
}

HTTPRequest::HTTPRequest(int connectionID, int method, const char *url, u64 contentLength, net::ResolveFunc customResolver) : client(customResolver), progress_(&cancelled_) {
	// Copy base data as initial base value for this
	// Since dynamic_cast/dynamic_pointer_cast/typeid requires RTTI to be enabled (ie. /GR instead of /GR- on msvc, enabled by default on most compilers), so we can only use static_cast here
	HTTPConnection::operator=(static_cast<HTTPConnection&>(*httpObjects.find(connectionID)->second.get()));
	
	// Initialize
	this->connectionID = connectionID;
	this->method = method;
	this->contentLength = contentLength;
	this->progress_ = net::RequestProgress(&cancelled_);

	if (tls.enabled) {
		NOTICE_LOG(Log::HTTP, "HTTPRequest::HTTPRequest() - Re-Enabling TLS Session");
		client.Initialize(this->tls, this->httpsOptions);
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
	client.Disconnect();
	if (Memory::IsValidAddress(headerAddr_))
		userMemory.Free(headerAddr_);
}

int HTTPRequest::getResponseContentLength() {
	// Split lines into responseHeaders
	static const std::string clen = "Content-Length:";
	static const std::string tenc = "Transfer-Encoding:";
	// Process additional conditions
	for (const std::string& line : responseHeaders_) {
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
	return this->contentLength;
}

int HTTPRequest::abortRequest() {
	// FIXME: Will sceHttpAbortRequest returns an error if the request was not sent yet?
	if (progress_.progress == 0.0f)
		return SCE_HTTP_ERROR_BEFORE_SEND;
	return 0;
}

int HTTPRequest::getStatusCode() {
	// Find HTTP Code
	{
		std::string line = responseHeaders_[0];
	
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
	std::copy(responseHeaders_.begin(), responseHeaders_.end(), std::ostream_iterator<std::string>(imploded, delim));
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
	// TODO: Read response entity within readData() in smaller chunk(based on size arg of sceHttpReadData) instead of the whole content at once here
	net::Buffer partial;
	int res = client.ReadPartialResponseEntity(&this->buffer_, size, contentLength, &partial, &progress_);
	if (res != 0) {
		ERROR_LOG(Log::sceNet, "Unable to read HTTP response entity: %d", res);
	}
	//entity_.TakeAll(&responseContent_);
	if (cancelled_) {
		return SCE_HTTP_ERROR_ABORTED;
	}

	std::string entity;
	partial.TakeAll(&entity);

	u32 sz = std::min(size, (u32)entity.length());
	if (sz > 0) {
		DEBUG_LOG(Log::HTTP, "Buffer has %d bytes, writing %d bytes", entity.length(), sz);
		Memory::MemcpyUnchecked(destDataPtr, entity.c_str(), sz);
		NotifyMemInfo(MemBlockFlags::WRITE, destDataPtr, sz, "HttpReadData");
		entity.erase(0, sz);
	}
	return sz;
}

int HTTPRequest::sendRequest(u32 postDataPtr, u32 postDataSize) {
	// FIXME: Probably doesn't adhere to the new requestHeaders format
	if (postDataSize > 0)
		requestHeaders_["Content-Length"] = std::to_string(postDataSize);
	const std::string delimiter = "\r\n";
	const std::string extraHeaders = std::accumulate(requestHeaders_.begin(), requestHeaders_.end(), std::string(),
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

	net::RequestProgress progress_(&cancelled_);
	http::RequestParams req(fileUrl.Resource(), "*/*");
	const char* postData = Memory::GetCharPointer(postDataPtr);
	if (postDataSize > 0)
		NotifyMemInfo(MemBlockFlags::READ, postDataPtr, postDataSize, "HttpSendRequest");
	
	int err = client.SendRequestWithData(methodstr.c_str(), req, std::string(postData ? postData : "", postData ? postDataSize : 0), extraHeaders.c_str(), &progress_);
	if (err < 0)
		return err;

	if (cancelled_) {
		ErrorCode = SCE_HTTP_ERROR_ABORTED;
		return ErrorCode;
	}

	responseCode_ = client.ReadResponseHeaders(&this->buffer_, responseHeaders_, &this->progress_, &httpLine_);
	return ErrorCode;
}

void __HttpInit() {
}

void __HttpShutdown() {
	std::lock_guard<std::mutex> guard(httpLock);
	httpInited = false;
	httpsInited = false;
	httpCacheInited = false;

	for (const auto& it : httpObjects) {
		if (it.second->className() == name_HTTPRequest)
			(static_cast<HTTPRequest*>(it.second.get()))->abortRequest();
	}
	httpObjects.clear();
}

// id: ID of the template or connection
int sceHttpSetResolveRetry(int connectionID, int retryCount) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpSetResolveRetry(%d, %d)", connectionID, retryCount);
	if (connectionID <= 0 || connectionID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(connectionID)->second.get();
	if (!(conn->className() == name_HTTPTemplate || conn->className() == name_HTTPConnection))
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id (%s)", conn->className());

	conn->setResolveRetry(retryCount);
	return 0;
}

static int sceHttpInit(int poolSize) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpInit(%i) at %08x", poolSize, currentMIPS->pc);
	if (httpInited)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_ALREADY_INITED, "http already inited");

	std::lock_guard<std::mutex> guard(httpLock);
	httpObjects.clear();
	// Reserve at least 1 element to prevent ::begin() from returning null when no element has been added yet
	//httpObjects.reserve(1);
	// sceHttpsInit fails if we don't have something in httpObjects
	u32 id = NextObjectID();
	httpObjects[id] = std::make_shared<HTTPTemplate>();
	httpInited = true;
	return id; // should we return the template id?
}

static int sceHttpEnd() {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpEnd()");
	std::lock_guard<std::mutex> guard(httpLock);
	httpObjects.clear();
	httpInited = false;
	return 0;
}

static int sceHttpInitCache(int size) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpInitCache(%d)", size);
	httpCacheInited = true;
	return 0;
}

static int sceHttpEndCache() {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpEndCache()");
	httpCacheInited = false;
	return 0;
}

static int sceHttpEnableCache(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpEnableCache(%d)", templateID);
	return 0;
}

// FIXME: Can be TemplateID or ConnectionID ? Megaman PoweredUp seems to use both id on sceHttpDisableCache
static int sceHttpDisableCache(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpDisableCache(%d)", templateID);
	return 0;
}

static u32 sceHttpGetProxy(u32 id, u32 activateFlagPtr, u32 modePtr, u32 proxyHostPtr, u32 len, u32 proxyPort) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpGetProxy(%d, %x, %x, %x, %d, %x)", id, activateFlagPtr, modePtr, proxyHostPtr, len, proxyPort);
	return 0;
}

static int sceHttpGetStatusCode(int requestID, u32 statusCodePtr) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpGetStatusCode(%d, %x)", requestID, statusCodePtr);
	if (requestID <= 0 || requestID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (!Memory::IsValidRange(statusCodePtr, 4))
		return hleLogError(Log::sceNet, -1, "invalid arg"); //SCE_HTTP_ERROR_INVALID_VALUE;

	const auto& req = (HTTPRequest*)httpObjects.find(requestID)->second.get();
	// FIXME: According to JPCSP, try to connect the request first
	//req->connect();
	int status = req->getStatusCode();
	
	WARN_LOG(Log::sceNet, "StatusCode = %d (in) => %d (out)", Memory::ReadUnchecked_U32(statusCodePtr), status);
	Memory::WriteUnchecked_U32(status, statusCodePtr);
	NotifyMemInfo(MemBlockFlags::WRITE, statusCodePtr, 4, "HttpGetStatusCode");
	return 0;
}

// Games will repeatedly called sceHttpReadData until it returns (the size read into the data buffer) 0
// FIXME: sceHttpReadData seems to be blocking current thread, since hleDelayResult can make Download progressbar to moves progressively instead of instantly jump to 100%
static int sceHttpReadData(int requestID, u32 dataPtr, u32 dataSize) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpReadData(%d, %x, %d)", requestID, dataPtr, dataSize);
	if (requestID <= 0 || requestID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (!Memory::IsValidRange(dataPtr, dataSize)) 
		return hleLogError(Log::sceNet, -1, "invalid arg"); // SCE_HTTP_ERROR_INVALID_VALUE

	const auto& req = (HTTPRequest*)httpObjects.find(requestID)->second.get();
	// FIXME: According to JPCSP, try to connect the request first
	//req->connect();

	DEBUG_LOG(Log::HTTP, "Entity remaining: size = %d / %d", req->getResponseRemainingContentLength(), req->getResponseContentLength());
	//if (req->getResponseContentLength()) == 0)
	//	return hleLogError(SCENET, SCE_HTTP_ERROR_NO_CONTENT_LENGTH, "no content length");
	int retval = req->readData(dataPtr, dataSize);
	if (retval < 0)
		return hleLogError(Log::sceNet, retval, "Invalid Data Response");

	// Debug Print
	if (retval > 0) {
		u8* data = (u8*)Memory::GetPointerUnchecked(dataPtr);
		char* strdata = new char[retval];
		memcpy(strdata, data, retval);
		HEX_LOG(Log::HTTP, "Data Dump:", strdata, retval);
		/*std::string datahex;
		DataToHexString(10, 0, data, retval, &datahex);
		DEBUG_LOG(Log::HTTP, "Data Dump (%d bytes):\n%s", retval, datahex.c_str());*/
	}

	// Faking latency to slow down download progressbar, since we currently downloading the full content at once instead of in chunk per sceHttpReadData's dataSize
	return hleDelayResult(hleLogDebug(Log::sceNet, retval), "fake read data latency", 5000);
}

// FIXME: JPCSP didn't do anything other than appending the data into internal buffer, does sceHttpSendRequest can be called multiple times before using sceHttpGetStatusCode or sceHttpReadData? any game do this?
static int sceHttpSendRequest(int requestID, u32 dataPtr, u32 dataSize) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpSendRequest(%d, %x, %d)", requestID, dataPtr, dataSize);
	if (!httpInited)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_BEFORE_INIT, "http not initialized yet");

	if (requestID <= 0 || requestID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (dataSize > 0 && !Memory::IsValidRange(dataPtr, dataSize))
		return hleLogError(Log::sceNet, -1, "invalid arg"); // SCE_HTTP_ERROR_INVALID_VALUE

	int objId = NextObjectID();
	const auto& req = (HTTPRequest*)httpObjects.find(requestID)->second.get();
	// Internally try to connect, and get response headers (at least the status code?)
	int retval = -1;
	/*if (req->isSSLEnabled())
		retval = req->sendSSLRequest(dataPtr, dataSize);
	else*/
		retval = req->sendRequest(dataPtr, dataSize);
	return hleLogDebug(Log::sceNet, retval);
}

static int sceHttpDeleteRequest(int requestID) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpDeleteRequest(%d)", requestID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (requestID <= 0 || requestID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects.find(requestID)->second->className() != name_HTTPRequest)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");
	//httpObjects.erase(httpObjects.begin() + requestID - 1);
	httpObjects.erase(requestID);
	return 0;
}

// id: ID of the template, connection or request 
static int sceHttpDeleteHeader(int id, const char *name) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpDeleteHeader(%d, %s)", id, safe_string(name));
	if (id <= 0 || id >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& req = (HTTPRequest*)httpObjects.find(id)->second.get();
	return req->removeRequestHeader(name);
}

static int sceHttpDeleteConnection(int connectionID) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpDisableCache(%d)", connectionID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (connectionID <= 0 || connectionID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects.find(connectionID)->second->className() != name_HTTPConnection)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = (HTTPConnection*)httpObjects.find(connectionID)->second.get();

	conn->Disconnect();
	//httpObjects.erase(httpObjects.begin() + connectionID - 1);
	httpObjects.erase(connectionID);
	return 0;
}

// id: ID of the template, connection or request
static int sceHttpSetConnectTimeOut(int templateID, u32 timeout) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpSetConnectTimeout(%d, %d)", templateID, timeout);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(templateID)->second.get();
	conn->setConnectTimeout(timeout);
	return 0;
}

// id: ID of the template, connection or request
static int sceHttpSetSendTimeOut(int templateID, u32 timeout) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetSendTimeout(%d, %d)", templateID, timeout);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(templateID)->second.get();
	conn->setSendTimeout(timeout);
	return 0;
}

static u32 sceHttpSetProxy(u32 templateID, u32 activateFlagPtr, u32 mode, u32 newProxyHostPtr, u32 newProxyPort) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetProxy(%d, %x, %x, %x, %d)", templateID, activateFlagPtr, mode, newProxyHostPtr, newProxyPort);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(templateID)->second.get();
	conn->setProxy();

	return 0;
}

// id: ID of the template or connection
static int sceHttpEnableCookie(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpEnableCookie(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(templateID)->second.get();
	conn->enableCookie();

	return 0;
}

// id: ID of the template or connection
static int sceHttpEnableKeepAlive(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpEnableKeepAlive(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(templateID)->second.get();
	conn->enableKeepAlive();

	return 0;
}

// id: ID of the template or connection
static int sceHttpDisableCookie(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpDisableCookie(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(templateID)->second.get();
	conn->enableCookie();

	return 0;
}

// id: ID of the template or connection
static int sceHttpDisableKeepAlive(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpDisableKeepAlive(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(templateID)->second.get();
	conn->enableKeepAlive();

	return 0;
}

static int sceHttpsInit(int ctxId, int certPtr, int unknown3, int unknown4) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpsInit(%d, %x, %d, %d)", ctxId, certPtr, unknown3, unknown4);
	if (httpsInited) {
		return 0;  // Already initialized
	}

	// Patapon3 doesn't provide a certPtr
    // Portable Ops doesn't provide a certPtr
	if (certPtr == 0)
		WARN_LOG(Log::sceNet, "sceHttpsInit: No cert provided");

	if (certPtr != 0) {

		u32 memPtr = Memory::Read_U32(certPtr);
		if (!Memory::IsValidRange(memPtr, 1)) {
			ERROR_LOG(Log::sceNet, "sceHttpsInit: certPtr points to invalid address: %08x", certPtr);
			return -1;
		}

		u32 certAddr = Memory::Read_U32(memPtr);
		if (!Memory::IsValidRange(certAddr, 1)) {
			ERROR_LOG(Log::sceNet, "sceHttpsInit: certAddrPtr points to invalid address: %08x", memPtr);
			return -1;
		}

		// Read 8192 bytes of data until we reach a zero terminal
		std::string certPEM = "";
		for (size_t i = 0; i < 8192; ++i) {
			if (!Memory::IsValidAddress(certAddr + i)) {
				ERROR_LOG(Log::sceNet, "sceHttpsInit: Invalid memory at PEM offset %08x", certAddr + i);
				return -1;
			}

			u8 ch = Memory::Read_U8(certAddr + i);
			if (ch == 0)
				break;

			certPEM.push_back(ch);
		}
		INFO_LOG(Log::sceNet, "%s - CERTIFICATE:", __FUNCTION__);
		size_t i = 0;
		while (i < certPEM.size()) {
			size_t newline = certPEM.find('\n', i);
			size_t end = std::min(i + 64, newline != std::string::npos ? newline + 1 : certPEM.size());
			INFO_LOG(Log::sceNet, "%s - %s", __FUNCTION__, certPEM.substr(i, end - i).c_str());
			i = end;
		}

		bufferTemplate.setCert(certPEM);
	}
	bufferTemplate.tls.enabled = true;
	httpsInited = true;
	return 0;
}

static int sceHttpsInitWithPath(int unknown1, int unknown2, int unknown3) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpsInitWithPath(%d, %d, %d)", unknown1, unknown2, unknown3);
	httpsInited = true;
	return 0;
}

static int sceHttpsEnd() {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpsEnd()");
	httpsInited = false;
	return 0;
}

static int sceHttpsEnableOption(int optionId) {
	// sceHttpsEnableOption accepts the ssl flags, not an id
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpsEnableOption(%d)", optionId);
	switch (optionId) {
	default:
		WARN_LOG(Log::sceNet, "%s - UNKNOWN %d Enabled", __FUNCTION__, optionId);
		break;
	}
	bufferTemplate.enableOption(optionId);
	return 0;
}

static int sceHttpsDisableOption(int optionId) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpsDisableOption(%d)", optionId);
	switch (optionId) {
	default:
		WARN_LOG(Log::sceNet, "%s - UNKNOWN %d Disabled", __FUNCTION__, optionId);
		break;
	}
	bufferTemplate.disableOption(optionId);
	return 0;
}

// Parameter "method" should be one of PSPHttpMethod's listed entries
static int sceHttpCreateRequest(int connectionID, int method, const char *path, u64 contentLength) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpCreateRequest(%d, %d, %s, %d)", connectionID, method, safe_string(path), contentLength);
	std::lock_guard<std::mutex> guard(httpLock);
	if (connectionID <= 0 || connectionID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects.find(connectionID)->second->className() != name_HTTPConnection)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (method < PSPHttpMethod::PSP_HTTP_METHOD_GET || method > PSPHttpMethod::PSP_HTTP_METHOD_HEAD)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_UNKNOWN_METHOD, "unknown method");

	int objId = NextObjectID();
	auto req = std::make_shared<HTTPRequest>(connectionID, method, path ? path : "", contentLength, &ProcessHostnameWithInfraDNS);
	if (req->getErrorCode() < 0)
		return hleLogError(Log::sceNet, req->getErrorCode());
	httpObjects[objId] = req;
	return hleLogDebug(Log::sceNet, objId);
}

// FIXME: port type is probably u16 (but passed in a single register anyway, so type doesn't matter)
static int sceHttpCreateConnection(int templateID, const char *hostString, const char *scheme, u32 port, int enableKeepalive) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpCreateConnection(%d, %s, %s, %d, %d)", templateID, safe_string(hostString), safe_string(scheme), port, enableKeepalive);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects.find(templateID)->second->className() != name_HTTPTemplate)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	// TODO: Look up hostString in DNS here.
	int objId = NextObjectID();
	auto conn = std::make_shared<HTTPConnection>(templateID, hostString ? hostString : "", scheme ? scheme : "", port, enableKeepalive);
	//conn->InitializeSSL();
	//conn->Connect();
	httpObjects[objId] = conn;
	return hleLogDebug(Log::sceNet, objId);
}

static int sceHttpGetNetworkErrno(int request, u32 errNumPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpGetNetworkErrno(%d, %x)", request, errNumPtr);
	if (Memory::IsValidRange(errNumPtr, 4)) {
		INFO_LOG(Log::sceNet, "Input errNum = %d", Memory::ReadUnchecked_U32(errNumPtr));
		Memory::WriteUnchecked_U32(0, errNumPtr); // dummy error code 0 (no error?)
		NotifyMemInfo(MemBlockFlags::WRITE, errNumPtr, 4, "HttpGetNetworkErrno");
	}
	return 0;
}

// id: ID of the template, connection or request
static int sceHttpAddExtraHeader(int id, const char *name, const char *value, int unknown) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpAddExtraHeader(%d, %s, %s, %d)", id, safe_string(name), safe_string(value), unknown);
	if (id <= 0 || id >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& req = httpObjects.find(id)->second.get();
	return req->addRequestHeader(name, value, unknown);
}

static int sceHttpAbortRequest(int requestID) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpAbortRequest(%d)", requestID);
	if (requestID <= 0 || requestID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& req = (HTTPRequest*)httpObjects.find(requestID)->second.get();
	return req->abortRequest();
}

static int sceHttpDeleteTemplate(int templateID) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpDeleteTemplate(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects.find(templateID)->second->className() != name_HTTPTemplate)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	httpObjects.erase(templateID);
	return 0;
}

static int sceHttpSetMallocFunction(u32 mallocFuncPtr, u32 freeFuncPtr, u32 reallocFuncPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetMallocFunction(%x, %x, %x)", mallocFuncPtr, freeFuncPtr, reallocFuncPtr);
	return 0;
}

// id: ID of the template or connection
static int sceHttpSetResolveTimeOut(int id, u32 timeout) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetResolveTimeOut(%d, %d)", id, timeout);
	if (id <= 0 || id >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(id)->second.get();
	if (!(conn->className() == name_HTTPTemplate || conn->className() == name_HTTPConnection))
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id (%s)", conn->className());

	conn->setResolveTimeout(timeout);
	return 0;
}

//typedef int(* SceHttpsCallback) (unsigned int verifyEsrr, void *const sslCert[], int certNum, void *userArg)
static int sceHttpsSetSslCallback(int id, u32 callbackFuncPtr, u32 userArgPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpsSetSslCallback(%d, %x, %x)", id, callbackFuncPtr, userArgPtr);
	return 0;
}

//typedef int(*SceHttpRedirectCallback) (int request, int statusCode, int* method, const char* location, void* userArg);
static int sceHttpSetRedirectCallback(int requestID, u32 callbackFuncPtr, u32 userArgPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetRedirectCallback(%d, %x, %x)", requestID, callbackFuncPtr, userArgPtr);
	return 0;
}

//typedef int(*SceHttpAuthInfoCallback) (int request, SceHttpAuthType authType, const char* realm, char* username, char* password, int needEntity, unsigned char** entityBody, unsigned int* entitySize, int* save, void* userArg);
static int sceHttpSetAuthInfoCallback(int id, u32 callbackFuncPtr, u32 userArgPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetAuthInfoCallback(%d, %x, %x)", id, callbackFuncPtr, userArgPtr);
	return 0;
}

static int sceHttpSetAuthInfoCB(int id, u32 callbackFuncPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetAuthInfoCB(%d, %x)", id, callbackFuncPtr);
	return 0;
}

// id: ID of the template or connection
static int sceHttpEnableRedirect(int id) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpEnableRedirect(%d)", id);
	return 0;
}

static int sceHttpEnableAuth(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpEnableAuth(%d)", templateID);
	return 0;
}

// id: ID of the template or connection
static int sceHttpDisableRedirect(int id) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpDisableRedirect(%d)", id);
	return 0;
}

static int sceHttpDisableAuth(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpDisableAuth(%d)", templateID);
	return 0;
}

static int sceHttpSaveSystemCookie() {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSaveSystemCookie()");
	return 0;
}

static int sceHttpsLoadDefaultCert(int unknown1, int unknown2) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpLoadDefaultCert(%d, %d)", unknown1, unknown2);
	return 0;
}

static int sceHttpLoadSystemCookie() {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpLoadSystemCookie()");
	return 0;
}

// PSP Browser seems to set userAgent to 0 and later set the User-Agent header using sceHttpAddExtraHeader
static int sceHttpCreateTemplate(const char *userAgent, int httpVer, int autoProxyConf) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpCreateTemplate(%s, %d, %d) at %08x", safe_string(userAgent), httpVer, autoProxyConf, currentMIPS->pc);
	// Reporting to find more games to be tested
	WARN_LOG_REPORT_ONCE(sceHttpCreateTemplate, Log::sceNet, "UNTESTED sceHttpCreateTemplate(%s, %d, %d)", safe_string(userAgent), httpVer, autoProxyConf);
	std::lock_guard<std::mutex> guard(httpLock);
	auto tmplate = std::make_shared<HTTPTemplate>(userAgent ? userAgent : "", httpVer, autoProxyConf);
	// Copy buffer data to new template
	// FIXME: Find a more appropriate way to buffer HTTPS Options
	tmplate->CopyFrom(bufferTemplate);
	u32 id = NextObjectID();
	httpObjects[id] = tmplate;

	return hleLogDebug(Log::sceNet, id);
}

// Parameter "method" should be one of PSPHttpMethod's listed entries
static int sceHttpCreateRequestWithURL(int connectionID, int method, const char *url, u64 contentLength) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpCreateRequestWithURL(%d, %d, %s, %llx)", connectionID, method, safe_string(url), contentLength);
	std::lock_guard<std::mutex> guard(httpLock);
	if (connectionID <= 0 || connectionID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects.find(connectionID)->second->className() != name_HTTPConnection)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (method < PSPHttpMethod::PSP_HTTP_METHOD_GET || method > PSPHttpMethod::PSP_HTTP_METHOD_HEAD)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_UNKNOWN_METHOD, "unknown method");

	Url baseURL(url ? url : "");
	if (!baseURL.Valid())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_URL, "invalid url");

	u32 id = NextObjectID();
	httpObjects[id] = std::make_shared<HTTPRequest>(connectionID, method, url ? url : "", contentLength, &ProcessHostnameWithInfraDNS);
	return hleLogDebug(Log::sceNet, id);
}

static int sceHttpCreateConnectionWithURL(int templateID, const char *url, int enableKeepalive) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpCreateConnectionWithURL(%d, %s, %d)", templateID, safe_string(url), enableKeepalive);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects.find(templateID)->second->className() != name_HTTPTemplate)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	Url baseURL(url ? url: "");
	if (!baseURL.Valid())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_URL, "invalid url");

	u32 id = NextObjectID();
	httpObjects[id] = std::make_shared<HTTPConnection>(templateID, baseURL.Host().c_str(), baseURL.Protocol().c_str(), baseURL.Port(), enableKeepalive);
	return hleLogDebug(Log::sceNet, id);
}

// id: ID of the template or connection
static int sceHttpSetRecvTimeOut(int id, u32 timeout) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpSetRecvTimeOut(%d, %d)", id, timeout);
	if (id <= 0 || id >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects.find(id)->second.get();
	if (!(conn->className() == name_HTTPTemplate || conn->className() == name_HTTPConnection))
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id (%s)", conn->className());

	conn->setRecvTimeout(timeout);
	return 0;
}

// FIXME: Headers should includes the "HTTP/MajorVer.MinorVer StatusCode Comment" line? so PSP Browser can parse it using sceParseHttpStatusLine
// Note: Megaman PoweredUp seems to have an invalid address stored at the headerAddrPtr location, may be the game expecting us (network library) to give them a valid header address?
static int sceHttpGetAllHeader(int requestID, u32 headerAddrPtr, u32 headerSizePtr) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpGetAllHeader(%d, %x, %x)", requestID, headerAddrPtr, headerSizePtr);
	if (requestID <= 0 || requestID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (!Memory::IsValidRange(headerAddrPtr, 4))
		return hleLogError(Log::sceNet, -1, "invalid arg"); //SCE_HTTP_ERROR_INVALID_VALUE;

	if (!Memory::IsValidRange(headerSizePtr, 4)) 
		return hleLogError(Log::sceNet, -1, "invalid arg"); //SCE_HTTP_ERROR_INVALID_VALUE;

	const auto& req = (HTTPRequest*)httpObjects.find(requestID)->second.get();
	// FIXME: According to JPCSP, try to connect the request first
	//req->connect();
	int retval = req->getAllResponseHeaders(headerAddrPtr, headerSizePtr);
	return hleLogDebug(Log::sceNet, retval);
}

// FIXME: contentLength is SceULong64 but this contentLengthPtr argument should be a 32bit pointer instead of 64bit, right?
static int sceHttpGetContentLength(int requestID, u32 contentLengthPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpGetContentLength(%d, %x)", requestID, contentLengthPtr);
	if (requestID <= 0 || requestID >= NextObjectID())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (!Memory::IsValidRange(contentLengthPtr, 8))
		return hleLogError(Log::sceNet, -1, "invalid arg"); //SCE_HTTP_ERROR_INVALID_VALUE;

	const auto& req = (HTTPRequest*)httpObjects.find(requestID)->second.get();
	// FIXME: According to JPCSP, try to connect the request first
	//req->connect();
	int len = req->getResponseContentLength();
	if (len < 0)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_NO_CONTENT_LENGTH, "no content length");

	DEBUG_LOG(Log::HTTP, "ContentLength = %lld (in) => %lld (out)", Memory::Read_U64(contentLengthPtr), (u64)len);
	Memory::Write_U64((u64)len, contentLengthPtr);
	NotifyMemInfo(MemBlockFlags::WRITE, contentLengthPtr, 8, "HttpGetContentLength");
	return 0;
}

/*
0x62411801 sceSircsInit
0x19155a2f sceSircsEnd
0x71eef62d sceSircsSend
*/
const HLEFunction sceHttp[] = {
	{0XAB1ABE07, &WrapI_I<sceHttpInit>,                      "sceHttpInit",                    'i', "i"     },
	{0XD1C8945E, &WrapI_V<sceHttpEnd>,                       "sceHttpEnd",                     'i', ""      },
	{0XA6800C34, &WrapI_I<sceHttpInitCache>,                 "sceHttpInitCache",               'i', "i"     },
	{0X78B54C09, &WrapI_V<sceHttpEndCache>,                  "sceHttpEndCache",                'i', ""      },
	{0X59E6D16F, &WrapI_I<sceHttpEnableCache>,               "sceHttpEnableCache",             'i', "i"     },
	{0XCCBD167A, &WrapI_I<sceHttpDisableCache>,              "sceHttpDisableCache",            'i', "i"     },
	{0XD70D4847, &WrapU_UUUUUU<sceHttpGetProxy>,             "sceHttpGetProxy",                'x', "xxxxxx"},
	{0X4CC7D78F, &WrapI_IU<sceHttpGetStatusCode>,            "sceHttpGetStatusCode",           'i', "ix"    },
	{0XEDEEB999, &WrapI_IUU<sceHttpReadData>,                "sceHttpReadData",                'i', "ixx"   },
	{0XBB70706F, &WrapI_IUU<sceHttpSendRequest>,             "sceHttpSendRequest",             'i', "ixx"   },
	{0XA5512E01, &WrapI_I<sceHttpDeleteRequest>,             "sceHttpDeleteRequest",           'i', "i"     },
	{0X15540184, &WrapI_IC<sceHttpDeleteHeader>,             "sceHttpDeleteHeader",            'i', "is"    },
	{0X5152773B, &WrapI_I<sceHttpDeleteConnection>,          "sceHttpDeleteConnection",        'i', "i"     },
	{0X8ACD1F73, &WrapI_IU<sceHttpSetConnectTimeOut>,        "sceHttpSetConnectTimeOut",       'i', "ix"    },
	{0X9988172D, &WrapI_IU<sceHttpSetSendTimeOut>,           "sceHttpSetSendTimeOut",          'i', "ix"    },
	{0XF0F46C62, &WrapU_UUUUU<sceHttpSetProxy>,              "sceHttpSetProxy",                'x', "xxxxx" },
	{0X0DAFA58F, &WrapI_I<sceHttpEnableCookie>,              "sceHttpEnableCookie",            'i', "i"     },
	{0X78A0D3EC, &WrapI_I<sceHttpEnableKeepAlive>,           "sceHttpEnableKeepAlive",         'i', "i"     },
	{0X0B12ABFB, &WrapI_I<sceHttpDisableCookie>,             "sceHttpDisableCookie",           'i', "i"     },
	{0XC7EF2559, &WrapI_I<sceHttpDisableKeepAlive>,          "sceHttpDisableKeepAlive",        'i', "i"     },
	{0XE4D21302, &WrapI_IIII<sceHttpsInit>,                  "sceHttpsInit",                   'i', "iiii"  },
	{0XF9D8EB63, &WrapI_V<sceHttpsEnd>,                      "sceHttpsEnd",                    'i', ""      },
	{0X47347B50, &WrapI_IICU64<sceHttpCreateRequest>,        "sceHttpCreateRequest",           'i', "iisX"  },
	{0X8EEFD953, &WrapI_ICCUI<sceHttpCreateConnection>,      "sceHttpCreateConnection",        'i', "issxi" },
	{0XD081EC8F, &WrapI_IU<sceHttpGetNetworkErrno>,          "sceHttpGetNetworkErrno",         'i', "ix"    },
	{0X3EABA285, &WrapI_ICCI<sceHttpAddExtraHeader>,         "sceHttpAddExtraHeader",          'i', "issi"  },
	{0XC10B6BD9, &WrapI_I<sceHttpAbortRequest>,              "sceHttpAbortRequest",            'i', "i"     },
	{0XFCF8C055, &WrapI_I<sceHttpDeleteTemplate>,            "sceHttpDeleteTemplate",          'i', "i"     },
	{0XF49934F6, &WrapI_UUU<sceHttpSetMallocFunction>,       "sceHttpSetMallocFunction",       'i', "xxx"   },
	{0X03D9526F, &WrapI_II<sceHttpSetResolveRetry>,          "sceHttpSetResolveRetry",         'i', "ii"    },
	{0X47940436, &WrapI_IU<sceHttpSetResolveTimeOut>,        "sceHttpSetResolveTimeOut",       'i', "ix"    },
	{0X2A6C3296, &WrapI_IU<sceHttpSetAuthInfoCB>,            "sceHttpSetAuthInfoCB",           'i', "ix"    },
	{0X0809C831, &WrapI_I<sceHttpEnableRedirect>,            "sceHttpEnableRedirect",          'i', "i"     },
	{0X9FC5F10D, &WrapI_I<sceHttpEnableAuth>,                "sceHttpEnableAuth",              'i', "i"     },
	{0X1A0EBB69, &WrapI_I<sceHttpDisableRedirect>,           "sceHttpDisableRedirect",         'i', "i"     },
	{0XAE948FEE, &WrapI_I<sceHttpDisableAuth>,               "sceHttpDisableAuth",             'i', "i"     },
	{0X76D1363B, &WrapI_V<sceHttpSaveSystemCookie>,          "sceHttpSaveSystemCookie",        'i', ""      },
	{0X87797BDD, &WrapI_II<sceHttpsLoadDefaultCert>,         "sceHttpsLoadDefaultCert",        'i', "ii"    },
	{0XF1657B22, &WrapI_V<sceHttpLoadSystemCookie>,          "sceHttpLoadSystemCookie",        'i', ""      },
	{0X9B1F1F36, &WrapI_CII<sceHttpCreateTemplate>,          "sceHttpCreateTemplate",          'i', "sii"   },
	{0XB509B09E, &WrapI_IICU64<sceHttpCreateRequestWithURL>, "sceHttpCreateRequestWithURL",    'i', "iisX"  },
	{0XCDF8ECB9, &WrapI_ICI<sceHttpCreateConnectionWithURL>, "sceHttpCreateConnectionWithURL", 'i', "isi"   },
	{0X1F0FC3E3, &WrapI_IU<sceHttpSetRecvTimeOut>,           "sceHttpSetRecvTimeOut",          'i', "ix"    },
	{0XDB266CCF, &WrapI_IUU<sceHttpGetAllHeader>,            "sceHttpGetAllHeader",            'i', "ixx"   },
	{0X0282A3BD, &WrapI_IU<sceHttpGetContentLength>,         "sceHttpGetContentLength",        'i', "ix"    },
	{0X7774BF4C, nullptr,                                    "sceHttpAddCookie",               '?', ""      },
	{0X68AB0F86, &WrapI_III<sceHttpsInitWithPath>,           "sceHttpsInitWithPath",           'i', "iii"   },
	{0XB3FAF831, &WrapI_I<sceHttpsDisableOption>,            "sceHttpsDisableOption",          'i', "i"     },
	{0X2255551E, nullptr,                                    "sceHttpGetNetworkPspError",      '?', ""      },
	{0XAB1540D5, nullptr,                                    "sceHttpsGetSslError",            '?', ""      },
	{0XA4496DE5, &WrapI_IUU<sceHttpSetRedirectCallback>,     "sceHttpSetRedirectCallback",     'i', "ixx"   },
	{0X267618F4, &WrapI_IUU<sceHttpSetAuthInfoCallback>,     "sceHttpSetAuthInfoCallback",     'i', "ixx"   },
	{0X569A1481, &WrapI_IUU<sceHttpsSetSslCallback>,         "sceHttpsSetSslCallback",         'i', "ixx"   },
	{0XBAC31BF1, &WrapI_I<sceHttpsEnableOption>,             "sceHttpsEnableOption",           'i', "i"     },
};				

void Register_sceHttp()
{
	RegisterHLEModule("sceHttp",ARRAY_SIZE(sceHttp),sceHttp);
}
