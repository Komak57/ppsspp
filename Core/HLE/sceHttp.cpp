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
#include "Core/Debugger/MemBlockInfo.h"
#include "Common/StringUtils.h"
#include "Common/LogReporting.h"
#include "Common/Net/URL.h"
#include "Common/Net/HTTPClient.h"
#include <mbedtls\debug.h>
 // HTTPS Requirements from OpenSSL 1.1.1
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <openssl/x509.h>
//#include <openssl/x509_vfy.h>
//static std::unordered_map<int, bool> httpsOptions;

static std::vector<std::shared_ptr<HTTPTemplate>> httpObjects;
static std::mutex httpLock;

bool httpInited = false;
bool httpsInited = false;
bool httpCacheInited = false;

HTTPTemplate bufferTemplate;
//static SSL_CTX* pspSslCtx = nullptr;

HTTPTemplate::HTTPTemplate(const char* userAgent, int httpVer, int autoProxyConf) {
	this->userAgent = userAgent ? userAgent : "";
	this->httpVer = (SceHttpVersion)httpVer;
	this->autoProxyConf = (SceHttpProxyMode)autoProxyConf;
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
	HTTPTemplate::operator=(*httpObjects[templateID - 1LL]);

	// Initialize
	this->templateID = templateID;
	this->hostString = hostString;
	this->scheme = scheme;
	this->port = port;
	this->enableKeepalive = enableKeepalive;
}
HTTPConnection::~HTTPConnection() {
	WARN_LOG(Log::sceNet, "HTTPConnection::~HTTPConnection(%i)", this->templateID);
	// Clean up and free SSL resources
}

int HTTPConnection::InitializeSSL() {
	WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::InitializeSSL()");
	this->useAuth = useAuth;

	mbedtls_net_init(&netCtx);
	mbedtls_ssl_init(&sslCtx);
	mbedtls_ssl_config_init(&sslConfig);
	mbedtls_ctr_drbg_init(&ctrDrbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_debug_set_threshold(4);

	if (mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
		ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to seed RNG");
		return -1;
	}

	// MPO Doesn't provide a cert here
	if (certPEM.size() == 0)
		WARN_LOG(Log::sceNet, "InitializeSSL: No cert provided.");
	// Initialize CA certificate store
	// Note: certPEM MUST be pointing to a valid certificate, or it will cause a strlen crash
	// PSP2i has it at 0x08e73a04
	if (certPEM.size() > 0) {
		mbedtls_x509_crt_init(&caCert);
		int ret = mbedtls_x509_crt_parse(&caCert, (const unsigned char*)certPEM.c_str(), certPEM.size() + 1);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to parse cert: -0x%04x", -ret);
			return -1;
		}
	}

	// Setup SSL config
	if (mbedtls_ssl_config_defaults(&sslConfig,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to set SSL config defaults");
		return -1;
	}

	/* OPTIONAL is not optimal for security,
	 * but makes interop easier in this simplified example */
	if (useAuth)
		mbedtls_ssl_conf_authmode(&sslConfig, MBEDTLS_SSL_VERIFY_OPTIONAL);
	else
		mbedtls_ssl_conf_authmode(&sslConfig, MBEDTLS_SSL_VERIFY_NONE);
	if (certPEM.size() > 0)
		mbedtls_ssl_conf_ca_chain(&sslConfig, &caCert, NULL);
	mbedtls_ssl_conf_rng(&sslConfig, mbedtls_ctr_drbg_random, &ctrDrbg);
	mbedtls_ssl_conf_dbg(&sslConfig, ssl_debug, NULL);

	// Check compiled Ciphers
	/*const int* ciphers = mbedtls_ssl_list_ciphersuites();
	int cipherCount = 0;
	for (const int* c = ciphers; *c != 0; ++c)
		++cipherCount;
	INFO_LOG(Log::sceNet, "sceHttpsInit: Parsing %i ciphers", cipherCount);
	for (int i = 0; i < cipherCount; i++) {
		INFO_LOG(Log::sceNet, "sceHttpsInit: ciphers[%i] = 0x%04x = %s", i, ciphers[i], mbedtls_ssl_get_ciphersuite_name(ciphers[i]));
	}*/

	// Enable Legacy Cipher
	//mbedtls_ssl_conf_ciphersuites(&sslConfig, net::legacy_ciphersuites_array); // optional if you’ve recompiled with weak cipher support
	// Limit to TLS 1.0 - TLS 1.2 to match Hardware Limitations
	mbedtls_ssl_conf_min_version(&sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
	mbedtls_ssl_conf_max_version(&sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	enableTLS();
	return 0;
}


HTTPRequest::HTTPRequest(int connectionID, int method, const char* url, u64 contentLength) {
	// Copy base data as initial base value for this
	// Since dynamic_cast/dynamic_pointer_cast/typeid requires RTTI to be enabled (ie. /GR instead of /GR- on msvc, enabled by default on most compilers), so we can only use static_cast here
	HTTPConnection::operator=(static_cast<HTTPConnection&>(*httpObjects[connectionID - 1LL]));
	
	// Initialize
	this->connectionID = connectionID;
	this->method = method;
	this->url = url ? url : "";
	this->contentLength = contentLength;

	if (tlsEnabled) {
		client.Initialize(this->sslCtx, this->netCtx, this->sslConfig, this->ctrDrbg, this->entropy, this->caCert);
	}
	//progress_.cancelled = &cancelled_;
	responseContent_.clear();
}

HTTPRequest::~HTTPRequest() {
	client.Disconnect();
	if (Memory::IsValidAddress(headerAddr_))
		userMemory.Free(headerAddr_);
}

int HTTPRequest::getResponseContentLength() {
	// FIXME: Will sceHttpGetContentLength returns an error if the request was not sent yet?
	//if (progress_.progress == 0.0f)
	//	return SCE_HTTP_ERROR_BEFORE_SEND;

	entityLength_ = -1; // FIXME: should we default to 0 instead?
	for (std::string& line : responseHeaders_) {
		if (startsWithNoCase(line, "Content-Length")) {
			size_t pos = line.find_first_of(':');
			if (pos != line.npos) {
				pos++;
				entityLength_ = atoi(&line[pos]);
			}
		}
	}
	return entityLength_;
}

int HTTPRequest::abortRequest() {
	cancelled_ = true;
	// FIXME: Will sceHttpAbortRequest returns an error if the request was not sent yet?
	//if (progress_.progress == 0.0f)
	//	return SCE_HTTP_ERROR_BEFORE_SEND;
	return 0;
}

int HTTPRequest::getStatusCode() {
	// FIXME: Will sceHttpGetStatusCode returns an error if the request was not sent yet?
	//if (progress_.progress == 0.0f)
	//	return SCE_HTTP_ERROR_BEFORE_SEND;
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
	DEBUG_LOG(Log::sceNet, "headerAddr: %08x => %08x", headerAddr.IsValid() ? *headerAddr : 0, headerAddr_);
	DEBUG_LOG(Log::sceNet, "headerSize: %d => %d", headerSize.IsValid() ? *headerSize : 0, sz);
	if (!header && sz > 0) {
		ERROR_LOG(Log::sceNet, "Failed to allocate internal header buffer.");
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

	DEBUG_LOG(Log::sceNet, "Headers: %s", s.c_str());
	return 0;
}

int HTTPRequest::readData(u32 destDataPtr, u32 size) {
	// FIXME: Will sceHttpReadData returns an error if the request was not sent yet?
	//if (progress_.progress == 0.0f)
	//	return SCE_HTTP_ERROR_BEFORE_SEND;
	u32 sz = std::min(size, (u32)responseContent_.size());
	if (sz > 0) {
		Memory::MemcpyUnchecked(destDataPtr, responseContent_.c_str(), sz);
		NotifyMemInfo(MemBlockFlags::WRITE, destDataPtr, sz, "HttpReadData");
		responseContent_.erase(0, sz);
	}
	return sz;
}

int HTTPRequest::sendRequest(u32 postDataPtr, u32 postDataSize) {
	// Initialize Connection
	client.SetDataTimeout(getRecvTimeout() / 1000000.0);
	// Initialize Headers
	if (getHttpVer() == SCE_HTTP_VERSION_1_0)
		client.SetHttpVersion("1.0");
	else
		client.SetHttpVersion("1.1");
	client.SetUserAgent(getUserAgent());
	if (postDataSize > 0)
		requestHeaders_["Content-Length"] = std::to_string(postDataSize);
	const std::string delimiter = "\r\n";
	const std::string extraHeaders = std::accumulate(requestHeaders_.begin(), requestHeaders_.end(), std::string(),
		[delimiter](const std::string& s, const std::pair<const std::string, std::string>& p) {
			return s + p.first + ": " + p.second + delimiter;
		});

	// TODO: Do this on a separate thread, since this may blocks "Emu" thread here
	// Try to resolve first
	// Note: LittleBigPlanet onlu passed the path (ie. /LITTLEBIGPLANETPSP_XML/login?) during sceHttpCreateRequest without the host domain, thus will need to be construced into a valid URI using the data from sceHttpCreateConnection upon validating/parsing the URL.
	std::string fullURL = url;
	if (startsWithNoCase(url, "/")) {
		fullURL = scheme + "://" + hostString + ":" + std::to_string(port) + fullURL;
	}

	Url fileUrl(fullURL);
	if (!fileUrl.Valid()) {
		return SCE_HTTP_ERROR_INVALID_URL;
	}
	if (!client.Resolve(fileUrl.Host().c_str(), fileUrl.Port())) {
		ERROR_LOG(Log::sceNet, "Failed resolving %s", fileUrl.ToString().c_str());
		return -1;
	}

	// Establish Connection
	if (!client.Connect(getResolveRetryCount(), getConnectTimeout() / 1000000.0, &cancelled_)) {
		ERROR_LOG(Log::sceNet, "Failed connecting to server or cancelled.");
		return -1; // SCE_HTTP_ERROR_ABORTED
	}
	if (cancelled_) {
		return SCE_HTTP_ERROR_ABORTED;
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
	net::Buffer buffer_;
	net::RequestProgress progress_(&cancelled_);
	http::RequestParams req(fileUrl.Resource(), "*/*");
	const char* postData = Memory::GetCharPointer(postDataPtr);
	if (postDataSize > 0)
		NotifyMemInfo(MemBlockFlags::READ, postDataPtr, postDataSize, "HttpSendRequest");
	
	/*if (isSSLEnabled()) {
		int err = client.SendSSLRequestWithData(ssl, methodstr.c_str(), req, std::string(postData ? postData : "", postData ? postDataSize : 0), extraHeaders.c_str(), &progress_);
		if (err < 0)
			return err;
	}
	else {*/
		int err = client.SendRequestWithData(methodstr.c_str(), req, std::string(postData ? postData : "", postData ? postDataSize : 0), extraHeaders.c_str(), &progress_);
		if (err < 0)
			return err;
	//}
	if (cancelled_) {
		return SCE_HTTP_ERROR_ABORTED;
	}

	// Retrieve Response's Status Code (and Headers too?)
	responseCode_ = client.ReadResponseHeaders(&buffer_, responseHeaders_, &progress_, &httpLine_);
	if (cancelled_) {
		return SCE_HTTP_ERROR_ABORTED;
	}

	// TODO: Read response entity within readData() in smaller chunk(based on size arg of sceHttpReadData) instead of the whole content at once here
	net::Buffer entity_;
	int res = client.ReadResponseEntity(&buffer_, responseHeaders_, &entity_, &progress_);
	if (res != 0) {
		ERROR_LOG(Log::sceNet, "Unable to read HTTP response entity: %d", res);
	}
	entity_.TakeAll(&responseContent_);
	if (cancelled_) {
		return SCE_HTTP_ERROR_ABORTED;
	}

	return 0;
}

void __HttpInit() {
}

void __HttpShutdown() {
	std::lock_guard<std::mutex> guard(httpLock);
	httpInited = false;
	httpsInited = false;
	httpCacheInited = false;

	for (const auto& it : httpObjects) {
		if (it->className() == name_HTTPRequest)
			(static_cast<HTTPRequest*>(it.get()))->abortRequest();
	}
	httpObjects.clear();
}

// id: ID of the template or connection
int sceHttpSetResolveRetry(int id, int retryCount) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpSetResolveRetry(%d, %d)", id, retryCount);
	if (id <= 0 || id > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects[id - 1LL];
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
	httpObjects.reserve(1);
	// sceHttpsInit fails if we don't have something in httpObjects
	httpObjects.emplace_back(std::make_shared<HTTPTemplate>());
	httpInited = true;
	return 0;
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
	if (requestID <= 0 || requestID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (!Memory::IsValidRange(statusCodePtr, 4))
		return hleLogError(Log::sceNet, -1, "invalid arg"); //SCE_HTTP_ERROR_INVALID_VALUE;

	const auto& req = (HTTPRequest*)httpObjects[requestID - 1LL].get();
	// FIXME: According to JPCSP, try to connect the request first
	//req->connect();
	int status = req->getStatusCode();
	
	DEBUG_LOG(Log::sceNet, "StatusCode = %d (in) => %d (out)", Memory::ReadUnchecked_U32(statusCodePtr), status);
	Memory::WriteUnchecked_U32(status, statusCodePtr);
	NotifyMemInfo(MemBlockFlags::WRITE, statusCodePtr, 4, "HttpGetStatusCode");
	return 0;
}

// Games will repeatedly called sceHttpReadData until it returns (the size read into the data buffer) 0
// FIXME: sceHttpReadData seems to be blocking current thread, since hleDelayResult can make Download progressbar to moves progressively instead of instantly jump to 100%
static int sceHttpReadData(int requestID, u32 dataPtr, u32 dataSize) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpReadData(%d, %x, %d)", requestID, dataPtr, dataSize);
	if (requestID <= 0 || requestID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (!Memory::IsValidRange(dataPtr, dataSize)) 
		return hleLogError(Log::sceNet, -1, "invalid arg"); // SCE_HTTP_ERROR_INVALID_VALUE

	const auto& req = (HTTPRequest*)httpObjects[requestID - 1LL].get();
	// FIXME: According to JPCSP, try to connect the request first
	//req->connect();

	DEBUG_LOG(Log::sceNet, "Entity remaining / size = %d / %d", req->getResponseRemainingContentLength(), req->getResponseContentLength());
	//if (req->getResponseContentLength()) == 0)
	//	return hleLogError(SCENET, SCE_HTTP_ERROR_NO_CONTENT_LENGTH, "no content length");
	int retval = req->readData(dataPtr, dataSize);

	if (retval > 0) {
		u8* data = (u8*)Memory::GetPointerUnchecked(dataPtr);
		std::string datahex;
		DataToHexString(10, 0, data, retval, &datahex);
		DEBUG_LOG(Log::sceNet, "Data Dump (%d bytes):\n%s", retval, datahex.c_str());
	}

	// Faking latency to slow down download progressbar, since we currently downloading the full content at once instead of in chunk per sceHttpReadData's dataSize
	return hleDelayResult(hleLogDebug(Log::sceNet, retval), "fake read data latency", 5000);
}

// FIXME: JPCSP didn't do anything other than appending the data into internal buffer, does sceHttpSendRequest can be called multiple times before using sceHttpGetStatusCode or sceHttpReadData? any game do this?
static int sceHttpSendRequest(int requestID, u32 dataPtr, u32 dataSize) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpSendRequest(%d, %x, %d)", requestID, dataPtr, dataSize);
	if (!httpInited)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_BEFORE_INIT, "http not initialized yet");

	if (requestID <= 0 || requestID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (dataSize > 0 && !Memory::IsValidRange(dataPtr, dataSize))
		return hleLogError(Log::sceNet, -1, "invalid arg"); // SCE_HTTP_ERROR_INVALID_VALUE

	const auto& req = (HTTPRequest*)httpObjects[requestID - 1LL].get();
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
	if (requestID <= 0 || requestID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects[requestID - 1LL]->className() != name_HTTPRequest)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");
	httpObjects.erase(httpObjects.begin() + requestID - 1);
	return 0;
}

// id: ID of the template, connection or request 
static int sceHttpDeleteHeader(int id, const char *name) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpDeleteHeader(%d, %s)", id, safe_string(name));
	if (id <= 0 || id > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& req = (HTTPRequest*)httpObjects[id - 1LL].get();
	return req->removeRequestHeader(name);
}

static int sceHttpDeleteConnection(int connectionID) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpDisableCache(%d)", connectionID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (connectionID <= 0 || connectionID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects[connectionID - 1LL]->className() != name_HTTPConnection)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	httpObjects.erase(httpObjects.begin() + connectionID - 1);
	return 0;
}

// id: ID of the template, connection or request
static int sceHttpSetConnectTimeOut(int templateID, u32 timeout) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpSetConnectTimeout(%d, %d)", templateID, timeout);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	auto& conn = httpObjects[templateID - 1LL];
	conn->setConnectTimeout(timeout);
	return 0;
}

// id: ID of the template, connection or request
static int sceHttpSetSendTimeOut(int templateID, u32 timeout) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetSendTimeout(%d, %d)", templateID, timeout);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	auto& conn = httpObjects[templateID - 1LL];
	conn->setSendTimeout(timeout);
	return 0;
}

static u32 sceHttpSetProxy(u32 templateID, u32 activateFlagPtr, u32 mode, u32 newProxyHostPtr, u32 newProxyPort) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetProxy(%d, %x, %x, %x, %d)", templateID, activateFlagPtr, mode, newProxyHostPtr, newProxyPort);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	auto& conn = httpObjects[templateID - 1LL];
	conn->setProxy();

	return 0;
}

// id: ID of the template or connection
static int sceHttpEnableCookie(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpEnableCookie(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	auto& conn = httpObjects[templateID - 1LL];
	conn->enableCookie();

	return 0;
}

// id: ID of the template or connection
static int sceHttpEnableKeepAlive(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpEnableKeepAlive(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	auto& conn = httpObjects[templateID - 1LL];
	conn->enableKeepAlive();

	return 0;
}

// id: ID of the template or connection
static int sceHttpDisableCookie(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpDisableCookie(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	auto& conn = httpObjects[templateID - 1LL];
	conn->enableCookie();

	return 0;
}

// id: ID of the template or connection
static int sceHttpDisableKeepAlive(int templateID) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpDisableKeepAlive(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	auto& conn = httpObjects[templateID - 1LL];
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
	bufferTemplate.enableTLS();
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
	if (connectionID <= 0 || connectionID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects[connectionID - 1LL]->className() != name_HTTPConnection)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (method < PSPHttpMethod::PSP_HTTP_METHOD_GET || method > PSPHttpMethod::PSP_HTTP_METHOD_HEAD)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_UNKNOWN_METHOD, "unknown method");

	httpObjects.emplace_back(std::make_shared<HTTPRequest>(connectionID, method, path? path:"", contentLength));
	int retid = (int)httpObjects.size();
	return hleLogDebug(Log::sceNet, retid);
}

// FIXME: port type is probably u16 (but passed in a single register anyway, so type doesn't matter)
static int sceHttpCreateConnection(int templateID, const char *hostString, const char *scheme, u32 port, int enableKeepalive) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpCreateConnection(%d, %s, %s, %d, %d)", templateID, safe_string(hostString), safe_string(scheme), port, enableKeepalive);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects[templateID - 1LL]->className() != name_HTTPTemplate)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	// TODO: Look up hostString in DNS here.
	auto conn = std::make_shared<HTTPConnection>(templateID, hostString ? hostString : "", scheme ? scheme : "", port, enableKeepalive);
	conn->InitializeSSL();
	httpObjects.emplace_back(conn);
	int retid = (int)httpObjects.size();
	return hleLogDebug(Log::sceNet, retid);
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
	if (id <= 0 || id > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& req = (HTTPRequest*)httpObjects[id - 1LL].get();
	return req->addRequestHeader(name, value, unknown);
}

static int sceHttpAbortRequest(int requestID) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpAbortRequest(%d)", requestID);
	if (requestID <= 0 || requestID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& req = (HTTPRequest*)httpObjects[requestID - 1LL].get();
	return req->abortRequest();
}

static int sceHttpDeleteTemplate(int templateID) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpDeleteTemplate(%d)", templateID);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects[templateID - 1LL]->className() != name_HTTPTemplate)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	httpObjects.erase(httpObjects.begin() + templateID - 1);
	return 0;
}

static int sceHttpSetMallocFunction(u32 mallocFuncPtr, u32 freeFuncPtr, u32 reallocFuncPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetMallocFunction(%x, %x, %x)", mallocFuncPtr, freeFuncPtr, reallocFuncPtr);
	return 0;
}

// id: ID of the template or connection
static int sceHttpSetResolveTimeOut(int id, u32 timeout) {
	ERROR_LOG(Log::sceNet, "UNIMPL sceHttpSetResolveTimeOut(%d, %d)", id, timeout);
	if (id <= 0 || id > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");
	
	const auto& conn = httpObjects[id - 1LL];
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
	httpObjects.push_back(tmplate);

	int retid = (int)httpObjects.size();
	return hleLogDebug(Log::sceNet, retid);
}

// Parameter "method" should be one of PSPHttpMethod's listed entries
static int sceHttpCreateRequestWithURL(int connectionID, int method, const char *url, u64 contentLength) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpCreateRequestWithURL(%d, %d, %s, %llx)", connectionID, method, safe_string(url), contentLength);
	std::lock_guard<std::mutex> guard(httpLock);
	if (connectionID <= 0 || connectionID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects[connectionID - 1LL]->className() != name_HTTPConnection)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (method < PSPHttpMethod::PSP_HTTP_METHOD_GET || method > PSPHttpMethod::PSP_HTTP_METHOD_HEAD)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_UNKNOWN_METHOD, "unknown method");

	Url baseURL(url ? url : "");
	if (!baseURL.Valid())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_URL, "invalid url");

	httpObjects.emplace_back(std::make_shared<HTTPRequest>(connectionID, method, url ? url : "", contentLength));
	int retid = (int)httpObjects.size();
	return hleLogDebug(Log::sceNet, retid);
}

static int sceHttpCreateConnectionWithURL(int templateID, const char *url, int enableKeepalive) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpCreateConnectionWithURL(%d, %s, %d)", templateID, safe_string(url), enableKeepalive);
	std::lock_guard<std::mutex> guard(httpLock);
	if (templateID <= 0 || templateID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (httpObjects[templateID - 1LL]->className() != name_HTTPTemplate)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	Url baseURL(url ? url: "");
	if (!baseURL.Valid())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_URL, "invalid url");

	// TODO: Here we should look up baseURL.Host() in DNS.

	httpObjects.emplace_back(std::make_shared<HTTPConnection>(templateID, baseURL.Host().c_str(), baseURL.Protocol().c_str(), baseURL.Port(), enableKeepalive));
	int retid = (int)httpObjects.size();
	return hleLogDebug(Log::sceNet, retid);
}

// id: ID of the template or connection
static int sceHttpSetRecvTimeOut(int id, u32 timeout) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpSetRecvTimeOut(%d, %d)", id, timeout);
	if (id <= 0 || id > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	const auto& conn = httpObjects[id - 1LL];
	if (!(conn->className() == name_HTTPTemplate || conn->className() == name_HTTPConnection))
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id (%s)", conn->className());

	conn->setRecvTimeout(timeout);
	return 0;
}

// FIXME: Headers should includes the "HTTP/MajorVer.MinorVer StatusCode Comment" line? so PSP Browser can parse it using sceParseHttpStatusLine
// Note: Megaman PoweredUp seems to have an invalid address stored at the headerAddrPtr location, may be the game expecting us (network library) to give them a valid header address?
static int sceHttpGetAllHeader(int requestID, u32 headerAddrPtr, u32 headerSizePtr) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpGetAllHeader(%d, %x, %x)", requestID, headerAddrPtr, headerSizePtr);
	if (requestID <= 0 || requestID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (!Memory::IsValidRange(headerAddrPtr, 4))
		return hleLogError(Log::sceNet, -1, "invalid arg"); //SCE_HTTP_ERROR_INVALID_VALUE;

	if (!Memory::IsValidRange(headerSizePtr, 4)) 
		return hleLogError(Log::sceNet, -1, "invalid arg"); //SCE_HTTP_ERROR_INVALID_VALUE;

	const auto& req = (HTTPRequest*)httpObjects[requestID - 1LL].get();
	// FIXME: According to JPCSP, try to connect the request first
	//req->connect();
	int retval = req->getAllResponseHeaders(headerAddrPtr, headerSizePtr);
	return hleLogDebug(Log::sceNet, retval);
}

// FIXME: contentLength is SceULong64 but this contentLengthPtr argument should be a 32bit pointer instead of 64bit, right?
static int sceHttpGetContentLength(int requestID, u32 contentLengthPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED sceHttpGetContentLength(%d, %x)", requestID, contentLengthPtr);
	if (requestID <= 0 || requestID > (int)httpObjects.size())
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_INVALID_ID, "invalid id");

	if (!Memory::IsValidRange(contentLengthPtr, 8))
		return hleLogError(Log::sceNet, -1, "invalid arg"); //SCE_HTTP_ERROR_INVALID_VALUE;

	const auto& req = (HTTPRequest*)httpObjects[requestID - 1LL].get();
	// FIXME: According to JPCSP, try to connect the request first
	//req->connect();
	int len = req->getResponseContentLength();
	if (len < 0)
		return hleLogError(Log::sceNet, SCE_HTTP_ERROR_NO_CONTENT_LENGTH, "no content length");

	DEBUG_LOG(Log::sceNet, "ContentLength = %lld (in) => %lld (out)", Memory::Read_U64(contentLengthPtr), (u64)len);
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
