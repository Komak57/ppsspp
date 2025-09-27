#pragma once
#include "Core/Net/HTTPS.h"
#include "Core/HLE/HttpTypes.h"
#include "Core/Net/Buffer.h"
#include <Common/CommonTypes.h>
#include <Common/Net/Resolve.h>
#include <Common/Net/SocketCompat.h>

// Just a holder for class names
static const char* name_HTTPTemplate = "HTTPTemplate";
static const char* name_HTTPConnection = "HTTPConnection";
static const char* name_HTTPRequest = "HTTPRequest";

// TODO: do something sane here
constexpr const char* DEFAULT_USERAGENT = "PPSSPP";
constexpr const char* HTTP_VERSION = "1.1";
struct addrinfo;

class HTTPTemplate : public HTTPS {
protected:
	std::string userAgent; // char userAgent[512];
	SceHttpVersion httpVer = SCE_HTTP_VERSION_1_0;
	SceHttpProxyMode autoProxyConf = SCE_HTTP_PROXY_AUTO;

	u32 connectTimeout = SCE_HTTP_DEFAULT_CONNECT_TIMEOUT;
	u32 sendTimeout = SCE_HTTP_DEFAULT_SEND_TIMEOUT;
	u32 recvTimeout = SCE_HTTP_DEFAULT_RECV_TIMEOUT;
	u32 resolveTimeout = SCE_HTTP_DEFAULT_RESOLVER_TIMEOUT;
	int resolveRetryCount = SCE_HTTP_DEFAULT_RESOLVER_RETRY;

	std::string certPEM;
	std::map<std::string, std::string> requestHeaders;

public:
	HTTPTemplate() {}
	HTTPTemplate(const char* userAgent, int httpVer, int autoProxyConf);
	virtual ~HTTPTemplate();

	virtual const char* className() { return name_HTTPTemplate; } // to be more consistent, unlike typeid(v).name() which may varies among different compilers and requires RTTI

	

	const std::string getUserAgent() { return userAgent; }
	int getHttpVer() { return httpVer; }
	int getAutoProxyConf() { return autoProxyConf; }

	u32 getConnectTimeout() { return connectTimeout; }
	u32 getSendTimeout() { return sendTimeout; }
	u32 getRecvTimeout() { return recvTimeout; }
	u32 getResolveTimeout() { return resolveTimeout; }
	int getResolveRetryCount() { return resolveRetryCount; }

	void setProxy() {};
	void enableCookie() { this->useCookie = 1; }
	void enableKeepAlive() { this->useKeepAlive = 1; }
	void enableCache() { this->useCache = 1; }
	void enableRedirect() { this->useRedirect = 1; }
	void enableAuth() { this->useAuth = 1; }
	void enableOption(int option) { this->httpsOptions[option] = 1; };
	void disableOption(int option) { this->httpsOptions[option] = 0; };

	void CopyFrom(HTTPTemplate parent) {
		this->certPEM = parent.certPEM;
		this->httpsOptions = parent.httpsOptions;
		this->tls = parent.tls;
	}

	void setUserAgent(const char* userAgent) { this->userAgent = userAgent ? userAgent : ""; }
	void setConnectTimeout(u32 timeout) { this->connectTimeout = timeout; }
	void setSendTimeout(u32 timeout) { this->sendTimeout = timeout; }
	void setRecvTimeout(u32 timeout) { this->recvTimeout = timeout; }
	void setResolveTimeout(u32 timeout) { this->resolveTimeout = timeout; }
	void setResolveRetry(u32 retryCount) { this->resolveRetryCount = retryCount; }

	int addRequestHeader(const char* name, const char* value, u32 mode);
	int removeRequestHeader(const char* name);
	int setCert(std::string certificate);
};

class HTTPConnection : public HTTPTemplate {
protected:
	int templateID = 0;
	std::string hostString;
	std::string scheme;
	std::string host;
	u16 port = 80;
	int enableKeepalive = 0;

	uintptr_t fd = 0;
	bool connected = false;
	u32 lastError = 0;
	addrinfo* resolved_ = nullptr;

public:
	HTTPConnection() {}
	HTTPConnection(int templateID, const char* hostString, const char* scheme, u32 port, int enableKeepalive);
	virtual ~HTTPConnection() override;

	virtual const char* className() override { return name_HTTPConnection; }
	bool Resolve(const char* host, int port, net::DNSType type);
	bool Connect(int connectionID, int maxTries = 2, double timeout = 20.0f, bool* cancelConnect = nullptr);
	bool SSLConnect(int connectionID, int maxTries = 2, double timeout = 20.0f, bool* cancelConnect = nullptr);
	void Disconnect();
	void InitSession(int connectionID);
	void DestroySession(int connectionID);

	
	bool connecting = false;
	

	int getTemplateID() { return templateID; }
	const std::string getHost() { return hostString; }
	const std::string getScheme() { return scheme; }
	u16 getPort() { return port; }
	int getKeepAlive() { return enableKeepalive; }
	bool GetOption(int id) {
		auto it = this->httpsOptions.find(id);
		if (it == this->httpsOptions.end())
			return false;
		return it->second;
	}
};

enum class ThreadState {
	HAS_ERROR,
	INIT,
	CONNECTED,
	HEADERS_AVAILABLE,
	DATA_AVAILABLE,
	COMPLETE
};
#include <thread>


class HTTPRequest : public HTTPConnection {
private:
	int connectionID;
	int method;
	u64 contentLength;
	std::string fullURL;
	int ErrorCode = 0;

	u32 headerAddr_ = 0;
	u32 headerSize_ = 0;
	int responseCode_ = -1;
	int entityLength_ = -1;

	bool cancelled = false;
	double dataTimeout_ = 900.0;
	core::Buffer readbuf;
	core::RequestProgress progress;
	std::vector<std::string> responseHeaders;
	std::string httpLine_;

public:
	HTTPRequest(int connectionID, int method, const char* url, u64 contentLength);
	virtual ~HTTPRequest() override;

	virtual const char* className() override { return name_HTTPRequest; }

	void setInternalHeaderAddr(u32 addr) { headerAddr_ = addr; }
	int getConnectionID() { return connectionID; }

	int ThreadID;
	std::thread handthread;
	
	int getResponseContentLength();
	int abortRequest();
	int getStatusCode();
	int getAllResponseHeaders(u32 headerAddrPtr, u32 headerSizePtr);
	int readData(u32 destDataPtr, u32 size);
	int sendRequest(u32 postDataPtr, u32 postDataSize);
	int getErrorCode() { return ErrorCode; }
};
