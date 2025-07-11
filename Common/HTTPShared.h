#pragma once
#include <vector>
#include <memory>
#include <string>
#include <map>
#include <unordered_map>
#include "CommonTypes.h"

namespace http {
// Based on https://docs.vitasdk.org/group__SceHttpUser.html
#define 	SCE_HTTP_DEFAULT_RESOLVER_TIMEOUT   (1 * 1000 * 1000U)
#define 	SCE_HTTP_DEFAULT_RESOLVER_RETRY   (5U)
#define 	SCE_HTTP_DEFAULT_CONNECT_TIMEOUT   (30* 1000 * 1000U)
#define 	SCE_HTTP_DEFAULT_SEND_TIMEOUT   (120* 1000 * 1000U)
#define 	SCE_HTTP_DEFAULT_RECV_TIMEOUT   (120* 1000 * 1000U)
#define 	SCE_HTTP_DEFAULT_RECV_BLOCK_SIZE   (1500U)
#define 	SCE_HTTP_DEFAULT_RESPONSE_HEADER_MAX   (5000U)
#define 	SCE_HTTP_DEFAULT_REDIRECT_MAX   (6U)
#define 	SCE_HTTP_DEFAULT_TRY_AUTH_MAX   (6U)
#define 	SCE_HTTP_INVALID_ID   0
#define 	SCE_HTTP_ENABLE   (1)
#define 	SCE_HTTP_DISABLE   (0)
#define 	SCE_HTTP_USERNAME_MAX_SIZE   256
#define 	SCE_HTTP_PASSWORD_MAX_SIZE   256

// Just a holder for class names
static const char* name_HTTPTemplate = "HTTPTemplate";
static const char* name_HTTPConnection = "HTTPConnection";
static const char* name_HTTPRequest = "HTTPRequest";

enum SceHttpVersion {
	SCE_HTTP_VERSION_1_0 = 1,
	SCE_HTTP_VERSION_1_1
};

enum SceHttpProxyMode {
	SCE_HTTP_PROXY_AUTO,
	SCE_HTTP_PROXY_MANUAL
};

class HTTPTemplate {
protected:
	std::string userAgent; // char userAgent[512];
	SceHttpVersion httpVer = SCE_HTTP_VERSION_1_0;
	SceHttpProxyMode autoProxyConf = SCE_HTTP_PROXY_AUTO;

	int useCookie = 0;
	int useKeepAlive = 0;
	int useCache = 0;
	int useAuth = 0;
	int useRedirect = 0;
	int httpsEnabled = 0;

	u32 connectTimeout = SCE_HTTP_DEFAULT_CONNECT_TIMEOUT;
	u32 sendTimeout = SCE_HTTP_DEFAULT_SEND_TIMEOUT;
	u32 recvTimeout = SCE_HTTP_DEFAULT_RECV_TIMEOUT;
	u32 resolveTimeout = SCE_HTTP_DEFAULT_RESOLVER_TIMEOUT;
	int resolveRetryCount = SCE_HTTP_DEFAULT_RESOLVER_RETRY;

	std::map<std::string, std::string> requestHeaders_;
	std::string certPEM;
	std::unordered_map<int, bool> httpsOptions = {};

public:
	HTTPTemplate() {}
	HTTPTemplate(const char* userAgent, int httpVer, int autoProxyConf);
	virtual ~HTTPTemplate() = default;

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
	void enableHTTPS() { this->httpsEnabled = 1; }

	void CopyFrom(HTTPTemplate parent) {
		this->certPEM = parent.certPEM;
		this->httpsOptions = parent.httpsOptions;
		this->httpsEnabled = parent.httpsEnabled;
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


extern std::vector<std::shared_ptr<HTTPTemplate>> httpObjects;
}
