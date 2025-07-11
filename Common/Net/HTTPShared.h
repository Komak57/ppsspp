#pragma once
#include <vector>
#include <memory>
#include <string>
#include <map>
#include <unordered_map>
#include <functional>
#include <algorithm> // std::transform
#include "Common/Common.h"

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

// Options not yet identified
enum SceHttpsOptions {
	SCE_HTTPS_OPTIONS_VERIFY_SERVER = 28,
	SCE_HTTPS_OPTIONS_TLS_ONLY = 31,
	SCE_HTTPS_OPTIONS_SSLv3 = 35,
	SCE_HTTPS_OPTIONS_TLS1_2 = 36,
	//SCE_HTTPS_OPTIONS_CA_CERT =			?
};
enum SceHttpAddHeaderMode {
	SCE_HTTP_HEADER_OVERWRITE,
	SCE_HTTP_HEADER_ADD
};

enum SceHttpVersion {
	SCE_HTTP_VERSION_1_0 = 1,
	SCE_HTTP_VERSION_1_1
};

enum SceHttpProxyMode {
	SCE_HTTP_PROXY_AUTO,
	SCE_HTTP_PROXY_MANUAL
};

enum class RequestMethod {
	GET = 0,
	POST = 1,
};

// TODO: Find a better place for this. Causes LNK4006 warning
inline const char* RequestMethodToString(RequestMethod method) {
	switch (method) {
	case RequestMethod::GET: return "GET";
	case RequestMethod::POST: return "POST";
	default: return "N/A";
	}
}

enum class RequestFlags {
	Default = 0,
	ProgressBar = 1,
	ProgressBarDelayed = 2,
	Cached24H = 4,
	KeepInMemory = 8,
};
ENUM_CLASS_BITOPS(RequestFlags);

class RequestParams {
public:
	RequestParams() {}
	explicit RequestParams(const char* r) : resource(r) {}
	RequestParams(const std::string& r, const char* a) : resource(r), acceptMime(a) {}

	std::string resource;
	const char* acceptMime = "*/*";
};

class RequestProgress {
public:
	//RequestProgress();
	explicit RequestProgress(bool* c) : cancelled(c) {};

	void Update(int64_t downloaded, int64_t totalBytes, bool done) {
		if (totalBytes) {
			progress = (double)downloaded / (double)totalBytes;
		}
		else {
			progress = 0.01f;
		}
		this->done = done;

		if (callback)
			callback(downloaded, totalBytes, done);
	}

	bool done = false;
	float progress = 0.0f;
	float kBps = 0.0f;
	bool* cancelled = nullptr;
	std::function<void(int64_t, int64_t, bool)> callback = nullptr;

	float Progress() const { return progress; }
	float SpeedKBps() const { return kBps; }
	bool Done() { return done; }
	void Cancel() { bool c = true; cancelled = &c; }
	bool IsCancelled() const { return cancelled; }
	bool Failed() const { return progress < 1.0f; }

};
