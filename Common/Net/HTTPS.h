#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <wolfssl/options.h> // wolfSSL_UseSNI
#include <wolfssl/ssl.h>
#include <unordered_map>
#include <string>
#undef OPTIONAL

class HTTPS_Config {
public:
	bool enabled = false;
	WOLFSSL* ssl = nullptr;
	WOLFSSL_CTX* ctx = nullptr;
};

class HTTPS {
public:
	int InitializeSSL(std::string certPEM = "");
	void ResetSSL();

	bool GetOption(int id) {
		auto it = this->httpsOptions.find(id);
		if (it == this->httpsOptions.end())
			return false;
		return it->second;
	}
public:
	HTTPS_Config tls;

	std::unordered_map<int, bool> httpsOptions;

	int useCookie = 0;
	int useKeepAlive = 0;
	int useCache = 0;
	int useAuth = 0;
	int useRedirect = 0;
};
