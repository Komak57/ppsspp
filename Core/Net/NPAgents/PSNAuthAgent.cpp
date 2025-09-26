#include "Core/Net/NPAgent.h"
#include <Core/HLE/HLE.h>
#include <Common/Net/URL.h>
#include "Common/Net/HTTPClient.h"
#include <Common/File/FileDescriptor.h>
#include <TimeUtil.h>
#include <Core/Net/Buffer.cpp>
#include <Core/HLE/sceNet.h>
namespace net {
	// FIXME: Populate with actual connection credentials for PSN
	PSNAuthAgent::PSNAuthAgent(std::string host, int port) {
		this->host_ = host;
		this->port_ = port;

		//std::string certificate = "";
		//InitializeSSL(certificate);
	}
	PSNAuthAgent::~PSNAuthAgent() {
		Disconnect();
	}

	int PSNAuthAgent::Login(const char* titleId, const char* token, const char* password) {
		return false;
	}
	int PSNAuthAgent::CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) {
		return false;
	}

	int PSNAuthAgent::ResendToken(const char* npid, const char* password) {
		return 0;
	}

	int PSNAuthAgent::SendResetToken(const char* npid, const char* email) {
		return 0;
	}

	int PSNAuthAgent::ResetPassword(const char* npid, const char* token, const char* password) {
		return 0;
	}

	u64 PSNAuthAgent::GetNetworkTime(u32 req_id) {
		return 0;
	}

	void PSNAuthAgent::Disconnect() {
		NOTICE_LOG(Log::sceNet, "NPAuthAgent::Disconnect()");
		cancelled = true;
		if (connected) {
			if (tls.enabled) {
				// First shut down network I/O so ssl_read unblocks
				ResetSSL();
			}
			else {
				if ((intptr_t)sock_ != -1) {
					closesocket(sock_);
					sock_ = -1;
				}
			}
		}
		connected = false;
	}

	std::unique_ptr<NPAgent> PSNAuthAgent::CreateAgent() {
		return net::CreateNPAgent(NPAgentType::PSN, this->host_, this->port_);
	}

	bool PSNAuthAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		WARN_LOG(Log::sceNet, "UNTESTED RPCNAuthAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
		std::string certPem = "-----BEGIN CERTIFICATE-----\n"
			"\n"
			"-----END CERTIFICATE-----\n";
		InitializeSSL(certPem);

		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "Connect - Bad port");
			return false;
		}
		if (connected) {
			return true;
			/*mbedtls_ssl_session_reset(&tls.sslCtx);
			mbedtls_ssl_config_free(&tls.sslConfig);

			mbedtls_ssl_free(&tls.sslCtx);
			mbedtls_net_free(&tls.netCtx);
			tls.connected = false;*/
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
				char* ip_address = new char[128];
				inet_ntop(possible->ai_family, &((sockaddr_in*)possible->ai_addr)->sin_addr, ip_address, 128);
				char portStr[8]{};
				memcpy(portStr, std::to_string(port_).c_str(), std::to_string(port_).length());
				if ((ret = mbedtls_net_connect(&tls.netCtx, ip_address, portStr, MBEDTLS_NET_PROTO_TCP)) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_net_connect(netCtx, %s, %s, PROTO_TCP) call failed with -0x%04x (%s))", ip_address, portStr, ret, errbuf);
					goto sslretry;
				}
				// Set NonBlocking
				fd_util::SetNonBlocking(tls.netCtx.fd, true);
				/*
				 * 2. Setup stuff
				 */
				if ((ret = mbedtls_ssl_setup(&tls.sslCtx, &tls.sslConfig)) != 0) {
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_ssl_setup returned 0x%04x", ret);
					goto sslretry;
				}

				//if ((ret = mbedtls_ssl_set_hostname(&sslCtx, possible->ai_addr->sa_data)) != 0) {
				if ((ret = mbedtls_ssl_set_hostname(&tls.sslCtx, host_.c_str())) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_ssl_set_hostname returned -0x%04x (%s)", (unsigned int)-ret, errbuf);
					goto sslretry;
				}

				mbedtls_ssl_set_bio(&tls.sslCtx, &tls.netCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

				/*
				 * 4. Handshake
				 */
				NOTICE_LOG(Log::sceNet, "Connect - Performing the SSL/TLS handshake...");

				while ((ret = mbedtls_ssl_handshake(&tls.sslCtx)) != 0) {
					if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
						char errbuf[128];
						mbedtls_strerror(ret, errbuf, sizeof(errbuf));
						ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_handshake ERROR -0x%x: %s", (unsigned int)-ret, errbuf);
						goto sslretry;
					}
				}

				/*
				 * 5. Verify the server certificate
				 */
				 // HTTPS Option 28 may relate to disabling this check
				NOTICE_LOG(Log::sceNet, "Connect - Verifying peer X.509 certificate...");

				/* In real life, we probably want to bail out when ret != 0 */
				u32 flags;
				if ((flags = mbedtls_ssl_get_verify_result(&tls.sslCtx)) != 0) {
					char vrfy_buf[512];

					mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

					ERROR_LOG(Log::sceNet, "Connect - mbedtls_ssl_get_verify_result failed: %s", vrfy_buf);
					goto sslretry;
				}

				INFO_LOG(Log::sceNet, "Connect - Connection Successful");
				connected = true;
				return true;
			sslretry:
				INFO_LOG(Log::sceNet, "Connect - Connection Failed, retrying");
				mbedtls_ssl_session_reset(&tls.sslCtx);
				mbedtls_ssl_config_free(&tls.sslConfig);

				mbedtls_ssl_free(&tls.sslCtx);
				mbedtls_net_free(&tls.netCtx);

				continue;
			}
			sleep_ms(1, "connect");
		}
		return false;
	}
}
