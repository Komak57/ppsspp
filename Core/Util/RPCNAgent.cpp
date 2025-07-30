#include "Core/Util/NPAgent.h"
#include <Core\HLE\HLE.h>
#include <File\FileDescriptor.h>
#include <mbedtls\error.h>
#include <TimeUtil.h>
namespace net {
	// FIXME: Populate with actual connection credentials for RPCN
	RPCNAgent::RPCNAgent(int serverId, std::string host, int port, u8 status) {
		this->ID = serverId;
		this->host_ = host;
		this->port_ = port;
		this->status = status;

		//std::string certificate = "";
		//InitializeSSL(certificate);
	}

	RPCNAgent::~RPCNAgent() {
		Disconnect();
	}

	bool RPCNAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		WARN_LOG(Log::sceNet, "UNTESTED RPCNAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "Connect - Bad port");
			return false;
		}
		if (tls.connected) {
			mbedtls_ssl_session_reset(&tls.sslCtx);
			mbedtls_ssl_config_free(&tls.sslConfig);

			mbedtls_ssl_free(&tls.sslCtx);
			mbedtls_net_free(&tls.netCtx);
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
				FormatAddr(addrStr, sizeof(addrStr), possible);
				char portStr[8]{};
				memcpy(portStr, std::to_string(port_).c_str(), std::to_string(port_).length());
				if ((ret = mbedtls_net_connect(&tls.netCtx, addrStr, portStr, MBEDTLS_NET_PROTO_UDP)) != 0) {
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_net_connect(netCtx, %s, %s, PROTO_TCP) call to %s failed with -0x%04x)", addrStr, portStr, (unsigned int)-ret);
					goto retry;
				}
				// Set NonBlocking
				fd_util::SetNonBlocking(tls.netCtx.fd, true);
				/*
				 * 2. Setup stuff
				 */
				if ((ret = mbedtls_ssl_setup(&tls.sslCtx, &tls.sslConfig)) != 0) {
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_ssl_setup returned 0x%04x", ret);
					goto retry;
				}

				//if ((ret = mbedtls_ssl_set_hostname(&sslCtx, possible->ai_addr->sa_data)) != 0) {
				if ((ret = mbedtls_ssl_set_hostname(&tls.sslCtx, host_.c_str())) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_ssl_set_hostname returned -0x%04x (%s)", (unsigned int)-ret, errbuf);
					goto retry;
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
						ERROR_LOG(Log::sceNet, "Connect - mbedtls_ssl_handshake ERROR -0x%x: %s", (unsigned int)-ret, errbuf);
						goto retry;
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
					goto retry;
				}

				INFO_LOG(Log::sceNet, "Connect - Connection Successful. TLS: %s, Cipher: %s", mbedtls_ssl_get_version(&tls.sslCtx), mbedtls_ssl_get_ciphersuite(&tls.sslCtx));
				tls.connected = true;
				return true;
			retry:
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

	int RPCNAgent::GetWorldInfo(char npTitleId[], std::map<u32, SceNpMatching2World>* worldInfoOut) {

		worldInfoOut->clear();
		// Should get an array of worlds
		SceNpMatching2World worldInfo = SceNpMatching2World();
		worldInfo.worldId = 1;

		worldInfo.numOfLobby = 2;
		worldInfo.curNumOfTotalLobbyMember = 0;
		worldInfo.maxNumOfTotalLobbyMember = 12;

		worldInfo.curNumOfRoom = 0;
		worldInfo.curNumOfTotalRoomMember = 0;

		worldInfo.withEntitlementId = 0;
		int i;
		for (i = 0; i < 32; i++)
			worldInfo.entitlementId[i] = 0;

		worldInfoOut->emplace(worldInfo.worldId, worldInfo);
		return 0;
	}

	int RPCNAgent::SearchRoom(SceNpMatching2RoomDataExternal* roomDataOut) {
		roomDataOut->roomId = 0; // No Room
		return 0;
	}

	int RPCNAgent::CreatJoinRoom(SceNpMatching2RoomDataInternal* roomDataOut) {
		roomDataOut->roomId = 1;
		return 0;
	}

	int RPCNAgent::GetRoomDataInternal(SceNpMatching2RoomDataInternal* roomDataOut) {
		return 0;
	}
}
