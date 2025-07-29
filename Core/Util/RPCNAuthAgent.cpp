#include "Core/Util/NPAgent.h"
#include <Core\HLE\HLE.h>
namespace net {
	// FIXME: Populate with actual connection credentials for RPCN
	RPCNAuthAgent::RPCNAuthAgent(std::string host, int port) {
		this->host_ = host;
		this->port_ = port;

		//std::string certificate = "";
		//InitializeSSL(certificate);
	}
	RPCNAuthAgent::~RPCNAuthAgent() {
		Disconnect();
	}
	bool RPCNAuthAgent::Login() {
		// npid
		// password
		// token

		// Send CommandType::Login, req_id, data, packet_data

		// Get Reply
		// online_name
		// avatar_url
		// user_id 
		// friends (PS3)

		// Disconnect on Error
		// Disconnect on malformed data
		Packet packet = Packet();
		packet.Write("NPJH50332\0");
		packet.Write("password\0");
		packet.Write("token\0");

		packet.Pack(CommandType::Login, 0);

		int i;
		std::string hexdata = "";
		for (i = 0; i < packet.Length(); i++) {
			char const c = packet.Data()[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Request: %s", hexdata.c_str());

		// packet.Pack(0x0112, packet.Length()+4);
		//net::Buffer buffer;
		//void* dst = buffer.Append(packet_size);
		//memcpy(dst, packet.Data(), packet.Length());

		//bool flushed = buffer.FlushSocket(sock_, 60.0, &canceled);
		bool flushed = Send(&packet, 5.0, &canceled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}
		//net::Buffer readbuf;
		//// Read response
		int ret;
		if ((ret = Recv(&packet, 4096)) < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return false;
		}

		//std::string response;
		//readbuf.Take(ret, &response);

		// 1002 0027 10010000 01001000 00000000 19490bc9118fc488581dcbfcb27a4a31 001d 0003 0001 01
		hexdata = "";
		for (i = 0; i < packet.Length(); i++) {
			int c = packet.Data()[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Response: %s", hexdata.c_str());
		return true;
	}

	int RPCNAuthAgent::GetServers(SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr) {
		serversPtr->emplace(1, net::CreateNPAgent(net::NPAgentType::RPCN, 1, "rpcn.revurb.us", 3657, SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE));
		serversPtr->emplace(2, net::CreateNPAgent(net::NPAgentType::RPCN, 2, "rpcn.revurb.us", 3657, SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE));
		return 0;
	}
}
