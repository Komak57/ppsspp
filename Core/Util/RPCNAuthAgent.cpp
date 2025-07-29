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
		const char* npTitleId = "NPJH50332";
		u32 packet_size = 0x36;
		Packet packet = Packet();

		uint8_t guid[16] = { 0xe2, 0x88, 0xf3, 0x36, 0xa6, 0x13, 0x98, 0x1d,
						 0x1f, 0x8b, 0x02, 0x53, 0xf3, 0x4d, 0x40, 0x28 };

		packet.Write((u16)0x1201);		// OPCODE ?
		packet.Write((u16)packet_size);	// PACKET_LEN
		packet.Write((u32)0x10010000);	// ?
		packet.Write((u32)0x01001000);	// ?
		packet.Write((u32)0x00000000);	// padding?
		int i = 0;
		for (i = 0; i < 16; i++)
			packet.Write((u8)guid[i]);	// GUID?
		packet.Write((u16)0x1010);		// ?

		packet.Write((u16)(sizeof(npTitleId) + 4));	// TITLE_LEN
		packet.Write(npTitleId);
		packet.Write("_00");

		packet.Write((u16)0x4073);		// ?
		packet.Write((u16)0x0002);		// ?
		packet.Write((u16)0x0001);		// ?

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
