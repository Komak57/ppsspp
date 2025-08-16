#pragma once
#include "Common/Net/SocketCompat.h"
#include "Common/Net/Resolve.h"
#include <CommonTypes.h>
#include <optional>
#include "Core/HLE/np_types.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include <mbedtls\timing.h>
#include <unordered_map>
#include <flatbuffers/flatbuffers.h>
#include <Core\np2_structs_generated.h>

// 0x88 bytes
//struct RoomInfo {
//	u16_le ID;
//	u16 Port;
//	u8 Status;
//	std::string Host;
//	u32_le IPAddr = 910526074; // 910526074 || 0x3645867a || 54.69.134.122 || elb001-mtc-ag09.mtc.usw2.np.cy.s0.playstation.net
//};
constexpr int RPCN_HEADER_SIZE = 15;
constexpr int COMMUNICATION_ID_SIZE = (9 + 3);

enum class PacketType : u8
{
	Request,
	Reply,
	Notification,
	ServerInfo,
};

enum class CommandType : u16
{
	Login,
	Terminate,
	Create,
	SendToken,
	SendResetToken,
	ResetPassword,
	ResetState,
	AddFriend,
	RemoveFriend,
	AddBlock,
	RemoveBlock,
	GetServerList,
	GetWorldList,
	CreateRoom,
	JoinRoom,
	LeaveRoom,
	SearchRoom,
	GetRoomDataExternalList,
	SetRoomDataExternal,
	GetRoomDataInternal,
	SetRoomDataInternal,
	GetRoomMemberDataInternal,
	SetRoomMemberDataInternal,
	SetUserInfo,
	PingRoomOwner,
	SendRoomMessage,
	RequestSignalingInfos,
	RequestTicket,
	SendMessage,
	GetBoardInfos,
	RecordScore,
	RecordScoreData,
	GetScoreData,
	GetScoreRange,
	GetScoreFriends,
	GetScoreNpid,
	GetNetworkTime,
	TusSetMultiSlotVariable,
	TusGetMultiSlotVariable,
	TusGetMultiUserVariable,
	TusGetFriendsVariable,
	TusAddAndGetVariable,
	TusTryAndSetVariable,
	TusDeleteMultiSlotVariable,
	TusSetData,
	TusGetData,
	TusGetMultiSlotDataStatus,
	TusGetMultiUserDataStatus,
	TusGetFriendsDataStatus,
	TusDeleteMultiSlotData,
	SetPresence,
	CreateRoomGUI,
	JoinRoomGUI,
	LeaveRoomGUI,
	GetRoomListGUI,
	SetRoomSearchFlagGUI,
	GetRoomSearchFlagGUI,
	SetRoomInfoGUI,
	GetRoomInfoGUI,
	QuickMatchGUI,
	SearchJoinRoomGUI,
};

enum class NotificationType : u16
{
	UserJoinedRoom,
	UserLeftRoom,
	RoomDestroyed,
	UpdatedRoomDataInternal,
	UpdatedRoomMemberDataInternal,
	FriendQuery,  // Other user sent a friend request
	FriendNew,    // Add a friend to the friendlist(either accepted a friend request or friend accepted it)
	FriendLost,   // Remove friend from the friendlist(user removed friend or friend removed friend)
	FriendStatus, // Set status of friend to Offline or Online
	RoomMessageReceived,
	MessageReceived,
	FriendPresenceChanged,
	SignalingHelper,
	MemberJoinedRoomGUI,
	MemberLeftRoomGUI,
	RoomDisappearedGUI,
	RoomOwnerChangedGUI,
	UserKickedGUI,
	QuickMatchCompleteGUI,
};

enum class rpcn_state
{
	failure_no_failure,
	failure_input,
	failure_wolfssl,
	failure_resolve,
	failure_binding,
	failure_connect,
	failure_id,
	failure_id_already_logged_in,
	failure_id_username,
	failure_id_password,
	failure_id_token,
	failure_protocol,
	failure_other,
};

enum class ErrorType : u8
{
	NoError,                     // No error
	Malformed,                   // Query was malformed, critical error that should close the connection
	Invalid,                     // The request type is invalid(wrong stage?)
	InvalidInput,                // The Input doesn't fit the constraints of the request
	TooSoon,                     // Time limited operation attempted too soon
	LoginError,                  // An error happened related to login
	LoginAlreadyLoggedIn,        // Can't log in because you're already logged in
	LoginInvalidUsername,        // Invalid username
	LoginInvalidPassword,        // Invalid password
	LoginInvalidToken,           // Invalid token
	CreationError,               // An error happened related to account creation
	CreationExistingUsername,    // Specific to Account Creation: username exists already
	CreationBannedEmailProvider, // Specific to Account Creation: the email provider is banned
	CreationExistingEmail,       // Specific to Account Creation: that email is already registered to an account
	RoomMissing,                 // User tried to interact with a non existing room
	RoomAlreadyJoined,           // User tried to join a room he's already part of
	RoomFull,                    // User tried to join a full room
	RoomPasswordMismatch,        // Room password didn't match
	RoomPasswordMissing,         // A password was missing during room creation
	RoomGroupNoJoinLabel,        // Tried to join a group room without a label
	RoomGroupFull,               // Room group is full
	RoomGroupJoinLabelNotFound,  // Join label was invalid in some way
	RoomGroupMaxSlotMismatch,    // Mismatch between max_slot and the listed slots in groups
	Unauthorized,                // User attempted an unauthorized operation
	DbFail,                      // Generic failure on db side
	EmailFail,                   // Generic failure related to email
	NotFound,                    // Object of the query was not found(user, etc), use RoomMissing for rooms instead
	Blocked,                     // The operation can't complete because you've been blocked
	AlreadyFriend,               // Can't add friend because already friend
	ScoreNotBest,                // A better score is already registered for that user/character_id
	ScoreInvalid,                // Score for player was found but wasn't what was expected
	ScoreHasData,                // Score already has data
	CondFail,                    // Condition related to query failed
	Unsupported,
};
inline const u32 ErrorToPSPError[] = {
	SCE_NP_MATCHING2_OKAY,									// No error
	SCE_NP_MATCHING2_ERROR_INVALID_ALIGNMENT,				// Query was malformed, critical error that should close the connection
	SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST,				// The request type is invalid(wrong stage?)
	SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT,				// The Input doesn't fit the constraints of the request
	SCE_NP_MATCHING2_SERVER_ERROR_BUSY,                     // Time limited operation attempted too soon
	SCE_NP_MATCHING2_SERVER_ERROR_REQUEST_OVERFLOW,         // An error happened related to login
	SCE_NP_MATCHING2_SERVER_ERROR_ALREADY_JOINED,			// Can't log in because you're already logged in
	SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_USER,				// Invalid username
	SCE_NP_MATCHING2_SERVER_ERROR_PASSWORD_MISMATCH,        // Invalid password
	SCE_NP_MATCHING2_SERVER_ERROR_INVALID_TICKET,           // Invalid token
	SCE_NP_MATCHING2_SERVER_ERROR_INTERNAL_SERVER_ERROR,    // An error happened related to account creation
	SCE_NP_MATCHING2_SERVER_ERROR_INTERNAL_SERVER_ERROR,    // Specific to Account Creation: username exists already
	SCE_NP_MATCHING2_SERVER_ERROR_INTERNAL_SERVER_ERROR,	// Specific to Account Creation: the email provider is banned
	SCE_NP_MATCHING2_SERVER_ERROR_INTERNAL_SERVER_ERROR,    // Specific to Account Creation: that email is already registered to an account
	SCE_NP_MATCHING2_ERROR_ROOM_NOT_FOUND,					// User tried to interact with a non existing room
	SCE_NP_MATCHING2_SERVER_ERROR_ALREADY_JOINED,           // User tried to join a room he's already part of
	SCE_NP_MATCHING2_SERVER_ERROR_ROOM_FULL,                // User tried to join a full room
	SCE_NP_MATCHING2_SERVER_ERROR_PASSWORD_MISMATCH,        // Room password didn't match
	SCE_NP_MATCHING2_SERVER_ERROR_INVALID_PASSWORD_SLOT_MASK,// A password was missing during room creation
	SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM_INSTANCE,    // Tried to join a group room without a label
	SCE_NP_MATCHING2_SERVER_ERROR_GROUP_FULL,               // Room group is full
	SCE_NP_MATCHING2_SERVER_ERROR_NO_ROOMGROUP,				// Join label was invalid in some way
	SCE_NP_MATCHING2_SERVER_ERROR_INVALID_GROUP_SLOT_NUM,   // Mismatch between max_slot and the listed slots in groups
	SCE_NP_MATCHING2_SERVER_ERROR_FORBIDDEN,                // User attempted an unauthorized operation
	SCE_NP_MATCHING2_SERVER_ERROR_INTERNAL_SERVER_ERROR,    // Generic failure on db side
	SCE_NP_MATCHING2_SERVER_ERROR_PLAYER_BANNED,            // Generic failure related to email
	SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_USER,             // Object of the query was not found(user, etc), use RoomMissing for rooms instead
	SCE_NP_MATCHING2_SERVER_ERROR_BLOCKED,                  // The operation can't complete because you've been blocked
	SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_CONTEXT,          // Can't add friend because already friend
	SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_CONTEXT,          // A better score is already registered for that user/character_id
	SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_CONTEXT,          // Score for player was found but wasn't what was expected
	SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_CONTEXT,          // Score already has data
	SCE_NP_MATCHING2_SERVER_ERROR_INTERNAL_SERVER_ERROR,    // Condition related to query failed
	SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_CONTEXT
};
constexpr const char* PacketTypeNames[] = {
	"NoError",                     // No error
	"Malformed",                   // Query was malformed, critical error that should close the connection
	"Invalid",                     // The request type is invalid(wrong stage?)
	"InvalidInput",                // The Input doesn't fit the constraints of the request
	"TooSoon",                     // Time limited operation attempted too soon
	"LoginError",                  // An error happened related to login
	"LoginAlreadyLoggedIn",        // Can't log in because you're already logged in
	"LoginInvalidUsername",        // Invalid username
	"LoginInvalidPassword",        // Invalid password
	"LoginInvalidToken",           // Invalid token
	"CreationError",               // An error happened related to account creation
	"CreationExistingUsername",    // Specific to Account Creation: username exists already
	"CreationBannedEmailProvider", // Specific to Account Creation: the email provider is banned
	"CreationExistingEmail",       // Specific to Account Creation: that email is already registered to an account
	"RoomMissing",                 // User tried to interact with a non existing room
	"RoomAlreadyJoined",           // User tried to join a room he's already part of
	"RoomFull",                    // User tried to join a full room
	"RoomPasswordMismatch",        // Room password didn't match
	"RoomPasswordMissing",         // A password was missing during room creation
	"RoomGroupNoJoinLabel",        // Tried to join a group room without a label
	"RoomGroupFull",               // Room group is full
	"RoomGroupJoinLabelNotFound",  // Join label was invalid in some way
	"RoomGroupMaxSlotMismatch",    // Mismatch between max_slot and the listed slots in groups
	"Unauthorized",                // User attempted an unauthorized operation
	"DbFail",                      // Generic failure on db side
	"EmailFail",                   // Generic failure related to email
	"NotFound",                    // Object of the query was not found(user, etc), use RoomMissing for rooms instead
	"Blocked",                     // The operation can't complete because you've been blocked
	"AlreadyFriend",               // Can't add friend because already friend
	"ScoreNotBest",                // A better score is already registered for that user/character_id
	"ScoreInvalid",                // Score for player was found but wasn't what was expected
	"ScoreHasData",                // Score already has data
	"CondFail",                    // Condition related to query failed
	"Unsupported"
};
inline char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
#pragma pack(push, 1)
struct PacketHeader {
	u8 request;
	u16_le command;
	u32_le size;
	u64 reqId;
};
#pragma pack(pop)
class Packet {
public:
	Packet();
	~Packet();

	// Supplies header to packet data
	bool Pack(CommandType command, u64 packet_id);

	void Write(u8 data);
	void Write(u16 data);
	void Write(u32 data);
	void Write(u64 data);
	void Write(std::string data);
	void Write(const std::vector<u8>& data);

	void Append(const char* data, int len) {
		memcpy(dataPtr + data_length, data, len);
		data_length += len;
	}

	u8* Data() { return dataPtr; }
	int Length() { return data_length; }
	void Clear() { data_length = 0; memset(dataPtr, 0, sizeof(data_bytes)); }
private:
	int data_length = 0;
	const int data_size = 1024;
	u8 data_bytes[1024];
	u8* dataPtr;
};

inline static void FormatAddr(char* addrbuf, size_t bufsize, const addrinfo* info) {
	switch (info->ai_family) {
	case AF_INET:
	case AF_INET6:
		inet_ntop(info->ai_family, &((sockaddr_in*)info->ai_addr)->sin_addr, addrbuf, bufsize);
		break;
	default:
		snprintf(addrbuf, bufsize, "(Unknown AF %d)", info->ai_family);
		break;
	}
}

// Forward Declare
struct SceNpMatching2World;
struct SceNpMatching2RoomDataExternal;
struct SceNpMatching2RoomDataInternal;
namespace net {
	struct RPCNResponse {
		PacketHeader header;
		u8 error;
		std::vector<u8> data;
	};
	class MBEDTLS_Connection {
	public:
		bool connected = false;
		mbedtls_ssl_context sslCtx;
		mbedtls_net_context netCtx;

		mbedtls_ssl_config sslConfig;
		mbedtls_ctr_drbg_context ctrDrbg;
		mbedtls_entropy_context entropy;
		mbedtls_x509_crt caCert;
		// For UDP retransmissions
		mbedtls_timing_delay_context timerCtx;
	};
	enum class NPAgentType { PSN, RPCN };
	class NPAgent {
	public:
		MBEDTLS_Connection tls;
		virtual ~NPAgent() = default;

		// Inits the sockaddr_in.
		bool Resolve(DNSType type = DNSType::ANY);
		int InitializeSSL(int transport, std::string certPEM);
		void Disconnect();
		bool Send(Packet* packet, double timeout, bool* cancelled);
		int Recv(Packet* packet);
		
		virtual bool Connect(int maxTries = 1, double timeout = 10.0f, bool* cancelConnect = nullptr) = 0;
		// NPAuthAgent Functions
		virtual int Login(const char* npid, const char* token, const char* password) = 0;
		virtual int CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) = 0;

		// NPAgent Functions
		virtual int GetWorldInfo(int server_id, char npTitleId[], std::map<u32, SceNpMatching2World>* worldInfoOut) = 0;
		virtual int SearchRoom(PSPPointer<SceNpMatching2SearchRoomRequest> req, SearchRoomResponse*& roomResp) = 0;
		virtual int CreateJoinRoom(PSPPointer<SceNpMatching2CreateJoinRoomRequest> req, RoomDataInternal*& roomDataOut) = 0;
		virtual int GetRoomDataInternal(SceNpMatching2GetRoomDataInternalRequest* req, SceNpMatching2RoomDataInternal* roomDataOut) = 0;


		u8 GetStatus();
		//int GetID() { return ID; }
		SceNpMatching2ServerInfo GetServerInfo() { return { ID, status }; };
		u64 generate_request_id();
		std::vector<u8> GetCommHeader() {
			u8* data = new u8[COMMUNICATION_ID_SIZE];
			memcpy(data, npTitleId, 9);		// NPWR01446
			memcpy(data + 9, "_00", 3);		// _00
			std::vector<u8> ret(data, data + COMMUNICATION_ID_SIZE);
			return ret;
		}

		// Only to be used for bring-up and debugging.
		uintptr_t sock() const { if (SSLEnabled) return tls.netCtx.fd; else return sock_; }
		bool isSslEnabled() { return SSLEnabled; }

		u32 worldInfoPtr;
		std::map<u32, SceNpMatching2World> worlds;
		u32 roomDataPtr;
		std::map<u32, SceNpMatching2RoomDataInternal> rooms;
	protected:
		u16 ID;
		uintptr_t sock_ = -1;
		bool canceled = false;

		std::string host_;
		int port_ = -1;
		u8 status;
		addrinfo* resolved_ = nullptr;
		addrinfo* conn = nullptr;


		bool SSLEnabled = false;

		std::unordered_map<u64, RPCNResponse> responses;
		char npTitleId[9];
	};

	class PSNAgent : public NPAgent {
	public:
		~PSNAgent();
		PSNAgent(int serverId, std::string host, int port, u8 status = 2);

		bool Connect(int maxTries = 1, double timeout = 10.0f, bool* cancelConnect = nullptr);
		int Login(const char* npid, const char* token, const char* password);
		int CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email);

		int GetWorldInfo(int server_id, char npTitleId[], std::map<u32, SceNpMatching2World>* worldInfoOut);
		int SearchRoom(PSPPointer<SceNpMatching2SearchRoomRequest> req, SearchRoomResponse*& roomResp);
		int CreateJoinRoom(PSPPointer<SceNpMatching2CreateJoinRoomRequest> req, RoomDataInternal*& roomDataOut);
		int GetRoomDataInternal(SceNpMatching2GetRoomDataInternalRequest* req, SceNpMatching2RoomDataInternal* roomDataOut);
	};

	class RPCNAgent : public NPAgent {
	public:
		static const u32 PROTOCOL_VERSION = 26;
		~RPCNAgent();
		RPCNAgent(int serverId, std::string host, int port, u8 status = 2);

		bool Connect(int maxTries = 1, double timeout = 10.0f, bool* cancelConnect = nullptr);
		int Login(const char* npid, const char* token, const char* password);
		int CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email);

		int GetWorldInfo(int server_id, char npTitleId[], std::map<u32, SceNpMatching2World>* worldInfoOut);
		int SearchRoom(PSPPointer<SceNpMatching2SearchRoomRequest> req, SearchRoomResponse*& roomResp);
		int CreateJoinRoom(PSPPointer<SceNpMatching2CreateJoinRoomRequest> req, RoomDataInternal*& roomDataOut);
		int GetRoomDataInternal(SceNpMatching2GetRoomDataInternalRequest* req, SceNpMatching2RoomDataInternal* roomDataOut);

		void start_read_thread();
		void stop_read_thread();

		// Waits for a response matching request_id
		// Blocks until the full packet for that request is ready
		RPCNResponse take_pending_request(u64 request_id);
	private:
		void read_loop();

		std::thread read_thread;
		bool running = false;

		std::mutex buffer_mutex;
		std::condition_variable buffer_cv;
	};

	class NPAuthAgent {
	public:
		MBEDTLS_Connection tls;

		virtual ~NPAuthAgent() = default;

		// Inits the sockaddr_in.
		bool Resolve(DNSType type = DNSType::ANY);
		int InitializeSSL(int transport, std::string certPEM);
		virtual bool Connect(int maxTries = 1, double timeout = 20.0f, bool* cancelConnect = nullptr) = 0;
		void Disconnect();

		bool Send(Packet* packet, double timeout, bool* cancelled);
		int Recv(Packet* packet);

		//int GetID() { return ID; }
		SceNpMatching2ServerInfo GetServerInfo() { return { ID, status }; };

		virtual bool Login(const char* npid, const char* token, const char* password) = 0;
		virtual bool CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) = 0;
		//virtual int GetServers(SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr) = 0;

		// Only to be used for bring-up and debugging.
		uintptr_t sock() const { if (SSLEnabled) return tls.netCtx.fd; else return sock_; }
		bool isSslEnabled() { return SSLEnabled; }

	protected:
		u16 ID;
		uintptr_t sock_ = -1;
		bool canceled = false;

		std::string host_;
		int port_ = -1;
		u8 status;
		addrinfo* resolved_ = nullptr;
		addrinfo* conn = nullptr;

		bool SSLEnabled = false;
	};
	class PSNAuthAgent : public NPAuthAgent {
	public:
		~PSNAuthAgent();
		PSNAuthAgent(std::string host, int port);
		bool Connect(int maxTries = 2, double timeout = 20.0f, bool* cancelConnect = nullptr);
		static int GetServers(SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr);
		bool Login(const char* npid, const char* token, const char* password);
		bool CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email);
	};
	class RPCNAuthAgent : public NPAuthAgent {
	public:
		~RPCNAuthAgent();
		RPCNAuthAgent(std::string host, int port);
		bool Connect(int maxTries = 2, double timeout = 20.0f, bool* cancelConnect = nullptr);
		static int GetServers(SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr);
		static std::string generate_npid();
		bool Login(const char* npid, const char* token, const char* password);
		bool CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email);
	};

	inline std::unique_ptr<NPAuthAgent> CreateNPAuthAgent(NPAgentType type, std::string host = "", int port = 0) {
		switch (type) {
		case NPAgentType::PSN: return std::make_unique<PSNAuthAgent>(host, port);
		case NPAgentType::RPCN: return std::make_unique<RPCNAuthAgent>(host, port);
		}
		return nullptr;
	}
	inline std::unique_ptr<NPAgent> CreateNPAgent(NPAgentType type, int serverId, std::string host = "", int port = 0, u8 status = 2) {
		switch (type) {
		case NPAgentType::PSN: return std::make_unique<PSNAgent>(serverId, host, port, status);
		case NPAgentType::RPCN: return std::make_unique<RPCNAgent>(serverId, host, port, status);
		}
		return nullptr;
	}
}
