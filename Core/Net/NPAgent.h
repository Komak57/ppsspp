#pragma once
#include <optional>
#include <type_traits> // is_constant_evaluated
#include <unordered_set>
#include <condition_variable>
#include <unordered_map>
#include <thread>   // For std::thread
#include <atomic>

#include "Common/CommonTypes.h"
#include "Common/Net/Resolve.h"
#include "Common/Net/SocketCompat.h"

#include "Core/HLE/NpTypes.h"
#include "Core/HLE/Np2Types.h"
#include "Core/np2_structs_generated.h"
#include "Core/Net/HTTPS.h"
#include "Core/Net/NpMatching2Cache.h"

// Port used to communicate with RPCN (3657)
const u16 SCE_RPCN_PORT = 3657;
constexpr int RPCN_HEADER_SIZE = 15;
//constexpr int COMMUNICATION_ID_SIZE = (9 + 3);

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
constexpr const char* NotificationTypeNames[] = {
	"UserJoinedRoom",
	"UserLeftRoom",
	"RoomDestroyed",
	"UpdatedRoomDataInternal",
	"UpdatedRoomMemberDataInternal",
	"FriendQuery",
	"FriendNew",
	"FriendLost",
	"FriendStatus",
	"RoomMessageReceived",
	"MessageReceived",
	"FriendPresenceChanged",
	"SignalingHelper",
	"MemberJoinedRoomGUI",
	"MemberLeftRoomGUI",
	"RoomDisappearedGUI",
	"RoomOwnerChangedGUI",
	"UserKickedGUI",
	"QuickMatchCompleteGUI",
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
	u64 uid;
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
	void AddCommId(flatbuffers::FlatBufferBuilder* builder, uint8_t* commId);

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

// COMID is sent as 9 chars - + '_' + 2 digits
constexpr std::size_t COMMUNICATION_ID_COMID_COMPONENT_SIZE = 9;
constexpr std::size_t COMMUNICATION_ID_SUBID_COMPONENT_SIZE = 2;
constexpr std::size_t COMMUNICATION_ID_SIZE = COMMUNICATION_ID_COMID_COMPONENT_SIZE + COMMUNICATION_ID_SUBID_COMPONENT_SIZE + 1;

template <typename T>
inline T read_from_ptr(const u8* ptr) {
	T val;
	std::memcpy(&val, ptr, sizeof(T));
	return val;
}

class vec_stream
{
public:
	vec_stream() = delete;
	vec_stream(std::vector<u8>& _vec, std::size_t initial_index = 0)
		: vec(_vec), i(initial_index) {
	}
	bool is_error() const
	{
		return error;
	}

	void dump() const;


	// Getters

	template <typename T>
	T get()
	{
		if (sizeof(T) + i > vec.size() || error)
		{
			error = true;
			return static_cast<T>(0);
		}
		T res = read_from_ptr<T>(&vec[i]);
		i += sizeof(T);
		return res;
	}
	std::string get_string(bool empty)
	{
		std::string res{};
		while (i < vec.size() && vec[i] != 0)
		{
			res.push_back(vec[i]);
			i++;
		}
		i++;

		if (!empty && res.empty())
		{
			error = true;
		}

		return res;
	}
	std::vector<u8> get_rawdata()
	{
		u32 size = get<u32>();
		//memcpy(&size, &vec[i], sizeof(u32));
		//i += sizeof(u32);

		if (i + size > vec.size())
		{
			error = true;
			return {};
		}

		std::vector<u8> ret;
		std::copy(vec.begin() + i, vec.begin() + i + size, std::back_inserter(ret));
		i += size;
		return ret;
	}

	SceNpCommunicationId get_com_id()
	{
		if (i + COMMUNICATION_ID_SIZE > vec.size() || error)
		{
			error = true;
			return {};
		}

		SceNpCommunicationId com_id{};
		std::memcpy(&com_id.data[0], &vec[i], COMMUNICATION_ID_COMID_COMPONENT_SIZE);
		const std::string sub_id(reinterpret_cast<const char*>(&vec[i + COMMUNICATION_ID_COMID_COMPONENT_SIZE + 1]), COMMUNICATION_ID_SUBID_COMPONENT_SIZE);
		const unsigned long result_num = std::strtoul(sub_id.c_str(), nullptr, 10);

		if (result_num > 99)
		{
			error = true;
			return {};
		}

		com_id.num = static_cast<u8>(result_num);
		i += COMMUNICATION_ID_SIZE;
		return com_id;
	}

	template <typename T>
	const T* get_flatbuffer()
	{
		auto rawdata_vec = get_rawdata();

		if (error)
			return nullptr;

		if (vec.empty())
		{
			error = true;
			return nullptr;
		}

		const T* ret = flatbuffers::GetRoot<T>(rawdata_vec.data());
		flatbuffers::Verifier verifier(rawdata_vec.data(), rawdata_vec.size());

		if (!ret->Verify(verifier))
		{
			error = true;
			return nullptr;
		}

		aligned_bufs.push_back(std::move(rawdata_vec));

		return ret;
	}

	// Setters

	//template <typename T>
	//void insert(T value)
	//{
	//	value = std::bit_cast<le_t<T>, T>(value);
	//	// resize + memcpy instead?
	//	for (usz index = 0; index < sizeof(T); index++)
	//	{
	//		vec.push_back(*(reinterpret_cast<u8*>(&value) + index));
	//	}
	//}
	void insert_string(const std::string& str) const
	{
		std::copy(str.begin(), str.end(), std::back_inserter(vec));
		vec.push_back(0);
	}

protected:
	std::vector<u8>& vec;
	std::vector<std::vector<u8>> aligned_bufs;
	std::size_t i = 0;
	bool error = false;
};

namespace np {
	bool is_valid_npid(const SceNpId& npid);

}

namespace net {
	typedef std::function<std::string(const std::string&)> ResolveFunc;

	static const int forceCiphers[] = {
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		0
	};

	enum class NPAgentType { PSN, RPCN };

	struct NPServerInfo {
		NPAgentType nptype;
		SceNpMatching2ServerId id;
		std::string host = "";
		np_in_port_t port;
		SceNpMatching2ServerStatus status;
	};

	struct RPCNResponse {
		PacketHeader header;
		u8 error;
		std::vector<u8> data;
		vec_stream* stream;
	};

	class NPAgent : public HTTPS {
	public:
		virtual ~NPAgent() = default;

		// Inits the sockaddr_in.
		bool Resolve(DNSType type = DNSType::ANY);
		virtual void Disconnect() = 0;
		bool Send(Packet* packet, double timeout, bool* cancelled);
		virtual std::chrono::microseconds HandleResponses() = 0;
		int Recv(Packet* packet, bool* cancelled);
		
		bool SelectServer(SceNpMatching2ServerId ServerID) {
			for (size_t i = 0; i < servers.size(); ++i) {
				if (servers[i].id == ServerID) {
					selected = &servers[i];
					return true;
				}
			}
			return false;
		}

		SceNpMatching2ServerInfo GetServerInfo(SceNpMatching2ServerId ServerID) {
			for (size_t i = 0; i < servers.size(); ++i)
				if (servers[i].id == ServerID)
					return { servers[i].id, servers[i].status };

			return { ServerID, SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE };
		};

		virtual bool Connect(int maxTries = 1, double timeout = 10.0f, bool* cancelConnect = nullptr) = 0;
		// NPAuthAgent Functions
		virtual int Login(const char* npid, const char* token, const char* password) = 0;
		virtual int CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) = 0;
		virtual int GetServers(SceNpCommunicationId npTitleId) = 0;
		virtual u64 GetNetworkTime() = 0;

		// NPAgent Functions
		virtual int GetWorldInfo(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, int server_id, SceNpCommunicationId npTitleId) = 0;
		virtual int RequestSignalingInfo(std::string npid, u32 conn_id) = 0;
		virtual int SearchRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2SearchRoomRequest> req) = 0;
		virtual int CreateJoinRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2CreateJoinRoomRequest> req) = 0;
		virtual int JoinRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2JoinRoomRequest> req) = 0;
		virtual int LeaveRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2LeaveRoomRequest> req) = 0;
		virtual int GetRoomDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataInternalRequest* req) = 0;
		virtual int SetRoomDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataInternalRequest* req) = 0;
		virtual int SetRoomDataExternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataExternalRequest* req) = 0;
		virtual int SendRoomMessage(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SendRoomMessageRequest* req) = 0;
		virtual int SetUserInfo(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetUserInfoRequest* req) = 0;
		virtual int GetRoomDataExternalList(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataExternalListRequest* req) = 0;

		virtual void start_read_thread() = 0;
		virtual void stop_read_thread() = 0;

		bool IsConnected() { return connected; }
		//u8 GetStatus();
		//int GetID() { return ID; }
		void UpdateOptions(s32 optionFlags) {
			include_onlinename = optionFlags & SCE_NP_MATCHING2_CONTEXT_OPTION_USE_ONLINENAME;
			include_avatarurl = optionFlags & SCE_NP_MATCHING2_CONTEXT_OPTION_USE_AVATARURL;
		}
		bool IncludeOnlineName() {
			return include_onlinename;
		}
		bool IncludeAvatarUrl() {
			return include_avatarurl;
		}
		std::string GetOnlineName() {
			return online_name;
		}
		std::string GetAvatarURL() {
			return avatar_url;
		}
		s64 GetUserID() {
			return user_id;
		}
		u32 GetConnAddr() {
			struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(conn->ai_addr);
			return addr->sin_addr.s_addr;
		}
		u32 GetLocalAddr() {
			std::unique_lock<std::mutex> lock(sig_mutex);
			if (local_addr_sig.load() == 0)
				sigv.wait_for(lock, std::chrono::seconds(10), [&] { return local_addr_sig.load() != 0; });
			return local_addr_sig.load();
		}
		u32 GetSigAddr() {
			std::unique_lock<std::mutex> lock(sig_mutex);
			if (addr_sig.load() == 0)
				sigv.wait_for(lock, std::chrono::seconds(10), [&] { return addr_sig.load() != 0; });
			return addr_sig.load();
		}
		u16 GetSigPort() {
			std::unique_lock<std::mutex> lock(sig_mutex);
			if (port_sig.load() == 0)
				sigv.wait_for(lock, std::chrono::seconds(10), [&] { return port_sig.load() != 0; });
			return port_sig.load();
		}
		u64 GetLatencyUs() {
			return latency.load();
		}
	public:
		// Holds all servers provided by GetServers
		// <index, NPServerInfo>
		std::vector<NPServerInfo> servers;
		// Pointer to the selected server
		NPServerInfo* selected = nullptr;

		// Only to be used for bring-up and debugging.
		uintptr_t sock() const { if (tls.enabled) return tls.netCtx.fd; else return sock_; }

		Cache cache;

	protected:
		uintptr_t sock_ = -1;
		bool cancelled = false;

		std::string host_;
		int port_ = -1;
		addrinfo* resolved_ = nullptr;
		addrinfo* conn = nullptr;

		bool connected = false;

		SceNpCommunicationId commId;
		std::string online_name;
		std::string avatar_url;
		std::atomic<s64> user_id;

		std::mutex sig_mutex;
		std::condition_variable sigv;
		std::atomic<u32> addr_sig;
		std::atomic<u16> port_sig;
		std::atomic<u32> local_addr_sig = 0;
		std::atomic<u64> latency = 0;

		std::chrono::steady_clock::time_point last_ping_time_ipv4{}, last_pong_time_ipv4{};
		std::chrono::steady_clock::time_point last_ping_time_ipv6{}, last_pong_time_ipv6{};

		bool include_onlinename = false;
		bool include_avatarurl = false;
	};

	class PSNAgent : public NPAgent {
	public:
		~PSNAgent();
		PSNAgent(std::string host, int port);
		std::chrono::microseconds HandleResponses();

		bool Connect(int maxTries = 1, double timeout = 10.0f, bool* cancelConnect = nullptr);
		void Disconnect();
		int Login(const char* npid, const char* token, const char* password);
		int CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email);
		int GetServers(SceNpCommunicationId npTitleId);
		u64 GetNetworkTime();

		int GetWorldInfo(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, int server_id, SceNpCommunicationId npTitleId);
		int RequestSignalingInfo(std::string npid, u32 conn_id);
		int SearchRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2SearchRoomRequest> req);
		int CreateJoinRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2CreateJoinRoomRequest> req);
		int JoinRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2JoinRoomRequest> req);
		int LeaveRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2LeaveRoomRequest> req);
		int GetRoomDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataInternalRequest* req);
		int SetRoomDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataInternalRequest* req);
		int SetRoomDataExternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataExternalRequest* req);
		int SendRoomMessage(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SendRoomMessageRequest* req);
		int SetUserInfo(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetUserInfoRequest* req);
		int GetRoomDataExternalList(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataExternalListRequest* req);

		void start_read_thread();
		void stop_read_thread();
	private:
		bool running = false;
	};

	class RPCNAgent : public NPAgent {
	public:
		static const u32 PROTOCOL_VERSION = 26;
		~RPCNAgent();
		RPCNAgent(std::string host, int port);
		std::chrono::microseconds HandleResponses();

		bool Connect(int maxTries = 1, double timeout = 10.0f, bool* cancelConnect = nullptr);
		void Disconnect();
		int Login(const char* npid, const char* token, const char* password);
		int CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email);
		int GetServers(SceNpCommunicationId npTitleId);
		u64 GetNetworkTime();

		int GetWorldInfo(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, int server_id, SceNpCommunicationId npTitleId);
		int GetWorldInfo_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int RequestSignalingInfo(std::string npid, u32 conn_id);
		int SearchRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2SearchRoomRequest> req);
		int SearchRoom_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int CreateJoinRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2CreateJoinRoomRequest> req);
		int CreateJoinRoom_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int JoinRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2JoinRoomRequest> req);
		int JoinRoom_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int LeaveRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2LeaveRoomRequest> req);
		int LeaveRoom_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int GetRoomDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataInternalRequest* req);
		int GetRoomDataInternal_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int SetRoomDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataInternalRequest* req);
		int SetRoomDataInternal_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int SetRoomDataExternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataExternalRequest* req);
		int SetRoomDataExternal_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int SendRoomMessage(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SendRoomMessageRequest* req);
		int SendRoomMessage_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int SetUserInfo(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetUserInfoRequest* req);
		int SetUserInfo_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);
		int GetRoomDataExternalList(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataExternalListRequest* req);
		int GetRoomDataExternalList_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp);

		void start_read_thread();
		void stop_read_thread();

		u64 generate_uid(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId app_req);
		std::vector<u8> GetCommHeader() {
			std::array<char, COMMUNICATION_ID_SIZE+1> buffer{};
			// Format directly into buffer: 9-char ID + "_%02d"
			snprintf(buffer.data(), buffer.size(), "%.9s_%02d", commId.data, commId.num);
			//std::vector<u8> ret(data, data + COMMUNICATION_ID_SIZE);
			return std::vector<u8>(buffer.begin(), buffer.end()-1);
		}
		// Waits for a response matching request_id
		// Blocks until the full packet for that request is ready
		RPCNResponse take_pending_request(u64 request_id);
	private:
		void read_loop();

		std::thread read_thread;
		std::thread signaling_thread;
		bool running = false;

		std::mutex buffer_mutex;
		std::condition_variable buffer_cv;

		std::unordered_map<u64, RPCNResponse> responses;
		std::unordered_map<u64, RPCNResponse> notifications;
	};

	class NPAuthAgent : public HTTPS {
	public:
		virtual ~NPAuthAgent() = default;

		// Inits the sockaddr_in.
		bool Resolve(DNSType type = DNSType::ANY);
		virtual std::unique_ptr<NPAgent> CreateAgent() = 0;
		virtual bool Connect(int maxTries = 1, double timeout = 20.0f, bool* cancelConnect = nullptr) = 0;
		virtual void Disconnect() = 0;
		virtual NPAgentType GetAuthType() const = 0;

		bool Send(Packet* packet, double timeout, bool* cancelled);
		int Recv(Packet* packet, bool* cancelled);

		//int GetID() { return ID; }
		//SceNpMatching2ServerInfo GetServerInfo() { return { ID, status }; };

		virtual int Login(const char* npid, const char* token, const char* password) = 0;
		virtual int CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) = 0;
		virtual int ResendToken(const char* npid, const char* password) = 0;
		virtual int SendResetToken(const char* npid, const char* email) = 0;
		virtual int ResetPassword(const char* npid, const char* token, const char* password) = 0;
		virtual u64 GetNetworkTime() = 0;

		// Only to be used for bring-up and debugging.
		uintptr_t sock() const { if (tls.enabled) return tls.netCtx.fd; else return sock_; }
		bool IsConnected() { return connected; }
		std::string GetOnlineName() {
			return online_name;
		}
		std::string GetAvatarURL() {
			return avatar_url;
		}
		s64 GetUserID() {
			return user_id;
		}
		u32 GetConnAddr() {
			struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(conn->ai_addr);
			return htonl(addr->sin_addr.s_addr);
		}
		int GetConnPort() { return port_; }

	protected:
		uintptr_t sock_ = -1;
		bool cancelled = false;

		std::string host_;
		int port_ = -1;
		addrinfo* resolved_ = nullptr;
		addrinfo* conn = nullptr;

		bool connected = false;
		SceNpCommunicationId commId;

		std::string online_name;
		std::string avatar_url;
		s64 user_id;
	};
	class PSNAuthAgent : public NPAuthAgent {
	public:
		~PSNAuthAgent();
		PSNAuthAgent(std::string host, int port);
		std::unique_ptr<NPAgent> CreateAgent();
		bool Connect(int maxTries = 2, double timeout = 20.0f, bool* cancelConnect = nullptr);
		void Disconnect();
		int Login(const char* npid, const char* token, const char* password);
		int CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email);
		int ResendToken(const char* npid, const char* password);
		int SendResetToken(const char* npid, const char* email);
		int ResetPassword(const char* npid, const char* token, const char* password);
		u64 GetNetworkTime();
		NPAgentType GetAuthType() const override { return NPAgentType::PSN; }
	};
	class RPCNAuthAgent : public NPAuthAgent {
	public:
		~RPCNAuthAgent();
		RPCNAuthAgent(std::string host, int port);
		std::unique_ptr<NPAgent> CreateAgent();
		bool Connect(int maxTries = 2, double timeout = 20.0f, bool* cancelConnect = nullptr);
		void Disconnect();
		static std::string generate_npid();
		int Login(const char* npid, const char* token, const char* password);
		int CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email);
		int ResendToken(const char* npid, const char* password);
		int SendResetToken(const char* npid, const char* email);
		int ResetPassword(const char* npid, const char* token, const char* password);
		u64 GetNetworkTime();

		NPAgentType GetAuthType() const override { return NPAgentType::RPCN; }
		void start_read_thread();
		void stop_read_thread();

		u64 generate_request_id();
		std::vector<u8> GetCommHeader() {
			std::array<char, COMMUNICATION_ID_SIZE + 1> buffer{};
			// Format directly into buffer: 9-char ID + "_%02d"
			snprintf(buffer.data(), buffer.size(), "%.9s_%02d", commId.data, commId.num);
			//std::vector<u8> ret(data, data + COMMUNICATION_ID_SIZE);
			return std::vector<u8>(buffer.begin(), buffer.end() - 1);
		}
		// Waits for a response matching request_id
		// Blocks until the full packet for that request is ready
		RPCNResponse take_pending_request(u64 request_id);
	private:
		void read_loop();

		std::thread read_thread;
		bool running = false;

		std::mutex buffer_mutex;
		std::condition_variable buffer_cv;

		std::unordered_map<u64, RPCNResponse> responses;
		std::unordered_map<u64, RPCNResponse> notifications;
	};

	inline std::unique_ptr<NPAuthAgent> CreateNPAuthAgent(NPAgentType type, std::string host = "", int port = 0) {
		switch (type) {
		case NPAgentType::PSN: return std::make_unique<PSNAuthAgent>(host, port);
		case NPAgentType::RPCN: return std::make_unique<RPCNAuthAgent>(host, port);
		}
		return nullptr;
	}
	inline std::unique_ptr<NPAgent> CreateNPAgent(NPAgentType type, std::string host = "", int port = 0) {
		switch (type) {
		case NPAgentType::PSN: return std::make_unique<PSNAgent>(host, port);
		case NPAgentType::RPCN: return std::make_unique<RPCNAgent>(host, port);
		}
		return nullptr;
	}
}

extern std::unique_ptr<net::NPAuthAgent> npAuthServer;
extern std::unique_ptr<net::NPAgent> npServer;
