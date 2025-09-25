#pragma once
#include <mutex>
#include <deque>
#include <map>

#include <sstream>
#include <string>
#include <iomanip>
#include <cstdint>
#include <algorithm>

#include "Common/CommonTypes.h"
#include "Common/Swap.h"
#include "Core/MemMap.h"
#include "Core/HLE/NpTypes.h"


#pragma pack(push,1)

// Based on https://gist.githubusercontent.com/raw/4140449/PS%20Vita (Might be slightly different with PSP?)
#define SCE_NP_MATCHING2_OKAY									0x00000000
#define SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY					0x80550c01
#define SCE_NP_MATCHING2_ERROR_ALREADY_INITIALIZED				0x80550c02
#define SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED					0x80550c03
#define SCE_NP_MATCHING2_ERROR_CONTEXT_MAX						0x80550c04 // might be "Invalid Argument" on PSP?
#define SCE_NP_MATCHING2_ERROR_CONTEXT_ALREADY_EXISTS			0x80550c05 // might be "Context Max/Context Id higher than 7" on PSP?
#define SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND				0x80550c06
#define SCE_NP_MATCHING2_ERROR_CONTEXT_ALREADY_STARTED			0x80550c07
#define SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_STARTED				0x80550c08
#define SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND					0x80550c09
#define SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT					0x80550c0a
#define SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID				0x80550c0b
#define SCE_NP_MATCHING2_ERROR_INVALID_SERVER_ID				0x80550c0c
#define SCE_NP_MATCHING2_ERROR_INVALID_LOBBY_ID					0x80550c0e
#define SCE_NP_MATCHING2_ERROR_INVALID_ROOM_ID					0x80550c0f
#define SCE_NP_MATCHING2_ERROR_INVALID_MEMBER_ID				0x80550c10
#define SCE_NP_MATCHING2_ERROR_INVALID_ATTRIBUTE_ID				0x80550c11
#define SCE_NP_MATCHING2_ERROR_INVALID_CASTTYPE					0x80550c12
#define SCE_NP_MATCHING2_ERROR_INVALID_SORT_METHOD				0x80550c13
#define SCE_NP_MATCHING2_ERROR_INVALID_MAX_SLOT					0x80550c14
#define SCE_NP_MATCHING2_ERROR_INVALID_OPT_SIZE					0x80550c15
#define SCE_NP_MATCHING2_ERROR_INVALID_MATCHING_SPACE			0x80550c16
#define SCE_NP_MATCHING2_ERROR_INVALID_BLOCK_KICK_FLAG			0x80550c18
#define SCE_NP_MATCHING2_ERROR_INVALID_MESSAGE_TARGET			0x80550c19
#define SCE_NP_MATCHING2_ERROR_RANGE_FILTER_MAX					0x80550c1a
#define SCE_NP_MATCHING2_ERROR_INVALID_ALIGNMENT				0x80550c1e
#define SCE_NP_MATCHING2_ERROR_CONNECTION_CLOSED_BY_SERVER		0x80550c22
#define SCE_NP_MATCHING2_ERROR_SSL_VERIFY_FAILED				0x80550c23
#define SCE_NP_MATCHING2_ERROR_SSL_HANDSHAKE					0x80550c24
#define SCE_NP_MATCHING2_ERROR_SSL_SEND							0x80550c25
#define SCE_NP_MATCHING2_ERROR_SSL_RECV							0x80550c26
#define SCE_NP_MATCHING2_ERROR_JOINED_SESSION_MAX				0x80550c27
#define SCE_NP_MATCHING2_ERROR_ALREADY_JOINED					0x80550c28
#define SCE_NP_MATCHING2_ERROR_INVALID_SESSION_TYPE				0x80550c29
#define SCE_NP_MATCHING2_ERROR_NP_SIGNED_OUT					0x80550c2b
#define SCE_NP_MATCHING2_ERROR_BUSY								0x80550c2c
#define SCE_NP_MATCHING2_ERROR_SERVER_NOT_AVAILABLE				0x80550c2d
#define SCE_NP_MATCHING2_ERROR_NOT_ALLOWED						0x80550c2e
#define SCE_NP_MATCHING2_ERROR_ABORTED							0x80550c2f
#define SCE_NP_MATCHING2_ERROR_REQUEST_NOT_FOUND				0x80550c30
#define SCE_NP_MATCHING2_ERROR_SESSION_DESTROYED				0x80550c31
#define SCE_NP_MATCHING2_ERROR_CONTEXT_STOPPED					0x80550c32
#define SCE_NP_MATCHING2_ERROR_INVALID_REQUEST_PARAMETER		0x80550c33
#define SCE_NP_MATCHING2_ERROR_NOT_NP_SIGN_IN					0x80550c34
#define SCE_NP_MATCHING2_ERROR_ROOM_NOT_FOUND					0x80550c35
#define SCE_NP_MATCHING2_ERROR_ROOM_MEMBER_NOT_FOUND			0x80550c36
#define SCE_NP_MATCHING2_ERROR_LOBBY_NOT_FOUND					0x80550c37
#define SCE_NP_MATCHING2_ERROR_LOBBY_MEMBER_NOT_FOUND			0x80550c38
#define SCE_NP_MATCHING2_ERROR_KEEPALIVE_TIMEOUT				0x80550c3a
#define SCE_NP_MATCHING2_ERROR_TIMEOUT_TOO_SHORT				0x80550c3b
#define SCE_NP_MATCHING2_ERROR_TIMEDOUT							0x80550c3c
#define SCE_NP_MATCHING2_ERROR_INVALID_SLOTGROUP				0x80550c3d
#define SCE_NP_MATCHING2_ERROR_INVALID_ATTRIBUTE_SIZE			0x80550c3e
#define SCE_NP_MATCHING2_ERROR_CANNOT_ABORT						0x80550c3f
#define SCE_NP_MATCHING2_ERROR_SESSION_NOT_FOUND				0x80550c40

#define SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST						0x80550d01
#define SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE				0x80550d02
#define SCE_NP_MATCHING2_SERVER_ERROR_BUSY								0x80550d03
#define SCE_NP_MATCHING2_SERVER_ERROR_END_OF_SERVICE					0x80550d04
#define SCE_NP_MATCHING2_SERVER_ERROR_INTERNAL_SERVER_ERROR				0x80550d05
#define SCE_NP_MATCHING2_SERVER_ERROR_PLAYER_BANNED						0x80550d06
#define SCE_NP_MATCHING2_SERVER_ERROR_FORBIDDEN							0x80550d07
#define SCE_NP_MATCHING2_SERVER_ERROR_BLOCKED							0x80550d08
#define SCE_NP_MATCHING2_SERVER_ERROR_UNSUPPORTED_NP_ENV				0x80550d09
#define SCE_NP_MATCHING2_SERVER_ERROR_INVALID_TICKET					0x80550d0a
#define SCE_NP_MATCHING2_SERVER_ERROR_INVALID_SIGNATURE					0x80550d0b
#define SCE_NP_MATCHING2_SERVER_ERROR_EXPIRED_TICKET					0x80550d0c
#define SCE_NP_MATCHING2_SERVER_ERROR_ENTITLEMENT_REQUIRED				0x80550d0d
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_CONTEXT					0x80550d0e
#define SCE_NP_MATCHING2_SERVER_ERROR_CLOSED							0x80550d0f
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_TITLE						0x80550d10
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_WORLD						0x80550d11
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_LOBBY						0x80550d12
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM						0x80550d13
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_LOBBY_INSTANCE			0x80550d14
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM_INSTANCE				0x80550d15
#define SCE_NP_MATCHING2_SERVER_ERROR_PASSWORD_MISMATCH					0x80550d17
#define SCE_NP_MATCHING2_SERVER_ERROR_LOBBY_FULL						0x80550d18
#define SCE_NP_MATCHING2_SERVER_ERROR_ROOM_FULL							0x80550d19
#define SCE_NP_MATCHING2_SERVER_ERROR_GROUP_FULL						0x80550d1b
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_USER						0x80550d1c
#define SCE_NP_MATCHING2_SERVER_ERROR_TITLE_PASSPHRASE_MISMATCH			0x80550d1e
#define SCE_NP_MATCHING2_SERVER_ERROR_CONSOLE_BANNED					0x80550d28
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_ROOMGROUP						0x80550d29
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_GROUP						0x80550d2a
#define SCE_NP_MATCHING2_SERVER_ERROR_NO_PASSWORD						0x80550d2b
#define SCE_NP_MATCHING2_SERVER_ERROR_INVALID_GROUP_SLOT_NUM			0x80550d2c
#define SCE_NP_MATCHING2_SERVER_ERROR_INVALID_PASSWORD_SLOT_MASK		0x80550d2d
#define SCE_NP_MATCHING2_SERVER_ERROR_DUPLICATE_GROUP_LABEL				0x80550d2e
#define SCE_NP_MATCHING2_SERVER_ERROR_REQUEST_OVERFLOW					0x80550d2f
#define SCE_NP_MATCHING2_SERVER_ERROR_ALREADY_JOINED					0x80550d30
#define SCE_NP_MATCHING2_SERVER_ERROR_NAT_TYPE_MISMATCH					0x80550d31
#define SCE_NP_MATCHING2_SERVER_ERROR_ROOM_INCONSISTENCY				0x80550d32

#define SCE_NP_MATCHING2_SIGNALING_ERROR_NOT_INITIALIZED				0x80550e01
#define SCE_NP_MATCHING2_SIGNALING_ERROR_ALREADY_INITIALIZED			0x80550e02
#define SCE_NP_MATCHING2_SIGNALING_ERROR_OUT_OF_MEMORY					0x80550e03
#define SCE_NP_MATCHING2_SIGNALING_ERROR_CTXID_NOT_AVAILABLE			0x80550e04
#define SCE_NP_MATCHING2_SIGNALING_ERROR_CTX_NOT_FOUND					0x80550e05
#define SCE_NP_MATCHING2_SIGNALING_ERROR_REQID_NOT_AVAILABLE			0x80550e06
#define SCE_NP_MATCHING2_SIGNALING_ERROR_REQ_NOT_FOUND					0x80550e07
#define SCE_NP_MATCHING2_SIGNALING_ERROR_PARSER_CREATE_FAILED			0x80550e08
#define SCE_NP_MATCHING2_SIGNALING_ERROR_PARSER_FAILED					0x80550e09
#define SCE_NP_MATCHING2_SIGNALING_ERROR_INVALID_NAMESPACE				0x80550e0a
#define SCE_NP_MATCHING2_SIGNALING_ERROR_NETINFO_NOT_AVAILABLE			0x80550e0b
#define SCE_NP_MATCHING2_SIGNALING_ERROR_PEER_NOT_RESPONDING			0x80550e0c
#define SCE_NP_MATCHING2_SIGNALING_ERROR_CONNID_NOT_AVAILABLE			0x80550e0d
#define SCE_NP_MATCHING2_SIGNALING_ERROR_CONN_NOT_FOUND					0x80550e0e
#define SCE_NP_MATCHING2_SIGNALING_ERROR_PEER_UNREACHABLE				0x80550e0f
#define SCE_NP_MATCHING2_SIGNALING_ERROR_TERMINATED_BY_PEER				0x80550e10
#define SCE_NP_MATCHING2_SIGNALING_ERROR_TIMEOUT						0x80550e11
#define SCE_NP_MATCHING2_SIGNALING_ERROR_CTX_MAX						0x80550e12
#define SCE_NP_MATCHING2_SIGNALING_ERROR_RESULT_NOT_FOUND				0x80550e13
#define SCE_NP_MATCHING2_SIGNALING_ERROR_CONN_IN_PROGRESS				0x80550e14
#define SCE_NP_MATCHING2_SIGNALING_ERROR_INVALID_ARGUMENT				0x80550e15
#define SCE_NP_MATCHING2_SIGNALING_ERROR_OWN_NP_ID						0x80550e16
#define SCE_NP_MATCHING2_SIGNALING_ERROR_TOO_MANY_CONN					0x80550e17
#define SCE_NP_MATCHING2_SIGNALING_ERROR_TERMINATED_BY_MYSELF			0x80550e18
#define SCE_NP_MATCHING2_SIGNALING_ERROR_MATCHING2_PEER_NOT_FOUND		0x80550e19

enum SceNpMatching2EventType
{
	SCE_NP_MATCHING2_REQUEST_EVENT,
	SCE_NP_MATCHING2_ROOM_EVENT,
	SCE_NP_MATCHING2_ROOM_MSG_EVENT,
	SCE_NP_MATCHING2_LOBBY_EVENT,
	SCE_NP_MATCHING2_LOBBY_MSG_EVENT,
	SCE_NP_MATCHING2_SIGNALING_EVENT
};

enum RPCNMatching2RequestEvent
{
	// Room event
	SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined = 0x1101,
	SCE_NP_MATCHING2_ROOM_EVENT_MemberLeft = 0x1102,
	SCE_NP_MATCHING2_ROOM_EVENT_Kickedout = 0x1103,
	SCE_NP_MATCHING2_ROOM_EVENT_RoomDestroyed = 0x1104,
	SCE_NP_MATCHING2_ROOM_EVENT_RoomOwnerChanged = 0x1105,
	SCE_NP_MATCHING2_ROOM_EVENT_UpdatedRoomDataInternal = 0x1106,
	SCE_NP_MATCHING2_ROOM_EVENT_UpdatedRoomMemberDataInternal = 0x1107,
	SCE_NP_MATCHING2_ROOM_EVENT_UpdatedSignalingOptParam = 0x1108,

	// Room message event
	SCE_NP_MATCHING2_ROOM_MSG_EVENT_ChatMessage = 0x2101,
	SCE_NP_MATCHING2_ROOM_MSG_EVENT_Message = 0x2102,

	// Lobby event
	SCE_NP_MATCHING2_LOBBY_EVENT_MemberJoined = 0x3201,
	SCE_NP_MATCHING2_LOBBY_EVENT_MemberLeft = 0x3202,
	SCE_NP_MATCHING2_LOBBY_EVENT_LobbyDestroyed = 0x3203,
	SCE_NP_MATCHING2_LOBBY_EVENT_UpdatedLobbyMemberDataInternal = 0x3204,

	// Lobby message event
	SCE_NP_MATCHING2_LOBBY_MSG_EVENT_ChatMessage = 0x4201,
	SCE_NP_MATCHING2_LOBBY_MSG_EVENT_Invitation = 0x4202,
};

#define SCE_NP_MATCHING2_SIGNALING_EVENT_Dead							0x5101
#define SCE_NP_MATCHING2_SIGNALING_EVENT_Established					0x5102
#define SCE_NP_MATCHING2_SIGNALING_EVENT_NetinfoResult					0x5103

enum SceNpError : u32 {
	// Signaling
	SCE_NP_SIGNALING_ERROR_NOT_INITIALIZED = 0x8002a801,
	SCE_NP_SIGNALING_ERROR_ALREADY_INITIALIZED = 0x8002a802,
	SCE_NP_SIGNALING_ERROR_OUT_OF_MEMORY = 0x8002a803,
	SCE_NP_SIGNALING_ERROR_CTXID_NOT_AVAILABLE = 0x8002a804,
	SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND = 0x8002a805,
	SCE_NP_SIGNALING_ERROR_REQID_NOT_AVAILABLE = 0x8002a806,
	SCE_NP_SIGNALING_ERROR_REQ_NOT_FOUND = 0x8002a807,
	SCE_NP_SIGNALING_ERROR_PARSER_CREATE_FAILED = 0x8002a808,
	SCE_NP_SIGNALING_ERROR_PARSER_FAILED = 0x8002a809,
	SCE_NP_SIGNALING_ERROR_INVALID_NAMESPACE = 0x8002a80a,
	SCE_NP_SIGNALING_ERROR_NETINFO_NOT_AVAILABLE = 0x8002a80b,
	SCE_NP_SIGNALING_ERROR_PEER_NOT_RESPONDING = 0x8002a80c,
	SCE_NP_SIGNALING_ERROR_CONNID_NOT_AVAILABLE = 0x8002a80d,
	SCE_NP_SIGNALING_ERROR_CONN_NOT_FOUND = 0x8002a80e,
	SCE_NP_SIGNALING_ERROR_PEER_UNREACHABLE = 0x8002a80f,
	SCE_NP_SIGNALING_ERROR_TERMINATED_BY_PEER = 0x8002a810,
	SCE_NP_SIGNALING_ERROR_TIMEOUT = 0x8002a811,
	SCE_NP_SIGNALING_ERROR_CTX_MAX = 0x8002a812,
	SCE_NP_SIGNALING_ERROR_RESULT_NOT_FOUND = 0x8002a813,
	SCE_NP_SIGNALING_ERROR_CONN_IN_PROGRESS = 0x8002a814,
	SCE_NP_SIGNALING_ERROR_INVALID_ARGUMENT = 0x8002a815,
	SCE_NP_SIGNALING_ERROR_OWN_NP_ID = 0x8002a816,
	SCE_NP_SIGNALING_ERROR_TOO_MANY_CONN = 0x8002a817,
	SCE_NP_SIGNALING_ERROR_TERMINATED_BY_MYSELF = 0x8002a818,
};
// Based on https://github.com/RPCS3/rpcs3/blob/master/rpcs3/Emu/Cell/Modules/sceNp2.h (Just as reference, might be slightly different than PSP)
// Event of request functions
enum PS3Matching2RequestEvent
{
	SCE_NP_MATCHING2_REQUEST_EVENT_Empty = 0x0000,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo = 0x0001,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList = 0x0002,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList = 0x0003,
	SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal = 0x0004,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList = 0x0005,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetLobbyInfoList = 0x0006,
	SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo = 0x0007,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList = 0x0008,
	SCE_NP_MATCHING2_REQUEST_EVENT_CreateServerContext = 0x0009,
	SCE_NP_MATCHING2_REQUEST_EVENT_DeleteServerContext = 0x000a,
	SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom = 0x0101,
	SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom = 0x0102,
	SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom = 0x0103,
	SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner = 0x0104,
	SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember = 0x0105,
	SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom = 0x0106,
	SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage = 0x0107,
	SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage = 0x0108,
	SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal = 0x0109,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal = 0x010a,
	SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal = 0x010b,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal = 0x010c,
	SCE_NP_MATCHING2_REQUEST_EVENT_SetSignalingOptParam = 0x010d,
	SCE_NP_MATCHING2_REQUEST_EVENT_JoinLobby = 0x0201,
	SCE_NP_MATCHING2_REQUEST_EVENT_LeaveLobby = 0x0202,
	SCE_NP_MATCHING2_REQUEST_EVENT_SendLobbyChatMessage = 0x0203,
	SCE_NP_MATCHING2_REQUEST_EVENT_SendLobbyInvitation = 0x0204,
	SCE_NP_MATCHING2_REQUEST_EVENT_SetLobbyMemberDataInternal = 0x0205,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetLobbyMemberDataInternal = 0x0206,
	SCE_NP_MATCHING2_REQUEST_EVENT_GetLobbyMemberDataInternalList = 0x0207,
	SCE_NP_MATCHING2_REQUEST_EVENT_SignalingGetPingInfo = 0x0e01,
};

// Based on decompiled np_matching2.prx, commented with syscalls where the event id is being used
#define PSP_NP_MATCHING2_EVENT_0001	0x0001	// GetServerInfo
#define PSP_NP_MATCHING2_EVENT_0002	0x0002	// GetWorldInfoList
#define PSP_NP_MATCHING2_EVENT_0003	0x0003	// SetUserInfo
#define PSP_NP_MATCHING2_EVENT_0004	0x0004	// GetUserInfoList
#define PSP_NP_MATCHING2_EVENT_0005	0x0005	// GetRoomMemberDataExternalList
#define PSP_NP_MATCHING2_EVENT_0006	0x0006	// SetRoomDataExternal
#define PSP_NP_MATCHING2_EVENT_0007	0x0007	// GetRoomDataExternalList

#define PSP_NP_MATCHING2_EVENT_0101	0x0101	// CreateJoinRoom
#define PSP_NP_MATCHING2_EVENT_0102	0x0102	// JoinRoom
#define PSP_NP_MATCHING2_EVENT_0103	0x0103	// LeaveRoom
#define PSP_NP_MATCHING2_EVENT_0104	0x0104	// GrantRoomOwner
#define PSP_NP_MATCHING2_EVENT_0105	0x0105	// KickoutRoomMember
#define PSP_NP_MATCHING2_EVENT_0106	0x0106	// SearchRoom
#define PSP_NP_MATCHING2_EVENT_0107	0x0107	// SendRoomChatMessage
#define PSP_NP_MATCHING2_EVENT_0108	0x0108	// SendRoomMessage, also used on various places (internal function)
#define PSP_NP_MATCHING2_EVENT_0109	0x0109	// SetRoomDataInternal
#define PSP_NP_MATCHING2_EVENT_010A	0x010A	// GetRoomDataInternal
#define PSP_NP_MATCHING2_EVENT_010B	0x010B	// SetRoomMemberDataInternal
#define PSP_NP_MATCHING2_EVENT_010C	0x010C	// GetRoomMemberDataInternal
#define PSP_NP_MATCHING2_EVENT_010D	0x010D	// GetRoomMemberDataInternalList
#define PSP_NP_MATCHING2_EVENT_010E	0x010E	// SetSignalingOptParam

#define PSP_NP_MATCHING2_EVENT_A102	0xA102	// Used on various places (internal function)

// Either this is an ID, state/status, flags, or might be size of data?
#define PSP_NP_MATCHING2_STATE_1001	0x1001
#define PSP_NP_MATCHING2_STATE_1006	0x1006
#define PSP_NP_MATCHING2_STATE_1007	0x1007
#define PSP_NP_MATCHING2_STATE_1008	0x1008

#define PSP_NP_MATCHING2_STATE_1200	0x1200
#define PSP_NP_MATCHING2_STATE_1206	0x1206
#define PSP_NP_MATCHING2_STATE_1207	0x1207
#define PSP_NP_MATCHING2_STATE_1208	0x1208
#define PSP_NP_MATCHING2_STATE_1209	0x1209
#define PSP_NP_MATCHING2_STATE_120B	0x120B
#define PSP_NP_MATCHING2_STATE_120C	0x120C

#define PSP_NP_MATCHING2_STATE_3202	0x3202
#define PSP_NP_MATCHING2_STATE_3203	0x3203
#define PSP_NP_MATCHING2_STATE_3204	0x3204
#define PSP_NP_MATCHING2_STATE_3205	0x3205
#define PSP_NP_MATCHING2_STATE_3206	0x3206
#define PSP_NP_MATCHING2_STATE_3207	0x3207
#define PSP_NP_MATCHING2_STATE_3208	0x3208
#define PSP_NP_MATCHING2_STATE_320A	0x320A
#define PSP_NP_MATCHING2_STATE_3210	0x3210
#define PSP_NP_MATCHING2_STATE_3211	0x3211

#define PSP_NP_MATCHING2_MAX_CONTEXTID	7;

// Constants for matching functions and structures
enum
{
	SCE_NP_MATCHING2_ALLOWED_USER_MAX = 100,
	SCE_NP_MATCHING2_BLOCKED_USER_MAX = 100,
	SCE_NP_MATCHING2_CHAT_MSG_MAX_SIZE = 1024,
	SCE_NP_MATCHING2_BIN_MSG_MAX_SIZE = 1024,
	SCE_NP_MATCHING2_GROUP_LABEL_SIZE = 8,
	SCE_NP_MATCHING2_INVITATION_OPTION_DATA_MAX_SIZE = 32,
	SCE_NP_MATCHING2_INVITATION_TARGET_SESSION_MAX = 2,
	SCE_NP_MATCHING2_LOBBY_MEMBER_DATA_INTERNAL_LIST_MAX = 256,
	SCE_NP_MATCHING2_LOBBY_MEMBER_DATA_INTERNAL_EXTENDED_DATA_LIST_MAX = 64,
	SCE_NP_MATCHING2_LOBBY_BIN_ATTR_INTERNAL_NUM = 2,
	SCE_NP_MATCHING2_LOBBYMEMBER_BIN_ATTR_INTERNAL_NUM = 1,
	SCE_NP_MATCHING2_LOBBYMEMBER_BIN_ATTR_INTERNAL_MAX_SIZE = 64,
	SCE_NP_MATCHING2_LOBBY_MAX_SLOT = 256,
	SCE_NP_MATCHING2_PRESENCE_OPTION_DATA_SIZE = 16,
	SCE_NP_MATCHING2_RANGE_FILTER_START_INDEX_MIN = 1,
	SCE_NP_MATCHING2_RANGE_FILTER_MAX = 20,
	SCE_NP_MATCHING2_ROOM_MAX_SLOT = 64,
	SCE_NP_MATCHING2_ROOM_GROUP_ID_MAX = 15,
	SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_NUM = 2,
	SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_MAX_SIZE = 256,
	SCE_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_NUM = 2,
	SCE_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_MAX_SIZE = 256,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_NUM = 8,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_BIN_ATTR_EXTERNAL_NUM = 1,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_BIN_ATTR_EXTERNAL_MAX_SIZE = 64,
	SCE_NP_MATCHING2_ROOMMEMBER_BIN_ATTR_INTERNAL_NUM = 1,
	SCE_NP_MATCHING2_ROOMMEMBER_BIN_ATTR_INTERNAL_MAX_SIZE = 64,
	SCE_NP_MATCHING2_SESSION_PASSWORD_SIZE = 8,
	SCE_NP_MATCHING2_USER_BIN_ATTR_NUM = 1,
	SCE_NP_MATCHING2_USER_BIN_ATTR_MAX_SIZE = 128,
	SCE_NP_MATCHING2_GET_USER_INFO_LIST_NPID_NUM_MAX = 25,
	SCE_NP_MATCHING2_GET_ROOM_DATA_EXTERNAL_LIST_ROOM_NUM_MAX = 20,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetServerInfo = 4,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetWorldInfoList = 3848,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetRoomMemberDataExternalList = 15624,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetRoomDataExternalList = 25768,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetLobbyInfoList = 1296,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetUserInfoList = 17604,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_CreateJoinRoom = 25224,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_JoinRoom = 25224,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_SearchRoom = 25776,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_SendRoomChatMessage = 1,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetRoomDataInternal = 25224,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetRoomMemberDataInternal = 372,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_JoinLobby = 1124,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_SendLobbyChatMessage = 1,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetLobbyMemberDataInternal = 672,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetLobbyMemberDataInternalList = 42760,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_SignalingGetPingInfo = 40,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_RoomMemberUpdateInfo = 396,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_RoomUpdateInfo = 28,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_RoomOwnerUpdateInfo = 40,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_RoomDataInternalUpdateInfo = 26208,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_RoomMemberDataInternalUpdateInfo = 493,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_SignalingOptParamUpdateInfo = 8,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_RoomMessageInfo = 1407,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_LobbyMemberUpdateInfo = 696,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_LobbyUpdateInfo = 8,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_LobbyMemberDataInternalUpdateInfo = 472,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_LobbyMessageInfo = 1790,
	SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_LobbyInvitationInfo = 870,
};

// Constants for commerce functions and structures
enum
{
	SCE_NP_COMMERCE2_VERSION = 2,
	SCE_NP_COMMERCE2_CTX_MAX = 1,
	SCE_NP_COMMERCE2_REQ_MAX = 1,
	SCE_NP_COMMERCE2_CURRENCY_CODE_LEN = 3,
	SCE_NP_COMMERCE2_CURRENCY_SYMBOL_LEN = 3,
	SCE_NP_COMMERCE2_THOUSAND_SEPARATOR_LEN = 4,
	SCE_NP_COMMERCE2_DECIMAL_LETTER_LEN = 4,
	SCE_NP_COMMERCE2_SP_NAME_LEN = 256,
	SCE_NP_COMMERCE2_CATEGORY_ID_LEN = 56,
	SCE_NP_COMMERCE2_CATEGORY_NAME_LEN = 256,
	SCE_NP_COMMERCE2_CATEGORY_DESCRIPTION_LEN = 1024,
	SCE_NP_COMMERCE2_PRODUCT_ID_LEN = 48,
	SCE_NP_COMMERCE2_PRODUCT_NAME_LEN = 256,
	SCE_NP_COMMERCE2_PRODUCT_SHORT_DESCRIPTION_LEN = 1024,
	SCE_NP_COMMERCE2_PRODUCT_LONG_DESCRIPTION_LEN = 4000,
	SCE_NP_COMMERCE2_SKU_ID_LEN = 56,
	SCE_NP_COMMERCE2_SKU_NAME_LEN = 180,
	SCE_NP_COMMERCE2_URL_LEN = 256,
	SCE_NP_COMMERCE2_RATING_SYSTEM_ID_LEN = 16,
	SCE_NP_COMMERCE2_RATING_DESCRIPTION_LEN = 60,
	SCE_NP_COMMERCE2_RECV_BUF_SIZE = 262144,
	SCE_NP_COMMERCE2_PRODUCT_CODE_BLOCK_LEN = 4,
	SCE_NP_COMMERCE2_PRODUCT_CODE_INPUT_MODE_USER_INPUT = 0,
	SCE_NP_COMMERCE2_PRODUCT_CODE_INPUT_MODE_CODE_SPECIFIED = 1,
	SCE_NP_COMMERCE2_GETCAT_MAX_COUNT = 60,
	SCE_NP_COMMERCE2_GETPRODLIST_MAX_COUNT = 60,
	SCE_NP_COMMERCE2_DO_CHECKOUT_MEMORY_CONTAINER_SIZE = 10485760,
	SCE_NP_COMMERCE2_DO_PROD_BROWSE_MEMORY_CONTAINER_SIZE = 16777216,
	SCE_NP_COMMERCE2_DO_DL_LIST_MEMORY_CONTAINER_SIZE = 10485760,
	SCE_NP_COMMERCE2_DO_PRODUCT_CODE_MEMORY_CONTAINER_SIZE = 16777216,
	SCE_NP_COMMERCE2_SYM_POS_PRE = 0,
	SCE_NP_COMMERCE2_SYM_POS_POST = 1,
};
#pragma pack(pop)

#pragma pack(push,1)
typedef u16 SceNpMatching2ServerId;
typedef u32 SceNpMatching2WorldId;
typedef u16 SceNpMatching2WorldNumber;
typedef u64 SceNpMatching2LobbyId;
typedef u16 SceNpMatching2LobbyNumber;
typedef u16 SceNpMatching2LobbyMemberId;
typedef u64 SceNpMatching2RoomId;
typedef u16 SceNpMatching2RoomNumber;
typedef u16 SceNpMatching2RoomMemberId;
typedef u8 SceNpMatching2RoomGroupId;
typedef u8 SceNpMatching2TeamId;
typedef u16 SceNpMatching2ContextId;
typedef u32 SceNpMatching2RequestId;
typedef u16 SceNpMatching2AttributeId;
typedef u32 SceNpMatching2FlagAttr;
typedef u8 SceNpMatching2NatType;
typedef u8 SceNpMatching2Operator;
typedef u8 SceNpMatching2CastType;
typedef u8 SceNpMatching2SessionType;
typedef u8 SceNpMatching2SignalingType;
typedef u8 SceNpMatching2SignalingFlag;
typedef u8 SceNpMatching2EventCause;
typedef u8 SceNpMatching2ServerStatus;
typedef u8 SceNpMatching2Role;
typedef u8 SceNpMatching2BlockKickFlag;
typedef u64 SceNpMatching2RoomPasswordSlotMask;
typedef u64 SceNpMatching2RoomJoinedSlotMask;
typedef u16 SceNpMatching2Event;
typedef u32 SceNpMatching2EventKey;
typedef u32 SceNpMatching2SignalingRequestId;
#pragma pack(pop)

// Request callback function
using SceNpMatching2RequestCallback = void(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2Event event, SceNpMatching2EventKey eventKey, s32 errorCode, u32 dataSize, PSPPointer<u8> arg); // PSPPointer<void> arg
using SceNpMatching2RoomEventCallback = void(SceNpMatching2ContextId ctxId, SceNpMatching2RoomId roomId, SceNpMatching2Event event, SceNpMatching2EventKey eventKey, s32 errorCode, u32 dataSize, PSPPointer<u8> arg); // PSPPointer<void> arg
using SceNpMatching2RoomMessageCallback = void(SceNpMatching2ContextId ctxId, SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId srcMemberId, SceNpMatching2Event event, SceNpMatching2EventKey eventKey, s32 errorCode, u32 dataSize, PSPPointer<u8> arg); // PSPPointer<void> arg
using SceNpMatching2LobbyEventCallback = void(SceNpMatching2ContextId ctxId, SceNpMatching2LobbyId lobbyId, SceNpMatching2Event event, SceNpMatching2EventKey eventKey, s32 errorCode, u32 dataSize, PSPPointer<u8> arg); // PSPPointer<void> arg
using SceNpMatching2LobbyMessageCallback = void(SceNpMatching2ContextId ctxId, SceNpMatching2LobbyId lobbyId, SceNpMatching2LobbyMemberId srcMemberId, SceNpMatching2Event event, SceNpMatching2EventKey eventKey, s32 errorCode, u32 dataSize, PSPPointer<u8> arg); // PSPPointer<void> arg
using SceNpMatching2SignalingCallback = void(SceNpMatching2ContextId ctxId, SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId peerMemberId, SceNpMatching2Event event, s32 errorCode, PSPPointer<u8> arg); // PSPPointer<void> arg
using SceNpMatching2ContextCallback = void(SceNpMatching2ContextId ctxId, SceNpMatching2Event event, SceNpMatching2EventCause eventCause, s32 errorCode, PSPPointer<u8> arg); // PSPPointer<void> arg


enum
{
	SCE_NP_MATCHING2_TITLE_PASSPHRASE_SIZE = 128
};

// Comparison operator specified as the search condition
enum
{
	SCE_NP_MATCHING2_OPERATOR_EQ = 1,
	SCE_NP_MATCHING2_OPERATOR_NE = 2,
	SCE_NP_MATCHING2_OPERATOR_LT = 3,
	SCE_NP_MATCHING2_OPERATOR_LE = 4,
	SCE_NP_MATCHING2_OPERATOR_GT = 5,
	SCE_NP_MATCHING2_OPERATOR_GE = 6,
};

// Message cast type
enum
{
	SCE_NP_MATCHING2_CASTTYPE_BROADCAST = 1,
	SCE_NP_MATCHING2_CASTTYPE_UNICAST = 2,
	SCE_NP_MATCHING2_CASTTYPE_MULTICAST = 3,
	SCE_NP_MATCHING2_CASTTYPE_MULTICAST_TEAM = 4,
};

// Session type
enum
{
	SCE_NP_MATCHING2_SESSION_TYPE_LOBBY = 1,
	SCE_NP_MATCHING2_SESSION_TYPE_ROOM = 2,
};

// Signaling type
enum
{
	SCE_NP_MATCHING2_SIGNALING_TYPE_NONE = 0,
	SCE_NP_MATCHING2_SIGNALING_TYPE_MESH = 1,
	SCE_NP_MATCHING2_SIGNALING_TYPE_STAR = 2,
};

enum
{
	SCE_NP_MATCHING2_SIGNALING_FLAG_MANUAL_MODE = 0x01
};

// Event cause
enum
{
	SCE_NP_MATCHING2_EVENT_CAUSE_LEAVE_ACTION = 1,
	SCE_NP_MATCHING2_EVENT_CAUSE_KICKOUT_ACTION = 2,
	SCE_NP_MATCHING2_EVENT_CAUSE_GRANT_OWNER_ACTION = 3,
	SCE_NP_MATCHING2_EVENT_CAUSE_SERVER_OPERATION = 4,
	SCE_NP_MATCHING2_EVENT_CAUSE_MEMBER_DISAPPEARED = 5,
	SCE_NP_MATCHING2_EVENT_CAUSE_SERVER_INTERNAL = 6,
	SCE_NP_MATCHING2_EVENT_CAUSE_CONNECTION_ERROR = 7,
	SCE_NP_MATCHING2_EVENT_CAUSE_NP_SIGNED_OUT = 8,
	SCE_NP_MATCHING2_EVENT_CAUSE_SYSTEM_ERROR = 9,
	SCE_NP_MATCHING2_EVENT_CAUSE_CONTEXT_ERROR = 10,
	SCE_NP_MATCHING2_EVENT_CAUSE_CONTEXT_ACTION = 11,
};

// Server status
enum
{
	SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE = 1,
	SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE = 2,
	SCE_NP_MATCHING2_SERVER_STATUS_BUSY = 3,
	SCE_NP_MATCHING2_SERVER_STATUS_MAINTENANCE = 4,
};

// Member role
enum
{
	SCE_NP_MATCHING2_ROLE_MEMBER = 1,
	SCE_NP_MATCHING2_ROLE_OWNER = 2,
};

// Status of kicked-out member with regards to rejoining
enum
{
	SCE_NP_MATCHING2_BLOCKKICKFLAG_OK = 0,
	SCE_NP_MATCHING2_BLOCKKICKFLAG_NG = 1,
};

// Sort method
enum
{
	SCE_NP_MATCHING2_SORT_METHOD_JOIN_DATE = 0,
	SCE_NP_MATCHING2_SORT_METHOD_SLOT_NUMBER = 1,
};

// Context options (matching)
enum
{
	SCE_NP_MATCHING2_CONTEXT_OPTION_USE_ONLINENAME = 0x01,
	SCE_NP_MATCHING2_CONTEXT_OPTION_USE_AVATARURL = 0x02,
};

// User information acquisition option
enum
{
	SCE_NP_MATCHING2_GET_USER_INFO_LIST_OPTION_WITH_ONLINENAME = 0x01,
	SCE_NP_MATCHING2_GET_USER_INFO_LIST_OPTION_WITH_AVATARURL = 0x02,
};

// Room search options
enum
{
	SCE_NP_MATCHING2_SEARCH_ROOM_OPTION_WITH_NPID = 0x01,
	SCE_NP_MATCHING2_SEARCH_ROOM_OPTION_WITH_ONLINENAME = 0x02,
	SCE_NP_MATCHING2_SEARCH_ROOM_OPTION_WITH_AVATARURL = 0x04,
	SCE_NP_MATCHING2_SEARCH_ROOM_OPTION_NAT_TYPE_FILTER = 0x08,
	SCE_NP_MATCHING2_SEARCH_ROOM_OPTION_RANDOM = 0x10,
};

// Send options
enum
{
	SCE_NP_MATCHING2_SEND_MSG_OPTION_WITH_NPID = 0x01,
	SCE_NP_MATCHING2_SEND_MSG_OPTION_WITH_ONLINENAME = 0x02,
	SCE_NP_MATCHING2_SEND_MSG_OPTION_WITH_AVATARURL = 0x04,
};

enum
{
	SCE_NP_MATCHING2_ROOM_ALLOWED_USER_MAX = 100,
	SCE_NP_MATCHING2_ROOM_BLOCKED_USER_MAX = 100,
};

// Flag-type lobby attribute
enum
{
	SCE_NP_MATCHING2_LOBBY_FLAG_ATTR_PERMANENT = 0x80000000,
	SCE_NP_MATCHING2_LOBBY_FLAG_ATTR_CLAN = 0x40000000,
	SCE_NP_MATCHING2_LOBBY_FLAG_ATTR_MEMBER_NOTIFICATION = 0x20000000,
};

// Attribute ID of lobby member internal binary attribute
enum
{
	SCE_NP_MATCHING2_LOBBYMEMBER_BIN_ATTR_INTERNAL_1_ID = 0x0039,
};

// Flag-type room attribute
enum
{
	SCE_NP_MATCHING2_ROOM_FLAG_ATTR_OWNER_AUTO_GRANT = 0x80000000,
	SCE_NP_MATCHING2_ROOM_FLAG_ATTR_CLOSED = 0x40000000,
	SCE_NP_MATCHING2_ROOM_FLAG_ATTR_FULL = 0x20000000,
	SCE_NP_MATCHING2_ROOM_FLAG_ATTR_HIDDEN = 0x10000000,
	SCE_NP_MATCHING2_ROOM_FLAG_ATTR_NAT_TYPE_RESTRICTION = 0x04000000,
	SCE_NP_MATCHING2_ROOM_FLAG_ATTR_PROHIBITIVE_MODE = 0x02000000,
};

// Flah-type room member attribute
enum
{
	SCE_NP_MATCHING2_LOBBYMEMBER_FLAG_ATTR_OWNER = 0x80000000,
	SCE_NP_MATCHING2_ROOMMEMBER_FLAG_ATTR_OWNER = 0x80000000,
};

// ID of external room search integer attribute
enum
{
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_1_ID = 0x004c,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_2_ID = 0x004d,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_3_ID = 0x004e,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_4_ID = 0x004f,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_5_ID = 0x0050,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_6_ID = 0x0051,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_7_ID = 0x0052,
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_8_ID = 0x0053,
};

// ID of external room search binary attribute
enum
{
	SCE_NP_MATCHING2_ROOM_SEARCHABLE_BIN_ATTR_EXTERNAL_1_ID = 0x0054,
};

// ID of external room binary attribute
enum
{
	SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_1_ID = 0x0055,
	SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_2_ID = 0x0056,
};

// ID of internal lobby binary attribute
enum
{
	SCE_NP_MATCHING2_LOBBY_BIN_ATTR_INTERNAL_1_ID = 0x0037,
	SCE_NP_MATCHING2_LOBBY_BIN_ATTR_INTERNAL_2_ID = 0x0038,
};

// ID of internal room binary attribute
enum
{
	SCE_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_1_ID = 0x0057,
	SCE_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_2_ID = 0x0058,
};

// ID of internal room member binary attribute
enum
{
	SCE_NP_MATCHING2_ROOMMEMBER_BIN_ATTR_INTERNAL_1_ID = 0x0059,
};

// Attribute ID of user binary attribute
enum
{
	SCE_NP_MATCHING2_USER_BIN_ATTR_1_ID = 0x005f,
};

struct NpMatching2Handler {
	u32 ctx_id;
	PSPPointer<SceNpMatching2RequestCallback> cb;
	PSPPointer<u8> cb_arg;
	u32 event_type;
};

// Arg1 and Arg2 seems to be a pair and predefined: 0x0001 with 0x1001, 0x0002 with 0x1008, 0x0003 with 0x1006, 0x0004 with 0x1007, 
//		0x0005 with 0x1206, 0x0006 with 0x1207, 0x0007 with 0x1208, 0x0101 with 0x1209, 0x0102 with 0x1209, 0x0103 with 0x3202,
//		0x0104 with 0x3210, 0x0105 with 0x3211, 0x0106 with 2 possibilities (0x1200 and 0x120c), 0x0107 with 0x3208, 0x0108 with 0x320a,
//		0x0109 with 0x3204, 0x010a with 0x3205, 0x010b with 0x3206, 0x010c with 0x3207, 0x010d with 0x3203, 0x010e with 0x3204,
//		0xa102 with 0x120b.
// Arg5 seems to be boolean (0/1), mostly 0, conditional when Arg1=0x0001
// Arg7 seems to be integer/state? (0..2), mostly 0, conditional when Arg1=0x0108 (0 on SendRoomMessage, 2 on others), 1 when Arg1=0xa102

// Contains all relevant information for a callback event
struct NpMatching2Args {
	// Now allows for optional arguments to be omitted in the sending process.
	static const size_t MAX_ARGS = 11;
	u32 request_id; // Only REQUEST_EVENT tracks request id's
	u32 event_code; // Everything has a matching Event code
	//u32 cbFunc;
	size_t argc = 0;
	u32_le args[MAX_ARGS]; // 7 elements (excluding optional data)? or may be 11 elements (including optional data)?
	// May be followed by optional data? since these Args usually created on the stack

	NpMatching2Args(u32 event_code, size_t argc, u32_le args[]) {
		this->request_id = 0;
		this->event_code = event_code;
		this->argc = (argc > MAX_ARGS) ? MAX_ARGS : argc;
		for (size_t i = 0; i < this->argc; ++i)
			this->args[i] = args[i];
	}
	NpMatching2Args(u32 request_id, u32 event_code, size_t argc, u32_le args[]) {
		this->request_id = request_id;
		this->event_code = event_code;
		this->argc = (argc > MAX_ARGS) ? MAX_ARGS : argc;
		for (size_t i = 0; i < this->argc; ++i)
			this->args[i] = args[i];
	}
	std::string ToString() {
		std::ostringstream oss;
		oss << "";

		for (size_t i = 0; i < argc; ++i) {
			if (i > 0) oss << ",";

			oss << std::setw(8) << std::setfill('0') << std::hex << args[i];
		}
		return oss.str();
	}

};

#pragma pack(push,1)
struct SceNpMatching2SignalingInfo {
	SceNpMatching2ServerStatus status;
	np_in_addr ipaddr;
	np_in_port_t port;
	u8 padding[1];
};

struct SceNpMatching2ServerInfo {
	SceNpMatching2ServerId id;
	SceNpMatching2ServerStatus status;
	u8 padding;
};

struct CellRtcTick
{
	u64 tick;
};

// Session password
struct SceNpMatching2SessionPassword
{
	u8 data[SCE_NP_MATCHING2_SESSION_PASSWORD_SIZE];
};

// Optional presence data
struct SceNpMatching2PresenceOptionData
{
	u8 data[SCE_NP_MATCHING2_PRESENCE_OPTION_DATA_SIZE];
	u32 length;
};

// Integer-type attribute
struct SceNpMatching2IntAttr
{
	SceNpMatching2AttributeId id;
	u8 padding[2];
	u32 num;
};

// Binary-type attribute
struct SceNpMatching2BinAttr
{
	SceNpMatching2AttributeId id;
	u8 padding[2];
	PSPPointer<u8> ptr;
	u32 size;
};

// Range filter
struct SceNpMatching2RangeFilter
{
	u32 startIndex;
	u32 max;
};

// Integer-type search condition
struct SceNpMatching2IntSearchFilter
{
	SceNpMatching2Operator searchOperator;
	u8 padding[3];
	SceNpMatching2IntAttr attr;
};

// Binary-type search condition
struct SceNpMatching2BinSearchFilter
{
	SceNpMatching2Operator searchOperator;
	u8 padding[3];
	SceNpMatching2BinAttr attr;
};

// Range of result
struct SceNpMatching2Range
{
	u32 startIndex;
	u32 total;
	u32 size;
};

// Session information about a session joined by the user
struct SceNpMatching2JoinedSessionInfo
{
	u8 sessionType;
	u8 padding1[1];
	SceNpMatching2ServerId serverId;
	SceNpMatching2WorldId worldId;
	SceNpMatching2LobbyId lobbyId;
	SceNpMatching2RoomId roomId;
	CellRtcTick joinDate;
};

// User information
struct SceNpMatching2UserInfo
{
	PSPPointer<SceNpMatching2UserInfo> next;
	SceNpUserInfo2 userInfo;
	PSPPointer<SceNpMatching2BinAttr> userBinAttr;
	u32 userBinAttrNum;
	SceNpMatching2JoinedSessionInfo joinedSessionInfo;
	u32 joinedSessionInfoNum;
};

// World
struct SceNpMatching2World
{
	u32 unk;
	SceNpMatching2WorldId worldId; // PS3 to PSP discrepency. WorldId is at offset +4
	u32 numOfLobby;
	u32 maxNumOfTotalLobbyMember;
	u32 curNumOfTotalLobbyMember;
	u32 curNumOfRoom;
	u32 curNumOfTotalRoomMember;
	u8 withEntitlementId;
	SceNpEntitlementId entitlementId;
	u8 padding[3];
};

// Lobby member internal binary attribute
struct SceNpMatching2LobbyMemberBinAttrInternal
{
	CellRtcTick updateDate;
	SceNpMatching2BinAttr data;
	u8 padding[4];
};

// Lobby-internal lobby member information
struct SceNpMatching2LobbyMemberDataInternal
{
	PSPPointer<SceNpMatching2LobbyMemberDataInternal> next;
	SceNpUserInfo2 userInfo;
	CellRtcTick joinDate;
	SceNpMatching2LobbyMemberId memberId;
	u8 padding[2];
	SceNpMatching2FlagAttr flagAttr;
	PSPPointer<SceNpMatching2JoinedSessionInfo> joinedSessionInfo;
	u32 joinedSessionInfoNum;
	PSPPointer<SceNpMatching2LobbyMemberBinAttrInternal> lobbyMemberBinAttrInternal;
	u32 lobbyMemberBinAttrInternalNum; // Unsigned ints are u32 not uint, right?
};

// Lobby member ID list
struct SceNpMatching2LobbyMemberIdList
{
	SceNpMatching2LobbyMemberId memberId;
	u32 memberIdNum;
	SceNpMatching2LobbyMemberId me;
	u8 padding[6];
};

// Lobby-internal binary attribute
struct SceNpMatching2LobbyBinAttrInternal
{
	CellRtcTick updateDate;
	SceNpMatching2LobbyMemberId updateMemberId;
	u8 padding[2];
	SceNpMatching2BinAttr data;
};

// Lobby-external lobby information
struct SceNpMatching2LobbyDataExternal
{
	PSPPointer<SceNpMatching2LobbyDataExternal> next;
	SceNpMatching2ServerId serverId;
	u8 padding1[2];
	SceNpMatching2WorldId worldId;
	u8 padding2[4];
	SceNpMatching2LobbyId	 lobbyId;
	u32 maxSlot;
	u32 curMemberNum;
	u32 flagAttr;
	PSPPointer<SceNpMatching2IntAttr> lobbySearchableIntAttrExternal;
	u32 lobbySearchableIntAttrExternalNum;
	PSPPointer<SceNpMatching2BinAttr> lobbySearchableBinAttrExternal;
	u32 lobbySearchableBinAttrExternalNum;
	PSPPointer<SceNpMatching2BinAttr> lobbyBinAttrExternal;
	u32 lobbyBinAttrExternalNum;
	u8 padding3[4];
};

// Lobby-internal lobby information
struct SceNpMatching2LobbyDataInternal
{
	SceNpMatching2ServerId serverId;
	u8 padding1[2];
	SceNpMatching2WorldId worldId;
	SceNpMatching2LobbyId lobbyId;
	u32 maxSlot;
	SceNpMatching2LobbyMemberIdList memberIdList;
	SceNpMatching2FlagAttr flagAttr;
	PSPPointer<SceNpMatching2LobbyBinAttrInternal> lobbyBinAttrInternal;
	u32 lobbyBinAttrInternalNum;
};

// Lobby message transmission destination
union SceNpMatching2LobbyMessageDestination
{
	SceNpMatching2LobbyMemberId unicastTarget;

	struct multicastTarget
	{
		PSPPointer<SceNpMatching2LobbyMemberId> memberId;
		u32 memberIdNum;
	};
};

// Group label
struct SceNpMatching2GroupLabel
{
	u8 data[SCE_NP_MATCHING2_GROUP_LABEL_SIZE];
};

// Set groups in a room
struct SceNpMatching2RoomGroupConfig
{
	u32 slotNum;
	u8 withLabel;
	SceNpMatching2GroupLabel label;
	u8 withPassword;
	u8 padding[2];
};

// Set group password
struct SceNpMatching2RoomGroupPasswordConfig
{
	SceNpMatching2RoomGroupId groupId;
	u8 withPassword;
	u8 padding[1];
};

// Group (of slots in a room)
struct SceNpMatching2RoomGroup
{
	SceNpMatching2RoomGroupId groupId;
	u8 withPassword;
	u8 withLabel;
	u8 padding[1];
	SceNpMatching2GroupLabel label;
	u32 slotNum;
	u32 curGroupMemberNum;
};

// Internal room member binary attribute
struct SceNpMatching2RoomMemberBinAttrInternal
{
	CellRtcTick updateDate;
	SceNpMatching2BinAttr data;
	u8 padding[4];
};

// External room member data
struct SceNpMatching2RoomMemberDataExternal
{
	PSPPointer<SceNpMatching2RoomMemberDataExternal> next;
	SceNpUserInfo2 userInfo;
	CellRtcTick joinDate;
	SceNpMatching2Role role;
	u8 padding[7];
};

// Internal room member data
struct SceNpMatching2RoomMemberDataInternal
{
	PSPPointer<SceNpMatching2RoomMemberDataInternal> next;
	SceNpUserInfo2 userInfo;
	CellRtcTick joinDate;
	SceNpMatching2RoomMemberId memberId;
	SceNpMatching2TeamId teamId;
	u8 padding1[1];
	PSPPointer<SceNpMatching2RoomGroup> roomGroup;
	SceNpMatching2NatType natType;
	u8 padding2[3];
	SceNpMatching2FlagAttr flagAttr;
	PSPPointer<SceNpMatching2RoomMemberBinAttrInternal> roomMemberBinAttrInternal;
	u32 roomMemberBinAttrInternalNum;
};

// Internal room member data list
struct SceNpMatching2RoomMemberDataInternalList
{
	PSPPointer<SceNpMatching2RoomMemberDataInternal> members;
	u32 membersNum;
	PSPPointer<SceNpMatching2RoomMemberDataInternal> me;
	PSPPointer<SceNpMatching2RoomMemberDataInternal> owner;
};

// Internal room binary attribute
struct SceNpMatching2RoomBinAttrInternal
{
	CellRtcTick updateDate;
	SceNpMatching2RoomMemberId updateMemberId;
	u8 padding[2];
	SceNpMatching2BinAttr data;
};

// External room data
struct SceNpMatching2RoomDataExternal
{
	PSPPointer<SceNpMatching2RoomDataExternal> next;
	SceNpMatching2ServerId serverId;
	u8 padding1[2];
	SceNpMatching2WorldId worldId;
	u16 publicSlotNum;
	u16 privateSlotNum;
	SceNpMatching2LobbyId lobbyId;
	SceNpMatching2RoomId roomId;
	u16 openPublicSlotNum;
	u16 maxSlot;
	u16 openPrivateSlotNum;
	u16 curMemberNum;
	SceNpMatching2RoomPasswordSlotMask passwordSlotMask;
	PSPPointer<SceNpUserInfo2> owner;
	PSPPointer<SceNpMatching2RoomGroup> roomGroup;
	u32 roomGroupNum;
	u32 flagAttr; // PSPo2i indicates +0x24 == owner (%s)
	PSPPointer<SceNpMatching2IntAttr> roomSearchableIntAttrExternal;
	u32 roomSearchableIntAttrExternalNum;
	PSPPointer<SceNpMatching2BinAttr> roomSearchableBinAttrExternal;
	u32 roomSearchableBinAttrExternalNum;
	PSPPointer<SceNpMatching2BinAttr> roomBinAttrExternal;
	u32 roomBinAttrExternalNum;
};

// Internal room data
struct SceNpMatching2RoomDataInternal
{
	SceNpMatching2ServerId serverId;
	u8 padding1[2];
	SceNpMatching2WorldId worldId;
	SceNpMatching2LobbyId lobbyId;
	SceNpMatching2RoomId roomId;
	SceNpMatching2RoomPasswordSlotMask passwordSlotMask;
	u32 maxSlot;
	SceNpMatching2RoomMemberDataInternalList memberList;
	PSPPointer<SceNpMatching2RoomGroup> roomGroup;
	u32 roomGroupNum;
	SceNpMatching2FlagAttr flagAttr;
	PSPPointer<SceNpMatching2RoomBinAttrInternal> roomBinAttrInternal;
	u32 roomBinAttrInternalNum;
};

// Room message recipient
union SceNpMatching2RoomMessageDestination
{
	SceNpMatching2RoomMemberId unicastTarget;

	struct multicastTarget
	{
		PSPPointer<SceNpMatching2RoomMemberId> memberId;
		u32 memberIdNum;
	} multicastTarget;

	SceNpMatching2TeamId multicastTargetTeamId;
};

// Invitation data
struct SceNpMatching2InvitationData
{
	PSPPointer<SceNpMatching2JoinedSessionInfo> targetSession;
	u32 targetSessionNum;
	PSPPointer<u8> optData; // PSPPointer<void>
	u32 optDataLen;
};

// Signaling option parameter
struct SceNpMatching2SignalingOptParam
{
	SceNpMatching2SignalingType type;
	SceNpMatching2SignalingFlag flag;
	SceNpMatching2RoomMemberId hubMemberId;
	u8 reserved2[4];
};

// Option parameters for requests
struct SceNpMatching2RequestOptParam
{
	PSPPointer<SceNpMatching2RequestCallback> cbFunc;
	PSPPointer<u8> cbFuncArg; // PSPPointer<void>
	// Discrepency between PS3 and PSP
	//u32 timeout;
	//u16 appReqId;
	//u8 padding[2];
};

// Room slot information
struct SceNpMatching2RoomSlotInfo
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2RoomJoinedSlotMask joinedSlotMask;
	SceNpMatching2RoomPasswordSlotMask passwordSlotMask;
	u16 publicSlotNum;
	u16 privateSlotNum;
	u16 openPublicSlotNum;
	u16 openPrivateSlotNum;
};

// Server data request parameter
struct SceNpMatching2GetServerInfoRequest
{
	SceNpMatching2ServerId serverId;
};

// Server data request response data
struct SceNpMatching2GetServerInfoResponse
{
	SceNpMatching2ServerInfo server;
};

// Request parameter for creating a server context
struct SceNpMatching2CreateServerContextRequest
{
	SceNpMatching2ServerId serverId;
};

// Request parameter for deleting a server context
struct SceNpMatching2DeleteServerContextRequest
{
	SceNpMatching2ServerId serverId;
};

// World data list request parameter
struct SceNpMatching2GetWorldInfoListRequest
{
	SceNpMatching2ServerId serverId;
};

// World data list request response data
struct SceNpMatching2GetWorldInfoListResponse
{
	PSPPointer<SceNpMatching2World> world;
	u32 worldNum;
};

// User information setting request parameter
struct SceNpMatching2SetUserInfoRequest
{
	SceNpMatching2ServerId serverId;
	u8 padding[2];
	PSPPointer<SceNpMatching2BinAttr> userBinAttr;
	u32 userBinAttrNum;
};

// User information list acquisition request parameter
struct SceNpMatching2GetUserInfoListRequest
{
	SceNpMatching2ServerId serverId;
	u8 padding[2];
	PSPPointer<SceNpId> npId;
	u32 npIdNum;
	PSPPointer<SceNpMatching2AttributeId> attrId;
	u32 attrIdNum;
	s32 option; // int should be be_t<s32, right?
};

// User information list acquisition response data
struct SceNpMatching2GetUserInfoListResponse
{
	PSPPointer<SceNpMatching2UserInfo> userInfo;
	u32 userInfoNum;
};

// External room member data list request parameter
struct SceNpMatching2GetRoomMemberDataExternalListRequest
{
	SceNpMatching2RoomId roomId;
};

// External room member data list request response data
struct SceNpMatching2GetRoomMemberDataExternalListResponse
{
	PSPPointer<SceNpMatching2RoomMemberDataExternal> roomMemberDataExternal;
	u32 roomMemberDataExternalNum;
};

// External room data configuration request parameters
struct SceNpMatching2SetRoomDataExternalRequest
{
	SceNpMatching2RoomId roomId;
	PSPPointer<SceNpMatching2IntAttr> roomSearchableIntAttrExternal;
	u32 roomSearchableIntAttrExternalNum;
	PSPPointer<SceNpMatching2BinAttr> roomSearchableBinAttrExternal;
	u32 roomSearchableBinAttrExternalNum;
	PSPPointer<SceNpMatching2BinAttr> roomBinAttrExternal;
	u32 roomBinAttrExternalNum;
};

// External room data list request parameters
struct SceNpMatching2GetRoomDataExternalListRequest
{
	PSPPointer<SceNpMatching2RoomId> roomId;
	u32 roomIdNum;
	PSPPointer<SceNpMatching2AttributeId> attrId;
	u32 attrIdNum;
};

// External room data list request response data
struct SceNpMatching2GetRoomDataExternalListResponse
{
	PSPPointer<SceNpMatching2RoomDataExternal> roomDataExternal;
	u32 roomDataExternalNum;
};

// Create-and-join room request parameters
struct SceNpMatching2CreateJoinRoomRequest
{
	SceNpMatching2WorldId worldId;
	u8 padding1[4];
	SceNpMatching2LobbyId lobbyId;
	u32 maxSlot;
	u32 flagAttr;
	PSPPointer<SceNpMatching2BinAttr> roomBinAttrInternal;
	u32 roomBinAttrInternalNum;
	PSPPointer<SceNpMatching2IntAttr> roomSearchableIntAttrExternal;
	u32 roomSearchableIntAttrExternalNum;
	PSPPointer<SceNpMatching2BinAttr> roomSearchableBinAttrExternal;
	u32 roomSearchableBinAttrExternalNum;
	PSPPointer<SceNpMatching2BinAttr> roomBinAttrExternal;
	u32 roomBinAttrExternalNum;
	PSPPointer<SceNpMatching2SessionPassword> roomPassword;
	PSPPointer<SceNpMatching2RoomGroupConfig> groupConfig;
	u32 groupConfigNum;
	PSPPointer<SceNpMatching2RoomPasswordSlotMask> passwordSlotMask;
	PSPPointer<SceNpId> allowedUser;
	u32 allowedUserNum;
	PSPPointer<SceNpId> blockedUser;
	u32 blockedUserNum;
	PSPPointer<SceNpMatching2GroupLabel> joinRoomGroupLabel;
	PSPPointer<SceNpMatching2BinAttr> roomMemberBinAttrInternal;
	u32 roomMemberBinAttrInternalNum;
	SceNpMatching2TeamId teamId;
	u8 padding2[3];
	PSPPointer<SceNpMatching2SignalingOptParam> sigOptParam;
	u8 padding3[4];
};

// Create-and-join room request response data
struct SceNpMatching2CreateJoinRoomResponse
{
	PSPPointer<SceNpMatching2RoomDataInternal> roomDataInternal;
};

// Join room request parameters
struct SceNpMatching2JoinRoomRequest
{
	SceNpMatching2RoomId roomId;
	PSPPointer<SceNpMatching2SessionPassword> roomPassword;
	PSPPointer<SceNpMatching2GroupLabel> joinRoomGroupLabel;
	PSPPointer<SceNpMatching2BinAttr> roomMemberBinAttrInternal;
	u32 roomMemberBinAttrInternalNum;
	SceNpMatching2PresenceOptionData optData;
	SceNpMatching2TeamId teamId;
	u8 padding[3];
};

// Join room request response data
struct SceNpMatching2JoinRoomResponse
{
	PSPPointer<SceNpMatching2RoomDataInternal> roomDataInternal;
};

// Leave room request parameters
struct SceNpMatching2LeaveRoomRequest
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2PresenceOptionData optData;
	u8 padding[4];
};

// Room ownership grant request parameters
struct SceNpMatching2GrantRoomOwnerRequest
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2RoomMemberId newOwner;
	u8 padding[2];
	SceNpMatching2PresenceOptionData optData;
};

// Kickout request parameters
struct SceNpMatching2KickoutRoomMemberRequest
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2RoomMemberId target;
	SceNpMatching2BlockKickFlag blockKickFlag;
	u8 padding[1];
	SceNpMatching2PresenceOptionData optData;
};

// Room search parameters
struct SceNpMatching2SearchRoomRequest
{
	s32 option;
	SceNpMatching2WorldId worldId;
	SceNpMatching2LobbyId lobbyId;
	SceNpMatching2RangeFilter rangeFilter;
	SceNpMatching2FlagAttr flagFilter;
	SceNpMatching2FlagAttr flagAttr;
	PSPPointer<SceNpMatching2IntSearchFilter> intFilter;
	u32 intFilterNum;
	PSPPointer<SceNpMatching2BinSearchFilter> binFilter;
	u32 binFilterNum;
	PSPPointer<SceNpMatching2AttributeId> attrId;
	u32 attrIdNum;
};

// Room search response data
struct SceNpMatching2SearchRoomResponse
{
	SceNpMatching2Range range;
	PSPPointer<SceNpMatching2RoomDataExternal> roomDataExternal;
};

// Room message send request parameters
struct SceNpMatching2SendRoomMessageRequest
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2CastType castType;
	u8 padding[3];
	SceNpMatching2RoomMessageDestination dst;
	PSPPointer<u8> msg; // PSPPointer<void>
	u32 msgLen;
	s32 option;
};

// Room chat message send request parameters
struct SceNpMatching2SendRoomChatMessageRequest
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2CastType castType;
	u8 padding[3];
	SceNpMatching2RoomMessageDestination dst;
	PSPPointer<u8> msg; // PSPPointer<void>
	u32 msgLen;
	s32 option;
};

// Room chat message send request response data
struct SceNpMatching2SendRoomChatMessageResponse
{
	u8 filtered;
};

// Internal room data configuration request parameters
struct SceNpMatching2SetRoomDataInternalRequest
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2FlagAttr flagFilter;
	SceNpMatching2FlagAttr flagAttr;
	PSPPointer<SceNpMatching2BinAttr> roomBinAttrInternal;
	u32 roomBinAttrInternalNum;
	PSPPointer<SceNpMatching2RoomGroupPasswordConfig> passwordConfig;
	u32 passwordConfigNum;
	PSPPointer<SceNpMatching2RoomPasswordSlotMask> passwordSlotMask;
	PSPPointer<SceNpMatching2RoomMemberId> ownerPrivilegeRank;
	u32 ownerPrivilegeRankNum;
	u8 padding[4];
};

// Internal room data request parameters
struct SceNpMatching2GetRoomDataInternalRequest
{
	SceNpMatching2RoomId roomId;
	PSPPointer<SceNpMatching2AttributeId> attrId;
	u32 attrIdNum;
};

// Internal room data request response data
struct SceNpMatching2GetRoomDataInternalResponse
{
	PSPPointer<SceNpMatching2RoomDataInternal> roomDataInternal;
};

// Internal room member data configuration request parameters
struct SceNpMatching2SetRoomMemberDataInternalRequest
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2RoomMemberId memberId;
	SceNpMatching2TeamId teamId;
	u8 padding[5];
	SceNpMatching2FlagAttr flagFilter;
	SceNpMatching2FlagAttr flagAttr;
	PSPPointer<SceNpMatching2BinAttr> roomMemberBinAttrInternal;
	u32 roomMemberBinAttrInternalNum;
};

// Internal room member data request parameters
struct SceNpMatching2GetRoomMemberDataInternalRequest
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2RoomMemberId memberId;
	u8 padding[6];
	PSPPointer<SceNpMatching2AttributeId> attrId;
	u32 attrIdNum;
};

// Internal room member data request response data
struct SceNpMatching2GetRoomMemberDataInternalResponse
{
	PSPPointer<SceNpMatching2RoomMemberDataInternal> roomMemberDataInternal;
};

// Signaling option parameter setting request parameter
struct SceNpMatching2SetSignalingOptParamRequest
{
	SceNpMatching2RoomId roomId;
	SceNpMatching2SignalingOptParam sigOptParam;
};

// Lobby information list acquisition request parameter
struct SceNpMatching2GetLobbyInfoListRequest
{
	SceNpMatching2WorldId worldId;
	SceNpMatching2RangeFilter rangeFilter;
	PSPPointer<SceNpMatching2AttributeId> attrId;
	u32 attrIdNum;
};

// Lobby information list acquisition response data
struct SceNpMatching2GetLobbyInfoListResponse
{
	SceNpMatching2Range range;
	PSPPointer<SceNpMatching2LobbyDataExternal> lobbyDataExternal;
};

// Lobby joining request parameter
struct SceNpMatching2JoinLobbyRequest
{
	SceNpMatching2LobbyId lobbyId;
	PSPPointer<SceNpMatching2JoinedSessionInfo> joinedSessionInfo;
	u32 joinedSessionInfoNum;
	PSPPointer<SceNpMatching2BinAttr> lobbyMemberBinAttrInternal;
	u32 lobbyMemberBinAttrInternalNum;
	SceNpMatching2PresenceOptionData optData;
	u8 padding[4];
};

// Lobby joining response data
struct SceNpMatching2JoinLobbyResponse
{
	PSPPointer<SceNpMatching2LobbyDataInternal> lobbyDataInternal;
};

// Lobby leaving request parameter
struct SceNpMatching2LeaveLobbyRequest
{
	SceNpMatching2LobbyId lobbyId;
	SceNpMatching2PresenceOptionData optData;
	u8 padding[4];
};

// Lobby chat message sending request parameter
struct SceNpMatching2SendLobbyChatMessageRequest
{
	SceNpMatching2LobbyId lobbyId;
	SceNpMatching2CastType castType;
	u8 padding[3];
	SceNpMatching2LobbyMessageDestination dst;
	PSPPointer<u8> msg; // PSPPointer<void>
	u32 msgLen;
	s32 option;
};

// Lobby chat message sending response data
struct SceNpMatching2SendLobbyChatMessageResponse
{
	u8 filtered;
};

// Lobby invitation message sending request parameter
struct SceNpMatching2SendLobbyInvitationRequest
{
	SceNpMatching2LobbyId lobbyId;
	SceNpMatching2CastType castType;
	u8 padding[3];
	SceNpMatching2LobbyMessageDestination dst;
	SceNpMatching2InvitationData invitationData;
	s32 option;
};

// Lobby-internal lobby member information setting request parameter
struct SceNpMatching2SetLobbyMemberDataInternalRequest
{
	SceNpMatching2LobbyId lobbyId;
	SceNpMatching2LobbyMemberId memberId;
	u8 padding1[2];
	SceNpMatching2FlagAttr flagFilter;
	SceNpMatching2FlagAttr flagAttr;
	PSPPointer<SceNpMatching2JoinedSessionInfo> joinedSessionInfo;
	u32 joinedSessionInfoNum;
	PSPPointer<SceNpMatching2BinAttr> lobbyMemberBinAttrInternal;
	u32 lobbyMemberBinAttrInternalNum;
	u8 padding2[4];
};

// Lobby-internal lobby member information acquisition request parameter
struct SceNpMatching2GetLobbyMemberDataInternalRequest
{
	SceNpMatching2LobbyId lobbyId;
	SceNpMatching2LobbyMemberId memberId;
	u8 padding[6];
	PSPPointer<SceNpMatching2AttributeId> attrId;
	u32 attrIdNum;
};

// Lobby-internal lobby member information acquisition response data
struct SceNpMatching2GetLobbyMemberDataInternalResponse
{
	PSPPointer<SceNpMatching2LobbyMemberDataInternal> lobbyMemberDataInternal;
};

// Request parameters for obtaining a list of lobby-internal lobby member information
struct SceNpMatching2GetLobbyMemberDataInternalListRequest
{
	SceNpMatching2LobbyId lobbyId;
	PSPPointer<SceNpMatching2LobbyMemberId> memberId;
	u32 memberIdNum;
	PSPPointer<SceNpMatching2AttributeId> attrId;
	u32 attrIdNum;
	u8 extendedData;
	u8 padding[7];
};

// Reponse data for obtaining a list of lobby-internal lobby member information
struct SceNpMatching2GetLobbyMemberDataInternalListResponse
{
	PSPPointer<SceNpMatching2LobbyMemberDataInternal> lobbyMemberDataInternal;
	u32 lobbyMemberDataInternalNum;
};

// Request parameters for obtaining Ping information
struct SceNpMatching2SignalingGetPingInfoRequest
{
	SceNpMatching2RoomId roomId;
	u8 reserved[16];
};

// Response data for obtaining Ping information
struct SceNpMatching2SignalingGetPingInfoResponse
{
	SceNpMatching2ServerId serverId;
	u8 padding1[2];
	SceNpMatching2WorldId worldId;
	SceNpMatching2RoomId roomId;
	u32 rtt;
	u8 reserved[20];
};

// Join request parameters for room in prohibitive mode
struct SceNpMatching2JoinProhibitiveRoomRequest
{
	SceNpMatching2JoinRoomRequest joinParam;
	PSPPointer<SceNpId> blockedUser;
	u32 blockedUserNum;
};

// Room member update information
struct SceNpMatching2RoomMemberUpdateInfo
{
	PSPPointer<SceNpMatching2RoomMemberDataInternal> roomMemberDataInternal;
	SceNpMatching2EventCause eventCause;
	u8 padding[3];
	SceNpMatching2PresenceOptionData optData;
};

// Room owner update information
struct SceNpMatching2RoomOwnerUpdateInfo
{
	SceNpMatching2RoomMemberId prevOwner;
	SceNpMatching2RoomMemberId newOwner;
	SceNpMatching2EventCause eventCause;
	u8 padding[3];
	PSPPointer<SceNpMatching2SessionPassword> roomPassword;
	SceNpMatching2PresenceOptionData optData;
};

// Room update information
struct SceNpMatching2RoomUpdateInfo
{
	SceNpMatching2EventCause eventCause;
	u8 padding[3];
	s32 errorCode;
	SceNpMatching2PresenceOptionData optData;
};

// Internal room data update information
struct SceNpMatching2RoomDataInternalUpdateInfo
{
	PSPPointer<SceNpMatching2RoomDataInternal> newRoomDataInternal;
	PSPPointer<SceNpMatching2FlagAttr> newFlagAttr;
	PSPPointer<SceNpMatching2FlagAttr> prevFlagAttr;
	PSPPointer<SceNpMatching2RoomPasswordSlotMask> newRoomPasswordSlotMask;
	PSPPointer<SceNpMatching2RoomPasswordSlotMask> prevRoomPasswordSlotMask;
	PSPPointer<SceNpMatching2RoomGroup> newRoomGroup;
	u32 newRoomGroupNum;
	PSPPointer<SceNpMatching2RoomBinAttrInternal> newRoomBinAttrInternal;
	u32 newRoomBinAttrInternalNum;
};

// Internal room member data update information
struct SceNpMatching2RoomMemberDataInternalUpdateInfo
{
	PSPPointer<SceNpMatching2RoomMemberDataInternal> newRoomMemberDataInternal;
	PSPPointer<SceNpMatching2FlagAttr> newFlagAttr;
	PSPPointer<SceNpMatching2FlagAttr> prevFlagAttr;
	PSPPointer<SceNpMatching2TeamId> newTeamId;
	PSPPointer<SceNpMatching2RoomMemberBinAttrInternal> newRoomMemberBinAttrInternal;
	u32 newRoomMemberBinAttrInternalNum;
};

// Room message information
struct SceNpMatching2RoomMessageInfo
{
	u8 filtered;
	SceNpMatching2CastType castType;
	u8 padding[2];
	PSPPointer<SceNpMatching2RoomMessageDestination> dst;
	PSPPointer<SceNpUserInfo2> srcMember;
	PSPPointer<u8> msg; // PSPPointer<void>
	u32 msgLen;
};

// Lobby member update information
struct SceNpMatching2LobbyMemberUpdateInfo
{
	PSPPointer<SceNpMatching2LobbyMemberDataInternal> lobbyMemberDataInternal;
	SceNpMatching2EventCause eventCause;
	u8 padding[3];
	SceNpMatching2PresenceOptionData optData;
};

// Lobby update information
struct SceNpMatching2LobbyUpdateInfo
{
	SceNpMatching2EventCause eventCause;
	u8 padding[3];
	s32 errorCode;
};

// Lobby-internal lobby member information update information
struct SceNpMatching2LobbyMemberDataInternalUpdateInfo
{
	SceNpMatching2LobbyMemberId memberId;
	u8 padding[2];
	SceNpId npId;
	SceNpMatching2FlagAttr flagFilter;
	SceNpMatching2FlagAttr newFlagAttr;
	SceNpMatching2JoinedSessionInfo newJoinedSessionInfo;
	u32 newJoinedSessionInfoNum;
	PSPPointer<SceNpMatching2LobbyMemberBinAttrInternal> newLobbyMemberBinAttrInternal;
	u32 newLobbyMemberBinAttrInternalNum;
};

// Lobby message information
struct SceNpMatching2LobbyMessageInfo
{
	u8 filtered;
	SceNpMatching2CastType castType;
	u8 padding[2];
	PSPPointer<SceNpMatching2LobbyMessageDestination> dst;
	PSPPointer<SceNpUserInfo2> srcMember;
	PSPPointer<u8> msg; // PSPPointer<void>
	u32 msgLen;
};

// Lobby invitation message information
struct SceNpMatching2LobbyInvitationInfo
{
	SceNpMatching2CastType castType;
	u8 padding[3];
	PSPPointer<SceNpMatching2LobbyMessageDestination> dst;
	PSPPointer<SceNpUserInfo2> srcMember;
	SceNpMatching2InvitationData invitationData;
};

// Update information of the signaling option parameter
struct SceNpMatching2SignalingOptParamUpdateInfo
{
	SceNpMatching2SignalingOptParam newSignalingOptParam;
};

// Matching2 utility intilization parameters
struct SceNpMatching2UtilityInitParam
{
	u32 containerId;
	u32 requestCbQueueLen;
	u32 sessionEventCbQueueLen;
	u32 sessionMsgCbQueueLen;
	u8 reserved[16];
};

// Matching2 memory information
struct SceNpMatching2MemoryInfo
{
	u32 totalMemSize;
	u32 curMemUsage;
	u32 maxMemUsage;
	u8 reserved[12];
};

// Matching2 information on the event data queues in the system
struct SceNpMatching2CbQueueInfo
{
	u32 requestCbQueueLen;
	u32 curRequestCbQueueLen;
	u32 maxRequestCbQueueLen;
	u32 sessionEventCbQueueLen;
	u32 curSessionEventCbQueueLen;
	u32 maxSessionEventCbQueueLen;
	u32 sessionMsgCbQueueLen;
	u32 curSessionMsgCbQueueLen;
	u32 maxSessionMsgCbQueueLen;
	u8 reserved[12];
};

struct SceNpMatching2SignalingNetInfo
{
	u32 size;
	u32 localAddr;
	u32 mappedAddr;
	s32 natStatus;
	// Nemoumbra: sceNpMatching2SignalingGetLocalNetInfo internally calls a function sceNetUpnp_0x1038E77A that returns a bunch of network-related info
	s32 UPnPStatus;
	s32 portStatus;
	u16 port;
	u8 padding[2];
};

// Common structure used when receiving data
struct SceNpCommerce2CommonData
{
	u32 version;
	u32 buf_head;
	u32 buf_size;
	u32 data;
	u32 data_size;
	u32 data2;
	u32 reserved[4];
};

// Structure indicating the range of results obtained
struct SceNpCommerce2Range
{
	u32 startPosition;
	u32 count;
	u32 totalCountOfResults;
};

struct SceNpCommerce2GetCategoryContentsResult
{
	SceNpCommerce2CommonData commonData;
	SceNpCommerce2Range rangeOfContents;
};

using SceNpCommerce2Handler = void(u32 ctx_id, u32 subject_id, s32 event, s32 error_code, void* arg);

// Union for connection information
union SceNpSignalingConnectionInfo
{
	u32 rtt;
	u32 bandwidth;
	SceNpId npId;
	struct
	{
		np_in_addr addr; // in_addr
		np_in_port_t port; // in_port_t
	} address;
	u32 packet_loss;
};

// Network information structure
struct SceNpSignalingNetInfo
{
	u32 size;
	u32 local_addr; // in_addr
	u32 mapped_addr; // in_addr
	s32 nat_status;
	s32 upnp_status;
	s32 npport_status;
	u16 npport;
};

#pragma pack(pop)
