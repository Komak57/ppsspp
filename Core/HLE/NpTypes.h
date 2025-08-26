#pragma once
#include <mutex>
#include <deque>
#include <map>

#include <sstream>
#include <string>
#include <iomanip>
#include <cstdint>
#include <Swap.h>
#include <algorithm>

#include "Core/MemMap.h"

#pragma pack(push,1)
#define SCE_NP_DEFINED

// Based on https://playstationdev.wiki/psvitadevwiki/index.php?title=Error_Codes
#define	SCE_NP_ERROR_ALREADY_INITIALIZED				0x80550001
#define	SCE_NP_ERROR_NOT_INITIALIZED					0x80550002
#define	SCE_NP_ERROR_INVALID_ARGUMENT					0x80550003

#define	SCE_NP_AUTH_ERROR_ALREADY_INITIALIZED			0x80550301
#define	SCE_NP_AUTH_ERROR_NOT_INITIALIZED				0x80550302
#define	SCE_NP_AUTH_ERROR_EINVAL						0x80550303
#define	SCE_NP_AUTH_ERROR_ENOMEM						0x80550304
#define	SCE_NP_AUTH_ERROR_ESRCH							0x80550305
#define	SCE_NP_AUTH_ERROR_EBUSY							0x80550306
#define	SCE_NP_AUTH_ERROR_ABORTED						0x80550307
#define	SCE_NP_AUTH_ERROR_INVALID_SERVICE_ID			0x80550308
#define	SCE_NP_AUTH_ERROR_INVALID_CREDENTIAL			0x80550309
#define	SCE_NP_AUTH_ERROR_INVALID_ENTITLEMENT_ID		0x8055030a
#define	SCE_NP_AUTH_ERROR_INVALID_DATA_LENGTH			0x8055030b
#define	SCE_NP_AUTH_ERROR_UNSUPPORTED_TICKET_VERSION	0x8055030c
#define	SCE_NP_AUTH_ERROR_STACKSIZE_TOO_SHORT			0x8055030d
#define	SCE_NP_AUTH_ERROR_TICKET_STATUS_CODE_INVALID	0x8055030e
#define	SCE_NP_AUTH_ERROR_TICKET_PARAM_NOT_FOUND		0x8055030f
#define	SCE_NP_AUTH_ERROR_INVALID_TICKET_VERSION		0x80550310
#define	SCE_NP_AUTH_ERROR_INVALID_ARGUMENT				0x80550311

#define	SCE_NP_AUTH_ERROR_SERVICE_END					0x80550400
#define	SCE_NP_AUTH_ERROR_SERVICE_DOWN					0x80550401
#define	SCE_NP_AUTH_ERROR_SERVICE_BUSY					0x80550402
#define	SCE_NP_AUTH_ERROR_SERVER_MAINTENANCE			0x80550403
#define SCE_NP_AUTH_ERROR_UNKNOWN						0x80550480

#define SCE_NP_MANAGER_ERROR_ALREADY_INITIALIZED		0x80550501
#define SCE_NP_MANAGER_ERROR_NOT_INITIALIZED			0x80550502
#define SCE_NP_MANAGER_ERROR_INVALID_ARGUMENT			0x80550503
#define SCE_NP_MANAGER_ERROR_OUT_OF_MEMORY				0x80550504
#define SCE_NP_MANAGER_ERROR_INVALID_TICKET_SIZE		0x80550505
#define SCE_NP_MANAGER_ERROR_INVALID_STATE				0x80550506
#define SCE_NP_MANAGER_ERROR_ABORTED					0x80550507
#define SCE_NP_MANAGER_ERROR_VARIANT_ACCOUNT_ID			0x80550508
#define SCE_NP_MANAGER_ERROR_ID_NOT_AVAIL				0x80550509
#define SCE_NP_MANAGER_ERROR_SIGNOUT					0x8055050a
#define SCE_NP_MANAGER_ERROR_NOT_SIGNIN 				0x8055050b

#define SCE_NP_UTIL_ERROR_INVALID_ARGUMENT 				0x80550601 
#define SCE_NP_UTIL_ERROR_INSUFFICIENT					0x80550602 
#define SCE_NP_UTIL_ERROR_PARSER_FAILED					0x80550603 
#define SCE_NP_UTIL_ERROR_INVALID_PROTOCOL_ID			0x80550604 
#define SCE_NP_UTIL_ERROR_INVALID_NP_ID					0x80550605 
#define SCE_NP_UTIL_ERROR_INVALID_NP_ENV 				0x80550606 
#define SCE_NP_UTIL_ERROR_INVALID_NPCOMMID				0x80550607 
#define SCE_NP_UTIL_ERROR_INVALID_CHARACTER 			0x80550608 
#define SCE_NP_UTIL_ERROR_NOT_MATCH 					0x80550609 
#define SCE_NP_UTIL_ERROR_INVALID_TITLEID				0x8055060a 
#define SCE_NP_UTIL_ERROR_INVALID_ESCAPE_STRING			0x8055060c 
#define SCE_NP_UTIL_ERROR_UNKNOWN_TYPE					0x8055060d 
#define SCE_NP_UTIL_ERROR_UNKNOWN 						0x8055060e

#define SCE_NP_COMMUNITY_ERROR_ALREADY_INITIALIZED 							0x80550701
#define SCE_NP_COMMUNITY_ERROR_NOT_INITIALIZED 								0x80550702
#define SCE_NP_COMMUNITY_ERROR_OUT_OF_MEMORY 								0x80550703
#define SCE_NP_COMMUNITY_ERROR_INVALID_ARGUMENT 							0x80550704
#define SCE_NP_COMMUNITY_ERROR_NO_LOGIN 									0x80550705 	
#define SCE_NP_COMMUNITY_ERROR_TOO_MANY_OBJECTS 							0x80550706 	
#define SCE_NP_COMMUNITY_ERROR_ABORTED 										0x80550707 	
#define SCE_NP_COMMUNITY_ERROR_BAD_RESPONSE 								0x80550708 	
#define SCE_NP_COMMUNITY_ERROR_BODY_TOO_LARGE 								0x80550709 	
#define SCE_NP_COMMUNITY_ERROR_HTTP_SERVER 									0x8055070a 	
#define SCE_NP_COMMUNITY_ERROR_INVALID_SIGNATURE 							0x8055070b 	
#define SCE_NP_COMMUNITY_ERROR_INSUFFICIENT_ARGUMENT 						0x8055070c 	
#define SCE_NP_COMMUNITY_ERROR_UNKNOWN_TYPE 								0x8055070d 	
#define SCE_NP_COMMUNITY_ERROR_INVALID_ID 									0x8055070e 	
#define SCE_NP_COMMUNITY_ERROR_INVALID_ONLINE_ID 							0x8055070f 	
#define SCE_NP_COMMUNITY_ERROR_CONNECTION_HANDLE_ALREADY_EXISTS 			0x80550710 	
#define SCE_NP_COMMUNITY_ERROR_INVALID_TYPE 								0x80550711 	
#define SCE_NP_COMMUNITY_ERROR_TRANSACTION_ALREADY_END 						0x80550712 	
#define SCE_NP_COMMUNITY_ERROR_INVALID_PARTITION 							0x80550713 	
#define SCE_NP_COMMUNITY_ERROR_INVALID_ALIGNMENT 							0x80550714 	
#define SCE_NP_COMMUNITY_ERROR_CLIENT_HANDLE_ALREADY_EXISTS 				0x80550715 	
#define SCE_NP_COMMUNITY_ERROR_NO_RESOURCE 									0x80550716 	

#define SCE_NP_COMMUNITY_SERVER_ERROR_BAD_REQUEST 							0x80550801 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_TICKET 						0x80550802 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_SIGNATURE 					0x80550803 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_NPID 							0x80550805 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_FORBIDDEN 							0x80550806 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INTERNAL_SERVER_ERROR 				0x80550807 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_VERSION_NOT_SUPPORTED 				0x80550808 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_SERVICE_UNAVAILABLE 					0x80550809 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_PLAYER_BANNED 						0x8055080a 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_CENSORED 								0x8055080b 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_RANKING_RECORD_FORBIDDEN 				0x8055080c 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_USER_PROFILE_NOT_FOUND 				0x8055080d 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_UPLOADER_DATA_NOT_FOUND 				0x8055080e 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_QUOTA_MASTER_NOT_FOUND 				0x8055080f 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_RANKING_TITLE_NOT_FOUND 				0x80550810 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_BLACKLISTED_USER_ID 					0x80550811 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_GAME_RANKING_NOT_FOUND 				0x80550812 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_RANKING_STORE_NOT_FOUND 				0x80550814 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_NOT_BEST_SCORE 						0x80550815 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_LATEST_UPDATE_NOT_FOUND 				0x80550816 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_RANKING_BOARD_MASTER_NOT_FOUND 		0x80550817 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_RANKING_GAME_DATA_MASTER_NOT_FOUND 	0x80550818 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_ANTICHEAT_DATA 				0x80550819 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_TOO_LARGE_DATA 						0x8055081a 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_USER_NPID 					0x8055081b 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_ENVIRONMENT 					0x8055081d 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_ONLINE_NAME_CHARACTER 		0x8055081f 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_ONLINE_NAME_LENGTH 			0x80550820 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_ABOUT_ME_CHARACTER			0x80550821 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_ABOUT_ME_LENGTH 				0x80550822 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_INVALID_SCORE 						0x80550823 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_OVER_THE_RANKING_LIMIT 				0x80550824 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_FAIL_TO_CREATE_SIGNATURE				0x80550826 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_RANKING_MASTER_INFO_NOT_FOUND			0x80550827 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_OVER_THE_GAME_DATA_LIMIT				0x80550828 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_SELF_DATA_NOT_FOUND 					0x8055082a
#define SCE_NP_COMMUNITY_SERVER_ERROR_USER_NOT_ASSIGNED 					0x8055082b 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_GAME_DATA_ALREADY_EXISTS 				0x8055082c 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_MATCHING_BEFORE_SERVICE 				0x805508a0 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_MATCHING_END_OF_SERVICE				0x805508a1 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_MATCHING_MAINTENANCE 					0x805508a2 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_RANKING_BEFORE_SERVICE				0x805508a3 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_RANKING_END_OF_SERVICE				0x805508a4 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_RANKING_MAINTENANCE 					0x805508a5 	
#define SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE 						0x805508a6 
#define SCE_NP_COMMUNITY_SERVER_ERROR_TITLE_USER_STORAGE_BEFORE_SERVICE 	0x805508aa 
#define SCE_NP_COMMUNITY_SERVER_ERROR_TITLE_USER_STORAGE_END_OF_SERVICE 	0x805508ab 
#define SCE_NP_COMMUNITY_SERVER_ERROR_TITLE_USER_STORAGE_MAINTENANCE		0x805508ac 
#define SCE_NP_COMMUNITY_SERVER_ERROR_FSR_BEFORE_SERVICE 					0x805508ad 
#define SCE_NP_COMMUNITY_SERVER_ERROR_FSR_END_OF_SERVICE					0x805508ae 
#define SCE_NP_COMMUNITY_SERVER_ERROR_FSR_MAINTENANCE 						0x805508af 
#define SCE_NP_COMMUNITY_SERVER_ERROR_UBS_BEFORE_SERVICE					0x805508b1 
#define SCE_NP_COMMUNITY_SERVER_ERROR_UBS_END_OF_SERVICE					0x805508b2 
#define SCE_NP_COMMUNITY_SERVER_ERROR_UBS_MAINTENANCE 						0x805508b3
#define SCE_NP_COMMUNITY_SERVER_ERROR_UNSPECIFIED 							0x805508ff

// Based on https://gist.githubusercontent.com/raw/4140449/PS%20Vita (Might be slightly different with PSP?)
#define SCE_NP_TROPHY_ERROR_UNKNOWN 						0x80551600
#define SCE_NP_TROPHY_ERROR_NOT_INITIALIZED 				0x80551601
#define SCE_NP_TROPHY_ERROR_ALREADY_INITIALIZED 			0x80551602
#define SCE_NP_TROPHY_ERROR_NO_MEMORY 						0x80551603
#define SCE_NP_TROPHY_ERROR_INVALID_ARGUMENT 				0x80551604
#define SCE_NP_TROPHY_ERROR_INSUFFICIENT_BUFFER				0x80551605
#define SCE_NP_TROPHY_ERROR_EXCEEDS_MAX 					0x80551606
#define SCE_NP_TROPHY_ERROR_ABORT 							0x80551607
#define SCE_NP_TROPHY_ERROR_INVALID_HANDLE					0x80551608
#define SCE_NP_TROPHY_ERROR_INVALID_CONTEXT					0x80551609
#define SCE_NP_TROPHY_ERROR_INVALID_NPCOMMID 				0x8055160a
#define SCE_NP_TROPHY_ERROR_INVALID_NPCOMMSIGN 				0x8055160b

#define SCE_NP_BASIC_ERROR_BASE 							0x80551d00 
#define SCE_NP_BASIC_ERROR_UNKNOWN							0x80551d01 
#define SCE_NP_BASIC_ERROR_INVALID_ARGUMENT					0x80551d02 
#define SCE_NP_BASIC_ERROR_OUT_OF_MEMORY 					0x80551d03 
#define SCE_NP_BASIC_ERROR_NOT_INITIALIZED					0x80551d04 
#define SCE_NP_BASIC_ERROR_ALREADY_INITIALIZED				0x80551d05 
#define SCE_NP_BASIC_ERROR_SIGNED_OUT						0x80551d06 
#define SCE_NP_BASIC_ERROR_NOT_ONLINE						0x80551d07 
#define SCE_NP_BASIC_ERROR_DATA_NOT_FOUND 					0x80551d08 
#define SCE_NP_BASIC_ERROR_BUSY 							0x80551d09 
#define SCE_NP_BASIC_ERROR_NOT_READY_TO_COMMUNICATE 		0x80551d0a 
#define SCE_NP_BASIC_ERROR_NO_COMM_ID_SUPPLIED				0x80551d0b


// Event types (including extended ones)
enum
{
	SCE_NP_SIGNALING_EVENT_DEAD = 0,
	SCE_NP_SIGNALING_EVENT_ESTABLISHED = 1,
	SCE_NP_SIGNALING_EVENT_NETINFO_ERROR = 2,
	SCE_NP_SIGNALING_EVENT_NETINFO_RESULT = 3,
	SCE_NP_SIGNALING_EVENT_EXT_PEER_ACTIVATED = 10,
	SCE_NP_SIGNALING_EVENT_EXT_PEER_DEACTIVATED = 11,
	SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED = 12,
};

// Connection states
enum
{
	SCE_NP_SIGNALING_CONN_STATUS_INACTIVE = 0,
	SCE_NP_SIGNALING_CONN_STATUS_PENDING = 1,
	SCE_NP_SIGNALING_CONN_STATUS_ACTIVE = 2,
};

// Connection information to obtain
enum
{
	SCE_NP_SIGNALING_CONN_INFO_RTT = 1,
	SCE_NP_SIGNALING_CONN_INFO_BANDWIDTH = 2,
	SCE_NP_SIGNALING_CONN_INFO_PEER_NPID = 3,
	SCE_NP_SIGNALING_CONN_INFO_PEER_ADDRESS = 4,
	SCE_NP_SIGNALING_CONN_INFO_MAPPED_ADDRESS = 5,
	SCE_NP_SIGNALING_CONN_INFO_PACKET_LOSS = 6,
};

// NAT status type
enum
{
	SCE_NP_SIGNALING_NETINFO_NAT_STATUS_UNKNOWN = 0,
	SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE1 = 1,
	SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE2 = 2,
	SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE3 = 3,
};

// UPnP status
enum
{
	SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_UNKNOWN = 0,
	SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_INVALID = 1,
	SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_VALID = 2,
};

// NP port status
enum
{
	SCE_NP_SIGNALING_NETINFO_NPPORT_STATUS_CLOSED = 0,
	SCE_NP_SIGNALING_NETINFO_NPPORT_STATUS_OPEN = 1,
};

// Based on https://github.com/RPCS3/rpcs3/blob/psp2/rpcs3/Emu/PSP2/Modules/sceNpCommon.h
enum SceNpServiceState : s32
{
	SCE_NP_SERVICE_STATE_UNKNOWN = 0,
	SCE_NP_SERVICE_STATE_SIGNED_OUT,
	SCE_NP_SERVICE_STATE_SIGNED_IN,
	SCE_NP_SERVICE_STATE_ONLINE
};

using np_in_addr_t = u32;
using np_in_port_t = u16;
using np_sa_family_t = u8;
using np_socklen_t = u32;

struct np_in_addr
{
	np_in_addr_t np_s_addr; // TODO: alignment?
};

using sys_memory_container_t = u32;

using system_time_t = u64; // s64 in documentation. But since this is in microseconds, it doesn't seem to make much sense.
using second_t = u32;
using usecond_t = u64;

using SceNpBasicAttachmentDataId = u32;
using SceNpBasicMessageId = u64;
using SceNpBasicMessageRecvAction = u32;

using SceNpClanId = u32;
using SceNpClansMessageId = u32;
using SceNpClansMemberStatus = s32;

using SceNpCustomMenuIndexMask = u32;
using SceNpCustomMenuSelectedType = u32;

using SceNpFriendlistCustomOptions = u64;

using SceNpPlatformType = s32;

using SceNpScoreBoardId = u32;
using SceNpScoreClansBoardId = u32;
using SceNpScorePcId = s32;
using SceNpScoreRankNumber = u32;
using SceNpScoreValue = s64;

using SceNpTime = s64;

struct SceNpCommunicationPassphrase
{
	u8 data[128];
};

struct SceNpCommunicationSignature
{
	u8 data[160];
};

struct SceNpCommunicationId
{
	char data[9];
	char term;
	u8 num;
	char dummy;
};

struct SceNpCommunicationConfig
{
	PSPPointer<SceNpCommunicationId> commId;
	PSPPointer<SceNpCommunicationPassphrase> commPassphrase;
	PSPPointer<SceNpCommunicationSignature> commSignature;
};

// Part of BCP 47 Code (ie. "fr" for France/French)?
struct SceNpCountryCode
{
	char data[2];
	char term;
	char padding[1];
};

// Username?
struct SceNpOnlineId
{
	char data[16];
	char term;
	char dummy[3];
};

struct SceNpId
{
	SceNpOnlineId handle;
	u8 opt[8];
	u8 reserved[8];
};

struct SceNpAvatarUrl
{
	char data[127];
	char term;
};

struct SceNpUserInformation
{
	SceNpId userId;
	SceNpAvatarUrl icon;
	u8 reserved[52];
};

// Online Name structure
struct SceNpOnlineName
{
	char data[48 + 1]; // char term;
	char padding[3];
};

// User information structure
struct SceNpUserInfo
{
	SceNpId userId;
	SceNpOnlineName name;
	SceNpAvatarUrl icon;
};
// User information structure
struct SceNpUserInfo2
{
	SceNpId npId;
	PSPPointer<SceNpOnlineName> onlineName;
	PSPPointer<SceNpAvatarUrl> avatarUrl;
};

// Language Code (ie. 1033 for "en-US")?
struct SceNpMyLanguages
{
	s32_le language1;
	s32_le language2;
	s32_le language3;
	u8 padding[4];
};

struct SceNpAvatarImage
{
	u8 data[200 * 1024];
	u32_le size;
	u8 reserved[12];
};

enum SceNpAvatarSizeType : s32
{
	SCE_NP_AVATAR_SIZE_LARGE,
	SCE_NP_AVATAR_SIZE_MIDDLE,
	SCE_NP_AVATAR_SIZE_SMALL
};

struct SceNpAboutMe
{
	char data[64];
};

struct SceNpDate
{
	u16_le year;
	u8 month;
	u8 day;
};

union SceNpTicketParam
{
	s32_le _s32;
	s64_le _s64;
	u32_le _u32;
	u64_le _u64;
	SceNpDate date;
	u8 data[256];
};

struct SceNpTicketVersion
{
	u16_le major;
	u16_le minor;
};

struct NpAuthHandler {
	u32 entryPoint;
	u32 argument;
};

union NpAuthArgs {
	u32_le data[3]; // id, result, ArgAddr
	struct {
		s32_le id;
		s32_le result;
		u32_le argAddr;
	};
};

using SceNpAuthCallback = s32(s32 id, s32 result, PSPPointer<void> arg);

struct SceNpAuthRequestParameter
{
	u32_le size; // Size of this struct
	SceNpTicketVersion version; // Highest ticket version supported by this game/device? so PSN server can return supported ticket
	u32_le serviceIdAddr; //PSPPointer<char> serviceId; // null-terminated string
	u32_le cookieAddr; //PSPPointer<char> cookie; // null-terminated string?
	u32_le cookieSize;
	u32_le entitlementIdAddr; //PSPPointer<char> entitlementId; // null-terminated string
	u32_le consumedCount; // related to entitlement?
	u32 ticketCbAddr; //PSPPointer<SceNpAuthCallback> ticketCb
	u32_le cbArgAddr; //PSPPointer<void> cbArg
};

struct SceNpEntitlementId
{
	u8 data[32];
};

struct SceNpEntitlement
{
	SceNpEntitlementId id;
	u64_le createdDate;
	u64_le expireDate;
	u32_le type;
	s32_le remainingCount;
	u32_le consumedCount;
	u8 padding[4];
};

#define	TICKET_VER_2_0	0x21000000;
#define	TICKET_VER_2_1	0x21010000;
#define	TICKET_VER_3_0	0x31000000;
#define	TICKET_VER_4_0	0x41000000;

#define	NUMBER_PARAMETERS			12

#define	PARAM_TYPE_NULL				0
#define	PARAM_TYPE_INT				1
#define	PARAM_TYPE_LONG				2
#define	PARAM_TYPE_STRING			4 // PSP returns maximum 255 bytes
#define	PARAM_TYPE_DATE				7
#define	PARAM_TYPE_STRING_ASCII		8 // PSP returns maximum 255 bytes, can contains control code

#define	SECTION_TYPE_BODY			0x3000
#define	SECTION_TYPE_FOOTER			0x3002

// Tickets data are in big-endian based on captured packets
struct SceNpTicketParamData
{
	u16_be type; // 0(NULL), 1(32-bit int), 2(64-bi long), 4(ansi string?), 7(date/timestamp), 8(ascii string)
	u16_be length; // size of the following data value
	//u8 value[]; // optional data of length size
};

struct SceNpTicketHeader
{
	u32_be version; // Version contents byte are: V1 0M 00 00, where V = major version, M = minor version according to https://www.psdevwiki.com/ps3/X-I-5-Ticket
	s32_be size; // total ticket size (excluding this 8-bytes header struct)
};

// Section contents byte are: 30 XX 00 YY, where XX = section type, YY = section size according to https://www.psdevwiki.com/ps3/X-I-5-Ticket
// A section can contain other sections or param data, thus sharing their enum/def?
struct SceNpTicketSection
{
	u16_be type; // section type? ie. 30 XX where known XX are 00(Body), 02(Footer), 10, 11
	u16_be size; // total section size (excluding this 4-bytes section delimiter struct)
};

struct SceNpTicket
{
	SceNpTicketHeader header;
	SceNpTicketSection section; // Body or Parameter sections?
	//SceNpTicketParamData parameters[]; // a list of TicketParamData following the section
	//u8 unknownBytes[]; // optional data?
};

struct SceNpAuthMemoryStat {
	int npMemSize;     // Memory allocated by the NP utility. Pool Size?
	int npMaxMemSize;  // Maximum memory used by the NP utility.
	int npFreeMemSize; // Free memory available to use by the NP utility.
};

// NP callback functions
using SceNpCustomMenuEventHandler = s32(s32 retCode, u32 index, PSPPointer<SceNpId> npid, SceNpCustomMenuSelectedType type, void* arg);
using SceNpBasicEventHandler = s32(s32 event, s32 retCode, u32 reqId, void* arg);
using SceNpCommerceHandler = void(u32 ctx_id, u32 subject_id, s32 event, s32 error_code, void* arg);
using SceNpSignalingHandler = void(u32 ctx_id, u32 subject_id, s32 event, s32 error_code, void* arg);
using SceNpFriendlistResultHandler = s32(s32 retCode, void* arg);
using SceNpMatchingHandler = void(u32 ctx_id, u32 req_id, s32 event, s32 error_code, void* arg);
using SceNpMatchingGUIHandler = void(u32 ctx_id, s32 event, s32 error_code, void* arg);
using SceNpProfileResultHandler = s32(s32 result, void* arg);

using SceNpManagerSubSigninCallback = void(s32 result, PSPPointer<SceNpId> npId, void* cb_arg);

#pragma pack(pop)

enum
{
	SCE_NP_LOOKUP_MAX_CTX_NUM = 32
};

// Constants for signaling functions and structures
enum
{
	SCE_NP_SIGNALING_CTX_MAX = 8,
};

struct SceNpRoomId
{
	u8 opt[28];
	u8 reserved[8];
};
