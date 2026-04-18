#include <Core/Net/SIGAgent.h>
#include <Core/HLE/SocketManager.h>
#include <Core/HLE/NetInetConstants.h>
#include <Core/HLE/proAdhoc.h>
#include <Core/HLE/sceNp.h>
#include <Core/HLE/sceNp2.h>
#include <Core/Net/fb_helpers.h>
#include <Core/Debugger/Np2Printer.h>
#include "Common/System/OSD.h"
#include "Common/Data/Text/I18n.h"
#include <Core/HLE/sceKernelMsgPipe.h>

// Used for things like 10s
using namespace std::chrono_literals;

namespace net {
    SceUID pipeUID;
    // Data Buffer for Main Thread
    PSPPointer<PipePacket> packet_buffer;
    // Address Buffer for Main Thread
    PSPPointer<SceNetInetSockaddr> addr_buffer;
    
    PSNSigAgent::~PSNSigAgent() {

    }
    PSNSigAgent::PSNSigAgent() {
        pipeUID = sceKernelCreateMsgPipe("SceNpSignaling", 2, 0, 0x400, 0);
        if (pipeUID < 0)
            return;
        
        u32 bufsize = sizeof(PipePacket); // 0x10
        // packet_buffer = PSPPointer<PipePacket>::Create(signaling_memory.Alloc(bufsize));
        u32 addr_size = sizeof(SceNetInetSockaddr);
        // addr_buffer = PSPPointer<SceNetInetSockaddr>::Create(signaling_memory.Alloc(addr_size));

        initialized = true;
    }
    
    int PSNSigAgent::UpnpThreadTick() {
        ProcessUPnPMessages();
        return 0;
    }

    int PSNSigAgent::MainThreadTick(BlockAllocator* signaling_memory) {
        WARN_LOG(Log::Signaling, "UNIMPL %s()", __FUNCTION__);
        int ret = 0;
        SceUID uid = sceKernelGetThreadId();
        // PSPPointer<SceNetInetSockaddr> addr;
        while ((ret = sceKernelReceiveMsgPipe(pipeUID, packet_buffer.ptr, sizeof(PipePacket), 0, addr_buffer.ptr, 0), -1 < ret) && (packet_buffer->type != 1) && (packet_buffer->sig_packet.IsValid())) {
            NOTICE_LOG(Log::Signaling, "SIGN MsgPipe Received {type: %d, conn_id: %d, packet: %08X, addr: %08X}", packet_buffer->type, packet_buffer->conn_id, packet_buffer->sig_packet.ptr, addr_buffer.ptr);
            // FUN_0882784c(iVar3, packet);
            // FUN_08825e80(iVar3, packet);
            // FUN_0882ec3c(iVar3, packet);
        }
        // int delayus = 1000000;
        // //ScheduleP2PState(3, newState, delayus, "P2P Wait State");
        // VERBOSE_LOG(Log::sceNp2, "SignalingMain Waiting %d ms", (delayus / 1000));
        // //int r = hleDelayResult(0, "P2P Wait State", delayus);
        // hleCall(ThreadManForUser, int, sceKernelDelayThread, delayus);
        // hleCall(ThreadManForUser, int, sceKernelSleepThread);
        
        SceUID thid = sceKernelGetThreadId();
        sceNetFreeThreadinfo(thid);
        // sceKernelSleepThread();
        return 0;
    }
    int PSNSigAgent::EchoThreadTick(BlockAllocator* signaling_memory) {
	    int delayus = 1000000;
        int n = 0; // TODO: Receive data from PSN socket?
        if (n > 0) {
            // TODO: Process socket data and forward to MsgPipe
            u32 alloc = sizeof(PipePacket);
            auto packet = PSPPointer<PipePacket>::Create(signaling_memory->Alloc(alloc));
            // FIXME: This might not be a SignalingPacket, and needs to process a variable length?
            u32 data_size = n;
            packet->sig_packet = PSPPointer<u8>::Create(signaling_memory->Alloc(data_size)).ptr;
            // memcpy(packet->sig_packet, buf, n);

            u32 addr_size = sizeof(SceNetInetSockaddr);
            // FIXME: Get addr from conn_id?
            packet->unk4 = PSPPointer<SceNetInetSockaddr>::Create(signaling_memory->Alloc(addr_size)).ptr;
            // memcpy(packet->unk4, &src, slen);

            sceKernelSendMsgPipe(pipeUID, packet.ptr, 0x10, 0, packet->unk4.ptr, 0);

            // int ret = sceKernelStartThread(signalingThreadId, 0, 0);
            // if (ret < 0)
            //     ERROR_LOG(Log::Signaling, "Failed to start SceNpSignalingMainThread: %08X", ret);
            // continue;
        }

        //ScheduleP2PState(3, newState, delayus, "SignalingEcho Wait State");
        VERBOSE_LOG(Log::sceNp2, "SignalingEcho Waiting %d ms", (delayus / 1000));
        //int r = hleDelayResult(0, "SignalingEcho Wait State", delayus);
        hleCall(ThreadManForUser, int, sceKernelDelayThread, delayus); // sceKernelDelayThread(delayus); // 
        return 0;
    }

    // void FUN_0882784c(PipeType* param_1, PipePacket* buffer) {
    // 	PipePacket copy = *buffer;
    // 	if (copy.type == Finished) {
    // 		//FUN_088278b8(param_1, &copy);
    // 	}
    // 	else if (copy.type == type_0x1a) {
    // 		//FUN_08827a5c(param_1, &copy);
    // 	}
    // 	return;
    // }

    // void FUN_08825e80(PipeType* param_1, PipePacket* buffer) {
    // 	PipePacket copy = *buffer;
    // 	switch (copy.type) {
    // 	case type_0x5:
    // 	case type_0x6:
    // 		break;
    // 	case type_0x7:
    // 	case type_0x8:
    // 		break;
    // 	case type_0x9:
    // 	case type_0xa:
    // 		break;
    // 	case type_0xb:
    // 		break;
    // 	case type_0xc:
    // 		break;
    // 	case type_0xd:
    // 	case type_0x20:
    // 		break;
    // 	case type_0xe:
    // 		break;
    // 	case type_0x15:
    // 		break;
    // 	case type_0x16:
    // 		break;
    // 	case type_0x19:
    // 		break;
    // 	case type_0x1e:
    // 	case type_0x1f:
    // 		break;
    // 	case type_0x21:
    // 	case type_0x22:
    // 		break;
    // 	default:
    // 		break;
    // 	}
    // }

    // void FUN_0882ec3c(PipeType* param_1, PipePacket* buffer) {
    // 	PipePacket copy = *buffer;
    // 	if (copy.type == Connect) {
    // 		//FUN_0882f0f0(param_1, &copy);
    // 	}
    // 	else if (copy.type < Confirm) {
    // 		if (copy.type == (type_0xe | type_0x1)) {
    // 			//FUN_0882ece0(param_1, &copy);
    // 		}
    // 	}
    // 	else if (copy.type == Confirm) {
    // 		//FUN_0882f324(param_1, &copy);
    // 	}
    // 	else if (copy.type == type_0x18) {
    // 		//FUN_0882f584(param_1, &copy);
    // 	}
    // }

    int PSNSigAgent::HandleP2PPacket() {
        return 0;
    }

    std::chrono::microseconds PSNSigAgent::ProcessUPnPMessages() {
        return std::chrono::duration_cast<std::chrono::microseconds>(5s);
	}

    void PSNSigAgent::ProcessP2PMessages(PSPPointer<PipePacket> packet) {
    }

    // Signaling Helpers

    u32 PSNSigAgent::init_sig(const SceNpId& npid) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
        return 0;
    }
    u32 PSNSigAgent::init_sig(const SceNpId& npid, SceNpMatching2RoomId room_id, SceNpMatching2RoomMemberId member_id) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
        return 0;
    }
    u32 PSNSigAgent::get_always_conn_id(const SceNpId& npid) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
        return 0;
    }
    std::optional<u32> PSNSigAgent::get_conn_id_from_npid(const SceNpId& npid) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
        return std::nullopt;
    }
    std::optional<SceSignalingPeer> PSNSigAgent::get_sig_infos(u32 conn_id) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
        return std::nullopt;
    }
    void PSNSigAgent::set_self_sig_info(SceNpId& npid) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
    }
    std::shared_ptr<SceSignalingPeer> PSNSigAgent::get_signaling_ptr(const SignalingPacket* sp) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
        return nullptr;
    }
    void PSNSigAgent::update_si_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
    }
    void PSNSigAgent::update_si_mapped_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
    }
    void PSNSigAgent::update_si_status(std::shared_ptr<SceSignalingPeer>& si, s32 new_status, s32 error_code) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
    }
    void PSNSigAgent::update_ext_si_status(std::shared_ptr<SceSignalingPeer>& si, bool op_activated) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
    }

    // Connection Helpers

    void PSNSigAgent::connect(u32 conn_id, u32 addr, u16 port) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
    }
    bool PSNSigAgent::create_connection() {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
        return false;
    }
    bool PSNSigAgent::destroy_connection() {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
        return false;
    }
    void PSNSigAgent::stop(const char* reason) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
    }
    void PSNSigAgent::DisconnectUsers(SceNpMatching2RoomId room_id) {
        ERROR_LOG(Log::Signaling, "UNINPLEMENTED");
    }

    // Notification Functions

    int PSNSigAgent::UserJoinedRoom(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI UNINPLEMENTED");
        auto noti = resp.stream;
        return 0;
    }
    int PSNSigAgent::UserLeftRoom(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI UNINPLEMENTED");
        auto noti = resp.stream;
        return 0;
    }
    int PSNSigAgent::RoomDestroyed(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI UNINPLEMENTED");
        auto noti = resp.stream;
        return 0;
    }
    int PSNSigAgent::UpdatedRoomDataInternal(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI UNINPLEMENTED");
        auto noti = resp.stream;
        return 0;
    }
    int PSNSigAgent::UpdatedRoomMemberDataInternal(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI UNINPLEMENTED");
        auto noti = resp.stream;
        return 0;
    }
    int PSNSigAgent::RoomMessageReceived(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI UNINPLEMENTED");
        auto noti = resp.stream;
        return 0;
    }
    void PSNSigAgent::SignalingHelper(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI UNINPLEMENTED");
        auto noti = resp.stream;
    }
    void PSNSigAgent::MemberJoinedRoomGUI(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI MemberJoinedRoomGUI UNINPLEMENTED");
        auto noti = resp.stream;
    }
    void PSNSigAgent::MemberLeftRoomGUI(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI MemberLeftRoomGUI UNINPLEMENTED");
        auto noti = resp.stream;
    }
    void PSNSigAgent::RoomDisappearedGUI(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI RoomDisappearedGUI UNINPLEMENTED");
        auto noti = resp.stream;
    }
    void PSNSigAgent::RoomOwnerChangedGUI(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI RoomOwnerChangedGUI UNINPLEMENTED");
        auto noti = resp.stream;
    }
    void PSNSigAgent::UserKickedGUI(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI UserKickedGUI UNINPLEMENTED");
        auto noti = resp.stream;
    }
    void PSNSigAgent::QuickMatchCompleteGUI(net::RPCNResponse resp) {
        ERROR_LOG(Log::Signaling, "NOTI QuickMatchCompleteGUI UNINPLEMENTED");
        auto noti = resp.stream;
    }
}