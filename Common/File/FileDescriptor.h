#pragma once

#include <cstring>
#include <string>
#include <string_view>

namespace fd_util {

// Returns true if the fd became ready, false if it didn't or
// if there was another error.
bool WaitUntilReady(int fd, double timeout, bool for_write = false);
//bool WaitUntilReady(mbedtls_net_context* netCtx, double timeout, bool for_write);

void SetNonBlocking(int fd, bool non_blocking);

std::string GetLocalIP(int sock);

}  // fd_util
