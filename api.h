#pragma once

#include "iapi.h"

#if defined(_WIN32)
#include <WinSock2.h> // WSADATA, SOCKET, BOOL, DWORD
#endif
#include <cstdarg> // var_list, va_start, vsnprintf

// Private definitions relevant to the entire app.

enum {
    cond_base_driver = 1000
};

#if defined(_WIN32)
#define WINSOCKVERSION 0x0202
#endif
