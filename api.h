#pragma once

#include "iapi.h"

#if defined(_WIN32)
#include <WinSock2.h> // WSADATA, SOCKET, BOOL, DWORD
#include <ws2ipdef.h> // sockaddr_in6
#include <WS2tcpip.h> // inet_pton
#else
#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h> // O_RDWR, open
#include <netdb.h>
#include <netinet/in.h> // socket, AF_, SOCK_, IPPROTO_
#include <signal.h> // sigaction
#endif
#include <arpa/inet.h> // inet_pton
#include <cstdarg> // var_list, va_start, vsnprintf
#include <cstring> // memcpy, memset, strlen
#include <unistd.h> // close, fork, setsid, STDIN_FILENO
#endif
#include <cstdint> // uint8_t
#include <cstdio> // printf
#include <cstdlib> // free
#include <time.h> // time

enum {
    cond_base_socket = 300,
    cond_base_driver = 1000
};

#if defined(_WIN32)
#define WINSOCKVERSION 0x0202
#else
#if defined(__linux__) || defined(__APPLE__)
#define closesocket(x) ::close(x)
#else
#endif
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define WSAENOBUFS ENOBUFS
#define WSAENOTCONN ENOTCONN
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAGetLastError() errno
#endif
#define HILO32(x) ((x << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >> 8) | (x >> 24))
#define HILO64(x) ((x << 56) | ((x & 0xFF00) << 40) | ((x & 0xFF0000) << 24) | ((x & 0xFF000000) << 8) | ((x >> 8) & 0xFF000000) | ((x >> 24) & 0xFF0000) | ((x >> 40) & 0xFF00) | (x >> 56))

#if defined(_WIN32)
using socklen_t = int;
using ssize_t = int;
#else
#if defined(__linux__)
using SOCKET = size_t;
#else
using SOCKET = int;
#endif
#endif

char* dupstr(const char* s);
void freestr(char** s);
void freeptr(uint8_t** ptr);
void setstr(char** ptr, const char* s);
