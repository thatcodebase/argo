#include "socket.h"
#include "logger.h"

Socket::Socket()
{
    //  Initialize members to default values.

    Init();
}

Socket::~Socket()
{
    //  Release storage and initialize members.

    Reset();
}

void Socket::Init()
{
    //  Initialize members to default values.

    _localAddr4 = { 0 };
    _remoteAddr4 = { 0 };
    _localAddr6 = { 0 };
    _remoteAddr6 = { 0 };
    _socket = 0;
    _localPort = 0;
    _remotePort = 0;
    _v6 = false;
}

void Socket::Reset()
{
    //  Close any connection.

    Close();

    //  Initalize members to default values.

    Init();
}

void Socket::GetRemoteAddress(char* addr)
{
    if (_v6) {
        inet_ntop(AF_INET6, &(_remoteAddr6.sin6_addr), addr, INET6_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET, &(_remoteAddr4.sin_addr), addr, INET_ADDRSTRLEN);
    }
}

void Socket::GetRemoteAddress(struct sockaddr_in& addr)
{
    addr = _remoteAddr4;
}

void Socket::GetRemoteAddress(struct sockaddr_in6& addr)
{
    addr = _remoteAddr6;
}

void Socket::SetRemoteAddress(Socket& socket)
{
    if (socket.V6()) {
        struct sockaddr_in6 addr;
        socket.GetRemoteAddress(addr);
        memcpy(&_remoteAddr6, &addr, sizeof(sockaddr_in6));
    } else {
        struct sockaddr_in addr;
        socket.GetRemoteAddress(addr);
        memcpy(&_remoteAddr4, &addr, sizeof(sockaddr_in));
    }
}

bool Socket::Readable()
{
    if (_socket) {
        fd_set rfds = { 0 };
        FD_SET(_socket, &rfds);
        struct timeval tv = { 0, 10 };
        if (select((int)_socket + 1, &rfds, 0, 0, &tv) > 0) {
            return true;
        }
    }
    return false;
}

bool Socket::Writable()
{
    if (_socket) {
        fd_set wfds = { 0 };
        FD_SET(_socket, &wfds);
        struct timeval tv = { 0, 10 };
        if (select((int)_socket + 1, 0, &wfds, 0, &tv) > 0) {
            return true;
        }
    }
    return false;
}

bool Socket::Stream(bool v6)
{
    _v6 = v6;
    _socket = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (INVALID_SOCKET == _socket) {
        OsErr(WSAGetLastError());
        AppErr(cond::socket::stream);
        return false;
    }
#if defined(_WIN32)
    unsigned long nonblock = 1;
    if (ioctlsocket(_socket, FIONBIO, &nonblock)) {
#else
    if (SOCKET_ERROR == fcntl(_socket, F_SETFL, O_NONBLOCK)) {
#endif
        OsErr(WSAGetLastError());
        AppErr(cond::socket::block);
        closesocket(_socket);
        _socket = 0;
        return false;
    }
    return true;
}

bool Socket::Datagram(bool v6)
{
    _v6 = v6;
    _socket = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (INVALID_SOCKET == _socket) {
        AppErr(cond::socket::datagram);
        return false;
    }
#if defined(_WIN32)
    unsigned long nonblock = 1;
    if (ioctlsocket(_socket, FIONBIO, &nonblock)) {
#else
    if (SOCKET_ERROR == fcntl(_socket, F_SETFL, O_NONBLOCK)) {
#endif
        AppErr(cond::socket::datagram);
        closesocket(_socket);
        _socket = 0;
        return false;
    }
    return true;
}

bool Socket::Bind()
{
    int on = 1;
    if (setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof on)) {
        OsErr(WSAGetLastError());
        AppErr(cond::socket::reuse);
        return false;
    }
    struct sockaddr_in sa4 = { 0 };
    struct sockaddr_in6 sa6 = { 0 };
    if (_v6) {
        sa6.sin6_port = htons(_localPort);
        sa6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "::1", &(sa6.sin6_addr));
        if (::bind(_socket, (struct sockaddr*)(&sa6), sizeof(sa6))) {
            OsErr(WSAGetLastError());
            AppErr(cond::socket::bind);
            return false;
        }
    } else {
        sa4.sin_port = htons(_localPort);
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, "0.0.0.0", &(sa4.sin_addr));
        if (::bind(_socket, (struct sockaddr*)(&sa4), sizeof(sa4))) {
            AppErr(cond::socket::bind);
            return false;
        }
    }
    return true;
}

bool Socket::Listen()
{
    if (::listen(_socket, SOMAXCONN)) {
        OsErr(WSAGetLastError());
        AppErr(cond::socket::listen);
        return false;
    }
    return true;
}

SOCKET Socket::Accept()
{
    fd_set rfds = { 0 };
    FD_SET(_socket, &rfds);
    struct timeval tv = { 0, 2 };
    int n = select((int)_socket + 1, &rfds, 0, 0, &tv);
    if (!n) {
        return 0;
    }
    if (n < 0) {
        int rc = WSAGetLastError();
        if (EINTR != rc) {
            AppErr(cond::socket::select);
        }
        return 0;
    }
    struct sockaddr_in addr4 = { 0 };
    struct sockaddr_in6 addr6 = { 0 };
    socklen_t addrLen = 0;
    SOCKET client = 0;
    if (_v6) {
        addrLen = sizeof(sockaddr_in6);
        client = accept(_socket, (sockaddr*)&addr6, &addrLen);
        if (INVALID_SOCKET == client) {
            AppErr(cond::socket::accept);
            return 0;
        }
        addrLen = sizeof(sockaddr_in6);
        if (getpeername(client, (sockaddr*)&addr6, &addrLen)) {
            OsErr(WSAGetLastError());
            AppErr(cond::socket::getpeername);
            closesocket(client);
            return 0;
        }
        memcpy(&_remoteAddr6, &addr6, sizeof(sockaddr_in6));
        _remotePort = addr6.sin6_port;
    } else {
        addrLen = sizeof(sockaddr_in);
        client = accept(_socket, (sockaddr*)&addr4, &addrLen);
        if (INVALID_SOCKET == client) {
            AppErr(cond::socket::accept);
            return 0;
        }
        addrLen = sizeof(sockaddr);
        if (getpeername(client, (sockaddr*)&addr4, &addrLen)) {
            OsErr(WSAGetLastError());
            AppErr(cond::socket::getpeername);
            closesocket(client);
            return 0;
        }
        memcpy(&_remoteAddr4, &addr4, sizeof(sockaddr));
        _remotePort = addr4.sin_port;
    }
    return client;
}

bool Socket::Read(uint8_t* buf, size_t* ret)
{
    size_t len = *ret;
    *ret = 0;
    ssize_t count = recv(_socket, (char*)buf, (int)len, 0);
    if (!count) {
        return false;
    }
    if (count < 0) {
        int err = WSAGetLastError();
        if (WSAEWOULDBLOCK == err) {
            return true;
        }
        OsErr(err);
        AppErr(cond::socket::recv);
        return false;
    }
    *ret = count;
    return true;
}

bool Socket::Get(uint8_t* buf, size_t* ret)
{
    size_t len = *ret;
    *ret = 0;
    struct sockaddr_in addr4 = { 0 };
    struct sockaddr_in6 addr6 = { 0 };
    socklen_t addrLen = 0;
    int count = 0;
    if (_v6) {
        addrLen = sizeof(sockaddr_in6);
        count = recvfrom(_socket, (char*)buf, (int)len, 0, (struct sockaddr*)&addr6, &addrLen);
    } else {
        addrLen = sizeof(sockaddr_in);
        count = recvfrom(_socket, (char*)buf, (int)len, 0, (struct sockaddr*)&addr4, &addrLen);
    }
    if (count < 1) {
        if (count < 0) {
            int err = WSAGetLastError();
            if (WSAEWOULDBLOCK == err) {
                return true;
            }
            AppErr(cond::socket::recvfrom);
        }
        return false;
    }
    if (_v6) {
        memcpy(&_remoteAddr6, &addr6, sizeof(_remoteAddr6));
        _remotePort = htons(addr6.sin6_port);
    } else {
        memcpy(&_remoteAddr4, &addr4, sizeof(_remoteAddr4));
        _remotePort = htons(addr4.sin_port);
    }
    *ret = count;
    return true;
}

bool Socket::Put(uint8_t* buf, size_t* ret)
{
    size_t len = *ret;
    *ret = 0;
    struct sockaddr_in addr4 = { 0 };
    struct sockaddr_in6 addr6 = { 0 };
    socklen_t addrLen = 0;
    int count = 0;
    if (_v6) {
        memcpy(&addr6, &_remoteAddr6, sizeof(addr6));
        addrLen = sizeof addr6;
        count = sendto(_socket, (char*)buf, (int)len, 0, (struct sockaddr*)&addr6, addrLen);
    } else {
        memcpy(&addr4, &_remoteAddr4, sizeof(addr4));
        addrLen = sizeof addr4;
        count = sendto(_socket, (char*)buf, (int)len, 0, (struct sockaddr*)&addr4, addrLen);
    }
    if (!count) {
        return false;
    }
    if (count < 0) {
        int err = WSAGetLastError();
        if (WSAEWOULDBLOCK == err) {
            return true;
        }
        AppErr(cond::socket::sendto);
        return false;
    }
    *ret = count;
    return true;
}

bool Socket::Write(uint8_t* buf, size_t* ret)
{
    size_t len = *ret;
    *ret = 0;
    ssize_t count = send(_socket, (char*)buf, (int)len, 0);
    if (count < 0) {
        int err = WSAGetLastError();
        if ((WSAEWOULDBLOCK != err) && (WSAENOBUFS != err)) {
            OsErr(err);
            AppErr(cond::socket::send);
            return false;
        }
    }
    *ret = count;
    return true;
}

bool Socket::Shutdown()
{
    if (_socket) {
        if (shutdown(_socket, 2)) {
            int rc = WSAGetLastError();
            if (WSAENOTCONN != rc) {
                OsErr(rc);
                AppErr(cond::socket::shutdown);
                return false;
            }
        }
    }
    return true;
}

bool Socket::Close()
{
    if (_socket) {
        if (closesocket(_socket)) {
            OsErr(WSAGetLastError());
            AppErr(cond::socket::close);
            return false;
        }
        _socket = 0;
    }
    return true;
}
