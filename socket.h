#pragma once

#include "api.h"

namespace cond {
    namespace socket {
        enum {
            start = cond_base_socket,
            stream,
            datagram,
            reuse,
            block,
            bind,
            listen,
            accept,
            getpeername,
            select,
            recv,
            recvfrom,
            send,
            sendto,
            shutdown,
            close
        };
    }
}

class Socket {
    struct sockaddr_in _localAddr4;
    struct sockaddr_in _remoteAddr4;
    struct sockaddr_in6 _localAddr6;
    struct sockaddr_in6 _remoteAddr6;

    SOCKET _socket;

    uint16_t _localPort;
    uint16_t _remotePort;

    bool _v6;

public:
    Socket();
    ~Socket();
    void Init();
    void Reset();

    void Port(uint16_t port) { _localPort = port; }
    void Sock(SOCKET socket) { _socket = socket; }
    void V6(bool v6) { _v6 = v6; }

    bool V6() { return _v6; }
    SOCKET Sock() { return _socket; }

    void GetRemoteAddress(char* addr);
    void GetRemoteAddress(struct sockaddr_in& addr);
    void GetRemoteAddress(struct sockaddr_in6& addr);
    void SetRemoteAddress(Socket& socket);

    bool Readable();
    bool Writable();
    bool Stream(bool v6 = false);
    bool Datagram(bool v6 = false);

    bool Bind();
    bool Listen();
    SOCKET Accept();

    bool Read(uint8_t* buf, size_t* ret);
    bool Get(uint8_t* buf, size_t* ret);
    bool Write(uint8_t* buf, size_t* ret);
    bool Put(uint8_t* buf, size_t* ret);

    bool Shutdown();
    bool Close();
};
