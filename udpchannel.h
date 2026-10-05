#pragma once

#include "channel.h"

namespace udpchannel {
    enum {
        size = 65535
    };
}

class UdpChannel final: public Channel {
public:
    Socket& Sock() { return _socket; }
    void Sock(SOCKET sock) { _socket.Sock(sock); }
    void V6(bool v6) { _socket.V6(v6); }
    void Read() override;
    void Write() override;
    void Service() override;
};