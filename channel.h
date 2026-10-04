#pragma once

#include "buffer.h"
#include "sha.h"
#include "socket.h"
#include "uri.h"

namespace channel {
    enum {
        size = 512
    };
    enum class state {
        ready = 0,
        connected,
        needfirstbytes,
        needplaintext,
        needhandshake,
        needdecryptedhandshake,
        needrectypechange,
        needrequest,
        haverequest,
        needheader,
        haveheader,
        needbody,
        havebody,
        done,
        close
    };
}

namespace http {
    enum class method {
        unspecified = 0,
        connect,
        get,
        head,
        options,
        post,
        put,
        trace
    };
    enum class response {
        ok = 200,
        badrequest = 400 
    };
}

namespace tls {
    enum alertlevel {
        warning = 1,
        fatal = 2
    };
    enum alerttype {
        unexpected = 10,
        param = 47,
        decode = 50,
        decrypt = 51,
        version = 70
    };
    enum max {
        plaintextsize = 16384
    };
    enum rec {
        change = 20,
        alert = 21,
        handshake = 22,
        data = 23
    };
    enum ver {
        ssl30 = 0x0300,
        tls10 = 0x0301,
        tls11 = 0x0302,
        tls12 = 0x0303,
        tls13 = 0x0304
    };
}


class Channel {
    Channel* _next;
    Channel* _prev;

    channel::state _state;
    http::method _method;

    time_t _expires;
    size_t _remain;

    uint16_t _plainTextVersion;
    uint16_t _plainTextSize;
    uint16_t _handShakeSize;

    uint8_t _httpMajor;
    uint8_t _httpMinor;
    uint8_t _tlsRecType;
    uint8_t _tlsHandShakeType;

    bool _haveChangeCipherSpec;

    URI _uri;
    SHA256 _sha256;

protected:
    Socket _socket;
    Buffer _read;
    Buffer _write;

public:
    Channel();
    ~Channel();

    Channel* Next() { return _next; }
    Channel* Prev() { return _prev; }
    channel::state State() { return _state; }

    void Next(Channel* next) { _next = next; }
    void Prev(Channel* prev) { _prev = prev; }
    void State(channel::state state) { _state = state; }
    void Expires(time_t expires) { _expires = expires; }

    void Sock(SOCKET sock) { _socket.Sock(sock); }
    void RemoteAddress(Socket& socket) { _socket.SetRemoteAddress(socket); }

    virtual void Init();
    virtual void Reset();
    virtual void Read();
    virtual void Write();
    virtual void Service();

    uint8_t* Prefetch(size_t remain);

    void Connected();
    void NeedFirstBytes();
    void NeedPlainText();
    void SendAlert(const uint8_t level, const uint8_t desc);
    void NeedHandShake();
    void NeedRecTypeChange();
    void NeedDecryptedHandshake();

    void NeedRequest();
    void HaveRequest();
    void BadRequest();
    void PutHttpResponseString(http::response response);
    void PutHttpResponse();
    bool CheckHttpMethod(uint8_t* p);
    bool CheckHttpVersion(uint8_t* p);
    bool CheckHttpSupportedVersion(uint8_t* p);
    void HaveHttpHeader();
    void NeedHttpHeader();
    void SaveHttpHeader(uint8_t* p);
    void NeedHttpBody();
    void HaveHttpBody();

    void Done();
    void Clear();
    void Close();
};
