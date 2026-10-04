#pragma once

#include "api.h"

namespace uri {
    namespace port {
        enum {
            ftp = 21,
            smtp = 25,
            http = 80,
            https = 443,
            hctl = 4197
        };
    }
    namespace protocol {
        enum {
            file = 1,
            smtp,
            ftp,
            http,
            https
        };
    }
}

class URI {
public:
    uint32_t _addr;
    uint16_t _port;
    uint8_t _protocol;

    char *_host;
    char *_resource;
    char *_user;
    char *_password;

    EXPORT URI();
    EXPORT ~URI();
    EXPORT void Init();
    EXPORT void Reset();
    EXPORT bool Put(char *uri_s);
};
