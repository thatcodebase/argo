#pragma once

#include "api.h"

namespace digest {
    enum {
        hasbytes = 16,
        blockbytes = 64
    };
}

typedef struct _hash32 {
    union {
        uint32_t _w[80];
        uint8_t _m[64];
    };
    union {
        uint32_t _h[8];
        uint8_t _d[32];
    };
} HASH32;

typedef struct _hash64 {
    union {
        uint64_t _w[80];
        uint8_t _m[128];
    };
    union {
        uint64_t _h[8];
        uint8_t _d[64];
    };
} HASH64;

class Digest {
public:
    size_t _blocks;
    size_t _len;
    size_t _hashBytes;
    size_t _blockBytes;
    size_t _remain;

    uint8_t* _first;
    uint8_t* _next;
    uint8_t* _digest;

    void Reset();
    void HashBuf(uint8_t* in, size_t len);

    virtual ~Digest() {};
    virtual void Begin() = 0;
    virtual void Transform() = 0;
    virtual void End() = 0;
    virtual uint8_t* PutOID(uint8_t* buf) = 0;
    virtual uint8_t* PutDigestInfo(uint8_t* buf) = 0;

    EXPORT void Update(uint8_t* in, size_t len);
    EXPORT uint8_t* GetDigest(uint8_t* buf);
};
