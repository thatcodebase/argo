#pragma once

#include "api.h"
#include "digest.h"

namespace sha1 {
    enum {
        hashbytes = 20,
        blockbytes = 64
    };
}
namespace sha256 {
    enum {
        hashbytes = 32,
        blockbytes = 64
    };
}
namespace sha224 {
    enum {
        hashbytes = 28,
        blockbytes = 64
    };
}
namespace sha512 {
    enum {
        hashbytes = 64,
        blockbytes = 128
    };
}
namespace sha384 {
    enum {
        hashbytes = 48,
        blockbytes = 128
    };
}

const uint32_t K256[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    0xCA273ECE, 0xD186B8C7, 0xEADA7DD6, 0xF57D4F7F,
    0x06F067AA, 0x0A637DC5, 0x113F9804, 0x1B710B35,
    0x28DB77F5, 0x32CAAB7B, 0x3C9EBE0A, 0x431D67C4,
    0x4CC5D4BE, 0x597F299C, 0x5FCB6FAB, 0x6C44198C };

const uint32_t K512[] = {
    0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc,
    0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
    0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2,
    0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
    0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65,
    0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
    0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4,
    0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
    0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df,
    0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
    0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30,
    0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
    0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8,
    0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
    0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec,
    0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
    0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178,
    0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
    0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c,
    0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817 };

#define SHA256_RR(x,y) (((x)>>(y))|((x)<<(32-(y))))
#define SHA256_RL(x,y) (((x)<<(y))|((x)>>(32-(y))))
#define SHA256_CH(x,y,z) (((x)&(y))^((~x)&(z)))
#define SHA256_MA(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))

#define SHA256_S0(x) ((SHA256_RR(x,2))^(SHA256_RR(x,13))^(SHA256_RR(x,22)))
#define SHA256_S1(x) ((SHA256_RR(x,6))^(SHA256_RR(x,11))^(SHA256_RR(x,25)))
#define SHA256_s0(x) ((SHA256_RR(x,7))^(SHA256_RR(x,18))^((x)>>3))
#define SHA256_s1(x) ((SHA256_RR(x,17))^(SHA256_RR(x,19))^((x)>>10))

#define SHA512_RR(x,y) (((x)>>(y))|((x)<<(64-(y))))
#define SHA512_RL(x,y) (((x)<<(y))|((x)>>(64-(y))))
#define SHA512_CH(x,y,z) (((x)&(y))^((~x)&(z)))
#define SHA512_MA(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))

#define SHA512_S0(x) ((SHA512_RR(x,28))^(SHA512_RR(x,34))^(SHA512_RR(x,39)))
#define SHA512_S1(x) ((SHA512_RR(x,14))^(SHA512_RR(x,18))^(SHA512_RR(x,41)))
#define SHA512_s0(x) ((SHA512_RR(x,1))^(SHA512_RR(x,8))^((x)>>7))
#define SHA512_s1(x) ((SHA512_RR(x,19))^(SHA512_RR(x,61))^((x)>>6))

class SHA1 : public Digest {
public:
    HASH32 _hash;

    EXPORT virtual void Begin() override;
    EXPORT virtual void Transform() override;
    EXPORT virtual void End() override;
    EXPORT virtual uint8_t* PutOID(uint8_t* buf) override;
    EXPORT virtual uint8_t* PutDigestInfo(uint8_t* buf) override;
    EXPORT SHA1();
    EXPORT ~SHA1() override;
};

class SHA256 : public SHA1 {
public:
    EXPORT virtual void Begin() override;
    EXPORT void Transform() override;
    EXPORT virtual uint8_t* PutOID(uint8_t* buf) override;
    EXPORT virtual uint8_t* PutDigestInfo(uint8_t* buf) override;
    EXPORT SHA256();
    EXPORT ~SHA256() override;
};

class SHA224 : public SHA256 {
public:
    EXPORT void Begin() override;
    EXPORT uint8_t* PutOID(uint8_t* buf) override;
    EXPORT uint8_t* PutDigestInfo(uint8_t* buf) override;
    EXPORT SHA224();
    EXPORT ~SHA224() override;
};

class SHA512 : public Digest {
public:
    HASH64 _hash;

    EXPORT virtual void Begin() override;
    EXPORT void Transform() override;
    EXPORT void End() override;
    EXPORT virtual uint8_t* PutOID(uint8_t* buf) override;
    EXPORT virtual uint8_t* PutDigestInfo(uint8_t* buf) override;
    EXPORT SHA512();
    EXPORT ~SHA512() override;
};

class SHA384 : public SHA512 {
public:
    EXPORT void Begin() override;
    EXPORT uint8_t* PutOID(uint8_t* buf) override;
    EXPORT uint8_t* PutDigestInfo(uint8_t* buf) override;
    EXPORT SHA384();
    EXPORT ~SHA384() override;
};
