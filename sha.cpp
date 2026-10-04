#include "sha.h"
#include "asn.h"
#include "oid.h"

SHA1::SHA1()
{
    Begin();
}

SHA1::~SHA1()
{
    Reset();
}

void SHA1::Begin()
{
    _blocks = _len = 0;
    _hashBytes = sha1::hashbytes;
    _blockBytes = _remain = sha1::blockbytes;
    _first = _next = _hash._m;
    _digest = _hash._d;
    memset(_hash._w, 0, sizeof(_hash._w));
    memset(_hash._d, 0, sizeof(_hash._d));
    _hash._h[0] = 0x67452301;
    _hash._h[1] = 0xefcdab89;
    _hash._h[2] = 0x98badcfe;
    _hash._h[3] = 0x10325476;
    _hash._h[4] = 0xc3d2e1f0;
}

void SHA1::Transform()
{
    uint32_t t, a, b, c, d, e;
    for (int i = 0; i < 16; i++)
        _hash._w[i] = HILO32(_hash._w[i]);
    for (int i = 16; i < 80; i++) {
        t = (_hash._w[i - 3] ^ _hash._w[i - 8] ^ _hash._w[i - 14] ^ _hash._w[i - 16]);
        _hash._w[i] = ((t << 1) | (t >> 31));
    }
    a = _hash._h[0]; b = _hash._h[1]; c = _hash._h[2]; d = _hash._h[3]; e = _hash._h[4];
    for (int i = 0; i < 20; i++) {
        t = ((a << 5) | (a >> 27)) + ((b & c) ^ ((~b) & d)) + e + 0x5A827999 + _hash._w[i];
        e = d; d = c; c = ((b << 30) | (b >> 2)); b = a; a = t;
    }
    for (int i = 20; i < 40; i++) {
        t = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 0x6ED9EBA1 + _hash._w[i];
        e = d; d = c; c = ((b << 30) | (b >> 2)); b = a; a = t;
    }
    for (int i = 40; i < 60; i++) {
        t = ((a << 5) | (a >> 27)) + ((b & c) ^ (b & d) ^ (c & d)) + e + 0x8F1BBCDC + _hash._w[i];
        e = d; d = c; c = ((b << 30) | (b >> 2)); b = a; a = t;
    }
    for (int i = 60; i < 80; i++) {
        t = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 0xCA62C1D6 + _hash._w[i];
        e = d; d = c; c = ((b << 30) | (b >> 2)); b = a; a = t;
    }
    _hash._h[0] += a; _hash._h[1] += b; _hash._h[2] += c; _hash._h[3] += d; _hash._h[4] += e;
}

void SHA1::End()
{
    size_t len;
    uint64_t bits = (((uint64_t)_blocks) << 9) + (((uint64_t)_len) << 3);
    _hash._m[_len++] = 0x80;
    if (_len == _blockBytes) {
        Transform();
        _len = 0;
    }
    len = _blockBytes - _len;
    if (len < 8) {
        memset(&_hash._m[_len], 0, len);
        Transform();
        memset(_hash._m, 0, _blockBytes - 8);
        _len = 0;
    } else
        memset(&_hash._m[_len], 0, len - 8);

    _hash._m[56] = (uint8_t)(bits >> 56);
    _hash._m[57] = (uint8_t)(bits >> 48);
    _hash._m[58] = (uint8_t)(bits >> 40);
    _hash._m[59] = (uint8_t)(bits >> 32);
    _hash._m[60] = (uint8_t)(bits >> 24);
    _hash._m[61] = (uint8_t)(bits >> 16);
    _hash._m[62] = (uint8_t)(bits >> 8);
    _hash._m[63] = (uint8_t)(bits);
    Transform();
    for (int i = 0; i < 8; i++)
        _hash._h[i] = HILO32(_hash._h[i]);
}

uint8_t* SHA1::PutOID(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 9;
    *p++ = asn::oid;
    *p++ = 5;
    *p++ = OID_BYTE1(oid::iso, oid::isoorg);
    *p++ = oid::isoorgoiw;
    *p++ = oid::isoorgoiw_sec;
    *p++ = oid::isoorgoiw_secalg;
    *p++ = oid::isoorgoiw_secalg_sha1;
    *p++ = asn::null;
    *p++ = 0;
    return p;
}

uint8_t* SHA1::PutDigestInfo(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 33;
    p = PutOID(p);
    *p++ = asn::octetstring;
    *p++ = sha1::hashbytes;
    memcpy(p, _hash._d, sha1::hashbytes);
    p += sha1::hashbytes;
    return p;
}

SHA256::SHA256()
{
    Begin();
}

SHA256::~SHA256()
{
    Reset();
}

void SHA256::Begin()
{
    _blocks = _len = 0;
    _hashBytes = sha256::hashbytes;
    _blockBytes = _remain = sha256::blockbytes;
    _first = _next = _hash._m;
    _digest = _hash._d;
    memset(_hash._w, 0, sizeof(_hash._w));
    memset(_hash._d, 0, sizeof(_hash._d));
    _hash._h[0] = 0x6a09e667;
    _hash._h[1] = 0xbb67ae85;
    _hash._h[2] = 0x3c6ef372;
    _hash._h[3] = 0xa54ff53a;
    _hash._h[4] = 0x510e527f;
    _hash._h[5] = 0x9b05688c;
    _hash._h[6] = 0x1f83d9ab;
    _hash._h[7] = 0x5be0cd19;
}

void SHA256::Transform()
{
    size_t u;
    for (u = 0; u < 16; u++)
        _hash._w[u] = HILO32(_hash._w[u]);
    for (u = 16; u < 64; u++)
        _hash._w[u] = SHA256_s1(_hash._w[u - 2]) + _hash._w[u - 7] + SHA256_s0(_hash._w[u - 15]) + _hash._w[u - 16];

    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    a = _hash._h[0]; b = _hash._h[1]; c = _hash._h[2]; d = _hash._h[3];
    e = _hash._h[4]; f = _hash._h[5]; g = _hash._h[6]; h = _hash._h[7];
    for (u = 0; u < 64; u++) {
        t1 = h + SHA256_S1(e) + SHA256_CH(e, f, g) + K256[u] + _hash._w[u];
        t2 = SHA256_S0(a) + SHA256_MA(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    _hash._h[0] += a; _hash._h[1] += b; _hash._h[2] += c; _hash._h[3] += d;
    _hash._h[4] += e; _hash._h[5] += f; _hash._h[6] += g; _hash._h[7] += h;
}

uint8_t* SHA256::PutOID(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 13;
    *p++ = asn::oid;
    *p++ = 9;
    *p++ = OID_BYTE1(oid::ccitt, oid::ccittco);
    *p++ = OID_HI(oid::ccittcous);
    *p++ = OID_LO(oid::ccittcous);
    *p++ = oid::ccittcous_org;
    *p++ = oid::ccittcous_orggov;
    *p++ = oid::ccittcous_orggovor;
    *p++ = oid::ccittcous_orggovor_nist;
    *p++ = oid::ccittcous_orggovor_nisthash;
    *p++ = oid::ccittcous_orggovor_nisthash_sha256;
    *p++ = asn::null;
    *p++ = 0;
    return p;
}

uint8_t* SHA256::PutDigestInfo(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 49;
    p = PutOID(p);
    *p++ = asn::octetstring;
    *p++ = sha256::hashbytes;
    memcpy(p, _hash._d, sha256::hashbytes);
    p += sha256::hashbytes;
    return p;
}

SHA224::SHA224()
{
    Begin();
}

SHA224::~SHA224()
{
    Reset();
}

void SHA224::Begin()
{
    _blocks = _len = 0;
    _hashBytes = sha224::hashbytes;
    _blockBytes = _remain = sha224::blockbytes;
    _first = _next = _hash._m;
    _digest = _hash._d;
    memset(_hash._w, 0, sizeof(_hash._w));
    memset(_hash._d, 0, sizeof(_hash._d));
    _hash._h[0] = 0xc1059ed8;
    _hash._h[1] = 0x367cd507;
    _hash._h[2] = 0x3070dd17;
    _hash._h[3] = 0xf70e5939;
    _hash._h[4] = 0xffc00b31;
    _hash._h[5] = 0x68581511;
    _hash._h[6] = 0x64f98fa7;
    _hash._h[7] = 0xbefa4fa4;
}

uint8_t* SHA224::PutOID(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 13;
    *p++ = asn::oid;
    *p++ = 9;
    *p++ = OID_BYTE1(oid::ccitt, oid::ccittco);
    *p++ = OID_HI(oid::ccittcous);
    *p++ = OID_LO(oid::ccittcous);
    *p++ = oid::ccittcous_org;
    *p++ = oid::ccittcous_orggov;
    *p++ = oid::ccittcous_orggovor;
    *p++ = oid::ccittcous_orggovor_nist;
    *p++ = oid::ccittcous_orggovor_nisthash;
    *p++ = oid::ccittcous_orggovor_nisthash_sha224;
    *p++ = asn::null;
    *p++ = 0;
    return p;
}

uint8_t* SHA224::PutDigestInfo(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 41;
    p = PutOID(p);
    *p++ = asn::octetstring;
    *p++ = sha224::hashbytes;
    memcpy(p, _hash._d, sha224::hashbytes);
    p += sha224::hashbytes;
    return p;
}

SHA512::SHA512()
{
    Begin();
}

SHA512::~SHA512()
{
    Reset();
}

void SHA512::Begin()
{
    _blocks = _len = 0;
    _hashBytes = sha512::hashbytes;
    _blockBytes = _remain = sha512::blockbytes;
    _first = _next = _hash._m;
    _digest = _hash._d;
    memset(_hash._w, 0, sizeof(_hash._w));
    memset(_hash._d, 0, sizeof(_hash._d));
    _hash._h[0] = 0x6a09e667f3bcc908;
    _hash._h[1] = 0xbb67ae8584caa73b;
    _hash._h[2] = 0x3c6ef372fe94f82b;
    _hash._h[3] = 0xa54ff53a5f1d36f1;
    _hash._h[4] = 0x510e527fade682d1;
    _hash._h[5] = 0x9b05688c2b3e6c1f;
    _hash._h[6] = 0x1f83d9abfb41bd6b;
    _hash._h[7] = 0x5be0cd19137e2179;
}

void SHA512::Transform()
{
    size_t u;
    for (u = 0; u < 16; u++)
        _hash._w[u] = HILO64(_hash._w[u]);
    for (u = 16; u < 80; u++)
        _hash._w[u] = SHA512_s1(_hash._w[u - 2]) + _hash._w[u - 7] + SHA512_s0(_hash._w[u - 15]) + _hash._w[u - 16];

    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    a = _hash._h[0]; b = _hash._h[1]; c = _hash._h[2]; d = _hash._h[3];
    e = _hash._h[4]; f = _hash._h[5]; g = _hash._h[6]; h = _hash._h[7];
    for (u = 0; u < 80; u++) {
        t1 = h + SHA512_S1(e) + SHA512_CH(e, f, g) + (((uint64_t)K256[u] << 32) | K512[u]) + _hash._w[u];
        t2 = SHA512_S0(a) + SHA512_MA(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    _hash._h[0] += a; _hash._h[1] += b; _hash._h[2] += c; _hash._h[3] += d;
    _hash._h[4] += e; _hash._h[5] += f; _hash._h[6] += g; _hash._h[7] += h;
}

void SHA512::End()
{
    size_t len;
    uint64_t bits_hi = ((uint64_t)_blocks >> 54);
    uint64_t bits_lo = ((uint64_t)_blocks << 10) + ((uint64_t)_len << 3);
    _hash._m[_len++] = 0x80;
    if (_len == _blockBytes) {
        Transform();
        _len = 0;
    }
    len = _blockBytes - _len;
    if (len < 16) {
        memset(&_hash._m[_len], 0, len);
        Transform();
        memset(&_hash._m, 0, _blockBytes - 16);
        _len = 0;
    } else
        memset(&_hash._m[_len], 0, len - 16);

    _hash._m[112] = (uint8_t)(bits_hi >> 56);
    _hash._m[113] = (uint8_t)(bits_hi >> 48);
    _hash._m[114] = (uint8_t)(bits_hi >> 40);
    _hash._m[115] = (uint8_t)(bits_hi >> 32);
    _hash._m[116] = (uint8_t)(bits_hi >> 24);
    _hash._m[117] = (uint8_t)(bits_hi >> 16);
    _hash._m[118] = (uint8_t)(bits_hi >> 8);
    _hash._m[119] = (uint8_t)(bits_hi);

    _hash._m[120] = (uint8_t)(bits_lo >> 56);
    _hash._m[121] = (uint8_t)(bits_lo >> 48);
    _hash._m[122] = (uint8_t)(bits_lo >> 40);
    _hash._m[123] = (uint8_t)(bits_lo >> 32);
    _hash._m[124] = (uint8_t)(bits_lo >> 24);
    _hash._m[125] = (uint8_t)(bits_lo >> 16);
    _hash._m[126] = (uint8_t)(bits_lo >> 8);
    _hash._m[127] = (uint8_t)(bits_lo);
    Transform();
    for (int i = 0; i < 8; i++)
        _hash._h[i] = HILO64(_hash._h[i]);
}

uint8_t* SHA512::PutOID(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 13;
    *p++ = asn::oid;
    *p++ = 9;
    *p++ = OID_BYTE1(oid::ccitt, oid::ccittco);
    *p++ = OID_HI(oid::ccittcous);
    *p++ = OID_LO(oid::ccittcous);
    *p++ = oid::ccittcous_org;
    *p++ = oid::ccittcous_orggov;
    *p++ = oid::ccittcous_orggovor;
    *p++ = oid::ccittcous_orggovor_nist;
    *p++ = oid::ccittcous_orggovor_nisthash;
    *p++ = oid::ccittcous_orggovor_nisthash_sha512;
    *p++ = asn::null;
    *p++ = 0;
    return p;
}

uint8_t* SHA512::PutDigestInfo(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 81;
    p = PutOID(p);
    *p++ = asn::octetstring;
    *p++ = sha512::hashbytes;
    memcpy(p, _hash._d, sha512::hashbytes);
    p += sha512::hashbytes;
    return p;
}

SHA384::SHA384()
{
    Begin();
}

SHA384::~SHA384()
{
    Reset();
}

void SHA384::Begin()
{
    _blocks = _len = 0;
    _hashBytes = sha384::hashbytes;
    _blockBytes = _remain = sha384::blockbytes;
    _first = _next = _hash._m;
    _digest = _hash._d;
    memset(_hash._w, 0, sizeof(_hash._w));
    memset(_hash._d, 0, sizeof(_hash._d));
    _hash._h[0] = 0xcbbb9d5dc1059ed8;
    _hash._h[1] = 0x629a292a367cd507;
    _hash._h[2] = 0x9159015a3070dd17;
    _hash._h[3] = 0x152fecd8f70e5939;
    _hash._h[4] = 0x67332667ffc00b31;
    _hash._h[5] = 0x8eb44a8768581511;
    _hash._h[6] = 0xdb0c2e0d64f98fa7;
    _hash._h[7] = 0x47b5481dbefa4fa4;
}

uint8_t* SHA384::PutOID(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 13;
    *p++ = asn::oid;
    *p++ = 9;
    *p++ = OID_BYTE1(oid::ccitt, oid::ccittco);
    *p++ = OID_HI(oid::ccittcous);
    *p++ = OID_LO(oid::ccittcous);
    *p++ = oid::ccittcous_org;
    *p++ = oid::ccittcous_orggov;
    *p++ = oid::ccittcous_orggovor;
    *p++ = oid::ccittcous_orggovor_nist;
    *p++ = oid::ccittcous_orggovor_nisthash;
    *p++ = oid::ccittcous_orggovor_nisthash_sha384;
    *p++ = asn::null;
    *p++ = 0;
    return p;
}

uint8_t* SHA384::PutDigestInfo(uint8_t* buf)
{
    uint8_t* p = buf;
    *p++ = asn::sequence;
    *p++ = 65;
    p = PutOID(p);
    *p++ = asn::octetstring;
    *p++ = sha384::hashbytes;
    memcpy(p, _hash._d, sha384::hashbytes);
    p += sha384::hashbytes;
    return p;
}
