#include "digest.h"

void Digest::Reset()
{
    Begin();
}

void Digest::Update(uint8_t* in, size_t len)
{
    while (len >= _remain) {
        memcpy(_next, in, _remain);
        in += _remain;
        len -= _remain;
        Transform();
        _blocks++;
        _len = 0;
        _remain = _blockBytes;
        _next = _first;
    }
    if (len) {
        memcpy(_next, in, len);
        _len += len;
        _remain -= len;
        _next += len;
    }
}

void Digest::HashBuf(uint8_t* in, size_t len)
{
    Begin();
    Update(in, len);
    End();
}

uint8_t* Digest::GetDigest(uint8_t* buf)
{
    memcpy(buf, _digest, _hashBytes);
    return buf + _hashBytes;
}
