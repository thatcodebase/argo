#include "buffer.h"

#include <cstdlib>

Buffer::Buffer()
{
    //  Initialize members to default values.

    Init();
}

Buffer::~Buffer()
{
    //  Release storage and initialize members.

    Reset();
}

void Buffer::Init()
{
    //  Initialize members to default values.

    _size = 0;
    _len = 0;
    _head = 0;
    _buf = nullptr;
}

void Buffer::Reset()
{
    //  Release storage and initialize members.

    freeptr(&_buf);

    Init();
}

void Buffer::Resize(size_t size)
{
    //  Release storage and initialize members.

    Reset();

    //  if we are given a size, allocate storage
    //  and initailize it to zeros.

    if (size) {
        _buf = (uint8_t*)calloc(size, 1);
        if (_buf) {
            _size = size;
        }
    }
}

void Buffer::Extend(size_t len)
{
    _len += len;
}

size_t Buffer::Size()
{
    return _size;
}

size_t Buffer::Length()
{
    return _len;
}

uint8_t* Buffer::Head()
{
    return &_buf[_head];
}

uint8_t* Buffer::Tail()
{
    return &_buf[_head + _len];
}

size_t Buffer::Avail()
{
    return (_buf ? _size - _len : 0);
}

void Buffer::Front()
{
    if (_buf && _head && _len) {
        memcpy(_buf, &_buf[_head], _len);
        _head = 0;
    }
}

void Buffer::Discard(size_t len)
{
    if (len > _len) {
        len = _len;
    }
    _head += len;
    _len -= len;
    if (!_len) {
        _head = 0;
        if (_buf && _size) {
            memset(_buf, 0, _size);
        }
    }
}

void Buffer::Append(uint8_t* buf)
{
    size_t len = strlen((char*)buf);
    Append(buf, len);
}

void Buffer::Append(char* buf)
{
    size_t len = strlen(buf);
    Append((uint8_t*)buf, len);
}

void Buffer::Append(const char* buf)
{
    size_t len = strlen(buf);
    Append((uint8_t*)buf, len);
}

void Buffer::Append(uint8_t* buf, size_t len)
{
    if (len) {
        uint8_t* t = (uint8_t*)calloc(_len + len, 1);
        if (t) {
            uint8_t* q = t;
            if (_buf) {
                memcpy(q, _buf, _len);
                q += _len;
                free(_buf);
            }
            if (buf) {
                memcpy(q, buf, len);
                q += len;
            }
            _buf = t;
            _len = q - _buf;
            _head = 0;
        }
    }
}

void Buffer::Emit(uint8_t* buf, size_t len)
{
    if (len > _len) {
        len = _len;
    }
    if (len && buf) {
        memcpy(buf, &_buf[_head], len);
    }
    Discard(len);
}
