#pragma once

#include "api.h"

class Buffer {
    size_t _size;
    size_t _len;
    size_t _head;

    uint8_t* _buf;

public:
    Buffer();
    ~Buffer();
    void Init();
    void Reset();

    void Resize(size_t size);
    void Extend(size_t len);

    size_t Size();
    size_t Avail();
    size_t Length();

    uint8_t* Head();
    uint8_t* Tail();
 
    void Front();
    void Discard(size_t len);

    void Append(uint8_t* buf);
    void Append(char* buf);
    void Append(const char* buf);

    void Append(uint8_t* buf, size_t len);
    void Emit(uint8_t* buf, size_t len);
};