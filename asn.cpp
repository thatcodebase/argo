#include "asn.h"

uint8_t* asnInto(uint8_t* p, size_t* len, size_t* indef)
{
    p++;
    uint8_t c = *p++; // len0
    size_t h = 0;
    if (0x80 == c) {
        (*indef)++;
    }
    if (0x80 & c) {
        c &= 0x7f;
        if (!c) {
            h = 0;
        } else if (1 == c) {
            h = *p;
        } else if (2 == c) {
            h = ((size_t)*p << 8) + *(p + 1);
        } else if (3 == c) {
            h = ((size_t)*p << 16) + ((size_t) * (p + 1) << 8) + *(p + 2);
        } else if (4 == c) {
            h = ((size_t)*p << 24) + ((size_t) * (p + 1) << 16) + ((size_t) * (p + 2) << 8) + *(p + 3);
        }
        p += c;
    } else {
        h = c;
    }
    *len = h;
    return p;
}

uint8_t* asnOver(uint8_t* p, size_t* len, size_t* indef)
{
    uint8_t t = *p++; // tag
    uint8_t c = *p++; // len0
    size_t h = 0;
    while (0x80 == c) {
        (*indef)++;
        p = asnOver(p, &h, indef);
        t = *p++;
        c = *p++;
    }
    if (0x80 & c) {
        c &= 0x7f;
        if (1 == c) {
            h = *p;
        } else if (2 == c) {
            h = ((size_t)*p << 8) + *(p + 1);
        } else if (3 == c) {
            h = ((size_t)*p << 16) + ((size_t) * (p + 1) << 8) + *(p + 2);
        } else if (4 == c) {
            h = ((size_t)*p << 24) + ((size_t) * (p + 1) << 16) + ((size_t) * (p + 2) << 8) + *(p + 3);
        }
        p += c;
    } else {
        h = c;
        if (!t && !c) {
            (*indef)--;
        }
    }
    *len = h;
    p += h;
    return p;
}

uint8_t* asnPutLength(uint8_t* buf, size_t len)
{
    if (len < 128) {
        *buf++ = (uint8_t)len;
    } else if (len < 0x100) {
        *buf++ = (uint8_t)'\x81';
        *buf++ = (uint8_t)len;
    } else if (len < 0x10000) {
        *buf++ = (uint8_t)'\x82';
        *buf++ = (uint8_t)(len >> 8) & 0xff;
        *buf++ = (uint8_t)(len & 0xff);
    } else if (len < 0x1000000) {
        *buf++ = (uint8_t)'\x83';
        *buf++ = (uint8_t)(len >> 16);
        *buf++ = (uint8_t)(len >> 8) & 0xff;
        *buf++ = (uint8_t)(len & 0xff);
    } else {
        *buf++ = (uint8_t)'\x84';
        *buf++ = (uint8_t)(len >> 24);
        *buf++ = (uint8_t)(len >> 16) & 0xff;
        *buf++ = (uint8_t)(len >> 8) & 0xff;
        *buf++ = (uint8_t)(len & 0xff);
    }
    return buf;
}

uint8_t* asnPutBool(uint8_t* buf, uint8_t val)
{
    *buf++ = asn::boolean;
    *buf++ = 1;
    *buf++ = val;
    return buf;
}

uint8_t* asnPutBoolTrue(uint8_t* buf)
{
    return asnPutBool(buf, asn::true_);
}
