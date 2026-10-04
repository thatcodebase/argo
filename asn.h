#pragma once

#include "api.h"

namespace asn {
    enum {
        boolean = 0x01,
        integer = 0x02,
        version3 = 0x02,
        bitstring = 0x03,
        octetstring = 0x04,
        null = 0x05,
        oid = 0x06,
        utf8string = 0x0c,
        prtstring = 0x13,
        t61string = 0x14,
        ia5string = 0x16,
        utctime = 0x17,
        gentime = 0x18,
        constructedoctetstring = 0x24,
        sequence = 0x30,
        set = 0x31,
        construct0 = 0x80,
        twobytes = 0x82,
        part0 = 0xa0,
        part1 = 0xa1,
        part2 = 0xa2,
        part3 = 0xa3,
        true_ = 0xff,
        version1 = 0x00
    };
}

uint8_t* asnInto(uint8_t* s, size_t* len, size_t* indef);
uint8_t* asnOver(uint8_t* s, size_t* len, size_t* indef);
uint8_t* asnPutLength(uint8_t* buf, size_t len);
uint8_t* asnPutBool(uint8_t* buf, uint8_t val);
uint8_t* asnPutBoolTrue(uint8_t* buf);
