#include "api.h"

#include <chrono>

typedef struct _digestTest {
    const char* label;
    int count;
    uint8_t* vector;
    uint8_t* digest;
    int len;
    int iter;
} DIGESTTEST;

typedef struct _hmacTest {
    const char* label;
    int count;
    uint8_t* key;
    int keylen;
    uint8_t* data;
    int datalen;
    uint8_t* digest;
    int digestlen;
} HMACTEST;

typedef struct _cipherTest {
    const char* label;
    int count;
    uint8_t* key;
    uint8_t* iv;
    uint8_t* plain;
    uint8_t* cipher;
    int len;
} CIPHERTEST;

namespace testargo {
    const char* all = "all";
    const char* dump = "dump";
    const char* help = "help";
    const char* test = "test";
}

const char Bin2AscHex[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

const char Bin2AscPrt[] = {
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
};

const uint32_t ByteOnes[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, // 00-0F
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, // 10-1F
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, // 20-2F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // 30-3F
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, // 40-4F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // 50-5F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // 60-6F
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, // 70-7F
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, // 80-8F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // 90-9F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // A0-AF
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, // B0-BF
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // C0-CF
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, // D0-DF
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, // E0-EF
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8 // FF-FF
};

uint8_t ByteRuns[128][8] = {
    { 8, 0, 0, 0, 0, 0, 0, 0 }, //  00000000 11111111
    { 7, 1, 0, 0, 0, 0, 0, 0 }, //  00000001 11111110
    { 6, 1, 1, 0, 0, 0, 0, 0 }, //  00000010 11111101
    { 6, 2, 0, 0, 0, 0, 0, 0 }, //  00000011 11111100
    { 5, 1, 2, 0, 0, 0, 0, 0 }, //  00000100 11111011
    { 5, 1, 1, 1, 0, 0, 0, 0 }, //  00000101 11111010
    { 5, 2, 1, 0, 0, 0, 0, 0 }, //  00000110 11111001
    { 5, 3, 0, 0, 0, 0, 0, 0 }, //  00000111 11111000

    { 4, 1, 3, 0, 0, 0, 0, 0 }, //  00001000
    { 4, 1, 2, 1, 0, 0, 0, 0 }, //  00001001
    { 4, 1, 1, 1, 1, 0, 0, 0 }, //  00001010
    { 4, 1, 1, 2, 0, 0, 0, 0 }, //  00001011
    { 4, 2, 2, 0, 0, 0, 0, 0 }, //  00001100
    { 4, 2, 1, 1, 0, 0, 0, 0 }, //  00001101
    { 4, 3, 1, 0, 0, 0, 0, 0 }, //  00001110
    { 4, 4, 0, 0, 0, 0, 0, 0 }, //  00001111

    { 3, 1, 4, 0, 0, 0, 0, 0 }, //  00010000
    { 3, 1, 3, 1, 0, 0, 0, 0 }, //  00010001
    { 3, 1, 2, 1, 1, 0, 0, 0 }, //  00010010
    { 3, 1, 2, 2, 0, 0, 0, 0 }, //  00010011
    { 3, 1, 1, 1, 2, 0, 0, 0 }, //  00010100
    { 3, 1, 1, 1, 1, 1, 0, 0 }, //  00010101
    { 3, 1, 1, 2, 1, 0, 0, 0 }, //  00010110
    { 3, 1, 1, 3, 0, 0, 0, 0 }, //  00010111

    { 3, 2, 3, 0, 0, 0, 0, 0 }, //  00011000
    { 3, 2, 2, 1, 0, 0, 0, 0 }, //  00011001
    { 3, 2, 1, 1, 1, 0, 0, 0 }, //  00011010
    { 3, 2, 1, 2, 0, 0, 0, 0 }, //  00011011
    { 3, 3, 2, 0, 0, 0, 0, 0 }, //  00011100
    { 3, 3, 1, 1, 0, 0, 0, 0 }, //  00011101
    { 3, 4, 1, 0, 0, 0, 0, 0 }, //  00011110
    { 3, 5, 0, 0, 0, 0, 0, 0 }, //  00011111

    { 2, 1, 5, 0, 0, 0, 0, 0 }, //  00100000
    { 2, 1, 4, 1, 0, 0, 0, 0 }, //  00100001
    { 2, 1, 3, 1, 1, 0, 0, 0 }, //  00100010
    { 2, 1, 3, 2, 0, 0, 0, 0 }, //  00100011
    { 2, 1, 2, 1, 2, 0, 0, 0 }, //  00100100
    { 2, 1, 2, 1, 1, 1, 0, 0 }, //  00100101
    { 2, 1, 2, 2, 1, 0, 0, 0 }, //  00100110
    { 2, 1, 2, 3, 0, 0, 0, 0 }, //  00100111

    { 2, 1, 1, 1, 3, 0, 0, 0 }, //  00101000
    { 2, 1, 1, 1, 2, 1, 0, 0 }, //  00101001
    { 2, 1, 1, 1, 1, 1, 1, 0 }, //  00101010
    { 2, 1, 1, 1, 1, 2, 0, 0 }, //  00101011
    { 2, 1, 1, 2, 2, 0, 0, 0 }, //  00101100
    { 2, 1, 1, 2, 1, 1, 0, 0 }, //  00101101
    { 2, 1, 1, 3, 1, 0, 0, 0 }, //  00101110
    { 2, 1, 1, 4, 0, 0, 0, 0 }, //  00101111

    { 2, 2, 4, 0, 0, 0, 0, 0 }, //  00110000
    { 2, 2, 3, 1, 0, 0, 0, 0 }, //  00110001
    { 2, 2, 2, 1, 1, 0, 0, 0 }, //  00110010
    { 2, 2, 2, 2, 0, 0, 0, 0 }, //  00110011
    { 2, 2, 1, 1, 2, 0, 0, 0 }, //  00110100
    { 2, 2, 1, 1, 1, 1, 0, 0 }, //  00110101
    { 2, 2, 1, 2, 1, 0, 0, 0 }, //  00110110
    { 2, 2, 1, 3, 0, 0, 0, 0 }, //  00110111

    { 2, 3, 3, 0, 0, 0, 0, 0 }, //  00111000
    { 2, 3, 2, 1, 0, 0, 0, 0 }, //  00111001
    { 2, 3, 1, 1, 1, 0, 0, 0 }, //  00111010
    { 2, 3, 1, 2, 0, 0, 0, 0 }, //  00111011
    { 2, 4, 2, 0, 0, 0, 0, 0 }, //  00111100
    { 2, 4, 1, 1, 0, 0, 0, 0 }, //  00111101
    { 2, 5, 1, 0, 0, 0, 0, 0 }, //  00111110
    { 2, 6, 0, 0, 0, 0, 0, 0 }, //  00111111

    { 1, 1, 6, 0, 0, 0, 0, 0 }, //  01000000
    { 1, 1, 5, 1, 0, 0, 0, 0 }, //  01000001
    { 1, 1, 4, 1, 1, 0, 0, 0 }, //  01000010
    { 1, 1, 4, 2, 0, 0, 0, 0 }, //  01000011
    { 1, 1, 3, 1, 2, 0, 0, 0 }, //  01000100
    { 1, 1, 3, 1, 1, 1, 0, 0 }, //  01000101
    { 1, 1, 3, 2, 1, 0, 0, 0 }, //  01000110
    { 1, 1, 3, 3, 0, 0, 0, 0 }, //  01000111

    { 1, 1, 2, 1, 3, 0, 0, 0 }, //  01001000
    { 1, 1, 2, 1, 2, 1, 0, 0 }, //  01001001
    { 1, 1, 2, 1, 1, 1, 1, 0 }, //  01001010
    { 1, 1, 2, 1, 1, 2, 0, 0 }, //  01001011
    { 1, 1, 2, 2, 2, 0, 0, 0 }, //  01001100
    { 1, 1, 2, 2, 1, 1, 0, 0 }, //  01001101
    { 1, 1, 2, 3, 1, 0, 0, 0 }, //  01001110
    { 1, 1, 2, 4, 0, 0, 0, 0 }, //  01001111

    { 1, 1, 1, 1, 4, 0, 0, 0 }, //  01010000
    { 1, 1, 1, 1, 3, 1, 0, 0 }, //  01010001
    { 1, 1, 1, 1, 2, 1, 1, 0 }, //  01010010
    { 1, 1, 1, 1, 2, 2, 0, 0 }, //  01010011
    { 1, 1, 1, 1, 1, 1, 2, 0 }, //  01010100
    { 1, 1, 1, 1, 1, 1, 1, 1 }, //  01010101
    { 1, 1, 1, 1, 1, 2, 1, 0 }, //  01010110
    { 1, 1, 1, 1, 1, 3, 0, 0 }, //  01010111

    { 1, 1, 1, 2, 3, 0, 0, 0 }, //  01011000
    { 1, 1, 1, 2, 2, 1, 0, 0 }, //  01011001
    { 1, 1, 1, 2, 1, 1, 1, 0 }, //  01011010
    { 1, 1, 1, 2, 1, 2, 0, 0 }, //  01011011
    { 1, 1, 1, 3, 2, 0, 0, 0 }, //  01011100
    { 1, 1, 1, 3, 1, 1, 0, 0 }, //  01011101
    { 1, 1, 1, 4, 1, 0, 0, 0 }, //  01011110
    { 1, 1, 1, 5, 0, 0, 0, 0 }, //  01011111

    { 1, 2, 5, 0, 0, 0, 0, 0 }, //  01100000
    { 1, 2, 4, 1, 0, 0, 0, 0 }, //  01100001
    { 1, 2, 3, 1, 1, 0, 0, 0 }, //  01100010
    { 1, 2, 3, 2, 0, 0, 0, 0 }, //  01100011
    { 1, 2, 2, 1, 2, 0, 0, 0 }, //  01100100
    { 1, 2, 2, 1, 1, 1, 0, 0 }, //  01100101 10011010
    { 1, 2, 2, 2, 1, 0, 0, 0 }, //  01100110 10011001
    { 1, 2, 2, 3, 0, 0, 0, 0 }, //  01100111 10011000

    { 1, 2, 1, 1, 3, 0, 0, 0 }, //  01101000 10010111
    { 1, 2, 1, 1, 2, 1, 0, 0 }, //  01101001 10010110
    { 1, 2, 1, 1, 1, 1, 1, 0 }, //  01101010 10010101
    { 1, 2, 1, 1, 1, 2, 0, 0 }, //  01101011 10010100
    { 1, 2, 1, 2, 2, 0, 0, 0 }, //  01101100 10010011
    { 1, 2, 1, 2, 1, 1, 0, 0 }, //  01101101 10010010
    { 1, 2, 1, 3, 1, 0, 0, 0 }, //  01101110 10010001
    { 1, 2, 1, 4, 0, 0, 0, 0 }, //  01101111 10010000

    { 1, 3, 4, 0, 0, 0, 0, 0 }, //  01110000 10001111
    { 1, 3, 3, 1, 0, 0, 0, 0 }, //  01110001 10001110
    { 1, 3, 2, 1, 1, 0, 0, 0 }, //  01110010 10001101
    { 1, 3, 2, 2, 0, 0, 0, 0 }, //  01110011 10001100
    { 1, 3, 1, 1, 2, 0, 0, 0 }, //  01110100 10001011
    { 1, 3, 1, 1, 1, 1, 0, 0 }, //  01110101 10001010
    { 1, 3, 1, 2, 1, 0, 0, 0 }, //  01110110 10001001
    { 1, 3, 1, 3, 0, 0, 0, 0 }, //  01110111 10001000

    { 1, 4, 3, 0, 0, 0, 0, 0 }, //  01111000 10000111
    { 1, 4, 2, 1, 0, 0, 0, 0 }, //  01111001 10000110
    { 1, 4, 1, 1, 1, 0, 0, 0 }, //  01111010 10000101
    { 1, 4, 1, 2, 0, 0, 0, 0 }, //  01111011 10000100
    { 1, 5, 2, 0, 0, 0, 0, 0 }, //  01111100 10000011
    { 1, 5, 1, 1, 0, 0, 0, 0 }, //  01111101 10000010
    { 1, 6, 1, 0, 0, 0, 0, 0 }, //  01111110 10000001
    { 1, 7, 0, 0, 0, 0, 0, 0 } //  01111111 10000000
};

/*

//  MD5 test vectors 1-7: RFC 1321

uint8_t* const md5_vector_1 = (uint8_t*)"";
uint8_t* const md5_vector_2 = (uint8_t*)"a";
uint8_t* const md5_vector_3 = (uint8_t*)"abc";
uint8_t* const md5_vector_4 = (uint8_t*)"message digest";
uint8_t* const md5_vector_5 = (uint8_t*)"abcdefghijklmnopqrstuvwxyz";
uint8_t* const md5_vector_6 = (uint8_t*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
uint8_t* const md5_vector_7 = (uint8_t*)"12345678901234567890123456789012345678901234567890123456789012345678901234567890";

uint8_t* const md5_digest_1 = (uint8_t*)"\xD4\x1D\x8C\xD9\x8F\x00\xB2\x04\xE9\x80\x09\x98\xEC\xF8\x42\x7E";
uint8_t* const md5_digest_2 = (uint8_t*)"\x0C\xC1\x75\xB9\xC0\xF1\xB6\xA8\x31\xC3\x99\xE2\x69\x77\x26\x61";
uint8_t* const md5_digest_3 = (uint8_t*)"\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72";
uint8_t* const md5_digest_4 = (uint8_t*)"\xF9\x6B\x69\x7D\x7C\xB7\x93\x8D\x52\x5A\x2F\x31\xAA\xF1\x61\xD0";
uint8_t* const md5_digest_5 = (uint8_t*)"\xC3\xFC\xD3\xD7\x61\x92\xE4\x00\x7D\xFB\x49\x6C\xCA\x67\xE1\x3B";
uint8_t* const md5_digest_6 = (uint8_t*)"\xD1\x74\xAB\x98\xD2\x77\xD9\xF5\xA5\x61\x1C\x2C\x9F\x41\x9D\x9F";
uint8_t* const md5_digest_7 = (uint8_t*)"\x57\xED\xF4\xA2\x2B\xE3\xC9\x55\xAC\x49\xDA\x2E\x21\x07\xB6\x7A";

DIGESTTEST md5_tests[] = {
    { "MD5", 7, md5_vector_1, md5_digest_1, 0, 1 },
    { "MD5", 7, md5_vector_2, md5_digest_2, 1, 1 },
    { "MD5", 7, md5_vector_3, md5_digest_3, 3, 1 },
    { "MD5", 7, md5_vector_4, md5_digest_4, 14, 1 },
    { "MD5", 7, md5_vector_5, md5_digest_5, 26, 1 },
    { "MD5", 7, md5_vector_6, md5_digest_6, 62, 1 },
    { "MD5", 7, md5_vector_7, md5_digest_7, 80, 1 }
};

// SHA1 test vectors 1-3: FIPS pub 180-2 appendix A examples 1-3
// SHA1 test vectors 4-6: NIST pub SHAVS appendix A.1 examples 2, 4 and appendix A.2 example 2

uint8_t* const sha1_vector_1 = (uint8_t*)"abc";
uint8_t* const sha1_vector_2 = (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint8_t* const sha1_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha1_vector_4 = (uint8_t*)"\x5e";
uint8_t* const sha1_vector_5 = (uint8_t*)"\x9a\x7d\xfd\xf1\xec\xea\xd0\x6e\xd6\x46\xaa\x55\xfe\x75\x71\x46";
uint8_t* const sha1_vector_6 = (uint8_t*)"\xf7\x8f\x92\x14\x1b\xcd\x17\x0a\xe8\x9b\x4f\xba\x15\xa1\xd5\x9f\x3f\xd8\x4d\x22\x3c\x92\x51\xbd\xac\xbb\xae\x61\xd0\x5e\xd1\x15"
"\xa0\x6a\x7c\xe1\x17\xb7\xbe\xea\xd2\x44\x21\xde\xd9\xc3\x25\x92\xbd\x57\xed\xea\xe3\x9c\x39\xfa\x1f\xe8\x94\x6a\x84\xd0\xcf\x1f"
"\x7b\xee\xad\x17\x13\xe2\xe0\x95\x98\x97\x34\x7f\x67\xc8\x0b\x04\x00\xc2\x09\x81\x5d\x6b\x10\xa6\x83\x83\x6f\xd5\x56\x2a\x56\xca"
"\xb1\xa2\x8e\x81\xb6\x57\x66\x54\x63\x1c\xf1\x65\x66\xb8\x6e\x3b\x33\xa1\x08\xb0\x53\x07\xc0\x0a\xff\x14\xa7\x68\xed\x73\x50\x60"
"\x6a\x0f\x85\xe6\xa9\x1d\x39\x6f\x5b\x5c\xbe\x57\x7f\x9b\x38\x80\x7c\x7d\x52\x3d\x6d\x79\x2f\x6e\xbc\x24\xa4\xec\xf2\xb3\xa4\x27"
"\xcd\xbb\xfb";

uint8_t* const sha1_digest_1 = (uint8_t*)"\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D";
uint8_t* const sha1_digest_2 = (uint8_t*)"\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1";
uint8_t* const sha1_digest_3 = (uint8_t*)"\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F";
uint8_t* const sha1_digest_4 = (uint8_t*)"\x5e\x6f\x80\xa3\x4a\x97\x98\xca\xfc\x6a\x5d\xb9\x6c\xc5\x7b\xa4\xc4\xdb\x59\xc2";
uint8_t* const sha1_digest_5 = (uint8_t*)"\x82\xab\xff\x66\x05\xdb\xe1\xc1\x7d\xef\x12\xa3\x94\xfa\x22\xa8\x2b\x54\x4a\x35";
uint8_t* const sha1_digest_6 = (uint8_t*)"\xcb\x00\x82\xc8\xf1\x97\xd2\x60\x99\x1b\xa6\xa4\x60\xe7\x6e\x20\x2b\xad\x27\xb3";

DIGESTTEST sha1_tests[] = {
    { "SHA1", 6, sha1_vector_1, sha1_digest_1, 3, 1 },
    { "SHA1", 6, sha1_vector_2, sha1_digest_2, 56, 1 },
    { "SHA1", 6, sha1_vector_3, sha1_digest_3, 100, 10000 },
    { "SHA1", 6, sha1_vector_4, sha1_digest_4, 1, 1 },
    { "SHA1", 6, sha1_vector_5, sha1_digest_5, 16, 1 },
    { "SHA1", 6, sha1_vector_6, sha1_digest_6, 163, 1 }
};

// SHA256 test vectors 1-3: FIPS pub 180-2 appendix B examples 1-3
// SHA256 test vectors 4-6: NIST pub SHAVS appendix C.1 examples 2, 4 and appendix C.2 example 2

uint8_t* const sha256_vector_1 = (uint8_t*)"abc";
uint8_t* const sha256_vector_2 = (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint8_t* const sha256_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha256_vector_4 = (uint8_t*)"\x19";
uint8_t* const sha256_vector_5 = (uint8_t*)"\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52";
uint8_t* const sha256_vector_6 = (uint8_t*)"\x83\x26\x75\x4e\x22\x77\x37\x2f\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0\x4d\x8a\x05\x69\x71\xb1\x1a\xd5\x71\x23\xa7\xc1\x37\x76\x00\x00"
"\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08\x3a\xa3\x9d\x81\x0d\xb3\x10\x77\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a\x26\xc7\x73\x32\x5f\x8b\x23\x74"
"\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f\x9d\x65\x92\xec\xed\xaa\x66\xca"
"\x82\xa2\x9d\x0c\x51\xbc\xf9\x33\x62\x30\xe5\xd7\x84\xe4\xc0\xa4\x3f\x8d\x79\xa3\x0a\x16\x5c\xba\xbe\x45\x2b\x77\x4b\x9c\x71\x09"
"\xa9\x7d\x13\x8f\x12\x92\x28\x96\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a\x9f\xdd\x30\x82\x57\x69\xb2\xc6\x71\xaf\x67\x59\xdf\x28\xeb\x39"
"\x3d\x54\xd6";

uint8_t* const sha256_digest_1 = (uint8_t*)"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad";
uint8_t* const sha256_digest_2 = (uint8_t*)"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1";
uint8_t* const sha256_digest_3 = (uint8_t*)"\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0";
uint8_t* const sha256_digest_4 = (uint8_t*)"\x68\xaa\x2e\x2e\xe5\xdf\xf9\x6e\x33\x55\xe6\xc7\xee\x37\x3e\x3d\x6a\x4e\x17\xf7\x5f\x95\x18\xd8\x43\x70\x9c\x0c\x9b\xc3\xe3\xd4";
uint8_t* const sha256_digest_5 = (uint8_t*)"\x17\x5e\xe6\x9b\x02\xba\x9b\x58\xe2\xb0\xa5\xfd\x13\x81\x9c\xea\x57\x3f\x39\x40\xa9\x4f\x82\x51\x28\xcf\x42\x09\xbe\xab\xb4\xe8";
uint8_t* const sha256_digest_6 = (uint8_t*)"\x97\xdb\xca\x7d\xf4\x6d\x62\xc8\xa4\x22\xc9\x41\xdd\x7e\x83\x5b\x8a\xd3\x36\x17\x63\xf7\xe9\xb2\xd9\x5f\x4f\x0d\xa6\xe1\xcc\xbc";

DIGESTTEST sha256_tests[] = {
    { "SHA256", 6, sha256_vector_1, sha256_digest_1, 3, 1 },
    { "SHA256", 6, sha256_vector_2, sha256_digest_2, 56, 1 },
    { "SHA256", 6, sha256_vector_3, sha256_digest_3, 100, 10000 },
    { "SHA256", 6, sha256_vector_4, sha256_digest_4, 1, 1 },
    { "SHA256", 6, sha256_vector_5, sha256_digest_5, 16, 1 },
    { "SHA256", 6, sha256_vector_6, sha256_digest_6, 163, 1 }
};

// SHA224 test vectors 1-3: FIPS pub 180-2 change notice 1 examples 1-3
// SHA224 test vectors 4-6: NIST pub SHAVS appendix B.1 examples 2, 4 and appendix B.2 example 2

uint8_t* const sha224_vector_1 = (uint8_t*)"abc";
uint8_t* const sha224_vector_2 = (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint8_t* const sha224_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha224_vector_4 = (uint8_t*)"\x07";
uint8_t* const sha224_vector_5 = (uint8_t*)"\x18\x80\x40\x05\xdd\x4f\xbd\x15\x56\x29\x9d\x6f\x9d\x93\xdf\x62";
uint8_t* const sha224_vector_6 = (uint8_t*)"\x55\xb2\x10\x07\x9c\x61\xb5\x3a\xdd\x52\x06\x22\xd1\xac\x97\xd5\xcd\xbe\x8c\xb3\x3a\xa0\xae\x34\x45\x17\xbe\xe4\xd7\xba\x09\xab"
"\xc8\x53\x3c\x52\x50\x88\x7a\x43\xbe\xbb\xac\x90\x6c\x2e\x18\x37\xf2\x6b\x36\xa5\x9a\xe3\xbe\x78\x14\xd5\x06\x89\x6b\x71\x8b\x2a"
"\x38\x3e\xcd\xac\x16\xb9\x61\x25\x55\x3f\x41\x6f\xf3\x2c\x66\x74\xc7\x45\x99\xa9\x00\x53\x86\xd9\xce\x11\x12\x24\x5f\x48\xee\x47"
"\x0d\x39\x6c\x1e\xd6\x3b\x92\x67\x0c\xa5\x6e\xc8\x4d\xee\xa8\x14\xb6\x13\x5e\xca\x54\x39\x2b\xde\xdb\x94\x89\xbc\x9b\x87\x5a\x8b"
"\xaf\x0d\xc1\xae\x78\x57\x36\x91\x4a\xb7\xda\xa2\x64\xbc\x07\x9d\x26\x9f\x2c\x0d\x7e\xdd\xd8\x10\xa4\x26\x14\x5a\x07\x76\xf6\x7c"
"\x87\x82\x73";

uint8_t* const sha224_digest_1 = (uint8_t*)"\x23\x09\x7d\x22\x34\x05\xd8\x22\x86\x42\xa4\x77\xbd\xa2\x55\xb3\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7\xe3\x6c\x9d\xa7";
uint8_t* const sha224_digest_2 = (uint8_t*)"\x75\x38\x8b\x16\x51\x27\x76\xcc\x5d\xba\x5d\xa1\xfd\x89\x01\x50\xb0\xc6\x45\x5c\xb4\xf5\x8b\x19\x52\x52\x25\x25";
uint8_t* const sha224_digest_3 = (uint8_t*)"\x20\x79\x46\x55\x98\x0c\x91\xd8\xbb\xb4\xc1\xea\x97\x61\x8a\x4b\xf0\x3f\x42\x58\x19\x48\xb2\xee\x4e\xe7\xad\x67";
uint8_t* const sha224_digest_4 = (uint8_t*)"\x00\xec\xd5\xf1\x38\x42\x2b\x8a\xd7\x4c\x97\x99\xfd\x82\x6c\x53\x1b\xad\x2f\xca\xbc\x74\x50\xbe\xe2\xaa\x8c\x2a";
uint8_t* const sha224_digest_5 = (uint8_t*)"\xdf\x90\xd7\x8a\xa7\x88\x21\xc9\x9b\x40\xba\x4c\x96\x69\x21\xac\xcd\x8f\xfb\x1e\x98\xac\x38\x8e\x56\x19\x1d\xb1";
uint8_t* const sha224_digest_6 = (uint8_t*)"\x0b\x31\x89\x4e\xc8\x93\x7a\xd9\xb9\x1b\xdf\xbc\xba\x29\x4d\x9a\xde\xfa\xa1\x8e\x09\x30\x5e\x9f\x20\xd5\xc3\xa4";

DIGESTTEST sha224_tests[] = {
    { "SHA224", 6, sha224_vector_1, sha224_digest_1, 3, 1 },
    { "SHA224", 6, sha224_vector_2, sha224_digest_2, 56, 1 },
    { "SHA224", 6, sha224_vector_3, sha224_digest_3, 100, 10000 },
    { "SHA224", 6, sha224_vector_4, sha224_digest_4, 1, 1 },
    { "SHA224", 6, sha224_vector_5, sha224_digest_5, 16, 1 },
    { "SHA224", 6, sha224_vector_6, sha224_digest_6, 163, 1 }
};

// SHA512 test vectors 1-3: FIPS pub 180-2 appendix C examples 1-3
// SHA512 test vectors 4-6: NIST pub SHAVS appendix E.1 examples 2, 4 and appendix E.2 example 2

uint8_t* const sha512_vector_1 = (uint8_t*)"abc";
uint8_t* const sha512_vector_2 = (uint8_t*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
uint8_t* const sha512_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha512_vector_4 = (uint8_t*)"\xd0";
uint8_t* const sha512_vector_5 = (uint8_t*)"\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91\x81\x6e\x9d\x98\xbf\xf0\xa0";
uint8_t* const sha512_vector_6 = (uint8_t*)"\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80\x7a\x50\x2d\x65\x82\x4e\x31\xa2\x30\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8\xd8\x4e\x0d\xe1\xde"
"\x69\x74\xbf\x49\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5\x8c\x26\xc4\x93\x60\xc3\xe8\x7a\xf5\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f\xf2"
"\xf8\x68\x00\x2b\xc3\xe4\x31\xed\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3\xb2\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69\x4f\xcb\xba\xf8\x8d\x95"
"\x19\xe4\xeb\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea\x95\xbc\x44\x65\xc8\x82\x1a\xac\xd2\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d\xc3\x2f"
"\x96\x90\x87\xa1\x45\xb0\xd9\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac\xe6\x34\x06\x4e\x6d\x99\x28"
"\x35\x13\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e\x9a\x0d\xc6\xd3\xb1\xf8\xb2\x46\xf1\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb\x20\x98\xe8"
"\xbf\x16\xf2\x68\xd6\x4f\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79\x1b\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51\x86\x3a\x96\xc9\x49\xad\x47\xd7"
"\xfb\x40\xd2";

uint8_t* const sha512_digest_1 = (uint8_t*)"\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a"
"\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f";
uint8_t* const sha512_digest_2 = (uint8_t*)"\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18"
"\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09";
uint8_t* const sha512_digest_3 = (uint8_t*)"\xe7\x18\x48\x3d\x0c\xe7\x69\x64\x4e\x2e\x42\xc7\xbc\x15\xb4\x63\x8e\x1f\x98\xb1\x3b\x20\x44\x28\x56\x32\xa8\x03\xaf\xa9\x73\xeb"
"\xde\x0f\xf2\x44\x87\x7e\xa6\x0a\x4c\xb0\x43\x2c\xe5\x77\xc3\x1b\xeb\x00\x9c\x5c\x2c\x49\xaa\x2e\x4e\xad\xb2\x17\xad\x8c\xc0\x9b";
uint8_t* const sha512_digest_4 = (uint8_t*)"\x99\x92\x20\x29\x38\xe8\x82\xe7\x3e\x20\xf6\xb6\x9e\x68\xa0\xa7\x14\x90\x90\x42\x3d\x93\xc8\x1b\xab\x3f\x21\x67\x8d\x4a\xce\xee"
"\xe5\x0e\x4e\x8c\xaf\xad\xa4\xc8\x5a\x54\xea\x83\x06\x82\x6c\x4a\xd6\xe7\x4c\xec\xe9\x63\x1b\xfa\x8a\x54\x9b\x4a\xb3\xfb\xba\x15";
uint8_t* const sha512_digest_5 = (uint8_t*)"\xcb\x0b\x67\xa4\xb8\x71\x2c\xd7\x3c\x9a\xab\xc0\xb1\x99\xe9\x26\x9b\x20\x84\x4a\xfb\x75\xac\xbd\xd1\xc1\x53\xc9\x82\x89\x24\xc3"
"\xdd\xed\xaa\xfe\x66\x9c\x5f\xdd\x0b\xc6\x6f\x63\x0f\x67\x73\x98\x82\x13\xeb\x1b\x16\xf5\x17\xad\x0d\xe4\xb2\xf0\xc9\x5c\x90\xf8";
uint8_t* const sha512_digest_6 = (uint8_t*)"\xc6\x65\xbe\xfb\x36\xda\x18\x9d\x78\x82\x2d\x10\x52\x8c\xbf\x3b\x12\xb3\xee\xf7\x26\x03\x99\x09\xc1\xa1\x6a\x27\x0d\x48\x71\x93"
"\x77\x96\x6b\x95\x7a\x87\x8e\x72\x05\x84\x77\x9a\x62\x82\x5c\x18\xda\x26\x41\x5e\x49\xa7\x17\x6a\x89\x4e\x75\x10\xfd\x14\x51\xf5";

DIGESTTEST sha512_tests[] = {
    { "SHA512", 6, sha512_vector_1, sha512_digest_1, 3, 1 },
    { "SHA512", 6, sha512_vector_2, sha512_digest_2, 112, 1 },
    { "SHA512", 6, sha512_vector_3, sha512_digest_3, 100, 10000 },
    { "SHA512", 6, sha512_vector_4, sha512_digest_4, 1, 1 },
    { "SHA512", 6, sha512_vector_5, sha512_digest_5, 16, 1 },
    { "SHA512", 6, sha512_vector_6, sha512_digest_6, 227, 1 }
};

// SHA384 test vectors 1-3: FIPS pub 180-2 appendix D examples 1-3
// SHA384 test vectors 4-6: NIST pub SHAVS appendix D.1 examples 2, 4 and appendix D.2 example 2

uint8_t* const sha384_vector_1 = (uint8_t*)"abc";
uint8_t* const sha384_vector_2 = (uint8_t*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
uint8_t* const sha384_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha384_vector_4 = (uint8_t*)"\xb9";
uint8_t* const sha384_vector_5 = (uint8_t*)"\xa4\x1c\x49\x77\x79\xc0\x37\x5f\xf1\x0a\x7f\x4e\x08\x59\x17\x39";
uint8_t* const sha384_vector_6 = (uint8_t*)"\x39\x96\x69\xe2\x8f\x6b\x9c\x6d\xbc\xbb\x69\x12\xec\x10\xff\xcf\x74\x79\x03\x49\xb7\xdc\x8f\xbe\x4a\x8e\x7b\x3b\x56\x21\xdb\x0f"
"\x3e\x7d\xc8\x7f\x82\x32\x64\xbb\xe4\x0d\x18\x11\xc9\xea\x20\x61\xe1\xc8\x4a\xd1\x0a\x23\xfa\xc1\x72\x7e\x72\x02\xfc\x3f\x50\x42"
"\xe6\xbf\x58\xcb\xa8\xa2\x74\x6e\x1f\x64\xf9\xb9\xea\x35\x2c\x71\x15\x07\x05\x3c\xf4\xe5\x33\x9d\x52\x86\x5f\x25\xcc\x22\xb5\xe8"
"\x77\x84\xa1\x2f\xc9\x61\xd6\x6c\xb6\xe8\x95\x73\x19\x9a\x2c\xe6\x56\x5c\xbd\xf1\x3d\xca\x40\x38\x32\xcf\xcb\x0e\x8b\x72\x11\xe8"
"\x3a\xf3\x2a\x11\xac\x17\x92\x9f\xf1\xc0\x73\xa5\x1c\xc0\x27\xaa\xed\xef\xf8\x5a\xad\x7c\x2b\x7c\x5a\x80\x3e\x24\x04\xd9\x6d\x2a"
"\x77\x35\x7b\xda\x1a\x6d\xae\xed\x17\x15\x1c\xb9\xbc\x51\x25\xa4\x22\xe9\x41\xde\x0c\xa0\xfc\x50\x11\xc2\x3e\xcf\xfe\xfd\xd0\x96"
"\x76\x71\x1c\xf3\xdb\x0a\x34\x40\x72\x0e\x16\x15\xc1\xf2\x2f\xbc\x3c\x72\x1d\xe5\x21\xe1\xb9\x9b\xa1\xbd\x55\x77\x40\x86\x42\x14"
"\x7e\xd0\x96";

uint8_t* const sha384_digest_1 = (uint8_t*)"\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
"\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7";
uint8_t* const sha384_digest_2 = (uint8_t*)"\x09\x33\x0c\x33\xf7\x11\x47\xe8\x3d\x19\x2f\xc7\x82\xcd\x1b\x47\x53\x11\x1b\x17\x3b\x3b\x05\xd2\x2f\xa0\x80\x86\xe3\xb0\xf7\x12"
"\xfc\xc7\xc7\x1a\x55\x7e\x2d\xb9\x66\xc3\xe9\xfa\x91\x74\x60\x39";
uint8_t* const sha384_digest_3 = (uint8_t*)"\x9d\x0e\x18\x09\x71\x64\x74\xcb\x08\x6e\x83\x4e\x31\x0a\x4a\x1c\xed\x14\x9e\x9c\x00\xf2\x48\x52\x79\x72\xce\xc5\x70\x4c\x2a\x5b"
"\x07\xb8\xb3\xdc\x38\xec\xc4\xeb\xae\x97\xdd\xd8\x7f\x3d\x89\x85";
uint8_t* const sha384_digest_4 = (uint8_t*)"\xbc\x80\x89\xa1\x90\x07\xc0\xb1\x41\x95\xf4\xec\xc7\x40\x94\xfe\xc6\x4f\x01\xf9\x09\x29\x28\x2c\x2f\xb3\x92\x88\x15\x78\x20\x8a"
"\xd4\x66\x82\x8b\x1c\x6c\x28\x3d\x27\x22\xcf\x0a\xd1\xab\x69\x38";
uint8_t* const sha384_digest_5 = (uint8_t*)"\xc9\xa6\x84\x43\xa0\x05\x81\x22\x56\xb8\xec\x76\xb0\x05\x16\xf0\xdb\xb7\x4f\xab\x26\xd6\x65\x91\x3f\x19\x4b\x6f\xfb\x0e\x91\xea"
"\x99\x67\x56\x6b\x58\x10\x9c\xbc\x67\x5c\xc2\x08\xe4\xc8\x23\xf7";
uint8_t* const sha384_digest_6 = (uint8_t*)"\x4f\x44\x0d\xb1\xe6\xed\xd2\x89\x9f\xa3\x35\xf0\x95\x15\xaa\x02\x5e\xe1\x77\xa7\x9f\x4b\x4a\xaf\x38\xe4\x2b\x5c\x4d\xe6\x60\xf5"
"\xde\x8f\xb2\xa5\xb2\xfb\xd2\xa3\xcb\xff\xd2\x0c\xff\x12\x88\xc0";

DIGESTTEST sha384_tests[] = {
    { "SHA384", 6, sha384_vector_1, sha384_digest_1, 3, 1 },
    { "SHA384", 6, sha384_vector_2, sha384_digest_2, 112, 1 },
    { "SHA384", 6, sha384_vector_3, sha384_digest_3, 100, 10000 },
    { "SHA384", 6, sha384_vector_4, sha384_digest_4, 1, 1 },
    { "SHA384", 6, sha384_vector_5, sha384_digest_5, 16, 1 },
    { "SHA384", 6, sha384_vector_6, sha384_digest_6, 227, 1 }
};

// HMAC-MD5 test vectors: RFC 2202

uint8_t* const hmac_md5_key_1 = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
uint8_t* const hmac_md5_key_2 = (uint8_t*)"Jefe";
uint8_t* const hmac_md5_key_3 = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
uint8_t* const hmac_md5_key_4 = (uint8_t*)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19";
uint8_t* const hmac_md5_key_5 = (uint8_t*)"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
uint8_t* const hmac_md5_key_6 = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
uint8_t* const hmac_md5_key_7 = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";

uint8_t* const hmac_md5_data_1 = (uint8_t*)"Hi There";
uint8_t* const hmac_md5_data_2 = (uint8_t*)"what do ya want for nothing?";
uint8_t* const hmac_md5_data_3 = (uint8_t*)"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd";
uint8_t* const hmac_md5_data_4 = (uint8_t*)"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd";
uint8_t* const hmac_md5_data_5 = (uint8_t*)"Test With Truncation";
uint8_t* const hmac_md5_data_6 = (uint8_t*)"Test Using Larger Than Block-Size Key - Hash Key First";
uint8_t* const hmac_md5_data_7 = (uint8_t*)"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";

uint8_t* const hmac_md5_digest_1 = (uint8_t*)"\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d";
uint8_t* const hmac_md5_digest_2 = (uint8_t*)"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38";
uint8_t* const hmac_md5_digest_3 = (uint8_t*)"\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6";
uint8_t* const hmac_md5_digest_4 = (uint8_t*)"\x69\x7e\xaf\x0a\xca\x3a\x3a\xea\x3a\x75\x16\x47\x46\xff\xaa\x79";
uint8_t* const hmac_md5_digest_5 = (uint8_t*)"\x56\x46\x1e\xf2\x34\x2e\xdc\x00\xf9\xba\xb9\x95\x69\x0e\xfd\x4c";
uint8_t* const hmac_md5_digest_6 = (uint8_t*)"\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f\x0b\x62\xe6\xce\x61\xb9\xd0\xcd";
uint8_t* const hmac_md5_digest_7 = (uint8_t*)"\x6f\x63\x0f\xad\x67\xcd\xa0\xee\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e";

HMACTEST hmac_md5_tests[] = {
    { "HMAC-MD5", 7, hmac_md5_key_1, 16, hmac_md5_data_1,  8, hmac_md5_digest_1, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_2,  4, hmac_md5_data_2, 28, hmac_md5_digest_2, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_3, 16, hmac_md5_data_3, 50, hmac_md5_digest_3, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_4, 25, hmac_md5_data_4, 50, hmac_md5_digest_4, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_5, 16, hmac_md5_data_5, 20, hmac_md5_digest_5, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_6, 80, hmac_md5_data_6, 54, hmac_md5_digest_6, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_7, 80, hmac_md5_data_7, 73, hmac_md5_digest_7, 16 }
};

// HMAC-SHA1 test vectors: RFC 2202

uint8_t* const hmac_sha_key_1 = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
uint8_t* const hmac_sha_key_2 = (uint8_t*)"Jefe";
uint8_t* const hmac_sha_key_3 = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
uint8_t* const hmac_sha_key_4 = (uint8_t*)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19";
uint8_t* const hmac_sha_key_5 = (uint8_t*)"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
uint8_t* const hmac_sha_key_n = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";

uint8_t* const hmac_sha_data_1 = (uint8_t*)"Hi There";
uint8_t* const hmac_sha_data_2 = (uint8_t*)"what do ya want for nothing?";
uint8_t* const hmac_sha_data_3 = (uint8_t*)"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd";
uint8_t* const hmac_sha_data_4 = (uint8_t*)"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd";
uint8_t* const hmac_sha_data_5 = (uint8_t*)"Test With Truncation";
uint8_t* const hmac_sha_data_6 = (uint8_t*)"Test Using Larger Than Block-Size Key - Hash Key First";
uint8_t* const hmac_sha_data_7 = (uint8_t*)"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";

uint8_t* const hmac_sha1_digest_1 = (uint8_t*)"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00";
uint8_t* const hmac_sha1_digest_2 = (uint8_t*)"\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79";
uint8_t* const hmac_sha1_digest_3 = (uint8_t*)"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3";
uint8_t* const hmac_sha1_digest_4 = (uint8_t*)"\x4c\x90\x07\xf4\x02\x62\x50\xc6\xbc\x84\x14\xf9\xbf\x50\xc8\x6c\x2d\x72\x35\xda";
uint8_t* const hmac_sha1_digest_5 = (uint8_t*)"\x4c\x1a\x03\x42\x4b\x55\xe0\x7f\xe7\xf2\x7b\xe1\xd5\x8b\xb9\x32\x4a\x9a\x5a\x04";
uint8_t* const hmac_sha1_digest_6 = (uint8_t*)"\xaa\x4a\xe5\xe1\x52\x72\xd0\x0e\x95\x70\x56\x37\xce\x8a\x3b\x55\xed\x40\x21\x12";
uint8_t* const hmac_sha1_digest_7 = (uint8_t*)"\xe8\xe9\x9d\x0f\x45\x23\x7d\x78\x6d\x6b\xba\xa7\x96\x5c\x78\x08\xbb\xff\x1a\x91";

HMACTEST hmac_sha1_tests[] = {
    { "HMAC-SHA1", 7, hmac_sha_key_1, 20, hmac_sha_data_1,  8, hmac_sha1_digest_1, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_2,  4, hmac_sha_data_2, 28, hmac_sha1_digest_2, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_3, 20, hmac_sha_data_3, 50, hmac_sha1_digest_3, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_4, 25, hmac_sha_data_4, 50, hmac_sha1_digest_4, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_5, 20, hmac_sha_data_5, 20, hmac_sha1_digest_5, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_n, 80, hmac_sha_data_6, 54, hmac_sha1_digest_6, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_n, 80, hmac_sha_data_7, 73, hmac_sha1_digest_7, 20 }
};

// HMAC-SHA256, 224, 512, 384 test vectors: RFC 4231

uint8_t* const hmac_sha2_key_n = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa";

uint8_t* const hmac_sha2_data_7 = (uint8_t*)"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

uint8_t* const hmac_sha256_digest_1 = (uint8_t*)"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7";
uint8_t* const hmac_sha256_digest_2 = (uint8_t*)"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43";
uint8_t* const hmac_sha256_digest_3 = (uint8_t*)"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe";
uint8_t* const hmac_sha256_digest_4 = (uint8_t*)"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b";
uint8_t* const hmac_sha256_digest_5 = (uint8_t*)"\xa3\xb6\x16\x74\x73\x10\x0e\xe0\x6e\x0c\x79\x6c\x29\x55\x55\x2b";
uint8_t* const hmac_sha256_digest_6 = (uint8_t*)"\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54";
uint8_t* const hmac_sha256_digest_7 = (uint8_t*)"\x9b\x09\xff\xa7\x1b\x94\x2f\xcb\x27\x63\x5f\xbc\xd5\xb0\xe9\x44\xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2";

HMACTEST hmac_sha256_tests[] = {
    { "HMAC-256", 7, hmac_sha_key_1,   20, hmac_sha_data_1,    8, hmac_sha256_digest_1, 32 },
    { "HMAC-256", 7, hmac_sha_key_2,    4, hmac_sha_data_2,   28, hmac_sha256_digest_2, 32  },
    { "HMAC-256", 7, hmac_sha_key_3,   20, hmac_sha_data_3,   50, hmac_sha256_digest_3, 32  },
    { "HMAC-256", 7, hmac_sha_key_4,   25, hmac_sha_data_4,   50, hmac_sha256_digest_4, 32  },
    { "HMAC-256", 7, hmac_sha_key_5,   20, hmac_sha_data_5,   20, hmac_sha256_digest_5, 16  },
    { "HMAC-256", 7, hmac_sha2_key_n, 131, hmac_sha_data_6,   54, hmac_sha256_digest_6, 32  },
    { "HMAC-256", 7, hmac_sha2_key_n, 131, hmac_sha2_data_7, 152, hmac_sha256_digest_7, 32  }
};

uint8_t* const hmac_sha224_digest_1 = (uint8_t*)"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22";
uint8_t* const hmac_sha224_digest_2 = (uint8_t*)"\xa3\x0e\x01\x09\x8b\xc6\xdb\xbf\x45\x69\x0f\x3a\x7e\x9e\x6d\x0f\x8b\xbe\xa2\xa3\x9e\x61\x48\x00\x8f\xd0\x5e\x44";
uint8_t* const hmac_sha224_digest_3 = (uint8_t*)"\x7f\xb3\xcb\x35\x88\xc6\xc1\xf6\xff\xa9\x69\x4d\x7d\x6a\xd2\x64\x93\x65\xb0\xc1\xf6\x5d\x69\xd1\xec\x83\x33\xea";
uint8_t* const hmac_sha224_digest_4 = (uint8_t*)"\x6c\x11\x50\x68\x74\x01\x3c\xac\x6a\x2a\xbc\x1b\xb3\x82\x62\x7c\xec\x6a\x90\xd8\x6e\xfc\x01\x2d\xe7\xaf\xec\x5a";
uint8_t* const hmac_sha224_digest_5 = (uint8_t*)"\x0e\x2a\xea\x68\xa9\x0c\x8d\x37\xc9\x88\xbc\xdb\x9f\xca\x6f\xa8";
uint8_t* const hmac_sha224_digest_6 = (uint8_t*)"\x95\xe9\xa0\xdb\x96\x20\x95\xad\xae\xbe\x9b\x2d\x6f\x0d\xbc\xe2\xd4\x99\xf1\x12\xf2\xd2\xb7\x27\x3f\xa6\x87\x0e";
uint8_t* const hmac_sha224_digest_7 = (uint8_t*)"\x3a\x85\x41\x66\xac\x5d\x9f\x02\x3f\x54\xd5\x17\xd0\xb3\x9d\xbd\x94\x67\x70\xdb\x9c\x2b\x95\xc9\xf6\xf5\x65\xd1";

HMACTEST hmac_sha224_tests[] = {
    { "HMAC-224", 7, hmac_sha_key_1,   20, hmac_sha_data_1,    8, hmac_sha224_digest_1, 28 },
    { "HMAC-224", 7, hmac_sha_key_2,    4, hmac_sha_data_2,   28, hmac_sha224_digest_2, 28 },
    { "HMAC-224", 7, hmac_sha_key_3,   20, hmac_sha_data_3,   50, hmac_sha224_digest_3, 28 },
    { "HMAC-224", 7, hmac_sha_key_4,   25, hmac_sha_data_4,   50, hmac_sha224_digest_4, 28 },
    { "HMAC-224", 7, hmac_sha_key_5,   20, hmac_sha_data_5,   20, hmac_sha224_digest_5, 16 },
    { "HMAC-224", 7, hmac_sha2_key_n, 131, hmac_sha_data_6,   54, hmac_sha224_digest_6, 28 },
    { "HMAC-224", 7, hmac_sha2_key_n, 131, hmac_sha2_data_7, 152, hmac_sha224_digest_7, 28 }
};

uint8_t* const hmac_sha512_digest_1 = (uint8_t*)"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54";
uint8_t* const hmac_sha512_digest_2 = (uint8_t*)"\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37";
uint8_t* const hmac_sha512_digest_3 = (uint8_t*)"\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb";
uint8_t* const hmac_sha512_digest_4 = (uint8_t*)"\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7\xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb\xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63\xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd";
uint8_t* const hmac_sha512_digest_5 = (uint8_t*)"\x41\x5f\xad\x62\x71\x58\x0a\x53\x1d\x41\x79\xbc\x89\x1d\x87\xa6";
uint8_t* const hmac_sha512_digest_6 = (uint8_t*)"\x80\xb2\x42\x63\xc7\xc1\xa3\xeb\xb7\x14\x93\xc1\xdd\x7b\xe8\xb4\x9b\x46\xd1\xf4\x1b\x4a\xee\xc1\x12\x1b\x01\x37\x83\xf8\xf3\x52\x6b\x56\xd0\x37\xe0\x5f\x25\x98\xbd\x0f\xd2\x21\x5d\x6a\x1e\x52\x95\xe6\x4f\x73\xf6\x3f\x0a\xec\x8b\x91\x5a\x98\x5d\x78\x65\x98";
uint8_t* const hmac_sha512_digest_7 = (uint8_t*)"\xe3\x7b\x6a\x77\x5d\xc8\x7d\xba\xa4\xdf\xa9\xf9\x6e\x5e\x3f\xfd\xde\xbd\x71\xf8\x86\x72\x89\x86\x5d\xf5\xa3\x2d\x20\xcd\xc9\x44\xb6\x02\x2c\xac\x3c\x49\x82\xb1\x0d\x5e\xeb\x55\xc3\xe4\xde\x15\x13\x46\x76\xfb\x6d\xe0\x44\x60\x65\xc9\x74\x40\xfa\x8c\x6a\x58";

HMACTEST hmac_sha512_tests[] = {
    { "HMAC-512", 7, hmac_sha_key_1,   20, hmac_sha_data_1,    8, hmac_sha512_digest_1, 64 },
    { "HMAC-512", 7, hmac_sha_key_2,    4, hmac_sha_data_2,   28, hmac_sha512_digest_2, 64 },
    { "HMAC-512", 7, hmac_sha_key_3,   20, hmac_sha_data_3,   50, hmac_sha512_digest_3, 64 },
    { "HMAC-512", 7, hmac_sha_key_4,   25, hmac_sha_data_4,   50, hmac_sha512_digest_4, 64 },
    { "HMAC-512", 7, hmac_sha_key_5,   20, hmac_sha_data_5,   20, hmac_sha512_digest_5, 16 },
    { "HMAC-512", 7, hmac_sha2_key_n, 131, hmac_sha_data_6,   54, hmac_sha512_digest_6, 64 },
    { "HMAC-512", 7, hmac_sha2_key_n, 131, hmac_sha2_data_7, 152, hmac_sha512_digest_7, 64 }
};

uint8_t* const hmac_sha384_digest_1 = (uint8_t*)"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6";
uint8_t* const hmac_sha384_digest_2 = (uint8_t*)"\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49";
uint8_t* const hmac_sha384_digest_3 = (uint8_t*)"\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f\x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27";
uint8_t* const hmac_sha384_digest_4 = (uint8_t*)"\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7\x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e\x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb";
uint8_t* const hmac_sha384_digest_5 = (uint8_t*)"\x3a\xbf\x34\xc3\x50\x3b\x2a\x23\xa4\x6e\xfc\x61\x9b\xae\xf8\x97";
uint8_t* const hmac_sha384_digest_6 = (uint8_t*)"\x4e\xce\x08\x44\x85\x81\x3e\x90\x88\xd2\xc6\x3a\x04\x1b\xc5\xb4\x4f\x9e\xf1\x01\x2a\x2b\x58\x8f\x3c\xd1\x1f\x05\x03\x3a\xc4\xc6\x0c\x2e\xf6\xab\x40\x30\xfe\x82\x96\x24\x8d\xf1\x63\xf4\x49\x52";
uint8_t* const hmac_sha384_digest_7 = (uint8_t*)"\x66\x17\x17\x8e\x94\x1f\x02\x0d\x35\x1e\x2f\x25\x4e\x8f\xd3\x2c\x60\x24\x20\xfe\xb0\xb8\xfb\x9a\xdc\xce\xbb\x82\x46\x1e\x99\xc5\xa6\x78\xcc\x31\xe7\x99\x17\x6d\x38\x60\xe6\x11\x0c\x46\x52\x3e";

HMACTEST hmac_sha384_tests[] = {
    { "HMAC-384", 7, hmac_sha_key_1,   20, hmac_sha_data_1,    8, hmac_sha384_digest_1, 48 },
    { "HMAC-384", 7, hmac_sha_key_2,    4, hmac_sha_data_2,   28, hmac_sha384_digest_2, 48 },
    { "HMAC-384", 7, hmac_sha_key_3,   20, hmac_sha_data_3,   50, hmac_sha384_digest_3, 48 },
    { "HMAC-384", 7, hmac_sha_key_4,   25, hmac_sha_data_4,   50, hmac_sha384_digest_4, 48 },
    { "HMAC-384", 7, hmac_sha_key_5,   20, hmac_sha_data_5,   20, hmac_sha384_digest_5, 16 },
    { "HMAC-384", 7, hmac_sha2_key_n, 131, hmac_sha_data_6,   54, hmac_sha384_digest_6, 48 },
    { "HMAC-384", 7, hmac_sha2_key_n, 131, hmac_sha2_data_7, 152, hmac_sha384_digest_7, 48 }
};

// DES-ECB variable plaintext test vectors

uint8_t* const desecb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const desecb_vp_plain_1 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const desecb_vp_plain_2 = (uint8_t*)"\x40\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const desecb_vp_plain_3 = (uint8_t*)"\x20\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const desecb_vp_plain_4 = (uint8_t*)"\x10\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desecb_vp_cipher_1 = (uint8_t*)"\x95\xF8\xA5\xE5\xDD\x31\xD9\x00";
uint8_t* const desecb_vp_cipher_2 = (uint8_t*)"\xDD\x7F\x12\x1C\xA5\x01\x56\x19";
uint8_t* const desecb_vp_cipher_3 = (uint8_t*)"\x2E\x86\x53\x10\x4F\x38\x34\xEA";
uint8_t* const desecb_vp_cipher_4 = (uint8_t*)"\x4B\xD3\x88\xFF\x6C\xD8\x1D\x4F";

CIPHERTEST desecb_vp_tests[] = {
    { "DES-ECB Variable Plaintext", 4, desecb_vp_key, nullptr, desecb_vp_plain_1, desecb_vp_cipher_1, des::recsize },
    { "DES-ECB Variable Plaintext", 4, desecb_vp_key, nullptr, desecb_vp_plain_2, desecb_vp_cipher_2, des::recsize },
    { "DES-ECB Variable Plaintext", 4, desecb_vp_key, nullptr, desecb_vp_plain_3, desecb_vp_cipher_3, des::recsize },
    { "DES-ECB Variable Plaintext", 4, desecb_vp_key, nullptr, desecb_vp_plain_4, desecb_vp_cipher_4, des::recsize }
};

// DES-ECB inverse permutation test vectors

uint8_t* const desecb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const desecb_ip_plain_1 = (uint8_t*)"\x2B\x9F\x98\x2F\x20\x03\x7F\xA9";
uint8_t* const desecb_ip_plain_2 = (uint8_t*)"\x88\x9D\xE0\x68\xA1\x6F\x0B\xE6";
uint8_t* const desecb_ip_plain_3 = (uint8_t*)"\xE1\x9E\x27\x5D\x84\x6A\x12\x98";
uint8_t* const desecb_ip_plain_4 = (uint8_t*)"\x32\x9A\x8E\xD5\x23\xD7\x1A\xEC";

uint8_t* const desecb_ip_cipher_1 = (uint8_t*)"\x00\x00\x80\x00\x00\x00\x00\x00";
uint8_t* const desecb_ip_cipher_2 = (uint8_t*)"\x00\x00\x40\x00\x00\x00\x00\x00";
uint8_t* const desecb_ip_cipher_3 = (uint8_t*)"\x00\x00\x20\x00\x00\x00\x00\x00";
uint8_t* const desecb_ip_cipher_4 = (uint8_t*)"\x00\x00\x10\x00\x00\x00\x00\x00";

CIPHERTEST desecb_ip_tests[] = {
    { "DES-ECB Inverse Permutation", 4, desecb_ip_key, nullptr, desecb_ip_plain_1, desecb_ip_cipher_1, des::recsize },
    { "DES-ECB Inverse Permutation", 4, desecb_ip_key, nullptr, desecb_ip_plain_2, desecb_ip_cipher_2, des::recsize },
    { "DES-ECB Inverse Permutation", 4, desecb_ip_key, nullptr, desecb_ip_plain_3, desecb_ip_cipher_3, des::recsize },
    { "DES-ECB Inverse Permutation", 4, desecb_ip_key, nullptr, desecb_ip_plain_4, desecb_ip_cipher_4, des::recsize }
};

// DES-ECB variable key test vectors

uint8_t* const desecb_vk_key_1 = (uint8_t*)"\x80\x01\x01\x01\x01\x01\x01\x01";
uint8_t* const desecb_vk_key_2 = (uint8_t*)"\x40\x01\x01\x01\x01\x01\x01\x01";
uint8_t* const desecb_vk_key_3 = (uint8_t*)"\x20\x01\x01\x01\x01\x01\x01\x01";
uint8_t* const desecb_vk_key_4 = (uint8_t*)"\x10\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const desecb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desecb_vk_cipher_1 = (uint8_t*)"\x95\xA8\xD7\x28\x13\xDA\xA9\x4D";
uint8_t* const desecb_vk_cipher_2 = (uint8_t*)"\x0E\xEC\x14\x87\xDD\x8C\x26\xD5";
uint8_t* const desecb_vk_cipher_3 = (uint8_t*)"\x7A\xD1\x6F\xFB\x79\xC4\x59\x26";
uint8_t* const desecb_vk_cipher_4 = (uint8_t*)"\xD3\x74\x62\x94\xCA\x6A\x6C\xF3";

CIPHERTEST desecb_vk_tests[] = {
    { "DES-ECB Variable Key", 4, desecb_vk_key_1, nullptr, desecb_vk_plain, desecb_vk_cipher_1, des::recsize },
    { "DES-ECB Variable Key", 4, desecb_vk_key_2, nullptr, desecb_vk_plain, desecb_vk_cipher_2, des::recsize },
    { "DES-ECB Variable Key", 4, desecb_vk_key_3, nullptr, desecb_vk_plain, desecb_vk_cipher_3, des::recsize },
    { "DES-ECB Variable Key", 4, desecb_vk_key_4, nullptr, desecb_vk_plain, desecb_vk_cipher_4, des::recsize }
};

// DES-ECB permutation operation test vectors

uint8_t* const desecb_po_key_1 = (uint8_t*)"\x10\x46\x91\x34\x89\x98\x01\x31";
uint8_t* const desecb_po_key_2 = (uint8_t*)"\x10\x07\x10\x34\x89\x98\x80\x20";
uint8_t* const desecb_po_key_3 = (uint8_t*)"\x10\x07\x10\x34\xC8\x98\x01\x20";
uint8_t* const desecb_po_key_4 = (uint8_t*)"\x10\x46\x10\x34\x89\x98\x80\x20";

uint8_t* const desecb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desecb_po_cipher_1 = (uint8_t*)"\x88\xD5\x5E\x54\xF5\x4C\x97\xB4";
uint8_t* const desecb_po_cipher_2 = (uint8_t*)"\x0C\x0C\xC0\x0C\x83\xEA\x48\xFD";
uint8_t* const desecb_po_cipher_3 = (uint8_t*)"\x83\xBC\x8E\xF3\xA6\x57\x01\x83";
uint8_t* const desecb_po_cipher_4 = (uint8_t*)"\xDF\x72\x5D\xCA\xD9\x4E\xA2\xE9";

CIPHERTEST desecb_po_tests[] = {
    { "DES-ECB Permutation Operation", 4, desecb_po_key_1, nullptr, desecb_po_plain, desecb_po_cipher_1, des::recsize },
    { "DES-ECB Permutation Operation", 4, desecb_po_key_2, nullptr, desecb_po_plain, desecb_po_cipher_2, des::recsize },
    { "DES-ECB Permutation Operation", 4, desecb_po_key_3, nullptr, desecb_po_plain, desecb_po_cipher_3, des::recsize },
    { "DES-ECB Permutaiton Operation", 4, desecb_po_key_4, nullptr, desecb_po_plain, desecb_po_cipher_4, des::recsize }
};

// DES-ECB substitution table test vectors

uint8_t* const desecb_st_key_1 = (uint8_t*)"\x7C\xA1\x10\x45\x4A\x1A\x6E\x57";
uint8_t* const desecb_st_key_2 = (uint8_t*)"\x01\x31\xD9\x61\x9D\xC1\x37\x6E";
uint8_t* const desecb_st_key_3 = (uint8_t*)"\x07\xA1\x13\x3E\x4A\x0B\x26\x86";
uint8_t* const desecb_st_key_4 = (uint8_t*)"\x38\x49\x67\x4C\x26\x02\x31\x9E";

uint8_t* const desecb_st_plain_1 = (uint8_t*)"\x01\xA1\xD6\xD0\x39\x77\x67\x42";
uint8_t* const desecb_st_plain_2 = (uint8_t*)"\x5C\xD5\x4C\xA8\x3D\xEF\x57\xDA";
uint8_t* const desecb_st_plain_3 = (uint8_t*)"\x02\x48\xD4\x38\x06\xF6\x71\x72";
uint8_t* const desecb_st_plain_4 = (uint8_t*)"\x51\x45\x4B\x58\x2D\xDF\x44\x0A";

uint8_t* const desecb_st_cipher_1 = (uint8_t*)"\x69\x0F\x5B\x0D\x9A\x26\x93\x9B";
uint8_t* const desecb_st_cipher_2 = (uint8_t*)"\x7A\x38\x9D\x10\x35\x4B\xD2\x71";
uint8_t* const desecb_st_cipher_3 = (uint8_t*)"\x86\x8E\xBB\x51\xCA\xB4\x59\x9A";
uint8_t* const desecb_st_cipher_4 = (uint8_t*)"\x71\x78\x87\x6E\x01\xF1\x9B\x2A";

CIPHERTEST desecb_st_tests[] = {
    { "DES-ECB Substitution Table", 4, desecb_st_key_1, nullptr, desecb_st_plain_1, desecb_st_cipher_1, des::recsize },
    { "DES-ECB Substitution Table", 4, desecb_st_key_2, nullptr, desecb_st_plain_2, desecb_st_cipher_2, des::recsize },
    { "DES-ECB Substitution Table", 4, desecb_st_key_3, nullptr, desecb_st_plain_3, desecb_st_cipher_3, des::recsize },
    { "DES-ECB Substitution Table", 4, desecb_st_key_4, nullptr, desecb_st_plain_4, desecb_st_cipher_4, des::recsize }
};

// DES-CBC variable plaintext test vectors

uint8_t* const descbc_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const descbc_vp_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descbc_vp_plain_1 = (uint8_t*)"\x08\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const descbc_vp_plain_2 = (uint8_t*)"\x04\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const descbc_vp_plain_3 = (uint8_t*)"\x02\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const descbc_vp_plain_4 = (uint8_t*)"\x01\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descbc_vp_cipher_1 = (uint8_t*)"\x20\xB9\xE7\x67\xB2\xFB\x14\x56";
uint8_t* const descbc_vp_cipher_2 = (uint8_t*)"\x55\x57\x93\x80\xD7\x71\x38\xEF";
uint8_t* const descbc_vp_cipher_3 = (uint8_t*)"\x6C\xC5\xDE\xFA\xAF\x04\x51\x2F";
uint8_t* const descbc_vp_cipher_4 = (uint8_t*)"\x0D\x9F\x27\x9B\xA5\xD8\x72\x60";

CIPHERTEST descbc_vp_tests[] = {
    { "DES-CBC Variable Plaintext", 4, descbc_vp_key, descbc_vp_iv, descbc_vp_plain_1, descbc_vp_cipher_1, des::recsize },
    { "DES-CBC Variable Plaintext", 4, descbc_vp_key, descbc_vp_iv, descbc_vp_plain_2, descbc_vp_cipher_2, des::recsize },
    { "DES-CBC Variable Plaintext", 4, descbc_vp_key, descbc_vp_iv, descbc_vp_plain_3, descbc_vp_cipher_3, des::recsize },
    { "DES-CBC Variable Plaintext", 4, descbc_vp_key, descbc_vp_iv, descbc_vp_plain_4, descbc_vp_cipher_4, des::recsize }
};

// DES-CBC inverse permutation test vectors

uint8_t* const descbc_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const descbc_ip_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descbc_ip_plain_1 = (uint8_t*)"\xE7\xFC\xE2\x25\x57\xD2\x3C\x97";
uint8_t* const descbc_ip_plain_2 = (uint8_t*)"\x12\xA9\xF5\x81\x7F\xF2\xD6\x5D";
uint8_t* const descbc_ip_plain_3 = (uint8_t*)"\xA4\x84\xC3\xAD\x38\xDC\x9C\x19";
uint8_t* const descbc_ip_plain_4 = (uint8_t*)"\xFB\xE0\x0A\x8A\x1E\xF8\xAD\x72";

uint8_t* const descbc_ip_cipher_1 = (uint8_t*)"\x00\x00\x08\x00\x00\x00\x00\x00";
uint8_t* const descbc_ip_cipher_2 = (uint8_t*)"\x00\x00\x04\x00\x00\x00\x00\x00";
uint8_t* const descbc_ip_cipher_3 = (uint8_t*)"\x00\x00\x02\x00\x00\x00\x00\x00";
uint8_t* const descbc_ip_cipher_4 = (uint8_t*)"\x00\x00\x01\x00\x00\x00\x00\x00";

CIPHERTEST descbc_ip_tests[] = {
    { "DES-CBC Inverse Permutation", 4, descbc_ip_key, descbc_ip_iv, descbc_ip_plain_1, descbc_ip_cipher_1, des::recsize },
    { "DES-CBC Inverse Permutation", 4, descbc_ip_key, descbc_ip_iv, descbc_ip_plain_2, descbc_ip_cipher_2, des::recsize },
    { "DES-CBC Inverse Permutation", 4, descbc_ip_key, descbc_ip_iv, descbc_ip_plain_3, descbc_ip_cipher_3, des::recsize },
    { "DES-CBC Inverse Permutation", 4, descbc_ip_key, descbc_ip_iv, descbc_ip_plain_4, descbc_ip_cipher_4, des::recsize }
};

// DES-CBC variable key test vectors

uint8_t* const descbc_vk_key_1 = (uint8_t*)"\x08\x01\x01\x01\x01\x01\x01\x01";
uint8_t* const descbc_vk_key_2 = (uint8_t*)"\x04\x01\x01\x01\x01\x01\x01\x01";
uint8_t* const descbc_vk_key_3 = (uint8_t*)"\x02\x01\x01\x01\x01\x01\x01\x01";
uint8_t* const descbc_vk_key_4 = (uint8_t*)"\x01\x80\x01\x01\x01\x01\x01\x01";

uint8_t* const descbc_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descbc_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descbc_vk_cipher_1 = (uint8_t*)"\x80\x9F\x5F\x87\x3C\x1F\xD7\x61";
uint8_t* const descbc_vk_cipher_2 = (uint8_t*)"\xC0\x2F\xAF\xFE\xC9\x89\xD1\xFC";
uint8_t* const descbc_vk_cipher_3 = (uint8_t*)"\x46\x15\xAA\x1D\x33\xE7\x2F\x10";
uint8_t* const descbc_vk_cipher_4 = (uint8_t*)"\x20\x55\x12\x33\x50\xC0\x08\x58";

CIPHERTEST descbc_vk_tests[] = {
    { "DES-CBC Variable Key", 4, descbc_vk_key_1, descbc_vk_iv, descbc_vk_plain, descbc_vk_cipher_1, des::recsize },
    { "DES-CBC Variable Key", 4, descbc_vk_key_2, descbc_vk_iv, descbc_vk_plain, descbc_vk_cipher_2, des::recsize },
    { "DES-CBC Variable Key", 4, descbc_vk_key_3, descbc_vk_iv, descbc_vk_plain, descbc_vk_cipher_3, des::recsize },
    { "DES-CBC Variable Key", 4, descbc_vk_key_4, descbc_vk_iv, descbc_vk_plain, descbc_vk_cipher_4, des::recsize }
};

// DES-CBC permutation operation test vectors

uint8_t* const descbc_po_key_1 = (uint8_t*)"\x10\x86\x91\x15\x19\x19\x01\x01";
uint8_t* const descbc_po_key_2 = (uint8_t*)"\x10\x86\x91\x15\x19\x58\x01\x01";
uint8_t* const descbc_po_key_3 = (uint8_t*)"\x51\x07\xB0\x15\x19\x58\x01\x01";
uint8_t* const descbc_po_key_4 = (uint8_t*)"\x10\x07\xB0\x15\x19\x19\x01\x01";

uint8_t* const descbc_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descbc_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descbc_po_cipher_1 = (uint8_t*)"\xE6\x52\xB5\x3B\x55\x0B\xE8\xB0";
uint8_t* const descbc_po_cipher_2 = (uint8_t*)"\xAF\x52\x71\x20\xC4\x85\xCB\xB0";
uint8_t* const descbc_po_cipher_3 = (uint8_t*)"\x0F\x04\xCE\x39\x3D\xB9\x26\xD5";
uint8_t* const descbc_po_cipher_4 = (uint8_t*)"\xC9\xF0\x0F\xFC\x74\x07\x90\x67";

CIPHERTEST descbc_po_tests[] = {
    { "DES-CBC Permutation Operation", 4, descbc_po_key_1, descbc_po_iv, descbc_po_plain, descbc_po_cipher_1, des::recsize },
    { "DES-CBC Permutation Operation", 4, descbc_po_key_2, descbc_po_iv, descbc_po_plain, descbc_po_cipher_2, des::recsize },
    { "DES-CBC Permutation Operation", 4, descbc_po_key_3, descbc_po_iv, descbc_po_plain, descbc_po_cipher_3, des::recsize },
    { "DES-CBC Permutation Operation", 4, descbc_po_key_4, descbc_po_iv, descbc_po_plain, descbc_po_cipher_4, des::recsize }
};

// DES-CBC substitution table test vectors

uint8_t* const descbc_st_key_1 = (uint8_t*)"\x04\xB9\x15\xBA\x43\xFE\xB5\xB6";
uint8_t* const descbc_st_key_2 = (uint8_t*)"\x01\x13\xB9\x70\xFD\x34\xF2\xCE";
uint8_t* const descbc_st_key_3 = (uint8_t*)"\x01\x70\xF1\x75\x46\x8F\xB5\xE6";
uint8_t* const descbc_st_key_4 = (uint8_t*)"\x43\x29\x7F\xAD\x38\xE3\x73\xFE";

uint8_t* const descbc_st_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descbc_st_plain_1 = (uint8_t*)"\x42\xFD\x44\x30\x59\x57\x7F\xA2";
uint8_t* const descbc_st_plain_2 = (uint8_t*)"\x05\x9B\x5E\x08\x51\xCF\x14\x3A";
uint8_t* const descbc_st_plain_3 = (uint8_t*)"\x07\x56\xD8\xE0\x77\x47\x61\xD2";
uint8_t* const descbc_st_plain_4 = (uint8_t*)"\x76\x25\x14\xB8\x29\xBF\x48\x6A";

uint8_t* const descbc_st_cipher_1 = (uint8_t*)"\xAF\x37\xFB\x42\x1F\x8C\x40\x95";
uint8_t* const descbc_st_cipher_2 = (uint8_t*)"\x86\xA5\x60\xF1\x0E\xC6\xD8\x5B";
uint8_t* const descbc_st_cipher_3 = (uint8_t*)"\x0C\xD3\xDA\x02\x00\x21\xDC\x09";
uint8_t* const descbc_st_cipher_4 = (uint8_t*)"\xEA\x67\x6B\x2C\xB7\xDB\x2B\x7A";

CIPHERTEST descbc_st_tests[] = {
    { "DES-CBC Substitution Table", 4, descbc_st_key_1, descbc_st_iv, descbc_st_plain_1, descbc_st_cipher_1, des::recsize },
    { "DES-CBC Substitution Table", 4, descbc_st_key_2, descbc_st_iv, descbc_st_plain_2, descbc_st_cipher_2, des::recsize },
    { "DES-CBC Substitution Table", 4, descbc_st_key_3, descbc_st_iv, descbc_st_plain_3, descbc_st_cipher_3, des::recsize },
    { "DES-CBC Substitution Table", 4, descbc_st_key_4, descbc_st_iv, descbc_st_plain_4, descbc_st_cipher_4, des::recsize }
};

// DES-CFB variable plaintext test vectors

uint8_t* const descfb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const descfb_vp_iv_1 = (uint8_t*)"\x00\x80\x00\x00\x00\x00\x00\x00";
uint8_t* const descfb_vp_iv_2 = (uint8_t*)"\x00\x40\x00\x00\x00\x00\x00\x00";
uint8_t* const descfb_vp_iv_3 = (uint8_t*)"\x00\x20\x00\x00\x00\x00\x00\x00";
uint8_t* const descfb_vp_iv_4 = (uint8_t*)"\x00\x10\x00\x00\x00\x00\x00\x00";

uint8_t* const descfb_vp_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descfb_vp_cipher_1 = (uint8_t*)"\xD9\x03\x1B\x02\x71\xBD\x5A\x0A";
uint8_t* const descfb_vp_cipher_2 = (uint8_t*)"\x42\x42\x50\xB3\x7C\x3D\xD9\x51";
uint8_t* const descfb_vp_cipher_3 = (uint8_t*)"\xB8\x06\x1B\x7E\xCD\x9A\x21\xE5";
uint8_t* const descfb_vp_cipher_4 = (uint8_t*)"\xF1\x5D\x0F\x28\x6B\x65\xBD\x28";

CIPHERTEST descfb_vp_tests[] = {
    { "DES-CFB Variable Plaintext", 4, descfb_vp_key, descfb_vp_iv_1, descfb_vp_plain, descfb_vp_cipher_1, des::recsize },
    { "DES-CFB Variable Plaintext", 4, descfb_vp_key, descfb_vp_iv_2, descfb_vp_plain, descfb_vp_cipher_2, des::recsize },
    { "DES-CFB Variable Plaintext", 4, descfb_vp_key, descfb_vp_iv_3, descfb_vp_plain, descfb_vp_cipher_3, des::recsize },
    { "DES-CFB Variable Plaintext", 4, descfb_vp_key, descfb_vp_iv_4, descfb_vp_plain, descfb_vp_cipher_4, des::recsize }
};

// DES-CFB inverse permutation test vectors

uint8_t* const descfb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const descfb_ip_iv_1 = (uint8_t*)"\x75\x0D\x07\x94\x07\x52\x13\x63";
uint8_t* const descfb_ip_iv_2 = (uint8_t*)"\x64\xFE\xED\x9C\x72\x4C\x2F\xAF";
uint8_t* const descfb_ip_iv_3 = (uint8_t*)"\xF0\x2B\x26\x3B\x32\x8E\x2B\x60";
uint8_t* const descfb_ip_iv_4 = (uint8_t*)"\x9D\x64\x55\x5A\x9A\x10\xB8\x52";

uint8_t* const descfb_ip_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descfb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x80\x00\x00\x00\x00";
uint8_t* const descfb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x40\x00\x00\x00\x00";
uint8_t* const descfb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x20\x00\x00\x00\x00";
uint8_t* const descfb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x10\x00\x00\x00\x00";

CIPHERTEST descfb_ip_tests[] = {
    { "DES-CFB Inverse Permutation", 4, descfb_ip_key, descfb_ip_iv_1, descfb_ip_plain, descfb_ip_cipher_1, des::recsize },
    { "DES-CFB Inverse Permutation", 4, descfb_ip_key, descfb_ip_iv_2, descfb_ip_plain, descfb_ip_cipher_2, des::recsize },
    { "DES-CFB Inverse Permutation", 4, descfb_ip_key, descfb_ip_iv_3, descfb_ip_plain, descfb_ip_cipher_3, des::recsize },
    { "DES-CFB Inverse Permutation", 4, descfb_ip_key, descfb_ip_iv_4, descfb_ip_plain, descfb_ip_cipher_4, des::recsize }
};

// DES-CFB variable key test vectors

uint8_t* const descfb_vk_key_1 = (uint8_t*)"\x01\x40\x01\x01\x01\x01\x01\x01";
uint8_t* const descfb_vk_key_2 = (uint8_t*)"\x01\x20\x01\x01\x01\x01\x01\x01";
uint8_t* const descfb_vk_key_3 = (uint8_t*)"\x01\x10\x01\x01\x01\x01\x01\x01";
uint8_t* const descfb_vk_key_4 = (uint8_t*)"\x01\x08\x01\x01\x01\x01\x01\x01";

uint8_t* const descfb_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descfb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descfb_vk_cipher_1 = (uint8_t*)"\xDF\x3B\x99\xD6\x57\x73\x97\xC8";
uint8_t* const descfb_vk_cipher_2 = (uint8_t*)"\x31\xFE\x17\x36\x9B\x52\x88\xC9";
uint8_t* const descfb_vk_cipher_3 = (uint8_t*)"\xDF\xDD\x3C\xC6\x4D\xAE\x16\x42";
uint8_t* const descfb_vk_cipher_4 = (uint8_t*)"\x17\x8C\x83\xCE\x2B\x39\x9D\x94";

CIPHERTEST descfb_vk_tests[] = {
    { "DES-CFB Variable Key", 4, descfb_vk_key_1, descfb_vk_iv, descfb_vk_plain, descfb_vk_cipher_1, des::recsize },
    { "DES-CFB Variable Key", 4, descfb_vk_key_2, descfb_vk_iv, descfb_vk_plain, descfb_vk_cipher_2, des::recsize },
    { "DES-CFB Variable Key", 4, descfb_vk_key_3, descfb_vk_iv, descfb_vk_plain, descfb_vk_cipher_3, des::recsize },
    { "DES-CFB Variable Key", 4, descfb_vk_key_4, descfb_vk_iv, descfb_vk_plain, descfb_vk_cipher_4, des::recsize }
};

// DES-CFB permutation operation test vectors

uint8_t* const descfb_po_key_1 = (uint8_t*)"\x31\x07\x91\x54\x98\x08\x01\x01";
uint8_t* const descfb_po_key_2 = (uint8_t*)"\x31\x07\x91\x94\x98\x08\x01\x01";
uint8_t* const descfb_po_key_3 = (uint8_t*)"\x10\x07\x91\x15\xB9\x08\x01\x40";
uint8_t* const descfb_po_key_4 = (uint8_t*)"\x31\x07\x91\x15\x98\x08\x01\x40";

uint8_t* const descfb_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descfb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descfb_po_cipher_1 = (uint8_t*)"\x7C\xFD\x82\xA5\x93\x25\x2B\x4E";
uint8_t* const descfb_po_cipher_2 = (uint8_t*)"\xCB\x49\xA2\xF9\xE9\x13\x63\xE3";
uint8_t* const descfb_po_cipher_3 = (uint8_t*)"\x00\xB5\x88\xBE\x70\xD2\x3F\x56";
uint8_t* const descfb_po_cipher_4 = (uint8_t*)"\x40\x6A\x9A\x6A\xB4\x33\x99\xAE";

CIPHERTEST descfb_po_tests[] = {
    { "DES-CFB Permutation Operation", 4, descfb_po_key_1, descfb_po_iv, descfb_po_plain, descfb_po_cipher_1, des::recsize },
    { "DES-CFB Permutation Operation", 4, descfb_po_key_2, descfb_po_iv, descfb_po_plain, descfb_po_cipher_2, des::recsize },
    { "DES-CFB Permutation Operation", 4, descfb_po_key_3, descfb_po_iv, descfb_po_plain, descfb_po_cipher_3, des::recsize },
    { "DES-CFB Permutation Operation", 4, descfb_po_key_4, descfb_po_iv, descfb_po_plain, descfb_po_cipher_4, des::recsize }
};

// DES-CFB substitution table test vectors

uint8_t* const descfb_st_key_1 = (uint8_t*)"\x07\xA7\x13\x70\x45\xDA\x2A\x16";
uint8_t* const descfb_st_key_2 = (uint8_t*)"\x04\x68\x91\x04\xC2\xFD\x3B\x2F";
uint8_t* const descfb_st_key_3 = (uint8_t*)"\x37\xD0\x6B\xB5\x16\xCB\x75\x46";
uint8_t* const descfb_st_key_4 = (uint8_t*)"\x1F\x08\x26\x0D\x1A\xC2\x46\x5E";

uint8_t* const descfb_st_iv_1 = (uint8_t*)"\x3B\xDD\x11\x90\x49\x37\x28\x02";
uint8_t* const descfb_st_iv_2 = (uint8_t*)"\x26\x95\x5F\x68\x35\xAF\x60\x9A";
uint8_t* const descfb_st_iv_3 = (uint8_t*)"\x16\x4D\x5E\x40\x4F\x27\x52\x32";
uint8_t* const descfb_st_iv_4 = (uint8_t*)"\x6B\x05\x6E\x18\x75\x9F\x5C\xCA";

uint8_t* const descfb_st_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const descfb_st_cipher_1 = (uint8_t*)"\xDF\xD6\x4A\x81\x5C\xAF\x1A\x0F";
uint8_t* const descfb_st_cipher_2 = (uint8_t*)"\x5C\x51\x3C\x9C\x48\x86\xC0\x88";
uint8_t* const descfb_st_cipher_3 = (uint8_t*)"\x0A\x2A\xEE\xAE\x3F\xF4\xAB\x77";
uint8_t* const descfb_st_cipher_4 = (uint8_t*)"\xEF\x1B\xF0\x3E\x5D\xFA\x57\x5A";

CIPHERTEST descfb_st_tests[] = {
    { "DES-CFB Substitution Table", 4, descfb_st_key_1, descfb_st_iv_1, descfb_st_plain, descfb_st_cipher_1, des::recsize },
    { "DES-CFB Substitution Table", 4, descfb_st_key_2, descfb_st_iv_2, descfb_st_plain, descfb_st_cipher_2, des::recsize },
    { "DES-CFB Substitution Table", 4, descfb_st_key_3, descfb_st_iv_3, descfb_st_plain, descfb_st_cipher_3, des::recsize },
    { "DES-CFB Substitution Table", 4, descfb_st_key_4, descfb_st_iv_4, descfb_st_plain, descfb_st_cipher_4, des::recsize }
};

// DES-OFB variable plaintext test vectors

uint8_t* const desofb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const desofb_vp_iv_1 = (uint8_t*)"\x00\x08\x00\x00\x00\x00\x00\x00";
uint8_t* const desofb_vp_iv_2 = (uint8_t*)"\x00\x04\x00\x00\x00\x00\x00\x00";
uint8_t* const desofb_vp_iv_3 = (uint8_t*)"\x00\x02\x00\x00\x00\x00\x00\x00";
uint8_t* const desofb_vp_iv_4 = (uint8_t*)"\x00\x01\x00\x00\x00\x00\x00\x00";

uint8_t* const desofb_vp_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desofb_vp_cipher_1 = (uint8_t*)"\xAD\xD0\xCC\x8D\x6E\x5D\xEB\xA1";
uint8_t* const desofb_vp_cipher_2 = (uint8_t*)"\xE6\xD5\xF8\x27\x52\xAD\x63\xD1";
uint8_t* const desofb_vp_cipher_3 = (uint8_t*)"\xEC\xBF\xE3\xBD\x3F\x59\x1A\x5E";
uint8_t* const desofb_vp_cipher_4 = (uint8_t*)"\xF3\x56\x83\x43\x79\xD1\x65\xCD";

CIPHERTEST desofb_vp_tests[] = {
    { "DES-OFB Variable Plaintext", 4, desofb_vp_key, desofb_vp_iv_1, desofb_vp_plain, desofb_vp_cipher_1, des::recsize },
    { "DES-OFB Variable Plaintext", 4, desofb_vp_key, desofb_vp_iv_2, desofb_vp_plain, desofb_vp_cipher_2, des::recsize },
    { "DES-OFB Variable Plaintext", 4, desofb_vp_key, desofb_vp_iv_3, desofb_vp_plain, desofb_vp_cipher_3, des::recsize },
    { "DES-OFB Variable Plaintext", 4, desofb_vp_key, desofb_vp_iv_4, desofb_vp_plain, desofb_vp_cipher_4, des::recsize }
};

// DES-OFB inverse permutation test vectors

uint8_t* const desofb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const desofb_ip_iv_1 = (uint8_t*)"\xD1\x06\xFF\x0B\xED\x52\x55\xD7";
uint8_t* const desofb_ip_iv_2 = (uint8_t*)"\xE1\x65\x2C\x6B\x13\x8C\x64\xA5";
uint8_t* const desofb_ip_iv_3 = (uint8_t*)"\xE4\x28\x58\x11\x86\xEC\x8F\x46";
uint8_t* const desofb_ip_iv_4 = (uint8_t*)"\xAE\xB5\xF5\xED\xE2\x2D\x1A\x36";

uint8_t* const desofb_ip_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desofb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x08\x00\x00\x00\x00";
uint8_t* const desofb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x04\x00\x00\x00\x00";
uint8_t* const desofb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x02\x00\x00\x00\x00";
uint8_t* const desofb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x01\x00\x00\x00\x00";

CIPHERTEST desofb_ip_tests[] = {
    { "DES-OFB Inverse Permutation", 4, desofb_ip_key, desofb_ip_iv_1, desofb_ip_plain, desofb_ip_cipher_1, des::recsize },
    { "DES-OFB Inverse Permutation", 4, desofb_ip_key, desofb_ip_iv_2, desofb_ip_plain, desofb_ip_cipher_2, des::recsize },
    { "DES-OFB Inverse Permutation", 4, desofb_ip_key, desofb_ip_iv_3, desofb_ip_plain, desofb_ip_cipher_3, des::recsize },
    { "DES-OFB Inverse Permutation", 4, desofb_ip_key, desofb_ip_iv_4, desofb_ip_plain, desofb_ip_cipher_4, des::recsize }
};

// DES-OFB variable key test vectors

uint8_t* const desofb_vk_key_1 = (uint8_t*)"\x01\x04\x01\x01\x01\x01\x01\x01";
uint8_t* const desofb_vk_key_2 = (uint8_t*)"\x01\x02\x01\x01\x01\x01\x01\x01";
uint8_t* const desofb_vk_key_3 = (uint8_t*)"\x01\x01\x80\x01\x01\x01\x01\x01";
uint8_t* const desofb_vk_key_4 = (uint8_t*)"\x01\x01\x40\x01\x01\x01\x01\x01";

uint8_t* const desofb_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desofb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desofb_vk_cipher_1 = (uint8_t*)"\x50\xF6\x36\x32\x4A\x9B\x7F\x80";
uint8_t* const desofb_vk_cipher_2 = (uint8_t*)"\xA8\x46\x8E\xE3\xBC\x18\xF0\x6D";
uint8_t* const desofb_vk_cipher_3 = (uint8_t*)"\xA2\xDC\x9E\x92\xFD\x3C\xDE\x92";
uint8_t* const desofb_vk_cipher_4 = (uint8_t*)"\xCA\xC0\x9F\x79\x7D\x03\x12\x87";

CIPHERTEST desofb_vk_tests[] = {
    { "DES-OFB Variable Key", 4, desofb_vk_key_1, desofb_vk_iv, desofb_vk_plain, desofb_vk_cipher_1, des::recsize },
    { "DES-OFB Variable Key", 4, desofb_vk_key_2, desofb_vk_iv, desofb_vk_plain, desofb_vk_cipher_2, des::recsize },
    { "DES-OFB Variable Key", 4, desofb_vk_key_3, desofb_vk_iv, desofb_vk_plain, desofb_vk_cipher_3, des::recsize },
    { "DES-OFB Variable Key", 4, desofb_vk_key_4, desofb_vk_iv, desofb_vk_plain, desofb_vk_cipher_4, des::recsize }
};

// DES-OFB permutation operation test vectors

uint8_t* const desofb_po_key_1 = (uint8_t*)"\x10\x07\xD0\x15\x89\x98\x01\x01";
uint8_t* const desofb_po_key_2 = (uint8_t*)"\x91\x07\x91\x15\x89\x98\x01\x01";
uint8_t* const desofb_po_key_3 = (uint8_t*)"\x91\x07\xD0\x15\x89\x19\x01\x01";
uint8_t* const desofb_po_key_4 = (uint8_t*)"\x10\x07\xD0\x15\x98\x98\x01\x20";

uint8_t* const desofb_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desofb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desofb_po_cipher_1 = (uint8_t*)"\x6C\xB7\x73\x61\x1D\xCA\x9A\xDA";
uint8_t* const desofb_po_cipher_2 = (uint8_t*)"\x67\xFD\x21\xC1\x7D\xBB\x5D\x70";
uint8_t* const desofb_po_cipher_3 = (uint8_t*)"\x95\x92\xCB\x41\x10\x43\x07\x87";
uint8_t* const desofb_po_cipher_4 = (uint8_t*)"\xA6\xB7\xFF\x68\xA3\x18\xDD\xD3";

CIPHERTEST desofb_po_tests[] = {
    { "DES-OFB Permutation Operation", 4, desofb_po_key_1, desofb_po_iv, desofb_po_plain, desofb_po_cipher_1, des::recsize },
    { "DES-OFB Permutation Operation", 4, desofb_po_key_2, desofb_po_iv, desofb_po_plain, desofb_po_cipher_2, des::recsize },
    { "DES-OFB Permutation Operation", 4, desofb_po_key_3, desofb_po_iv, desofb_po_plain, desofb_po_cipher_3, des::recsize },
    { "DES-OFB Permutation Operation", 4, desofb_po_key_4, desofb_po_iv, desofb_po_plain, desofb_po_cipher_4, des::recsize }
};

// DES-OFB substitution table test vectors

uint8_t* const desofb_st_key_1 = (uint8_t*)"\x58\x40\x23\x64\x1A\xBA\x61\x76";
uint8_t* const desofb_st_key_2 = (uint8_t*)"\x02\x58\x16\x16\x46\x29\xB0\x07";
uint8_t* const desofb_st_key_3 = (uint8_t*)"\x49\x79\x3E\xBC\x79\xB3\x25\x8F";
uint8_t* const desofb_st_key_4 = (uint8_t*)"\x4F\xB0\x5E\x15\x15\xAB\x73\xA7";

uint8_t* const desofb_st_iv_1 = (uint8_t*)"\x00\x4B\xD6\xEF\x09\x17\x60\x62";
uint8_t* const desofb_st_iv_2 = (uint8_t*)"\x48\x0D\x39\x00\x6E\xE7\x62\xF2";
uint8_t* const desofb_st_iv_3 = (uint8_t*)"\x43\x75\x40\xC8\x69\x8F\x3C\xFA";
uint8_t* const desofb_st_iv_4 = (uint8_t*)"\x07\x2D\x43\xA0\x77\x07\x52\x92";

uint8_t* const desofb_st_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const desofb_st_cipher_1 = (uint8_t*)"\x88\xBF\x0D\xB6\xD7\x0D\xEE\x56";
uint8_t* const desofb_st_cipher_2 = (uint8_t*)"\xA1\xF9\x91\x55\x41\x02\x0B\x56";
uint8_t* const desofb_st_cipher_3 = (uint8_t*)"\x6F\xBF\x1C\xAF\xCF\xFD\x05\x56";
uint8_t* const desofb_st_cipher_4 = (uint8_t*)"\x2F\x22\xE4\x9B\xAB\x7C\xA1\xAC";

CIPHERTEST desofb_st_tests[] = {
    { "DES-OFB Substitution Table", 4, desofb_st_key_1, desofb_st_iv_1, desofb_st_plain, desofb_st_cipher_1, des::recsize },
    { "DES-OFB Substitution Table", 4, desofb_st_key_2, desofb_st_iv_2, desofb_st_plain, desofb_st_cipher_2, des::recsize },
    { "DES-OFB Substitution Table", 4, desofb_st_key_3, desofb_st_iv_3, desofb_st_plain, desofb_st_cipher_3, des::recsize },
    { "DES-OFB Substitution Table", 4, desofb_st_key_4, desofb_st_iv_4, desofb_st_plain, desofb_st_cipher_4, des::recsize }
};

// DES-EDE-ECB variable plaintext test vectors

uint8_t* const des3ecb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const des3ecb_vp_plain_1 = (uint8_t*)"\x00\x00\x00\x00\x80\x00\x00\x00";
uint8_t* const des3ecb_vp_plain_2 = (uint8_t*)"\x00\x00\x00\x00\x40\x00\x00\x00";
uint8_t* const des3ecb_vp_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x20\x00\x00\x00";
uint8_t* const des3ecb_vp_plain_4 = (uint8_t*)"\x00\x00\x00\x00\x10\x00\x00\x00";

uint8_t* const des3ecb_vp_cipher_1 = (uint8_t*)"\xE9\x43\xD7\x56\x8A\xEC\x0C\x5C";
uint8_t* const des3ecb_vp_cipher_2 = (uint8_t*)"\xDF\x98\xC8\x27\x6F\x54\xB0\x4B";
uint8_t* const des3ecb_vp_cipher_3 = (uint8_t*)"\xB1\x60\xE4\x68\x0F\x6C\x69\x6F";
uint8_t* const des3ecb_vp_cipher_4 = (uint8_t*)"\xFA\x07\x52\xB0\x7D\x9C\x4A\xB8";

CIPHERTEST des3ecb_vp_tests[] = {
    { "DES-EDE-ECB Variable Plaintext", 4, des3ecb_vp_key, nullptr, des3ecb_vp_plain_1, des3ecb_vp_cipher_1, des3::recsize },
    { "DES-EDE-ECB Variable Plaintext", 4, des3ecb_vp_key, nullptr, des3ecb_vp_plain_2, des3ecb_vp_cipher_2, des3::recsize },
    { "DES-EDE-ECB Variable Plaintext", 4, des3ecb_vp_key, nullptr, des3ecb_vp_plain_3, des3ecb_vp_cipher_3, des3::recsize },
    { "DES-EDE-ECB Variable Plaintext", 4, des3ecb_vp_key, nullptr, des3ecb_vp_plain_4, des3ecb_vp_cipher_4, des3::recsize }
};

// DES-EDE-ECB inverse permutation test vectors

uint8_t* const des3ecb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const des3ecb_ip_plain_1 = (uint8_t*)"\x10\x29\xD5\x5E\x88\x0E\xC2\xD0";
uint8_t* const des3ecb_ip_plain_2 = (uint8_t*)"\x5D\x86\xCB\x23\x63\x9D\xBE\xA9";
uint8_t* const des3ecb_ip_plain_3 = (uint8_t*)"\x1D\x1C\xA8\x53\xAE\x7C\x0C\x5F";
uint8_t* const des3ecb_ip_plain_4 = (uint8_t*)"\xCE\x33\x23\x29\x24\x8F\x32\x28";

uint8_t* const des3ecb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x80\x00";
uint8_t* const des3ecb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x40\x00";
uint8_t* const des3ecb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x20\x00";
uint8_t* const des3ecb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x10\x00";

CIPHERTEST des3ecb_ip_tests[] = {
    { "DES-EDE-ECB Inverse Permutation", 4, des3ecb_ip_key, nullptr, des3ecb_ip_plain_1, des3ecb_ip_cipher_1, des3::recsize },
    { "DES-EDE-ECB Inverse Permutation", 4, des3ecb_ip_key, nullptr, des3ecb_ip_plain_2, des3ecb_ip_cipher_2, des3::recsize },
    { "DES-EDE-ECB Inverse Permutation", 4, des3ecb_ip_key, nullptr, des3ecb_ip_plain_3, des3ecb_ip_cipher_3, des3::recsize },
    { "DES-EDE-ECB Inverse Permutation", 4, des3ecb_ip_key, nullptr, des3ecb_ip_plain_4, des3ecb_ip_cipher_4, des3::recsize }
};

// DES-EDE-ECB variable key test vectors

uint8_t* const des3ecb_vk_key_1 = (uint8_t*)"\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01";
uint8_t* const des3ecb_vk_key_2 = (uint8_t*)"\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01";
uint8_t* const des3ecb_vk_key_3 = (uint8_t*)"\x01\x01\x08\x01\x01\x01\x01\x01\x01\x01\x08\x01\x01\x01\x01\x01\x01\x01\x08\x01\x01\x01\x01\x01";
uint8_t* const des3ecb_vk_key_4 = (uint8_t*)"\x01\x01\x04\x01\x01\x01\x01\x01\x01\x01\x04\x01\x01\x01\x01\x01\x01\x01\x04\x01\x01\x01\x01\x01";

uint8_t* const des3ecb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3ecb_vk_cipher_1 = (uint8_t*)"\x90\xBA\x68\x0B\x22\xAE\xB5\x25";
uint8_t* const des3ecb_vk_cipher_2 = (uint8_t*)"\xCE\x7A\x24\xF3\x50\xE2\x80\xB6";
uint8_t* const des3ecb_vk_cipher_3 = (uint8_t*)"\x88\x2B\xFF\x0A\xA0\x1A\x0B\x87";
uint8_t* const des3ecb_vk_cipher_4 = (uint8_t*)"\x25\x61\x02\x88\x92\x45\x11\xC2";

CIPHERTEST des3ecb_vk_tests[] = {
    { "DES-EDE-ECB Variable Key", 4, des3ecb_vk_key_1, nullptr, des3ecb_vk_plain, des3ecb_vk_cipher_1, des3::recsize },
    { "DES-EDE-ECB Variable Key", 4, des3ecb_vk_key_2, nullptr, des3ecb_vk_plain, des3ecb_vk_cipher_2, des3::recsize },
    { "DES-EDE-ECB Variable Key", 4, des3ecb_vk_key_3, nullptr, des3ecb_vk_plain, des3ecb_vk_cipher_3, des3::recsize },
    { "DES-EDE-ECB Variable Key", 4, des3ecb_vk_key_4, nullptr, des3ecb_vk_plain, des3ecb_vk_cipher_4, des3::recsize }
};

// DES-EDE-ECB permutation operation test vectors

uint8_t* const des3ecb_po_key_1 = (uint8_t*)"\x10\x07\x94\x04\x98\x19\x01\x01\x10\x07\x94\x04\x98\x19\x01\x01\x10\x07\x94\x04\x98\x19\x01\x01";
uint8_t* const des3ecb_po_key_2 = (uint8_t*)"\x01\x07\x91\x04\x91\x19\x04\x01\x01\x07\x91\x04\x91\x19\x04\x01\x01\x07\x91\x04\x91\x19\x04\x01";
uint8_t* const des3ecb_po_key_3 = (uint8_t*)"\x01\x07\x91\x04\x91\x19\x01\x01\x01\x07\x91\x04\x91\x19\x01\x01\x01\x07\x91\x04\x91\x19\x01\x01";
uint8_t* const des3ecb_po_key_4 = (uint8_t*)"\x01\x07\x94\x04\x91\x19\x04\x01\x01\x07\x94\x04\x91\x19\x04\x01\x01\x07\x94\x04\x91\x19\x04\x01";

uint8_t* const des3ecb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3ecb_po_cipher_1 = (uint8_t*)"\x4D\x10\x21\x96\xC9\x14\xCA\x16";
uint8_t* const des3ecb_po_cipher_2 = (uint8_t*)"\x2D\xFA\x9F\x45\x73\x59\x49\x65";
uint8_t* const des3ecb_po_cipher_3 = (uint8_t*)"\xB4\x66\x04\x81\x6C\x0E\x07\x74";
uint8_t* const des3ecb_po_cipher_4 = (uint8_t*)"\x6E\x7E\x62\x21\xA4\xF3\x4E\x87";

CIPHERTEST des3ecb_po_tests[] = {
    { "DES-EDE-ECB Permutation Operation", 4, des3ecb_po_key_1, nullptr, des3ecb_po_plain, des3ecb_po_cipher_1, des3::recsize },
    { "DES-EDE-ECB Permutation Operation", 4, des3ecb_po_key_2, nullptr, des3ecb_po_plain, des3ecb_po_cipher_2, des3::recsize },
    { "DES-EDE-ECB Permutation Operation", 4, des3ecb_po_key_3, nullptr, des3ecb_po_plain, des3ecb_po_cipher_3, des3::recsize },
    { "DES-EDE-ECB Permutation Operation", 4, des3ecb_po_key_4, nullptr, des3ecb_po_plain, des3ecb_po_cipher_4, des3::recsize }
};

// DES-EDE-ECB substitution table test vectors

uint8_t* const des3ecb_st_key_1 = (uint8_t*)"\x7C\xA1\x10\x45\x4A\x1A\x6E\x57\x7C\xA1\x10\x45\x4A\x1A\x6E\x57\x7C\xA1\x10\x45\x4A\x1A\x6E\x57";
uint8_t* const des3ecb_st_key_2 = (uint8_t*)"\x01\x31\xD9\x61\x9D\xC1\x37\x6E\x01\x31\xD9\x61\x9D\xC1\x37\x6E\x01\x31\xD9\x61\x9D\xC1\x37\x6E";
uint8_t* const des3ecb_st_key_3 = (uint8_t*)"\x07\xA1\x13\x3E\x4A\x0B\x26\x86\x07\xA1\x13\x3E\x4A\x0B\x26\x86\x07\xA1\x13\x3E\x4A\x0B\x26\x86";
uint8_t* const des3ecb_st_key_4 = (uint8_t*)"\x38\x49\x67\x4C\x26\x02\x31\x9E\x38\x49\x67\x4C\x26\x02\x31\x9E\x38\x49\x67\x4C\x26\x02\x31\x9E";

uint8_t* const des3ecb_st_plain_1 = (uint8_t*)"\x01\xA1\xD6\xD0\x39\x77\x67\x42";
uint8_t* const des3ecb_st_plain_2 = (uint8_t*)"\x5C\xD5\x4C\xA8\x3D\xEF\x57\xDA";
uint8_t* const des3ecb_st_plain_3 = (uint8_t*)"\x02\x48\xD4\x38\x06\xF6\x71\x72";
uint8_t* const des3ecb_st_plain_4 = (uint8_t*)"\x51\x45\x4B\x58\x2D\xDF\x44\x0A";

uint8_t* const des3ecb_st_cipher_1 = (uint8_t*)"\x69\x0F\x5B\x0D\x9A\x26\x93\x9B";
uint8_t* const des3ecb_st_cipher_2 = (uint8_t*)"\x7A\x38\x9D\x10\x35\x4B\xD2\x71";
uint8_t* const des3ecb_st_cipher_3 = (uint8_t*)"\x86\x8E\xBB\x51\xCA\xB4\x59\x9A";
uint8_t* const des3ecb_st_cipher_4 = (uint8_t*)"\x71\x78\x87\x6E\x01\xF1\x9B\x2A";

CIPHERTEST des3ecb_st_tests[] = {
    { "DES-EDE-ECB Substitution Table", 4, des3ecb_st_key_1, nullptr, des3ecb_st_plain_1, des3ecb_st_cipher_1, des3::recsize },
    { "DES-EDE-ECB Substitution Table", 4, des3ecb_st_key_2, nullptr, des3ecb_st_plain_2, des3ecb_st_cipher_2, des3::recsize },
    { "DES-EDE-ECB Substitution Table", 4, des3ecb_st_key_3, nullptr, des3ecb_st_plain_3, des3ecb_st_cipher_3, des3::recsize },
    { "DES-EDE-ECB Substitution Table", 4, des3ecb_st_key_4, nullptr, des3ecb_st_plain_4, des3ecb_st_cipher_4, des3::recsize }
};

// DES-EDE-CBC variable plaintext test vectors

uint8_t* const des3cbc_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const des3cbc_vp_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cbc_vp_plain_1 = (uint8_t*)"\x00\x00\x00\x00\x08\x00\x00\x00";
uint8_t* const des3cbc_vp_plain_2 = (uint8_t*)"\x00\x00\x00\x00\x04\x00\x00\x00";
uint8_t* const des3cbc_vp_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x02\x00\x00\x00";
uint8_t* const des3cbc_vp_plain_4 = (uint8_t*)"\x00\x00\x00\x00\x01\x00\x00\x00";

uint8_t* const des3cbc_vp_cipher_1 = (uint8_t*)"\xCA\x3A\x2B\x03\x6D\xBC\x85\x02";
uint8_t* const des3cbc_vp_cipher_2 = (uint8_t*)"\x5E\x09\x05\x51\x7B\xB5\x9B\xCF";
uint8_t* const des3cbc_vp_cipher_3 = (uint8_t*)"\x81\x4E\xEB\x3B\x91\xD9\x07\x26";
uint8_t* const des3cbc_vp_cipher_4 = (uint8_t*)"\x4D\x49\xDB\x15\x32\x91\x9C\x9F";

CIPHERTEST des3cbc_vp_tests[] = {
    { "DES-EDE-CBC Variable Plaintext", 4, des3cbc_vp_key, des3cbc_vp_iv, des3cbc_vp_plain_1, des3cbc_vp_cipher_1, des3::recsize },
    { "DES-EDE-CBC Variable Plaintext", 4, des3cbc_vp_key, des3cbc_vp_iv, des3cbc_vp_plain_2, des3cbc_vp_cipher_2, des3::recsize },
    { "DES-EDE-CBC Variable Plaintext", 4, des3cbc_vp_key, des3cbc_vp_iv, des3cbc_vp_plain_3, des3cbc_vp_cipher_3, des3::recsize },
    { "DES-EDE-CBC Variable Plaintext", 4, des3cbc_vp_key, des3cbc_vp_iv, des3cbc_vp_plain_4, des3cbc_vp_cipher_4, des3::recsize }
};

// DES-EDE-CBC inverse permutation test vectors

uint8_t* const des3cbc_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const des3cbc_ip_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cbc_ip_plain_1 = (uint8_t*)"\x84\x05\xD1\xAB\xE2\x4F\xB9\x42";
uint8_t* const des3cbc_ip_plain_2 = (uint8_t*)"\xE6\x43\xD7\x80\x90\xCA\x42\x07";
uint8_t* const des3cbc_ip_plain_3 = (uint8_t*)"\x48\x22\x1B\x99\x37\x74\x8A\x23";
uint8_t* const des3cbc_ip_plain_4 = (uint8_t*)"\xDD\x7C\x0B\xBD\x61\xFA\xFD\x54";

uint8_t* const des3cbc_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x08\x00";
uint8_t* const des3cbc_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x04\x00";
uint8_t* const des3cbc_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x02\x00";
uint8_t* const des3cbc_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x01\x00";

CIPHERTEST des3cbc_ip_tests[] = {
    { "DES-EDE-CBC Inverse Permutation", 4, des3cbc_ip_key, des3cbc_ip_iv, des3cbc_ip_plain_1, des3cbc_ip_cipher_1, des3::recsize },
    { "DES-EDE-CBC Inverse Permutation", 4, des3cbc_ip_key, des3cbc_ip_iv, des3cbc_ip_plain_2, des3cbc_ip_cipher_2, des3::recsize },
    { "DES-EDE-CBC Inverse Permutation", 4, des3cbc_ip_key, des3cbc_ip_iv, des3cbc_ip_plain_3, des3cbc_ip_cipher_3, des3::recsize },
    { "DES-EDE-CBC Inverse Permutation", 4, des3cbc_ip_key, des3cbc_ip_iv, des3cbc_ip_plain_4, des3cbc_ip_cipher_4, des3::recsize }
};

// DES-EDE-CBC variable key test vectors

uint8_t* const des3cbc_vk_key_1 = (uint8_t*)"\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01";
uint8_t* const des3cbc_vk_key_2 = (uint8_t*)"\x01\x01\x01\x80\x01\x01\x01\x01\x01\x01\x01\x80\x01\x01\x01\x01\x01\x01\x01\x80\x01\x01\x01\x01";
uint8_t* const des3cbc_vk_key_3 = (uint8_t*)"\x01\x01\x01\x40\x01\x01\x01\x01\x01\x01\x01\x40\x01\x01\x01\x01\x01\x01\x01\x40\x01\x01\x01\x01";
uint8_t* const des3cbc_vk_key_4 = (uint8_t*)"\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01";

uint8_t* const des3cbc_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cbc_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cbc_vk_cipher_1 = (uint8_t*)"\xC7\x15\x16\xC2\x9C\x75\xD1\x70";
uint8_t* const des3cbc_vk_cipher_2 = (uint8_t*)"\x51\x99\xC2\x9A\x52\xC9\xF0\x59";
uint8_t* const des3cbc_vk_cipher_3 = (uint8_t*)"\xC2\x2F\x0A\x29\x4A\x71\xF2\x9F";
uint8_t* const des3cbc_vk_cipher_4 = (uint8_t*)"\xEE\x37\x14\x83\x71\x4C\x02\xEA";

CIPHERTEST des3cbc_vk_tests[] = {
    { "DES-EDE-CBC Variable Key", 4, des3cbc_vk_key_1, des3cbc_vk_iv, des3cbc_vk_plain, des3cbc_vk_cipher_1, des3::recsize },
    { "DES-EDE-CBC Variable Key", 4, des3cbc_vk_key_2, des3cbc_vk_iv, des3cbc_vk_plain, des3cbc_vk_cipher_2, des3::recsize },
    { "DES-EDE-CBC Variable Key", 4, des3cbc_vk_key_3, des3cbc_vk_iv, des3cbc_vk_plain, des3cbc_vk_cipher_3, des3::recsize },
    { "DES-EDE-CBC Variable Key", 4, des3cbc_vk_key_4, des3cbc_vk_iv, des3cbc_vk_plain, des3cbc_vk_cipher_4, des3::recsize }
};

// DES-EDE-CBC permutation operation test vectors

uint8_t* const des3cbc_po_key_1 = (uint8_t*)"\x19\x07\x92\x10\x98\x1A\x01\x01\x19\x07\x92\x10\x98\x1A\x01\x01\x19\x07\x92\x10\x98\x1A\x01\x01";
uint8_t* const des3cbc_po_key_2 = (uint8_t*)"\x10\x07\x91\x19\x98\x19\x08\x01\x10\x07\x91\x19\x98\x19\x08\x01\x10\x07\x91\x19\x98\x19\x08\x01";
uint8_t* const des3cbc_po_key_3 = (uint8_t*)"\x10\x07\x91\x19\x98\x1A\x08\x01\x10\x07\x91\x19\x98\x1A\x08\x01\x10\x07\x91\x19\x98\x1A\x08\x01";
uint8_t* const des3cbc_po_key_4 = (uint8_t*)"\x10\x07\x92\x10\x98\x19\x01\x01\x10\x07\x92\x10\x98\x19\x01\x01\x10\x07\x92\x10\x98\x19\x01\x01";

uint8_t* const des3cbc_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cbc_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cbc_po_cipher_1 = (uint8_t*)"\xAA\x85\xE7\x46\x43\x23\x31\x99";
uint8_t* const des3cbc_po_cipher_2 = (uint8_t*)"\x2E\x5A\x19\xDB\x4D\x19\x62\xD6";
uint8_t* const des3cbc_po_cipher_3 = (uint8_t*)"\x23\xA8\x66\xA8\x09\xD3\x08\x94";
uint8_t* const des3cbc_po_cipher_4 = (uint8_t*)"\xD8\x12\xD9\x61\xF0\x17\xD3\x20";

CIPHERTEST des3cbc_po_tests[] = {
    { "DES-EDE-CBC Permutation Operation", 4, des3cbc_po_key_1, des3cbc_po_iv, des3cbc_po_plain, des3cbc_po_cipher_1, des3::recsize },
    { "DES-EDE-CBC Permutation Operation", 4, des3cbc_po_key_2, des3cbc_po_iv, des3cbc_po_plain, des3cbc_po_cipher_2, des3::recsize },
    { "DES-EDE-CBC Permutation Operation", 4, des3cbc_po_key_3, des3cbc_po_iv, des3cbc_po_plain, des3cbc_po_cipher_3, des3::recsize },
    { "DES-EDE-CBC Permutation Operation", 4, des3cbc_po_key_4, des3cbc_po_iv, des3cbc_po_plain, des3cbc_po_cipher_4, des3::recsize }
};

// DES-EDE-CBC substitution table test vectors

uint8_t* const des3cbc_st_key_1 = (uint8_t*)"\x04\xB9\x15\xBA\x43\xFE\xB5\xB6\x04\xB9\x15\xBA\x43\xFE\xB5\xB6\x04\xB9\x15\xBA\x43\xFE\xB5\xB6";
uint8_t* const des3cbc_st_key_2 = (uint8_t*)"\x01\x13\xB9\x70\xFD\x34\xF2\xCE\x01\x13\xB9\x70\xFD\x34\xF2\xCE\x01\x13\xB9\x70\xFD\x34\xF2\xCE";
uint8_t* const des3cbc_st_key_3 = (uint8_t*)"\x01\x70\xF1\x75\x46\x8F\xB5\xE6\x01\x70\xF1\x75\x46\x8F\xB5\xE6\x01\x70\xF1\x75\x46\x8F\xB5\xE6";
uint8_t* const des3cbc_st_key_4 = (uint8_t*)"\x43\x29\x7F\xAD\x38\xE3\x73\xFE\x43\x29\x7F\xAD\x38\xE3\x73\xFE\x43\x29\x7F\xAD\x38\xE3\x73\xFE";

uint8_t* const des3cbc_st_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cbc_st_plain_1 = (uint8_t*)"\x42\xFD\x44\x30\x59\x57\x7F\xA2";
uint8_t* const des3cbc_st_plain_2 = (uint8_t*)"\x05\x9B\x5E\x08\x51\xCF\x14\x3A";
uint8_t* const des3cbc_st_plain_3 = (uint8_t*)"\x07\x56\xD8\xE0\x77\x47\x61\xD2";
uint8_t* const des3cbc_st_plain_4 = (uint8_t*)"\x76\x25\x14\xB8\x29\xBF\x48\x6A";

uint8_t* const des3cbc_st_cipher_1 = (uint8_t*)"\xAF\x37\xFB\x42\x1F\x8C\x40\x95";
uint8_t* const des3cbc_st_cipher_2 = (uint8_t*)"\x86\xA5\x60\xF1\x0E\xC6\xD8\x5B";
uint8_t* const des3cbc_st_cipher_3 = (uint8_t*)"\x0C\xD3\xDA\x02\x00\x21\xDC\x09";
uint8_t* const des3cbc_st_cipher_4 = (uint8_t*)"\xEA\x67\x6B\x2C\xB7\xDB\x2B\x7A";

CIPHERTEST des3cbc_st_tests[] = {
    { "DES-EDE-CBC Substitution Table", 4, des3cbc_st_key_1, des3cbc_st_iv, des3cbc_st_plain_1, des3cbc_st_cipher_1, des3::recsize },
    { "DES-EDE-CBC Substitution Table", 4, des3cbc_st_key_2, des3cbc_st_iv, des3cbc_st_plain_2, des3cbc_st_cipher_2, des3::recsize },
    { "DES-EDE-CBC Substitution Table", 4, des3cbc_st_key_3, des3cbc_st_iv, des3cbc_st_plain_3, des3cbc_st_cipher_3, des3::recsize },
    { "DES-EDE-CBC Substitution Table", 4, des3cbc_st_key_4, des3cbc_st_iv, des3cbc_st_plain_4, des3cbc_st_cipher_4, des3::recsize }
};

// DES-EDE-CFB variable plaintext test vectors

uint8_t* const des3cfb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const des3cfb_vp_iv_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x80\x00\x00";
uint8_t* const des3cfb_vp_iv_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x40\x00\x00";
uint8_t* const des3cfb_vp_iv_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x20\x00\x00";
uint8_t* const des3cfb_vp_iv_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x10\x00\x00";

uint8_t* const des3cfb_vp_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cfb_vp_cipher_1 = (uint8_t*)"\x25\xEB\x5F\xC3\xF8\xCF\x06\x21";
uint8_t* const des3cfb_vp_cipher_2 = (uint8_t*)"\xAB\x6A\x20\xC0\x62\x0D\x1C\x6F";
uint8_t* const des3cfb_vp_cipher_3 = (uint8_t*)"\x79\xE9\x0D\xBC\x98\xF9\x2C\xCA";
uint8_t* const des3cfb_vp_cipher_4 = (uint8_t*)"\x86\x6E\xCE\xDD\x80\x72\xBB\x0E";

CIPHERTEST des3cfb_vp_tests[] = {
    { "DES-EDE-CFB Variable Plaintext", 4, des3cfb_vp_key, des3cfb_vp_iv_1, des3cfb_vp_plain, des3cfb_vp_cipher_1, des3::recsize },
    { "DES-EDE-CFB Variable Plaintext", 4, des3cfb_vp_key, des3cfb_vp_iv_2, des3cfb_vp_plain, des3cfb_vp_cipher_2, des3::recsize },
    { "DES-EDE-CFB Variable Plaintext", 4, des3cfb_vp_key, des3cfb_vp_iv_3, des3cfb_vp_plain, des3cfb_vp_cipher_3, des3::recsize },
    { "DES-EDE-CFB Variable Plaintext", 4, des3cfb_vp_key, des3cfb_vp_iv_4, des3cfb_vp_plain, des3cfb_vp_cipher_4, des3::recsize }
};

// DES-EDE-CFB inverse permutation test vectors

uint8_t* const des3cfb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const des3cfb_ip_iv_1 = (uint8_t*)"\x2F\xBC\x29\x1A\x57\x0D\xB5\xC4";
uint8_t* const des3cfb_ip_iv_2 = (uint8_t*)"\xE0\x7C\x30\xD7\xE4\xE2\x6E\x12";
uint8_t* const des3cfb_ip_iv_3 = (uint8_t*)"\x09\x53\xE2\x25\x8E\x8E\x90\xA1";
uint8_t* const des3cfb_ip_iv_4 = (uint8_t*)"\x5B\x71\x1B\xC4\xCE\xEB\xF2\xEE";

uint8_t* const des3cfb_ip_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cfb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x80";
uint8_t* const des3cfb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x40";
uint8_t* const des3cfb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x20";
uint8_t* const des3cfb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x10";

CIPHERTEST des3cfb_ip_tests[] = {
    { "DES-EDE-CFB Inverse Permuatation", 4, des3cfb_ip_key, des3cfb_ip_iv_1, des3cfb_ip_plain, des3cfb_ip_cipher_1, des3::recsize },
    { "DES-EDE-CFB Inverse Permuatation", 4, des3cfb_ip_key, des3cfb_ip_iv_2, des3cfb_ip_plain, des3cfb_ip_cipher_2, des3::recsize },
    { "DES-EDE-CFB Inverse Permuatation", 4, des3cfb_ip_key, des3cfb_ip_iv_3, des3cfb_ip_plain, des3cfb_ip_cipher_3, des3::recsize },
    { "DES-EDE-CFB Inverse Permuatation", 4, des3cfb_ip_key, des3cfb_ip_iv_4, des3cfb_ip_plain, des3cfb_ip_cipher_4, des3::recsize }
};

// DES-EDE-CFB variable key test vectors

uint8_t* const des3cfb_vk_key_1 = (uint8_t*)"\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01";
uint8_t* const des3cfb_vk_key_2 = (uint8_t*)"\x01\x01\x01\x08\x01\x01\x01\x01\x01\x01\x01\x08\x01\x01\x01\x01\x01\x01\x01\x08\x01\x01\x01\x01";
uint8_t* const des3cfb_vk_key_3 = (uint8_t*)"\x01\x01\x01\x04\x01\x01\x01\x01\x01\x01\x01\x04\x01\x01\x01\x01\x01\x01\x01\x04\x01\x01\x01\x01";
uint8_t* const des3cfb_vk_key_4 = (uint8_t*)"\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01";

uint8_t* const des3cfb_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cfb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cfb_vk_cipher_1 = (uint8_t*)"\xA8\x1F\xBD\x44\x8F\x9E\x52\x2F";
uint8_t* const des3cfb_vk_cipher_2 = (uint8_t*)"\x4F\x64\x4C\x92\xE1\x92\xDF\xED";
uint8_t* const des3cfb_vk_cipher_3 = (uint8_t*)"\x1A\xFA\x9A\x66\xA6\xDF\x92\xAE";
uint8_t* const des3cfb_vk_cipher_4 = (uint8_t*)"\xB3\xC1\xCC\x71\x5C\xB8\x79\xD8";

CIPHERTEST des3cfb_vk_tests[] = {
    { "DES-EDE-CFB Variable Key", 4, des3cfb_vk_key_1, des3cfb_vk_iv, des3cfb_vk_plain, des3cfb_vk_cipher_1, des3::recsize },
    { "DES-EDE-CFB Variable Key", 4, des3cfb_vk_key_2, des3cfb_vk_iv, des3cfb_vk_plain, des3cfb_vk_cipher_2, des3::recsize },
    { "DES-EDE-CFB Variable Key", 4, des3cfb_vk_key_3, des3cfb_vk_iv, des3cfb_vk_plain, des3cfb_vk_cipher_3, des3::recsize },
    { "DES-EDE-CFB Variable Key", 4, des3cfb_vk_key_4, des3cfb_vk_iv, des3cfb_vk_plain, des3cfb_vk_cipher_4, des3::recsize }
};

// DES-EDE-CFB permutation operation test vectors

uint8_t* const des3cfb_po_key_1 = (uint8_t*)"\x10\x07\x91\x15\x98\x19\x01\x0B\x10\x07\x91\x15\x98\x19\x01\x0B\x10\x07\x91\x15\x98\x19\x01\x0B";
uint8_t* const des3cfb_po_key_2 = (uint8_t*)"\x10\x04\x80\x15\x98\x19\x01\x01\x10\x04\x80\x15\x98\x19\x01\x01\x10\x04\x80\x15\x98\x19\x01\x01";
uint8_t* const des3cfb_po_key_3 = (uint8_t*)"\x10\x04\x80\x15\x98\x19\x01\x02\x10\x04\x80\x15\x98\x19\x01\x02\x10\x04\x80\x15\x98\x19\x01\x02";
uint8_t* const des3cfb_po_key_4 = (uint8_t*)"\x10\x04\x80\x15\x98\x19\x01\x08\x10\x04\x80\x15\x98\x19\x01\x08\x10\x04\x80\x15\x98\x19\x01\x08";

uint8_t* const des3cfb_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cfb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cfb_po_cipher_1 = (uint8_t*)"\x05\x56\x05\x81\x6E\x58\x60\x8F";
uint8_t* const des3cfb_po_cipher_2 = (uint8_t*)"\xAB\xD8\x8E\x8B\x1B\x77\x16\xF1";
uint8_t* const des3cfb_po_cipher_3 = (uint8_t*)"\x53\x7A\xC9\x5B\xE6\x9D\xA1\xE1";
uint8_t* const des3cfb_po_cipher_4 = (uint8_t*)"\xAE\xD0\xF6\xAE\x3C\x25\xCD\xD8";

CIPHERTEST des3cfb_po_tests[] = {
    { "DES-EDE-CFB Permutation Operation", 4, des3cfb_po_key_1, des3cfb_po_iv, des3cfb_po_plain, des3cfb_po_cipher_1, des3::recsize },
    { "DES-EDE-CFB Permutation Operation", 4, des3cfb_po_key_2, des3cfb_po_iv, des3cfb_po_plain, des3cfb_po_cipher_2, des3::recsize },
    { "DES-EDE-CFB Permutation Operation", 4, des3cfb_po_key_3, des3cfb_po_iv, des3cfb_po_plain, des3cfb_po_cipher_3, des3::recsize },
    { "DES-EDE-CFB Permutation Operation", 4, des3cfb_po_key_4, des3cfb_po_iv, des3cfb_po_plain, des3cfb_po_cipher_4, des3::recsize }
};

// DES-EDE-CFB substitution table test vectors

uint8_t* const des3cfb_st_key_1 = (uint8_t*)"\x07\xA7\x13\x70\x45\xDA\x2A\x16\x07\xA7\x13\x70\x45\xDA\x2A\x16\x07\xA7\x13\x70\x45\xDA\x2A\x16";
uint8_t* const des3cfb_st_key_2 = (uint8_t*)"\x04\x68\x91\x04\xC2\xFD\x3B\x2F\x04\x68\x91\x04\xC2\xFD\x3B\x2F\x04\x68\x91\x04\xC2\xFD\x3B\x2F";
uint8_t* const des3cfb_st_key_3 = (uint8_t*)"\x37\xD0\x6B\xB5\x16\xCB\x75\x46\x37\xD0\x6B\xB5\x16\xCB\x75\x46\x37\xD0\x6B\xB5\x16\xCB\x75\x46";
uint8_t* const des3cfb_st_key_4 = (uint8_t*)"\x1F\x08\x26\x0D\x1A\xC2\x46\x5E\x1F\x08\x26\x0D\x1A\xC2\x46\x5E\x1F\x08\x26\x0D\x1A\xC2\x46\x5E";

uint8_t* const des3cfb_st_iv_1 = (uint8_t*)"\x3B\xDD\x11\x90\x49\x37\x28\x02";
uint8_t* const des3cfb_st_iv_2 = (uint8_t*)"\x26\x95\x5F\x68\x35\xAF\x60\x9A";
uint8_t* const des3cfb_st_iv_3 = (uint8_t*)"\x16\x4D\x5E\x40\x4F\x27\x52\x32";
uint8_t* const des3cfb_st_iv_4 = (uint8_t*)"\x6B\x05\x6E\x18\x75\x9F\x5C\xCA";

uint8_t* const des3cfb_st_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3cfb_st_cipher_1 = (uint8_t*)"\xDF\xD6\x4A\x81\x5C\xAF\x1A\x0F";
uint8_t* const des3cfb_st_cipher_2 = (uint8_t*)"\x5C\x51\x3C\x9C\x48\x86\xC0\x88";
uint8_t* const des3cfb_st_cipher_3 = (uint8_t*)"\x0A\x2A\xEE\xAE\x3F\xF4\xAB\x77";
uint8_t* const des3cfb_st_cipher_4 = (uint8_t*)"\xEF\x1B\xF0\x3E\x5D\xFA\x57\x5A";

CIPHERTEST des3cfb_st_tests[] = {
    { "DES-EDE-CFB Substitution Table", 4, des3cfb_st_key_1, des3cfb_st_iv_1, des3cfb_st_plain, des3cfb_st_cipher_1, des3::recsize },
    { "DES-EDE-CFB Substitution Table", 4, des3cfb_st_key_2, des3cfb_st_iv_2, des3cfb_st_plain, des3cfb_st_cipher_2, des3::recsize },
    { "DES-EDE-CFB Substitution Table", 4, des3cfb_st_key_3, des3cfb_st_iv_3, des3cfb_st_plain, des3cfb_st_cipher_3, des3::recsize },
    { "DES-EDE-CFB Substitution Table", 4, des3cfb_st_key_4, des3cfb_st_iv_4, des3cfb_st_plain, des3cfb_st_cipher_4, des3::recsize }
};

// DES-EDE-OFB variable plaintext test vectors

uint8_t* const des3ofb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const des3ofb_vp_iv_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x08\x00\x00";
uint8_t* const des3ofb_vp_iv_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x04\x00\x00";
uint8_t* const des3ofb_vp_iv_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x02\x00\x00";
uint8_t* const des3ofb_vp_iv_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x01\x00\x00";

uint8_t* const des3ofb_vp_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3ofb_vp_cipher_1 = (uint8_t*)"\x8B\x54\x53\x6F\x2F\x3E\x64\xA8";
uint8_t* const des3ofb_vp_cipher_2 = (uint8_t*)"\xEA\x51\xD3\x97\x55\x95\xB8\x6B";
uint8_t* const des3ofb_vp_cipher_3 = (uint8_t*)"\xCA\xFF\xC6\xAC\x45\x42\xDE\x31";
uint8_t* const des3ofb_vp_cipher_4 = (uint8_t*)"\x8D\xD4\x5A\x2D\xDF\x90\x79\x6C";

CIPHERTEST des3ofb_vp_tests[] = {
    { "DES-EDE-OFB Variable Plaintext", 4, des3ofb_vp_key, des3ofb_vp_iv_1, des3ofb_vp_plain, des3ofb_vp_cipher_1, des3::recsize },
    { "DES-EDE-OFB Variable Plaintext", 4, des3ofb_vp_key, des3ofb_vp_iv_2, des3ofb_vp_plain, des3ofb_vp_cipher_2, des3::recsize },
    { "DES-EDE-OFB Variable Plaintext", 4, des3ofb_vp_key, des3ofb_vp_iv_3, des3ofb_vp_plain, des3ofb_vp_cipher_3, des3::recsize },
    { "DES-EDE-OFB Variable Plaintext", 4, des3ofb_vp_key, des3ofb_vp_iv_4, des3ofb_vp_plain, des3ofb_vp_cipher_4, des3::recsize }
};

// DES-EDE-OFB inverse permutation test vectors

uint8_t* const des3ofb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* const des3ofb_ip_iv_1 = (uint8_t*)"\xCC\x08\x3F\x1E\x6D\x9E\x85\xF6";
uint8_t* const des3ofb_ip_iv_2 = (uint8_t*)"\xD2\xFD\x88\x67\xD5\x0D\x2D\xFE";
uint8_t* const des3ofb_ip_iv_3 = (uint8_t*)"\x06\xE7\xEA\x22\xCE\x92\x70\x8F";
uint8_t* const des3ofb_ip_iv_4 = (uint8_t*)"\x16\x6B\x40\xB4\x4A\xBA\x4B\xD6";

uint8_t* const des3ofb_ip_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3ofb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x08";
uint8_t* const des3ofb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x04";
uint8_t* const des3ofb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x02";
uint8_t* const des3ofb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x01";

CIPHERTEST des3ofb_ip_tests[] = {
    { "DES-EDE-OFB Inverse Permutation", 4, des3ofb_ip_key, des3ofb_ip_iv_1, des3ofb_ip_plain, des3ofb_ip_cipher_1, des3::recsize },
    { "DES-EDE-OFB Inverse Permutation", 4, des3ofb_ip_key, des3ofb_ip_iv_2, des3ofb_ip_plain, des3ofb_ip_cipher_2, des3::recsize },
    { "DES-EDE-OFB Inverse Permutation", 4, des3ofb_ip_key, des3ofb_ip_iv_3, des3ofb_ip_plain, des3ofb_ip_cipher_3, des3::recsize },
    { "DES-EDE-OFB Inverse Permutation", 4, des3ofb_ip_key, des3ofb_ip_iv_4, des3ofb_ip_plain, des3ofb_ip_cipher_4, des3::recsize }
};

// DES-EDE-OFB variable key test vectors

uint8_t* const des3ofb_vk_key_1 = (uint8_t*)"\x01\x01\x01\x01\x80\x01\x01\x01\x01\x01\x01\x01\x80\x01\x01\x01\x01\x01\x01\x01\x80\x01\x01\x01";
uint8_t* const des3ofb_vk_key_2 = (uint8_t*)"\x01\x01\x01\x01\x40\x01\x01\x01\x01\x01\x01\x01\x40\x01\x01\x01\x01\x01\x01\x01\x40\x01\x01\x01";
uint8_t* const des3ofb_vk_key_3 = (uint8_t*)"\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01";
uint8_t* const des3ofb_vk_key_4 = (uint8_t*)"\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01";

uint8_t* const des3ofb_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3ofb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3ofb_vk_cipher_1 = (uint8_t*)"\x19\xD0\x32\xE6\x4A\xB0\xBD\x8B";
uint8_t* const des3ofb_vk_cipher_2 = (uint8_t*)"\x3C\xFA\xA7\xA7\xDC\x87\x20\xDC";
uint8_t* const des3ofb_vk_cipher_3 = (uint8_t*)"\xB7\x26\x5F\x7F\x44\x7A\xC6\xF3";
uint8_t* const des3ofb_vk_cipher_4 = (uint8_t*)"\x9D\xB7\x3B\x3C\x0D\x16\x3F\x54";

CIPHERTEST des3ofb_vk_tests[] = {
    { "DES-EDE-OFB Variable Key", 4, des3ofb_vk_key_1, des3ofb_vk_iv, des3ofb_vk_plain, des3ofb_vk_cipher_1, des3::recsize },
    { "DES-EDE-OFB Variable Key", 4, des3ofb_vk_key_2, des3ofb_vk_iv, des3ofb_vk_plain, des3ofb_vk_cipher_2, des3::recsize },
    { "DES-EDE-OFB Variable Key", 4, des3ofb_vk_key_3, des3ofb_vk_iv, des3ofb_vk_plain, des3ofb_vk_cipher_3, des3::recsize },
    { "DES-EDE-OFB Variable Key", 4, des3ofb_vk_key_4, des3ofb_vk_iv, des3ofb_vk_plain, des3ofb_vk_cipher_4, des3::recsize }
};

// DES-EDE-OFB permutation operation test vectors

uint8_t* const des3ofb_po_key_1 = (uint8_t*)"\x10\x02\x91\x15\x98\x10\x01\x04\x10\x02\x91\x15\x98\x10\x01\x04\x10\x02\x91\x15\x98\x10\x01\x04";
uint8_t* const des3ofb_po_key_2 = (uint8_t*)"\x10\x02\x91\x15\x98\x19\x01\x04\x10\x02\x91\x15\x98\x19\x01\x04\x10\x02\x91\x15\x98\x19\x01\x04";
uint8_t* const des3ofb_po_key_3 = (uint8_t*)"\x10\x02\x91\x15\x98\x10\x02\x01\x10\x02\x91\x15\x98\x10\x02\x01\x10\x02\x91\x15\x98\x10\x02\x01";
uint8_t* const des3ofb_po_key_4 = (uint8_t*)"\x10\x02\x91\x16\x98\x10\x01\x01\x10\x02\x91\x16\x98\x10\x01\x01\x10\x02\x91\x16\x98\x10\x01\x01";

uint8_t* const des3ofb_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3ofb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3ofb_po_cipher_1 = (uint8_t*)"\xB3\xE3\x5A\x5E\xE5\x3E\x7B\x8D";
uint8_t* const des3ofb_po_cipher_2 = (uint8_t*)"\x61\xC7\x9C\x71\x92\x1A\x2E\xF8";
uint8_t* const des3ofb_po_cipher_3 = (uint8_t*)"\xE2\xF5\x72\x8F\x09\x95\x01\x3C";
uint8_t* const des3ofb_po_cipher_4 = (uint8_t*)"\x1A\xEA\xC3\x9A\x61\xF0\xA4\x64";

CIPHERTEST des3ofb_po_tests[] = {
    { "DES-EDE-OFB Permutation Operation", 4, des3ofb_po_key_1, des3ofb_po_iv, des3ofb_po_plain, des3ofb_po_cipher_1, des3::recsize },
    { "DES-EDE-OFB Permutation Operation", 4, des3ofb_po_key_2, des3ofb_po_iv, des3ofb_po_plain, des3ofb_po_cipher_2, des3::recsize },
    { "DES-EDE-OFB Permutation Operation", 4, des3ofb_po_key_3, des3ofb_po_iv, des3ofb_po_plain, des3ofb_po_cipher_3, des3::recsize },
    { "DES-EDE-OFB Permutation Operation", 4, des3ofb_po_key_4, des3ofb_po_iv, des3ofb_po_plain, des3ofb_po_cipher_4, des3::recsize }
};

// DES-EDE-OFB substitution table test vectors

uint8_t* const des3ofb_st_key_1 = (uint8_t*)"\x58\x40\x23\x64\x1A\xBA\x61\x76\x58\x40\x23\x64\x1A\xBA\x61\x76\x58\x40\x23\x64\x1A\xBA\x61\x76";
uint8_t* const des3ofb_st_key_2 = (uint8_t*)"\x02\x58\x16\x16\x46\x29\xB0\x07\x02\x58\x16\x16\x46\x29\xB0\x07\x02\x58\x16\x16\x46\x29\xB0\x07";
uint8_t* const des3ofb_st_key_3 = (uint8_t*)"\x49\x79\x3E\xBC\x79\xB3\x25\x8F\x49\x79\x3E\xBC\x79\xB3\x25\x8F\x49\x79\x3E\xBC\x79\xB3\x25\x8F";
uint8_t* const des3ofb_st_key_4 = (uint8_t*)"\x4F\xB0\x5E\x15\x15\xAB\x73\xA7\x4F\xB0\x5E\x15\x15\xAB\x73\xA7\x4F\xB0\x5E\x15\x15\xAB\x73\xA7";

uint8_t* const des3ofb_st_iv_1 = (uint8_t*)"\x00\x4B\xD6\xEF\x09\x17\x60\x62";
uint8_t* const des3ofb_st_iv_2 = (uint8_t*)"\x48\x0D\x39\x00\x6E\xE7\x62\xF2";
uint8_t* const des3ofb_st_iv_3 = (uint8_t*)"\x43\x75\x40\xC8\x69\x8F\x3C\xFA";
uint8_t* const des3ofb_st_iv_4 = (uint8_t*)"\x07\x2D\x43\xA0\x77\x07\x52\x92";

uint8_t* const des3ofb_st_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const des3ofb_st_cipher_1 = (uint8_t*)"\x88\xBF\x0D\xB6\xD7\x0D\xEE\x56";
uint8_t* const des3ofb_st_cipher_2 = (uint8_t*)"\xA1\xF9\x91\x55\x41\x02\x0B\x56";
uint8_t* const des3ofb_st_cipher_3 = (uint8_t*)"\x6F\xBF\x1C\xAF\xCF\xFD\x05\x56";
uint8_t* const des3ofb_st_cipher_4 = (uint8_t*)"\x2F\x22\xE4\x9B\xAB\x7C\xA1\xAC";

CIPHERTEST des3ofb_st_tests[] = {
    { "DES-EDE-OFB Substitution Table", 4, des3ofb_st_key_1, des3ofb_st_iv_1, des3ofb_st_plain, des3ofb_st_cipher_1, des3::recsize },
    { "DES-EDE-OFB Substitution Table", 4, des3ofb_st_key_2, des3ofb_st_iv_2, des3ofb_st_plain, des3ofb_st_cipher_2, des3::recsize },
    { "DES-EDE-OFB Substitution Table", 4, des3ofb_st_key_3, des3ofb_st_iv_3, des3ofb_st_plain, des3ofb_st_cipher_3, des3::recsize },
    { "DES-EDE-OFB Substitution Table", 4, des3ofb_st_key_4, des3ofb_st_iv_4, des3ofb_st_plain, des3ofb_st_cipher_4, des3::recsize }
};

// AES-ECB-128 test vectors

uint8_t* const aes128ecb_key_1 = (uint8_t*)"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
uint8_t* const aes128ecb_key_2 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
uint8_t* const aes128ecb_key_3 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const aes128ecb_key_4 = (uint8_t*)"\x10\xa5\x88\x69\xd7\x4b\xe5\xa3\x74\xcf\x86\x7c\xfb\x47\x38\x59";
uint8_t* const aes128ecb_key_5 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const aes128ecb_plain_1 = (uint8_t*)"\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34";
uint8_t* const aes128ecb_plain_2 = (uint8_t*)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
uint8_t* const aes128ecb_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const aes128ecb_plain_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const aes128ecb_plain_5 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const aes128ecb_cipher_1 = (uint8_t*)"\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32";
uint8_t* const aes128ecb_cipher_2 = (uint8_t*)"\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a";
uint8_t* const aes128ecb_cipher_3 = (uint8_t*)"\x0e\xdd\x33\xd3\xc6\x21\xe5\x46\x45\x5b\xd8\xba\x14\x18\xbe\xc8";
uint8_t* const aes128ecb_cipher_4 = (uint8_t*)"\x6d\x25\x1e\x69\x44\xb0\x51\xe0\x4e\xaa\x6f\xb4\xdb\xf7\x84\x65";
uint8_t* const aes128ecb_cipher_5 = (uint8_t*)"\x3a\xd7\x8e\x72\x6c\x1e\xc0\x2b\x7e\xbf\xe9\x2b\x23\xd9\xec\x34";

CIPHERTEST aes128ecb_tests[] = {
    { "AES-128-ECB", 5, aes128ecb_key_1, nullptr, aes128ecb_plain_1, aes128ecb_cipher_1, aes::blockbytes },
    { "AES-128-ECB", 5, aes128ecb_key_2, nullptr, aes128ecb_plain_2, aes128ecb_cipher_2, aes::blockbytes },
    { "AES-128-ECB", 5, aes128ecb_key_3, nullptr, aes128ecb_plain_3, aes128ecb_cipher_3, aes::blockbytes },
    { "AES-128-ECB", 5, aes128ecb_key_4, nullptr, aes128ecb_plain_4, aes128ecb_cipher_4, aes::blockbytes },
    { "AES-128-ECB", 5, aes128ecb_key_5, nullptr, aes128ecb_plain_5, aes128ecb_cipher_5, aes::blockbytes }
};

// AES-ECB-192 test vectors

uint8_t* const aes192ecb_key_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17";
uint8_t* const aes192ecb_key_2 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const aes192ecb_key_3 = (uint8_t*)"\xe9\xf0\x65\xd7\xc1\x35\x73\x58\x7f\x78\x75\x35\x7d\xfb\xb1\x6c\x53\x48\x9f\x6a\x4b\xd0\xf7\xcd";
uint8_t* const aes192ecb_key_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const aes192ecb_plain_1 = (uint8_t*)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
uint8_t* const aes192ecb_plain_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const aes192ecb_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const aes192ecb_plain_4 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const aes192ecb_cipher_1 = (uint8_t*)"\xdd\xa9\x7c\xa4\x86\x4c\xdf\xe0\x6e\xaf\x70\xa0\xec\x0d\x71\x91";
uint8_t* const aes192ecb_cipher_2 = (uint8_t*)"\xde\x88\x5d\xc8\x7f\x5a\x92\x59\x40\x82\xd0\x2c\xc1\xe1\xb4\x2c";
uint8_t* const aes192ecb_cipher_3 = (uint8_t*)"\x09\x56\x25\x9c\x9c\xd5\xcf\xd0\x18\x1c\xca\x53\x38\x0c\xde\x06";
uint8_t* const aes192ecb_cipher_4 = (uint8_t*)"\x6c\xd0\x25\x13\xe8\xd4\xdc\x98\x6b\x4a\xfe\x08\x7a\x60\xbd\x0c";

CIPHERTEST aes192ecb_tests[] = {
    { "AES-192-ECB", 4, aes192ecb_key_1, nullptr, aes192ecb_plain_1, aes192ecb_cipher_1, aes::blockbytes },
    { "AES-192-ECB", 4, aes192ecb_key_2, nullptr, aes192ecb_plain_2, aes192ecb_cipher_2, aes::blockbytes },
    { "AES-192-ECB", 4, aes192ecb_key_3, nullptr, aes192ecb_plain_3, aes192ecb_cipher_3, aes::blockbytes },
    { "AES-192-ECB", 4, aes192ecb_key_4, nullptr, aes192ecb_plain_4, aes192ecb_cipher_4, aes::blockbytes }
};

// AES-ECB-256 test vectors

uint8_t* const aes256ecb_key_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
uint8_t* const aes256ecb_key_2 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const aes256ecb_key_3 = (uint8_t*)"\xc4\x7b\x02\x94\xdb\xbb\xee\x0f\xec\x47\x57\xf2\x2f\xfe\xee\x35\x87\xca\x47\x30\xc3\xd3\x3b\x69\x1d\xf3\x8b\xab\x07\x6b\xc5\x58";
uint8_t* const aes256ecb_key_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const aes256ecb_plain_1 = (uint8_t*)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
uint8_t* const aes256ecb_plain_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const aes256ecb_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const aes256ecb_plain_4 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* const aes256ecb_cipher_1 = (uint8_t*)"\x8e\xa2\xb7\xca\x51\x67\x45\xbf\xea\xfc\x49\x90\x4b\x49\x60\x89";
uint8_t* const aes256ecb_cipher_2 = (uint8_t*)"\xe3\x5a\x6d\xcb\x19\xb2\x01\xa0\x1e\xbc\xfa\x8a\xa2\x2b\x57\x59";
uint8_t* const aes256ecb_cipher_3 = (uint8_t*)"\x46\xf2\xfb\x34\x2d\x6f\x0a\xb4\x77\x47\x6f\xc5\x01\x24\x2c\x5f";
uint8_t* const aes256ecb_cipher_4 = (uint8_t*)"\xdd\xc6\xbf\x79\x0c\x15\x76\x0d\x8d\x9a\xeb\x6f\x9a\x75\xfd\x4e";

CIPHERTEST aes256ecb_tests[] = {
    { "AES-256-ECB", 4, aes256ecb_key_1, nullptr, aes256ecb_plain_1, aes256ecb_cipher_1, aes::blockbytes },
    { "AES-256-ECB", 4, aes256ecb_key_2, nullptr, aes256ecb_plain_2, aes256ecb_cipher_2, aes::blockbytes },
    { "AES-256-ECB", 4, aes256ecb_key_3, nullptr, aes256ecb_plain_3, aes256ecb_cipher_3, aes::blockbytes },
    { "AES-256-ECB", 4, aes256ecb_key_4, nullptr, aes256ecb_plain_4, aes256ecb_cipher_4, aes::blockbytes }
};

// AES-CBC-128 test vectors

uint8_t* const aes128cbc_key_1 = (uint8_t*)"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
uint8_t* const aes128cbc_key_2 = (uint8_t*)"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
uint8_t* const aes128cbc_key_3 = (uint8_t*)"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
uint8_t* const aes128cbc_key_4 = (uint8_t*)"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";

uint8_t* const aes128cbc_iv_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
uint8_t* const aes128cbc_iv_2 = (uint8_t*)"\x76\x49\xAB\xAC\x81\x19\xB2\x46\xCE\xE9\x8E\x9B\x12\xE9\x19\x7D";
uint8_t* const aes128cbc_iv_3 = (uint8_t*)"\x50\x86\xCB\x9B\x50\x72\x19\xEE\x95\xDB\x11\x3A\x91\x76\x78\xB2";
uint8_t* const aes128cbc_iv_4 = (uint8_t*)"\x73\xBE\xD6\xB8\xE3\xC1\x74\x3B\x71\x16\xE6\x9E\x22\x22\x95\x16";

uint8_t* const aes128cbc_plain_1 = (uint8_t*)"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A";
uint8_t* const aes128cbc_plain_2 = (uint8_t*)"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51";
uint8_t* const aes128cbc_plain_3 = (uint8_t*)"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF";
uint8_t* const aes128cbc_plain_4 = (uint8_t*)"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";

uint8_t* const aes128cbc_cipher_1 = (uint8_t*)"\x76\x49\xAB\xAC\x81\x19\xB2\x46\xCE\xE9\x8E\x9B\x12\xE9\x19\x7D";
uint8_t* const aes128cbc_cipher_2 = (uint8_t*)"\x50\x86\xCB\x9B\x50\x72\x19\xEE\x95\xDB\x11\x3A\x91\x76\x78\xB2";
uint8_t* const aes128cbc_cipher_3 = (uint8_t*)"\x73\xBE\xD6\xB8\xE3\xC1\x74\x3B\x71\x16\xE6\x9E\x22\x22\x95\x16";
uint8_t* const aes128cbc_cipher_4 = (uint8_t*)"\x3F\xF1\xCA\xA1\x68\x1F\xAC\x09\x12\x0E\xCA\x30\x75\x86\xE1\xA7";

CIPHERTEST aes128cbc_tests[] = {
    { "AES-128-CBC", 4, aes128cbc_key_1, aes128cbc_iv_1, aes128cbc_plain_1, aes128cbc_cipher_1, aes::blockbytes },
    { "AES-128-CBC", 4, aes128cbc_key_2, aes128cbc_iv_2, aes128cbc_plain_2, aes128cbc_cipher_2, aes::blockbytes },
    { "AES-128-CBC", 4, aes128cbc_key_3, aes128cbc_iv_3, aes128cbc_plain_3, aes128cbc_cipher_3, aes::blockbytes },
    { "AES-128-CBC", 4, aes128cbc_key_4, aes128cbc_iv_4, aes128cbc_plain_4, aes128cbc_cipher_4, aes::blockbytes }
};

// AES-CBC-192 test vectors

uint8_t* const aes192cbc_key_1 = (uint8_t*)"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B";
uint8_t* const aes192cbc_key_2 = (uint8_t*)"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B";
uint8_t* const aes192cbc_key_3 = (uint8_t*)"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B";
uint8_t* const aes192cbc_key_4 = (uint8_t*)"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B";

uint8_t* const aes192cbc_iv_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
uint8_t* const aes192cbc_iv_2 = (uint8_t*)"\x4F\x02\x1D\xB2\x43\xBC\x63\x3D\x71\x78\x18\x3A\x9F\xA0\x71\xE8";
uint8_t* const aes192cbc_iv_3 = (uint8_t*)"\xB4\xD9\xAD\xA9\xAD\x7D\xED\xF4\xE5\xE7\x38\x76\x3F\x69\x14\x5A";
uint8_t* const aes192cbc_iv_4 = (uint8_t*)"\x57\x1B\x24\x20\x12\xFB\x7A\xE0\x7F\xA9\xBA\xAC\x3D\xF1\x02\xE0";

uint8_t* const aes192cbc_plain_1 = (uint8_t*)"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A";
uint8_t* const aes192cbc_plain_2 = (uint8_t*)"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51";
uint8_t* const aes192cbc_plain_3 = (uint8_t*)"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF";
uint8_t* const aes192cbc_plain_4 = (uint8_t*)"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";

uint8_t* const aes192cbc_cipher_1 = (uint8_t*)"\x4F\x02\x1D\xB2\x43\xBC\x63\x3D\x71\x78\x18\x3A\x9F\xA0\x71\xE8";
uint8_t* const aes192cbc_cipher_2 = (uint8_t*)"\xB4\xD9\xAD\xA9\xAD\x7D\xED\xF4\xE5\xE7\x38\x76\x3F\x69\x14\x5A";
uint8_t* const aes192cbc_cipher_3 = (uint8_t*)"\x57\x1B\x24\x20\x12\xFB\x7A\xE0\x7F\xA9\xBA\xAC\x3D\xF1\x02\xE0";
uint8_t* const aes192cbc_cipher_4 = (uint8_t*)"\x08\xB0\xE2\x79\x88\x59\x88\x81\xD9\x20\xA9\xE6\x4F\x56\x15\xCD";

CIPHERTEST aes192cbc_tests[] = {
    { "AES-192-CBC", 4, aes192cbc_key_1, aes192cbc_iv_1, aes192cbc_plain_1, aes192cbc_cipher_1, aes::blockbytes },
    { "AES-192-CBC", 4, aes192cbc_key_2, aes192cbc_iv_2, aes192cbc_plain_2, aes192cbc_cipher_2, aes::blockbytes },
    { "AES-192-CBC", 4, aes192cbc_key_3, aes192cbc_iv_3, aes192cbc_plain_3, aes192cbc_cipher_3, aes::blockbytes },
    { "AES-192-CBC", 4, aes192cbc_key_4, aes192cbc_iv_4, aes192cbc_plain_4, aes192cbc_cipher_4, aes::blockbytes }
};

// AES-CBC-256 test vectors

uint8_t* const aes256cbc_key_1 = (uint8_t*)"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4";
uint8_t* const aes256cbc_key_2 = (uint8_t*)"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4";
uint8_t* const aes256cbc_key_3 = (uint8_t*)"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4";
uint8_t* const aes256cbc_key_4 = (uint8_t*)"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4";

uint8_t* const aes256cbc_iv_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
uint8_t* const aes256cbc_iv_2 = (uint8_t*)"\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6";
uint8_t* const aes256cbc_iv_3 = (uint8_t*)"\x9C\xFC\x4E\x96\x7E\xDB\x80\x8D\x67\x9F\x77\x7B\xC6\x70\x2C\x7D";
uint8_t* const aes256cbc_iv_4 = (uint8_t*)"\x39\xF2\x33\x69\xA9\xD9\xBA\xCF\xA5\x30\xE2\x63\x04\x23\x14\x61";

uint8_t* const aes256cbc_plain_1 = (uint8_t*)"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A";
uint8_t* const aes256cbc_plain_2 = (uint8_t*)"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51";
uint8_t* const aes256cbc_plain_3 = (uint8_t*)"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF";
uint8_t* const aes256cbc_plain_4 = (uint8_t*)"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";

uint8_t* const aes256cbc_cipher_1 = (uint8_t*)"\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6";
uint8_t* const aes256cbc_cipher_2 = (uint8_t*)"\x9C\xFC\x4E\x96\x7E\xDB\x80\x8D\x67\x9F\x77\x7B\xC6\x70\x2C\x7D";
uint8_t* const aes256cbc_cipher_3 = (uint8_t*)"\x39\xF2\x33\x69\xA9\xD9\xBA\xCF\xA5\x30\xE2\x63\x04\x23\x14\x61";
uint8_t* const aes256cbc_cipher_4 = (uint8_t*)"\xB2\xEB\x05\xE2\xC3\x9B\xE9\xFC\xDA\x6C\x19\x07\x8C\x6A\x9D\x1B";

CIPHERTEST aes256cbc_tests[]{
    { "AES-256-CBC", 4, aes256cbc_key_1, aes256cbc_iv_1, aes256cbc_plain_1, aes256cbc_cipher_1, aes::blockbytes },
    { "AES-256-CBC", 4, aes256cbc_key_2, aes256cbc_iv_2, aes256cbc_plain_2, aes256cbc_cipher_2, aes::blockbytes },
    { "AES-256-CBC", 4, aes256cbc_key_3, aes256cbc_iv_3, aes256cbc_plain_3, aes256cbc_cipher_3, aes::blockbytes },
    { "AES-256-CBC", 4, aes256cbc_key_4, aes256cbc_iv_4, aes256cbc_plain_4, aes256cbc_cipher_4, aes::blockbytes }
};

// ANSI X9.31 test vectors: ANSI X9.31 Appendix A.2.4 using Triple-DES

uint8_t* const x931des3_key = (uint8_t*)"\xfb\xf7\x31\x26\xd0\xd3\xbf\x51\xae\xce\x9d\x98\xa1\x13\xc8\x68\xb9\x16\x15\xb9\x1f\x6d\xb9\x26";
uint8_t* const x931des3_dt = (uint8_t*)"\x5c\x8d\x9e\x2d\x2b\x61\x9b\x0e";
uint8_t* const x931des3_v = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00";
uint8_t* const x931des3_r = (uint8_t*)"\xF7\xdf\x53\x33\x3a\x5b\x44\xeb";

// PBKDF2 test vectors: https://tools.ietf.org/html/draft-josefsson-ppkdf2-test-vectors-06

uint8_t* const pbkdf2_p_1 = (uint8_t*)"password";
uint8_t* const pbkdf2_s_1 = (uint8_t*)"salt";
uint32_t const pbkdf2_c_1 = 1;
uint32_t const pbkdf2_dklen_1 = 20;
uint8_t* const pbkdf2_o_1 = (uint8_t*)"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6";

uint8_t* const pbkdf2_p_2 = (uint8_t*)"password";
uint8_t* const pbkdf2_s_2 = (uint8_t*)"salt";
uint32_t const pbkdf2_c_2 = 2;
uint32_t const pbkdf2_dklen_2 = 20;
uint8_t* const pbkdf2_o_2 = (uint8_t*)"\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57";

// large integer test vectors

uint8_t* inthex_vector_1 = (uint8_t*)
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f";

// compression test value

#define COMPRESS_RECORD     "When in the Course of human events it becomes necessary " \
                            "for one people to dissolve the political bands which have " \
                            "connected them with another and to assume among the powers " \
                            "of the earth, the separate and equal station to which the " \
                            "Laws of Nature and of Nature's God entitle them, a decent " \
                            "respect to the opinions of mankind requires that they " \
                            "should declare the causes which impel them to the separation."

*/

bool _all = false;
bool _dump = false;

/*

void queryRun(const char* prompt, void(*fn)())
{
    char ch[3] = { 0 };
    if (!_all) {
        printf("Run %s Tests? (y/N) ", prompt);
        fflush(stdin);
        fgets(ch, sizeof(ch), stdin);
        if (('y' == ch[0]) || ('Y' == ch[0]))
            fn();
    } else
        fn();
}

void dumpMem(uint8_t* p, size_t len)
{
    uint16_t adr = 0;
    uint16_t col = 0;
    uint8_t byte;
    char line[73];
    memset(line, ' ', sizeof(line));
    line[54] = '|';
    line[71] = '|';
    line[72] = '\0';
    for (; len; adr += 16) {
        line[0] = Bin2AscHex[(adr >> 12) & 15];
        line[1] = Bin2AscHex[(adr >> 8) & 15];
        line[2] = Bin2AscHex[(adr >> 4) & 15];
        line[3] = Bin2AscHex[(adr) & 15];
        for (col = 0; col < 16; col++) {
            if (len) {
                len--;
                byte = *p++;
                line[col + 55] = Bin2AscPrt[byte];
                line[col * 3 + 6] = Bin2AscHex[(byte >> 4) & 15];
                line[col * 3 + 7] = Bin2AscHex[(byte) & 15];
            } else {
                line[col + 55] = ' ';
                line[col * 3 + 6] = ' ';
                line[col * 3 + 7] = ' ';
            }
        }
        printf("%s\n", line);
    }
}

void testDigest(Digest& digest, uint8_t* hash, DIGESTTEST* tests)
{
    printf("Testing %s\n", tests[0].label);
    if (!_dump)
        printf("\n");
    for (int x = 0; x < tests[0].count; x++) {
        digest.Begin();
        for (int i = tests[x].iter; i; i--)
            digest.Update(tests[x].vector, tests[x].len);
        digest.End();
        digest.GetDigest(hash);
        if (_dump) {
            printf("\n");
            printf("Vector (iterated %i %s):\n", tests[x].iter, tests[x].iter > 1 ? "times" : "time");
            dumpMem(tests[x].vector, tests[x].len);
            printf("Digest:\n");
            dumpMem(hash, digest._hashBytes);
            printf("\n");
        }
        printf("%-5s %s %i of %i\n", memcmp(hash, tests[x].digest, digest._hashBytes) ? "FAIL" : "OK", tests[x].label, x + 1, tests[x].count);
    }
    printf("\n");
}

void testMD5()
{
    uint8_t hash[md5::hashbytes] = { 0 };
    MD5 digest;
    testDigest(digest, hash, md5_tests);
}

void testSHA1()
{
    uint8_t hash[sha1::hashbytes] = { 0 };
    SHA1 sha;
    testDigest(sha, hash, sha1_tests);
}

void testSHA256()
{
    uint8_t hash[sha256::hashbytes] = { 0 };
    SHA256 sha;
    testDigest(sha, hash, sha256_tests);
}

void testSHA224()
{
    uint8_t hash[sha224::hashbytes] = { 0 };
    SHA224 sha;
    testDigest(sha, hash, sha224_tests);
}

void testSHA512()
{
    uint8_t hash[sha512::hashbytes] = { 0 };
    SHA512 sha;
    testDigest(sha, hash, sha512_tests);
}

void testSHA384()
{
    uint8_t hash[sha384::hashbytes] = { 0 };
    SHA384 sha;
    testDigest(sha, hash, sha384_tests);
}

void testDigestAlgs()
{
    queryRun(md5_tests[0].label, testMD5);
    queryRun(sha1_tests[0].label, testSHA1);
    queryRun(sha256_tests[0].label, testSHA256);
    queryRun(sha224_tests[0].label, testSHA224);
    queryRun(sha512_tests[0].label, testSHA512);
    queryRun(sha384_tests[0].label, testSHA384);
}

void testHMAC(uint8_t alg, HMACTEST* tests)
{
    uint8_t buf[hmac::maxhashbytes] = { 0 };
    HMAC hmac;
    printf("Testing %s\n", tests[0].label);
    if (!_dump)
        printf("\n");
    hmac.SetDigestAlg(alg);
    for (int x = 0; x < tests[0].count; x++) {
        hmac.SetKey(tests[x].key, tests[x].keylen);
        hmac.Begin();
        hmac.Update(tests[x].data, tests[x].datalen);
        hmac.End();
        hmac.GetMAC(buf, sizeof(buf));
        if (_dump) {
            printf("\n");
            printf("Key:\n");
            dumpMem(tests[x].key, tests[x].keylen);
            printf("Data:\n");
            dumpMem(tests[x].data, tests[x].datalen);
            printf("Digest:\n");
            dumpMem(tests[x].digest, tests[x].digestlen);
            printf("HMAC:\n");
            dumpMem(buf, tests[x].digestlen);
            printf("\n");
        }
        printf("%-5s %s %i of %i\n", memcmp(buf, tests[x].digest, tests[x].digestlen) ? "FAIL" : "OK", tests[x].label, x + 1, tests[x].count);
    }
    printf("\n");
}

void testHMACMD5()
{
    testHMAC(hmac::alg::md5, hmac_md5_tests);
}

void testHMACSHA1()
{
    testHMAC(hmac::alg::sha1, hmac_sha1_tests);
}

void testHMACSHA256()
{
    testHMAC(hmac::alg::sha256, hmac_sha256_tests);
}

void testHMACSHA224()
{
    testHMAC(hmac::alg::sha224, hmac_sha224_tests);
}

void testHMACSHA512()
{
    testHMAC(hmac::alg::sha512, hmac_sha512_tests);
}

void testHMACSHA384()
{
    testHMAC(hmac::alg::sha384, hmac_sha384_tests);
}

void testHMACAlgs()
{
    queryRun("HMAC-MD5", testHMACMD5);
    queryRun("HMAC-SHA1", testHMACSHA1);
    queryRun("HMAC-SHA256", testHMACSHA256);
    queryRun("HMAC-SHA224", testHMACSHA224);
    queryRun("HMAC-SHA512", testHMACSHA512);
    queryRun("HMAC-SHA384", testHMACSHA384);
}

void testCipher(Cipher& cipher, uint8_t* ct, uint8_t* pt, CIPHERTEST* tests)
{
    printf("Testing %s\n", tests[0].label);
    if (!_dump)
        printf("\n");
    for (int x = 0; x < tests[0].count; x++) {
        cipher.SetKey(tests[x].key);
        if (tests[x].iv) cipher.SetIV(tests[x].iv);
        cipher.Encrypt(tests[x].plain, ct);
        if (tests[x].iv) cipher.SetIV(tests[x].iv);
        cipher.Decrypt(ct, pt);
        if (_dump) {
            printf("\n");
            printf("Key:\n");
            dumpMem(tests[x].key, tests[x].len);
            if (tests[x].iv) {
                printf("IV:\n");
                dumpMem(tests[x].iv, cipher.GetBlockBytes());
            }
            printf("Plain:\n");
            dumpMem(tests[x].plain, tests[x].len);
            printf("Cipher:\n");
            dumpMem(tests[x].cipher, tests[x].len);
            printf("Encrypted:\n");
            dumpMem(ct, cipher.GetBlockBytes());
            printf("Decrypted:\n");
            dumpMem(pt, cipher.GetBlockBytes());
            printf("\n");
        }
        printf("%-5s %s %i of %i Encryption\n", memcmp(ct, tests[x].cipher, cipher.GetBlockBytes()) ? "FAIL" : "OK", tests[x].label, x + 1, tests[x].count);
        printf("%-5s %s %i of %i Decryption\n", memcmp(pt, tests[x].plain, cipher.GetBlockBytes()) ? "FAIL" : "OK", tests[x].label, x + 1, tests[x].count);
    }
    printf("\n");
}

void testDESECB()
{
    uint8_t ct[des::recsize];
    uint8_t pt[des::recsize];
    DES des;
    testCipher(des, ct, pt, desecb_vp_tests);
    testCipher(des, ct, pt, desecb_ip_tests);
    testCipher(des, ct, pt, desecb_vk_tests);
    testCipher(des, ct, pt, desecb_po_tests);
    testCipher(des, ct, pt, desecb_st_tests);
}

void testDESCBC()
{
    uint8_t ct[des::recsize];
    uint8_t pt[des::recsize];
    DESCBC des;
    testCipher(des, ct, pt, descbc_vp_tests);
    testCipher(des, ct, pt, descbc_ip_tests);
    testCipher(des, ct, pt, descbc_vk_tests);
    testCipher(des, ct, pt, descbc_po_tests);
    testCipher(des, ct, pt, descbc_st_tests);
}

void testDESCFB()
{
    uint8_t ct[des::recsize];
    uint8_t pt[des::recsize];
    DESCFB des;
    testCipher(des, ct, pt, descfb_vp_tests);
    testCipher(des, ct, pt, descfb_ip_tests);
    testCipher(des, ct, pt, descfb_vk_tests);
    testCipher(des, ct, pt, descfb_po_tests);
    testCipher(des, ct, pt, descfb_st_tests);
}

void testDESOFB()
{
    uint8_t ct[des::recsize];
    uint8_t pt[des::recsize];
    DESOFB des;
    testCipher(des, ct, pt, desofb_vp_tests);
    testCipher(des, ct, pt, desofb_ip_tests);
    testCipher(des, ct, pt, desofb_vk_tests);
    testCipher(des, ct, pt, desofb_po_tests);
    testCipher(des, ct, pt, desofb_st_tests);
}

void testDES()
{
    queryRun("DES-ECB", testDESECB);
    queryRun("DES-CBC", testDESCBC);
    queryRun("DES-CFB", testDESCFB);
    queryRun("DES-OFB", testDESOFB);
}

void testDES3ECB()
{
    uint8_t ct[des3::recsize];
    uint8_t pt[des3::recsize];
    DES3 des;
    testCipher(des, ct, pt, des3ecb_vp_tests);
    testCipher(des, ct, pt, des3ecb_ip_tests);
    testCipher(des, ct, pt, des3ecb_vk_tests);
    testCipher(des, ct, pt, des3ecb_po_tests);
    testCipher(des, ct, pt, des3ecb_st_tests);
}

void testDES3CBC()
{
    uint8_t ct[des3::recsize];
    uint8_t pt[des3::recsize];
    DES3CBC des;
    testCipher(des, ct, pt, des3cbc_vp_tests);
    testCipher(des, ct, pt, des3cbc_ip_tests);
    testCipher(des, ct, pt, des3cbc_vk_tests);
    testCipher(des, ct, pt, des3cbc_po_tests);
    testCipher(des, ct, pt, des3cbc_st_tests);
}

void testDES3CFB()
{
    uint8_t ct[des3::recsize];
    uint8_t pt[des3::recsize];
    DES3CFB des;
    testCipher(des, ct, pt, des3cfb_vp_tests);
    testCipher(des, ct, pt, des3cfb_ip_tests);
    testCipher(des, ct, pt, des3cfb_vk_tests);
    testCipher(des, ct, pt, des3cfb_po_tests);
    testCipher(des, ct, pt, des3cfb_st_tests);
}

void testDES3OFB()
{
    uint8_t ct[des3::recsize];
    uint8_t pt[des3::recsize];
    DES3OFB des;
    testCipher(des, ct, pt, des3ofb_vp_tests);
    testCipher(des, ct, pt, des3ofb_ip_tests);
    testCipher(des, ct, pt, des3ofb_vk_tests);
    testCipher(des, ct, pt, des3ofb_po_tests);
    testCipher(des, ct, pt, des3ofb_st_tests);
}

void testDES3()
{
    queryRun("DES-EDE-ECB", testDES3ECB);
    queryRun("DES-EDE-CBC", testDES3CBC);
    queryRun("DES-EDE-CFB", testDES3CFB);
    queryRun("DES-EDE-OFB", testDES3OFB);
}

void testAESECB()
{
    uint8_t ct[aes::blockbytes];
    uint8_t pt[aes::blockbytes];
    AES128ECB aes128ecb;
    testCipher(aes128ecb, ct, pt, aes128ecb_tests);
    AES192ECB aes192ecb;
    testCipher(aes192ecb, ct, pt, aes192ecb_tests);
    AES256ECB aes256ecb;
    testCipher(aes256ecb, ct, pt, aes256ecb_tests);
}

void testAESCBC()
{
    uint8_t ct[aes::blockbytes];
    uint8_t pt[aes::blockbytes];
    AES128CBC aes128cbc;
    testCipher(aes128cbc, ct, pt, aes128cbc_tests);
    AES192CBC aes192cbc;
    testCipher(aes192cbc, ct, pt, aes192cbc_tests);
    AES256CBC aes256cbc;
    testCipher(aes256cbc, ct, pt, aes256cbc_tests);
}

void testAES()
{
    queryRun("AES-ECB", testAESECB);
    queryRun("AES-CBC", testAESCBC);
}

void testSymmetricEncryption()
{
    queryRun("DES", testDES);
    queryRun("DES-EDE (Triple-DES)", testDES3);
    queryRun("AES", testAES);
}

void testFastRandom()
{
    int i;
    uint32_t h, j;
    union {
        uint32_t k[640]; // 20,480 bits
        uint8_t kb[2560];
    } kval;
    uint32_t nybs[16]; // nybble accumulators
    uint32_t a[8]; // 1's run lengths
    uint32_t b[8]; // 0's run lengths
    double dbl, dbl2;
    uint8_t l, m, v, x, y, z;
    Random rand;
    printf("Testing Fast Pseudo-Random Algorithm\n\n");
    for (i = 0; i < 80; i++) {
        for (j = 0; j < 8; j++) {
            h = rand.Rand();
            printf(" %08X", h);
            kval.k[(i * 8) + j] = h;
        }
        printf("\n");
    }
    printf("\nRandom Distribution by Bit\n\n");
    dbl2 = 0;
    for (i = 1; i; i <<= 1) {
        dbl = 0;
        for (j = 0; j < 640; j++) {
            if (kval.k[j] & i)
                dbl++;
        }
        dbl /= 640;
        printf(" 0x%08X = %lf %s\n", i, dbl, ((dbl >= 0.55) || (dbl < 0.45) ? "<--" : " "));
        dbl2 += dbl;
    }
    printf("\nAverage Distribution by Bit = %lf\n", (dbl2 / 32));
    printf("\nCounting the number of one's in a 20,000 bit random stream (\"monobit\" test)\n");
    h = 0;
    for (i = 0; i < 625; i++) {
        j = kval.k[i];
        h += ByteOnes[(j >> 24) & 0xFF];
        h += ByteOnes[(j >> 16) & 0xFF];
        h += ByteOnes[(j >> 8) & 0xFF];
        h += ByteOnes[(j) & 0xFF];
    }
    printf("\n Total ones in 20,000 random bits = %d", h);
    printf("\n This is %s the FIPS 140-2 acceptable range of 9,725 to 10,275\n", ((h <= 9725) || (h >= 10275)) ? "outside" : "within");
    printf("\nCounting the number of instance of distinct nybbles in 20,000 bit random stream (\"poker\" test)\n\n");
    for (i = 0; i < 16; i++) { nybs[i] = 0; }
    for (i = 0; i < 625; i++) {
        j = kval.k[i];
        nybs[(j >> 28) & 0x0f]++;
        nybs[(j >> 24) & 0x0f]++;
        nybs[(j >> 20) & 0x0f]++;
        nybs[(j >> 16) & 0x0f]++;
        nybs[(j >> 12) & 0x0f]++;
        nybs[(j >> 8) & 0x0f]++;
        nybs[(j >> 4) & 0x0f]++;
        nybs[(j) & 0x0f]++;
    }
    for (i = 0; i < 16; i++) printf(" 0x%02X : %d\n", i, nybs[i]);
    for (i = 0, dbl = 0; i < 16; i++) dbl += ((uint64_t)nybs[i] * nybs[i]);
    dbl2 = 16;
    dbl2 /= 5000;
    dbl2 *= dbl;
    dbl2 -= 5000;
    printf("\n Poker test result = %lf\n", (dbl2));
    printf(" This is %s the FIPS 140-2 acceptable range of 2.16 to 46.17\n", ((dbl2 <= 2.16) || (dbl2 >= 46.17)) ? "outside" : "within");
    printf("\nPerforming \"runs\" test on 20,000 bit random stream\n\n");
    for (i = 0; i < 8; i++) { a[i] = 0, b[i] = 0; }
    for (i = 0, m = 6, z = 0xFF; i < 2500; i++) {
        x = kval.kb[i];
        y = (uint8_t)(x & 0x80);
        v = (uint8_t)(y ? ~x : x);
        if (y == z) {
            if (m < 6) {
                if (y)
                    a[m]--;
                else
                    b[m]--;
                m = (uint8_t)(m + ByteRuns[v][0]);
                if (m > 6)
                    m = 6;
                if (y)
                    a[m]++;
                else
                    b[m]++;
            }
            j = 1;
        }
        else
            j = 0;
        for (; j < 8; j++) {
            l = ByteRuns[v][j];
            if (!l)
                break;
            m = (uint8_t)(l > 5 ? 6 : l);
            if (y)
                if (!(j & 1))
                    a[m]++;
                else
                    b[m]++;
            else if (j & 1)
                a[m]++;
            else
                b[m]++;
        }
        z = (uint8_t)(x & 1 ? 0x80 : 0);
    }
    printf(" 1 one  = %4d %4s   1 zero  = %4d %4s\n", a[1], ((a[1] < 2343) || (a[1] > 2657)) ? "FAIL" : "OK", b[1], ((b[1] < 2343) || (b[1] > 2657)) ? "FAIL" : "OK");
    printf(" 2 ones = %4d %4s   2 zeros = %4d %4s\n", a[2], ((a[2] < 1135) || (a[2] > 1365)) ? "FAIL" : "OK", b[2], ((b[2] < 1135) || (b[2] > 1365)) ? "FAIL" : "OK");
    printf(" 3 ones = %4d %4s   3 zeros = %4d %4s\n", a[3], ((a[3] < 542) || (a[3] > 708)) ? "FAIL" : "OK", b[3], ((b[3] < 542) || (b[3] > 708)) ? "FAIL" : "OK");
    printf(" 4 ones = %4d %4s   4 zeros = %4d %4s\n", a[4], ((a[4] < 251) || (a[4] > 373)) ? "FAIL" : "OK", b[4], ((b[4] < 251) || (b[4] > 373)) ? "FAIL" : "OK");
    printf(" 5 ones = %4d %4s   5 zeros = %4d %4s\n", a[5], ((a[5] < 111) || (a[5] > 201)) ? "FAIL" : "OK", b[5], ((b[5] < 111) || (b[5] > 201)) ? "FAIL" : "OK");
    printf(">5 ones = %4d %4s  >5 zeros = %4d %4s\n\n", a[6], ((a[6] < 111) || (a[6] > 201)) ? "FAIL" : "OK", b[6], ((b[6] < 111) || (b[6] > 201)) ? "FAIL" : "OK");

    printf("Measuring 1,000 iterations of RANDOM::random()\n");
    auto start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) {
        rand.Rand();
    }
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    printf("RANDOM::Random() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());
}

void testX931Random()
{
    uint32_t h;
    uint8_t plain[cipher::recsize];
    uint8_t cipher_pre[cipher::recsize];
    uint8_t mask[cipher::recsize];
    uint8_t cipher[cipher::recsize];
    uint8_t random_pre[cipher::recsize];
    uint8_t random[cipher::recsize];
    DES3 des3;
    PRNG prng;
    printf("Testing ANSI X9.31 Pseudo-Random Generation\n");
    if (!_dump)
        printf("\n");
    des3.SetKey(x931des3_key);
    memcpy(plain, x931des3_dt, sizeof(plain));
    memcpy(mask, x931des3_v, sizeof(mask));
    des3.Encrypt(plain, cipher_pre);
    for (h = 0; h < sizeof(cipher); h++) { cipher[h] = cipher_pre[h] ^ mask[h]; }
    des3.Encrypt(cipher, random_pre);
    for (h = 0; h < sizeof(random); h++) { random[h] = random_pre[h] ^ mask[h]; }
    if (_dump) {
        printf("\n");
        printf("Key:\n");
        dumpMem(x931des3_key, 24);
        printf("Plain:\n");
        dumpMem(plain, sizeof(plain));
        printf("Mask:\n");
        dumpMem(mask, sizeof(mask));
        printf("Cipher (before mask):\n");
        dumpMem(cipher_pre, sizeof(cipher_pre));
        printf("Cipher (after mask):\n");
        dumpMem(cipher, sizeof(cipher));
        printf("Random (before mask):\n");
        dumpMem(random_pre, sizeof(random_pre));
        printf("Random (after mask):\n");
        dumpMem(random, sizeof(random));
        printf("\n");
    }
    printf("%-5s ANSI X9.31 1 of 1\n\n", !memcmp(random, x931des3_r, sizeof(random)) ? "OK" : "FAIL");
}

void testPBKDF2()
{
    PBC2 pbc2;
    uint8_t dk[20] = { 0 };
    printf("Testing Password-Based Key Derivation Function 2 (PBKDF2)\n");
    if (!_dump)
        printf("\n");
    pbc2.SetPassword(pbkdf2_p_1, 8);
    pbc2.SetSalt(pbkdf2_s_1, 4);
    pbc2.SetCount(1);
    pbc2.DeriveKey(dk, sizeof(dk));
    if (_dump) {
        printf("\n");
        printf("Password:\n");
        dumpMem(pbkdf2_p_1, 8);
        printf("Salt\n");
        dumpMem(pbkdf2_s_1, 4);
        printf("Count: %u\n", 1);
        printf("Derived Key Length: %u\n", 20);
        printf("Derived Key:\n");
        dumpMem(dk, sizeof(dk));
        printf("\n");
    }
    printf("%-5s PBKDF2 1 of 1\n\n", !memcmp(dk, pbkdf2_o_1, sizeof(dk)) ? "OK" : "FAIL");
}

void testRandom()
{
    queryRun("Fast Random", testFastRandom);
    queryRun("X9.31 Random", testX931Random);
    queryRun("PBKDF2 Key Derivation", testPBKDF2);
}

void testInt()
{
    size_t bits;
    uint32_t i, j;
    Num A, B, C, D, E, X, Y, G;
    Random rand;
    uint8_t bytebuf[256];

    printf("Testing Large Integer Arithmetic\n\n");

    printf("Testing Num::bits()\n\n");
    A.Init();
    printf("%-5s Num::bits() 1 of 4\n", 1 == A.bits() ? "OK" : "FAIL");
    A._word[21] = 0x00000008;
    A._hiword = 21;
    printf("%-5s Num::bits() 2 of 4\n", num::wordbits * 21 + 4 == A.bits() ? "OK" : "FAIL");
    A._byte[num::bytes - 1] = 0x80;
    A._hiword = num::words - 1;
    printf("%-5s Num::bits() 3 of 4\n", num::bits == A.bits() ? "OK" : "FAIL");
    A.Init();
    for (i = 0; i < num::words; i++) {
        A._hiword = i;
        bits = A.bits();
        if (bits >> num::bit2word != i)
            break;
    }
    printf("%-5s Num::bits() 4 of 4\n\n", i == num::words ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::bits()\n");
    A.Init();
    A._hiword = (num::words >> 1) - 1;
    for (i = 0; i <= A._hiword; i++) {
        A._word[i] = rand.Rand();
    }
    auto start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) {
        A.bits();
    }
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    printf("Num::bits() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::bytes()\n\n");
    A.Init();
    printf("%-5s Num::bytes() 1 of 3\n", 1 == A.bytes() ? "OK" : "FAIL");
    A._byte[44] = 0xff;
    A._hiword = (44 >> num::byte2word);
    printf("%-5s Num::bytes() 2 of 3\n", 45 == A.bytes() ? "OK" : "FAIL");
    A._byte[num::hibyte] = 0xff;
    A._hiword = num::hiword;
    printf("%-5s Num::bytes() 3 of 3\n\n", num::bytes == A.bytes() ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::bytes()\n");
    A.Init();
    A._hiword = (num::words >> 1) - 1;
    for (i = 0; i <= A._hiword; i++) { A._word[i] = rand.Rand(); }
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.bytes(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::bytes() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::words()\n\n");
    A.Init();
    A._hiword = 31;
    printf("%-5s Num::words() 1 of 1\n\n", 32 == A.words() ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::words()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.words(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::words() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::bit()\n\n");
    A.Init();
    A._word[0] = 0x12345678;
    A._word[1] = 0xfedcba98;
    A._word[num::hiword] = (uint32_t)num::hibitmask - 1;
    printf("%-5s Num::bit() 1 of 3\n", 1 == A.bit(18) ? "OK" : "FAIL");
    printf("%-5s Num::bit() 2 of 3\n", 0 == A.bit(53) ? "OK" : "FAIL");
    printf("%-5s Num::bit() 3 of 3\n\n", 0 == A.bit(num::bits - 1) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::bit()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.bit(269); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::bit() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::byte()\n\n");
    A.Init();
    A._byte[0] = 0x12;
    A._byte[6] = 0xdc;
    A._byte[num::hibyte] = 0x7f;
    printf("%-5s Num::byte() 1 of 3\n", 0x12 == A.byte(0) ? "OK" : "FAIL");
    printf("%-5s Num::byte() 2 of 3\n", 0xdc == A.byte(6) ? "OK" : "FAIL");
    printf("%-5s Num::byte() 3 of 3\n\n", 0x7f == A.byte(num::hibyte) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::byte()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.byte(44); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::byte() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::word()\n\n");
    A.Init();
    A._word[0] = 0x76543210;
    A._word[1] = 0xfedcba98;
    A._word[num::hiword] = (uint32_t)num::hibitmask - 1;
    printf("%-5s Num::word() 1 of 3\n", (0x76543210 == A.word(0)) ? "OK" : "FAIL");
    printf("%-5s Num::word() 2 of 3\n", (0xfedcba98 == A.word(1)) ? "OK" : "FAIL");
    printf("%-5s Num::word() 3 of 3\n\n", (uint32_t)num::hibitmask - 1 == A.word(num::hiword) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::word()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.word(17); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::word() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::resetBit()\n\n");
    A.Init();
    A._word[0] = (uint32_t)-1;
    A.resetBit(23);
    printf("%-5s Num::resetBit() 1 of 4\n", (0x7f == A._byte[2]) ? "OK" : "FAIL");
    A.resetBit(0);
    printf("%-5s Num::resetBit() 2 of 4\n", (0xfe == A._byte[0]) ? "OK" : "FAIL");
    A._word[num::hiword] = (uint32_t)-1;
    A.resetBit(num::bits - 1);
    printf("%-5s Num::resetBit() 3 of 4\n", (0x7f == A._byte[num::hibyte]) ? "OK" : "FAIL");
    A._word[1] = (uint32_t)num::hibitmask - 1;
    A.resetBit(num::wordbits);
    printf("%-5s Num::resetBit() 4 of 4\n\n", (0xfe == A._byte[num::wordbytes]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::resetBit()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.resetBit(147); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::resetBit() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::resetByte()\n\n");
    A.Init();
    A._byte[73] = 0xff;
    A.resetByte(73);
    printf("%-5s Num::resetByte() 1 of 3\n", (0x00 == A._byte[73]) ? "OK" : "FAIL");
    A.Init();
    A._byte[0] = 0xff;
    A.resetByte(0);
    printf("%-5s Num::resetByte() 2 of 3\n", (0x00 == A._byte[0]) ? "OK" : "FAIL");
    A.Init();
    A._byte[num::hibyte] = 0xff;
    A.resetByte(num::hibyte);
    printf("%-5s Num::resetByte() 3 of 3\n\n", (0x00 == A._byte[num::hibyte]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::resetByte()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.resetByte(66); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::resetByte() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::resetWord()\n\n");
    A.Init();
    A._word[2] = 1;
    A.resetWord(2);
    printf("%-5s Num::resetWord() 1 of 1\n\n", (0 == A._word[0]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::resetWord()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.resetWord(2); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::resetWord() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::setBit()\n\n");
    A.Init();
    A.setBit(196);
    printf("%-5s Num::setBit() 1 of 3\n", (0x10 == A._byte[24]) ? "OK" : "FAIL");
    A.Init();
    A._byte[0] = 0x5a;
    A.setBit(0);
    printf("%-5s Num::setBit() 2 of 3\n", (0x5b == A._byte[0]) ? "OK" : "FAIL");
    A.Init();
    A._word[num::hiword] = 0;
    A.setBit(num::hibit);
    printf("%-5s Num::setBit() 3 of 3\n\n", (0x80 == A._byte[num::hibyte]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::setBit()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.setBit(147); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::setBit() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::setByte()\n\n");
    A.Init();
    A.setByte(73, 0x5a);
    printf("%-5s Num::setByte() 1 of 3\n", (0x5a == A._byte[73]) ? "OK" : "FAIL");
    A.Init();
    A.setByte(0, 0xbb);
    printf("%-5s Num::setByte() 2 of 3\n", (0xbb == A._byte[0]) ? "OK" : "FAIL");
    A.Init();
    A.setByte(num::hibyte, 0xa2);
    printf("%-5s Num::setByte() 3 of 3\n\n", (0xa2 == A._byte[num::hibyte]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::setByte()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.setByte(66, 0x33); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::setByte() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::setWord()\n\n");
    A.Init();
    A.setWord(2, 0x69696969);
    printf("%-5s Num::setWord() 1 of 1\n\n", (0x69696969 == A._word[2]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::setWord()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.setWord(2, 0x69696969); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::setWord() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::bin()\n\n");
    A.Init();
    for (i = 0; i < 48; A._byte[i] = inthex_vector_1[47 - i], i++);
    A._hiword = 47 >> num::byte2word;
    memset(bytebuf, 0, sizeof(bytebuf));
    A.bin(bytebuf, 48);
    printf("%-5s Num::bin() 1 of 1\n\n", (!memcmp(bytebuf, inthex_vector_1, 48)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::bin()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.bin(bytebuf, 48); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::bin() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putZero()\n\n");
    A.putZero();
    printf("%-5s Num::putZero() 1 of 1\n\n", ((0 == A.word(0)) && (1 == A.bits()) && (1 == A.bytes()) && (1 == A.words())) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putZero()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putZero(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putZero() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putOne()\n\n");
    A.putOne();
    printf("%-5s Num::putOne() 1 of 1\n\n", ((1 == A.word(0)) && (1 == A.bits()) && (1 == A.bytes()) && (1 == A.words())) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putOne()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putOne(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putOne() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putTwo()\n\n");
    A.putTwo();
    printf("%-5s Num::putTwo() 1 of 1\n", ((2 == A.word(0)) && (2 == A.bits()) && (1 == A.bytes()) && (1 == A.words())) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putTwo()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putTwo(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putTwo() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putRandom()\n\n");
    A.putRandom(rand, 1);
    printf("%-5s Num:putRandom() 1 of 5\n", ((0 == A._sign) && (1 >= A.bits()) && (1 == A.words())) ? "OK" : "FAIL");
    A.putRandom(rand, 8);
    printf("%-5s Num:putRandom() 2 of 5\n", ((0 == A._sign) && (8 >= A.bits()) && (1 == A.words())) ? "OK" : "FAIL");
    A.putRandom(rand, 32);
    printf("%-5s Num:putRandom() 3 of 5\n", ((0 == A._sign) && (32 >= A.bits()) && (1 == A.words())) ? "OK" : "FAIL");
    A.putRandom(rand, 63);
    printf("%-5s Num:putRandom() 4 of 5\n", ((0 == A._sign) && (63 >= A.bits()) && (2 >= A.words())) ? "OK" : "FAIL");
    A.putRandom(rand, 69);
    printf("%-5s Num:putRandom() 5 of 5\n\n", ((0 == A._sign) && (69 >= A.bits()) && (3 >= A.words())) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putRandom()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putRandom(rand, 509); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putRandom() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putWord()\n\n");
    A.putWord(0);
    printf("%-5s Num:putWord() 1 of 5\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (0 == A.word(0))) ? "OK" : "FAIL");
    A.putWord(1);
    printf("%-5s Num:putWord() 2 of 5\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (1 == A.word(0))) ? "OK" : "FAIL");
    A.putWord(2);
    printf("%-5s Num:putWord() 3 of 5\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (2 == A.bits()) && (2 == A.word(0))) ? "OK" : "FAIL");
    A.putWord(0x12345);
    printf("%-5s Num:putWord() 4 of 5\n", ((0 == A._sign) && (1 == A.words()) && (3 == A.bytes()) && (17 == A.bits()) && (0x12345 == A.word(0))) ? "OK" : "FAIL");
    A.putWord((uint32_t)-1);
    printf("%-5s Num:putWord() 5 of 5\n\n", ((0 == A._sign) && (1 == A.words()) && (num::wordbytes == A.bytes()) && (num::wordbits == A.bits()) && ((uint32_t)-1 == A.word(0))) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putWord()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putWord(0x12345678); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putWord() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putLong()\n\n");
    A.putLong(0);
    printf("%-5s Num:putLong() 1 of 7\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (0 == A.word(0))) ? "OK" : "FAIL");
    A.putLong(1);
    printf("%-5s Num:putLong() 2 of 7\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (1 == A.word(0))) ? "OK" : "FAIL");
    A.putLong(2);
    printf("%-5s Num:putLong() 3 of 7\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (2 == A.bits()) && (2 == A.word(0))) ? "OK" : "FAIL");
    A.putLong(0x7fffffff);
    printf("%-5s Num:putLong() 4 of 7\n", ((0 == A._sign) && (1 == A.words()) && (4 == A.bytes()) && (num::wordbits - 1 == A.bits()) && (0x7fffffff == A.word(0))) ? "OK" : "FAIL");
    A.putLong(num::hibitmask);
    printf("%-5s Num:putLong() 5 of 7\n", (((uint32_t)-1 == A._sign) && (1 == A.words()) && (num::wordbytes == A.bytes()) && (num::wordbits == A.bits()) && (num::hibitmask == A.word(0))) ? "OK" : "FAIL");
    A.putLong((uint32_t)-1);
    printf("%-5s Num:putLong() 6 of 7\n", (((uint32_t)-1 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (1 == A.word(0))) ? "OK" : "FAIL");
    A.putLong((uint32_t)-98765);
    printf("%-5s Num:putLong() 7 of 7\n\n", (((uint32_t)-1 == A._sign) && (1 == A.words()) && (3 == A.bytes()) && (17 == A.bits()) && (0x181cd == A.word(0))) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putLong()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putLong(-9999); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putLong() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putBin()\n\n");
    A.putBin((uint8_t*)"\x00\x00\x01\x23\x45\x67\x89\xab\xcd\xef", 10);
    printf("%-5s Num:putBin() 1 of 1\n\n", ((0 == A._sign) && (2 == A.words()) && (0x89abcdef == A.word(0)) && (0x01234567 == A.word(1))) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putBin()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putBin((uint8_t*)"\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01", 17); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putBin() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putHex()\n\n");
    A.putHex((uint8_t*)"0123456789abcdef", 16);
    printf("%-5s Num:putHex() 1 of 1\n\n", ((0 == A._sign) && (2 == A.words()) && (0x89abcdef == A.word(0)) && (0x01234567 == A.word(1))) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putHex()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putHex((uint8_t*)"123456789abcdef01", 17); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putHex() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::copy()\n\n");
    A.putRandom(rand, 1024);
    B.copy(A);
    printf("%-5s Num::copy() 1 of 1\n\n", (!memcmp(&A, &B, num::bytes) && (A._overflow == B._overflow) && (A._sign == B._sign) && (A._hiword == B._hiword)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { B.copy(A); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::compare()\n\n");
    A.putLong(-2);
    B.putLong(-1);
    C.putLong(0);
    D.putLong(1);
    E.putLong(2);
    printf("%-5s Num::compare() 1 of 16\n", (1 == E.compare(D)) ? "OK" : "FAIL"); // 2 > 1
    printf("%-5s Num::compare() 2 of 16\n", (-1 == D.compare(E)) ? "OK" : "FAIL"); // 1 < 2
    printf("%-5s Num::compare() 3 of 16\n", (0 == E.compare(E)) ? "OK" : "FAIL"); // 2 = 2
    printf("%-5s Num::compare() 4 of 16\n", (0 == C.compare(C)) ? "OK" : "FAIL"); // 0 = 0
    printf("%-5s Num::compare() 5 of 16\n", (-1 == C.compare(D)) ? "OK" : "FAIL"); // 0 < 1
    printf("%-5s Num::compare() 6 of 16\n", (1 == D.compare(C)) ? "OK" : "FAIL"); // 1 > 0
    printf("%-5s Num::compare() 7 of 16\n", (0 == D.compare(D)) ? "OK" : "FAIL"); // 1 = 1
    printf("%-5s Num::compare() 8 of 16\n", (1 == C.compare(B)) ? "OK" : "FAIL"); // 0 > -1
    printf("%-5s Num::compare() 9 of 16\n", (-1 == B.compare(C)) ? "OK" : "FAIL"); // -1 < 0
    printf("%-5s Num::compare() 10 of 16\n", (1 == D.compare(B)) ? "OK" : "FAIL"); // 1 > -1
    printf("%-5s Num::compare() 11 of 16\n", (-1 == B.compare(D)) ? "OK" : "FAIL"); // -1 < 1
    printf("%-5s Num::compare() 12 of 16\n", (0 == B.compare(B)) ? "OK" : "FAIL"); // -1 = -1
    printf("%-5s Num::compare() 13 of 16\n", (1 == B.compare(A)) ? "OK" : "FAIL"); // -1 > -2
    printf("%-5s Num::compare() 14 of 16\n", (-1 == A.compare(B)) ? "OK" : "FAIL"); // -2 < -1
    A.putZero();
    A.setWord(21, 1);
    A.setWord(24, 1);
    A._hiword = 24;
    A._loword = 21;
    B.putZero();
    B.setWord(20, 1);
    B.setWord(25, 1);
    B._hiword = 25;
    B._loword = 20;
    printf("%-5s Num::compare() 15 of 16\n", (-1 == A.compare(B)) ? "OK" : "FAIL");
    B.putZero();
    B.setWord(20, 1);
    B.setWord(24, 1);
    B.setWord(25, 0);
    B._hiword = 24;
    B._loword = 20;
    printf("%-5s Num::compare() 16 of 16\n\n", (1 == A.compare(B)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::compareAbs() 1024-bit comparators w/_loword = 0\n");
    A.putZero();
    for (i = 0; i < 32; A.setWord(i, (uint32_t)-1), i--);
    A._hiword = 31;
    A._loword = 0;
    B.copy(A);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.compareAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::compareAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::compareAbs() 1024-bit comparators w/_loword = 16\n");
    A.putZero();
    for (i = 16; i < 32; A.setWord(i, (uint32_t)-1), i--);
    A._hiword = 31;
    A._loword = 16;
    B.copy(A);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.compareAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::compareAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::compare() 1024-bit comparators w/_loword = 16\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.compare(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::compare() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::neg()\n\n");
    A.putRandom(rand, 512);
    B.copy(A);
    B.neg();
    printf("%-5s Num::neg() 1 of 1\n\n", (!memcmp(&A._word[0], &B._word[0], num::bytes) && !A._sign && (uint32_t)-1 == B._sign) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::neg()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.neg(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::neg() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mul2()\n\n");
    A.putZero();
    A.mul2();
    printf("%-5s Num::mul2() 1 of 5\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0 = 0.mul2()
    A.putOne();
    A.mul2();
    printf("%-5s Num::mul2() 2 of 5\n", (1 == A.words() && 2 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 2 = 1.mul2()
    A.putWord(0xb4b4b4b4);
    A.mul2();
    printf("%-5s Num::mul2() 3 of 5\n", (2 == A.words() && 0x00000001 == A.word(1) && 0x69696968 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0x1 0x69696968 = 0xb4b4b4b4.mul2()
    A.putBin((uint8_t*)"\xff\xff\xff\xff\x80\x00\x00\x00", 8);
    A.mul2();
    printf("%-5s Num::mul2() 4 of 5\n", (3 == A.words() && 0x00000001 == A.word(2) && 0xffffffff == A.word(1) && 0 == A.word(0) && 2 == A._hiword && 1 == A._loword && !A._overflow) ? "OK" : "FAIL"); // 0x1 0xffffffff 0x0 = 0xffffffff 0x80000000 .mul2() 
    A.putZero();
    A.setWord(num::hiword, (uint32_t)num::hibitmask);
    A._hiword = num::hiword;
    A._loword = num::hiword;
    A.mul2();
    printf("%-5s Num::mul2() 5 of 5\n\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0 = num::hibit .mul2()

    printf("Measuring 1,000 iterations of Num::mul2() 2048-bit integers w/_loword = 0\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.mul2(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::mul2() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::mul2() 2048-bit integers w/_loword = 32\n");
    A.putRandom(rand, 2048);
    for (i = 0; i < 32; A.setWord(i, 0), i++);
    A._loword = 32;
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.mul2(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::mul2() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::div2()\n\n");
    A.putZero();
    A.div2();
    printf("%-5s Num::div2() 1 of 5\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0 == 0.div2()
    A.putOne();
    A.div2();
    printf("%-5s Num::div2() 2 of 5\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0 == 1.div2()
    A.putTwo();
    A.div2();
    printf("%-5s Num::div2() 3 of 5\n", (1 == A.words() && 1 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1 == 2.div2()
    A.putZero();
    A.setWord(1, 0x00000001);
    A.setWord(0, 0x69696969);
    A._hiword = 1;
    A.div2();
    printf("%-5s Num::div2() 4 of 5\n", (1 == A.words() && 0xb4b4b4b4 == A.word(0) && !A._hiword && !A._loword && !A._overflow) ? "OK" : "FAIL"); // 0xb4b4b4b4 == 0x1 0x69696969.div2()
    A.putZero();
    A.setWord(2, 0x00000001);
    A.setWord(1, 0xffffffff);
    A.setWord(0, 0x00000000);
    A._hiword = 2;
    A._loword = 1;
    A.div2();
    printf("%-5s Num::div2() 5 of 5\n\n", (2 == A.words() && 0x80000000 == A.word(0) && 0xffffffff == A.word(1) && 1 == A._hiword && !A._loword && !A._overflow) ? "OK" : "FAIL"); // 0xb4b4b4b4 == 0x1 0x69696969.div2()

    printf("Measuring 1,000 iterations of Num::div2() 3072-bit integers w/_loword = 0\n");
    A.putRandom(rand, 3072);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.div2(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::div2() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::div2() 3072-bit integers w/_loword = 32\n");
    A.putRandom(rand, 3072);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.div2(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::div2() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::shiftLeft() and Num::shiftRight()\n\n");
    A.putRandom(rand, 512);
    B.copy(A);
    A.shiftLeft(0);
    printf("%-5s Num::shiftLeft() 1 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // B = A; B = A >> 0
    A.putZero();
    B.copy(A);
    A.shiftLeft(57);
    printf("%-5s Num::shiftLeft() 2 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // B = A; B = A = 0 >> 57
    A.putRandom(rand, 512);
    B.putZero();
    A.shiftLeft(num::bits);
    printf("%-5s Num::shiftLeft() 3 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // A.rand() << num::bits = 0
    A.putHex((uint8_t*)"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000", 64);
    B.copy(A);
    for (i = 0; i < 16; i++) A.shiftLeft(i);
    A.shiftLeft(8);
    A.shiftRight(64);
    A.shiftRight(32);
    A.shiftRight(16);
    A.shiftRight(8);
    A.shiftRight(4);
    A.shiftRight(2);
    A.shiftRight(1);
    A.shiftRight(1);
    printf("%-5s Num::shiftLeft() 4 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // word intensity; no bit shift
    A.putRandom(rand, 512);
    B.copy(A);
    A.shiftLeft(23);
    A.shiftRight(23);
    printf("%-5s Num::shiftLeft() 5 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // bit shift; no word intensity
    A.putRandom(rand, 512);
    B.copy(A);
    A.shiftLeft(57);
    A.shiftRight(57);
    printf("%-5s Num::shiftLeft() 6 of 8\n", !(A.compare(B)) ? "OK" : "FAIL"); // 1-word intensity and bit shift
    A.putRandom(rand, 512);
    B.copy(A);
    A.shiftLeft(108);
    A.shiftRight(108);
    printf("%-5s Num::shiftLeft() 7 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // multiple-word intensity and bit shift
    A.putRandom(rand, 2048);
    B.copy(A);
    A.shiftLeft(num::bits - 1024);
    A.shiftRight(num::bits - 1024);
    printf("%-5s Num::shiftLeft() 8 of 8\n\n", (A.compare(B)) ? "OK" : "FAIL"); // shift partial beyond limit

    printf("Measuring 1,000 iterations of Num::shiftLeft() and Num::ShiftRight()\n");
    printf("(512-bit integer shifted left and right 57 bits w/_loword = 0)\n");
    A.putRandom(rand, 512);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 500; i++) { A.shiftLeft(57); A.shiftRight(57); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::shiftLeft() and Num::shiftRight() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::ShiftLeft() and Num::ShiftRight()\n");
    printf("(2048-bit integer shifted left 999 bits w/_loword = 0)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 500; i++) { A.shiftLeft(999); A.shiftRight(999); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::shiftLeft() and Num::shiftRight() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::IncrementAbs\n\n");
    A.putZero();
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 1 of 10\n", (!A._sign && !A._hiword && !A._loword && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 00 00 --> 00 00 01
    A.putOne();
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 2 of 10\n", (!A._sign && !A._hiword && !A._loword && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // 00 00 01 --> 00 00 02
    A.setWord(0, (uint32_t)-1);
    A._hiword = 0;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 3 of 10\n", (!A._sign && 1 == A._hiword && 1 == A._loword && (num::wordbits + 1) == A.bits() && 2 == A.words() && 1 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 00 00 FF --> 00 01 00
    A.setWord(0, 0);
    A.setWord(1, 1);
    A._hiword = 1;
    A._loword = 1;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 4 of 10\n", (!A._sign && 1 == A._hiword && !A._loword && (num::wordbits + 1) == A.bits() && 2 == A.words() && 1 == A.word(1) && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 01 00 --> 00 01 01
    A.setWord(0, 1);
    A.setWord(1, 1);
    A._hiword = 1;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 5 of 10\n", (!A._sign && 1 == A._hiword && !A._loword && (num::wordbits + 1) == A.bits() && 2 == A.words() && 1 == A.word(1) && 2 == A.word(0)) ? "OK" : "FAIL"); // 00 01 01 --> 00 01 02
    A.setWord(0, (uint32_t)-1);
    A.setWord(1, 1);
    A._hiword = 1;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 6 of 10\n", (!A._sign && 1 == A._hiword && 1 == A._loword && (num::wordbits + 2) == A.bits() && 2 == A.words() && 2 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 00 01 FF --> 00 02 00
    A.setWord(0, (uint32_t)-1);
    A.setWord(1, 0);
    A.setWord(2, 1);
    A._hiword = 2;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 7 of 10\n", (!A._sign && 2 == A._hiword && 1 == A._loword && (num::wordbits * 2 + 1) == A.bits() && 3 == A.words() && 1 == A.word(2) && 1 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 01 00 FF --> 01 01 00
    A.setWord(0, (uint32_t)-1);
    A.setWord(1, 1);
    A.setWord(2, 1);
    A._hiword = 2;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 8 of 10\n", (!A._sign && 2 == A._hiword && 1 == A._loword && (num::wordbits * 2 + 1) == A.bits() && 3 == A.words() && 1 == A.word(2) && 2 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 01 01 FF --> 01 02 00
    A.setWord(0, (uint32_t)-1);
    A.setWord(1, (uint32_t)-1);
    A.setWord(2, 1);
    A._hiword = 2;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 9 of 10\n", (!A._sign && 2 == A._hiword && 2 == A._loword && (num::wordbits * 2 + 2) == A.bits() && 3 == A.words() && 2 == A.word(2) && !A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 01 FF FF --> 02 00 00
    A.putZero();
    for (i = 0; i < num::words; i++) A.setWord(i, (uint32_t)-1);
    A._hiword = num::hiword;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 10 of 10\n\n", (!A._sign && !A._hiword && !A._loword && 1 == A.bits() && 1 == A.words() && !A.word(0)) ? "OK" : "FAIL"); // FF FF FF --> 00 00 00

    printf("Measuring 1,000 iterations of Num::incrementAbs()\n");
    printf("(2048-bit integer incremented 1,000 times)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.incrementAbs(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::incrementAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::decrementAbs()\n\n");
    A.putZero();
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 1 of 9\n", ((uint32_t)-1 == A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 00 00 --> -(00 00 01)
    A.putOne();
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 2 of 9\n", (!A._sign && 1 == A.bits() && 1 == A.words() && !A.word(0)) ? "OK" : "FAIL"); // 00 00 01 --> 00 00 00
    A.putTwo();
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 3 of 9\n", (!A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 00 02 --> 00 00 01
    A.setWord(0, 0);
    A.setWord(1, 1);
    A._hiword = 1;
    A._loword = 1;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 4 of 9\n", (!A._sign && !A._hiword && !A._loword && num::wordbits == A.bits() && 1 == A.words() && !A.word(1) && (uint32_t)-1 == A.word(0)) ? "OK" : "FAIL"); // 00 01 00 --> 00 00 FF
    A.setWord(0, 0);
    A.setWord(1, 2);
    A._hiword = 1;
    A._loword = 1;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 5 of 9\n", (!A._sign && 1 == A._hiword && !A._loword && num::wordbits + 1 == A.bits() && 2 == A.words() && 1 == A.word(1) && (uint32_t)-1 == A.word(0)) ? "OK" : "FAIL"); // 00 02 00 --> 00 01 FF
    A.setWord(0, 1);
    A.setWord(1, 2);
    A._hiword = 1;
    A._loword = 0;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 6 of 9\n", (!A._sign && 1 == A._hiword && 1 == A._loword && num::wordbits + 2 == A.bits() && 2 == A.words() && 2 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 00 02 01 --> 00 02 00
    A.setWord(0, 2);
    A.setWord(1, 2);
    A._hiword = 1;
    A._loword = 0;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 7 of 9\n", (!A._sign && 1 == A._hiword && !A._loword && num::wordbits + 2 == A.bits() && 2 == A.words() && 2 == A.word(1) && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 02 02 --> 00 02 01
    A.setWord(0, 0);
    A.setWord(1, 1);
    A.setWord(2, 1);
    A._hiword = 2;
    A._loword = 1;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 8 of 9\n", (!A._sign && 2 == A._hiword && !A._loword && num::wordbits * 2 + 1 == A.bits() && 3 == A.words() && 1 == A.word(2) && !A.word(1) && (uint32_t)-1 == A.word(0)) ? "OK" : "FAIL"); // 01 01 00 --> 01 00 FF
    for (i = 0; i < num::words; A.setWord(i, (uint32_t)-1), i++);
    A._hiword = num::hiword;
    A._loword = 0;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 9 of 9\n\n", (!A._sign && num::hiword == A._hiword && !A._loword && num::bits == A.bits() && num::words == A.words() && (uint32_t)-1 == A.word(num::hiword) && (uint32_t)-2 == A.word(0)) ? "OK" : "FAIL"); // FF FF FF --> FF FF FE

    printf("Measuring 1,000 iterations of Num::decrementAbs()\n");
    printf("(2048-bit integer decremented 1,000 times)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.decrementAbs(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::decrementAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::addAbs()\n\n");
    A.putWord(0x5a5a5a5a);
    A.addAbs(A);
    printf("%-5s Num::addAbs() 1 of 10\n", (0xb4b4b4b4 == A.word(0) && 1 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 1-word --> no word overflow
    A.addAbs(A);
    printf("%-5s Num::addAbs() 2 of 10\n", (0x69696968 == A.word(0) && 1 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 1-word --> word overflow
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0x55555555);
    A.addAbs(B);
    printf("%-5s Num::addAbs() 3 of 10\n", (0xdf012344 == A.word(0) && 0x01234567 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 2-word --> no word overflow
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0xaaaaaaaa);
    A.addAbs(B);
    printf("%-5s Num::addAbs() 4 of 10\n", (0x34567899 == A.word(0) && 0x01234568 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 2-word --> word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0xffffffff);
    A._hiword = 3;
    B.putTwo();
    A.addAbs(B);
    printf("%-5s Num::addAbs() 5 of 10\n", (1 == A.word(0) && !A.word(1) && !A.word(2) && !A.word(3) && 1 == A.word(4) && 5 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + n-word --> n-word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0xffffffff);
    A._hiword = 3;
    B.putZero();
    B.setWord(0, 0x00000001);
    B.setWord(1, 0x00000001);
    B._hiword = 1;
    A.addAbs(B);
    printf("%-5s Num::addAbs() 6 of 10\n", (!A.word(0) && 1 == A.word(1) && !A.word(2) && !A.word(3) && 1 == A.word(4) && 5 == A.words() && !A._overflow) ? "OK" : "FAIL"); // n-word + n-word --> n-word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0x33333333);
    A.setWord(4, 0x22222222);
    A.setWord(5, 0x11111111);
    A._hiword = 5;
    B.putTwo();
    A.addAbs(B);
    printf("%-5s Num::addAbs() 7 of 10\n", (1 == A.word(0) && !A.word(1) && !A.word(2) && 0x33333334 == A.word(3) && 0x22222222 == A.word(4) && 0x11111111 == A.word(5) && 6 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + n-word --> word overflow, no increase in A.words()
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0x33333333);
    A.setWord(4, 0x22222222);
    A.setWord(5, 0x11111111);
    A._hiword = 5;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.addAbs(B);
    printf("%-5s Num::addAbs() 8 of 10\n", (!A.word(0) && 1 == A.word(1) && !A.word(2) && 0x33333334 == A.word(3) && 0x22222222 == A.word(4) && 0x11111111 == A.word(5) && 6 == A.words() && !A._overflow) ? "OK" : "FAIL"); // n-word + n-word --> n-word overflow, no increase in A.words()
    A.putZero();
    for (i = 0; i < num::words; A.setWord(i, 0xffffffff), i++);
    A._hiword = num::hiword;
    B.putTwo();
    A.addAbs(B);
    printf("%-5s Num::addAbs() 9 of 10\n", (1 == A.word(0) && 1 == A.words() && !A._overflow) ? "OK" : "FAIL"); // (-1) + 2 --> overflow
    A.putZero();
    for (i = 0; i < num::words; A.setWord(i, 0xffffffff), i++);
    A._hiword = num::hiword;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.addAbs(B);
    printf("%-5s Num::addAbs() 10 of 10\n\n", (!A.word(0) && 1 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // (-1) + n-word --> overflow 

    printf("Measuring 1,000 iterations of Num::addAbs()\n");
    printf("(512-bits plus 128 bits)\n");
    A.putRandom(rand, 512);
    B.putRandom(rand, 128);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.addAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::addAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::subAbs()\n\n");
    A.putWord(0xffffffff);
    B.putWord(0xffffffff);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 1 of 8\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1-word - same --> zero
    A.putWord(0xffffffff);
    B.putWord(0xdddddddd);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 2 of 8\n", (1 == A.words() && 0x22222222 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1-word - 1-word --> positive value
    A.putZero();
    A.setWord(1, 1);
    A.setWord(0, 0x69696968);
    A._hiword = 1;
    B.copy(A);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 3 of 8\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // n-word - same --> zero
    A.putZero();
    A.setWord(0, 0x69696968);
    A.setWord(1, 1);
    A._hiword = 1;
    B.putWord(0xb4b4b4b4);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 4 of 8\n", (1 == A.words() && 0xb4b4b4b4 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // n-word - n-word --> positive value
    B.putWord(0x5a5a5a5a);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 5 of 8\n", (1 == A.words() && 0x5a5a5a5a == A.word(0) && !A._hiword) ? "OK" : "FAIL"); // n-word - half-value --> 1-word value
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0x55555555);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 6 of 8\n", (2 == A.words() && 0x3456789a == A.word(0) && 0x01234567 == A.word(1) && !A._overflow) ? "OK" : "FAIL"); // n-word - 1-word --> n-word
    A.putZero();
    A.setWord(0, 1);
    A.setWord(3, 1);
    A._hiword = 3;
    B.putTwo();
    A.subAbs(B);
    printf("%-5s Num::subAbs() 7 of 8\n", (3 == A.words() && 0xffffffff == A.word(0) && 0xffffffff == A.word(1) && 0xffffffff == A.word(2) && !A.word(3) && !A._overflow) ? "OK" : "FAIL"); // n-word - 1-word --> n-word w/fewer words
    A.putZero();
    A.setWord(0, 1);
    A.setWord(3, 1);
    A._hiword = 3;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.subAbs(B);
    printf("%-5s Num::subAbs() 8 of 8\n\n", (3 == A.words() && !A.word(0) && 0xffffffff == A.word(1) && 0xffffffff == A.word(2) && !A._overflow) ? "OK" : "FAIL"); // n-word - n-word --> n-word w/fewer words

    printf("Measuring 1,000 iterations of Num::subAbs()\n");
    printf("(512-bits minus 128 bits)\n");
    A.putRandom(rand, 512);
    B.putRandom(rand, 128);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.subAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::subAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mulAbs()\n\n");
    A.putWord(93492);
    B.putWord(63861);
    A.mulAbs(B);
    printf("%-5s Num::mulAbs() 1 of 3\n", (2 == A.words() && 0x63de7cc4 == A.word(0) && 1 == A.word(1) && !A._overflow) ? "OK" : "FAIL");
    A.putString((uint8_t*)"5555555555");
    B.putString((uint8_t*)"4444444444");
    A.mulAbs(B);
    printf("%-5s Num::mulAbs() 2 of 3\n", (3 == A.words() && 0x6d600dd4 == A.word(0) && 0x56a9534c == A.word(1) && 1 == A.word(2) && !A._overflow) ? "OK" : "FAIL");
    A.mulAbs(B);
    printf("%-5s Num::mulAbs() 3 of 3\n\n", (4 == A.words() && 0xca3e8f30 == A.word(0) && 0xfd887986 == A.word(1) && 0x62964747 == A.word(2) && 1 == A.word(3) && !A._overflow) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::mulAbs()\n");
    printf("(1024 bits times 1024 bits)\n");
    B.putRandom(rand, 1024);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B);  A.mulAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::mulAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::divAbs()\n\n");
    A.putZero();
    A.setWord(0, 0x63de7cc4);
    A.setWord(1, 1);
    A._hiword = 1;
    B.putWord(93492);
    A.divAbs(B);
    printf("%-5s Num::divAbs() 1 of 1\n\n", (1 == A.words() && 63861 == A.word(0) && !A.word(1) && !A._overflow) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::divAbs()\n");
    printf("(2048 bits divided by 256 bits with _loword = 0)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.divAbs(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::divAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::copy and Num::divAbs()\n");
    printf("(2048 bits divided by 256 bits with _loword = 4)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    for (i = 0; i < 4; B.setWord(i, 0), C.setWord(i, 0), i++);
    B._loword = 4;
    C._loword = 4;
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.divAbs(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::divAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::modAbs()\n\n");
    A.putWord(88888888);
    B.putWord(12345);
    A.modAbs(B);
    printf("%-5s Num::modAbs() 1 of 2\n", (1 == A.words() && 4888 == A.word(0) && 13 == A.bits()) ? "OK" : "FAIL");
    A.putString((uint8_t*)"55555555555555555555");
    B.putString((uint8_t*)"444444444444");
    A.modAbs(B);
    printf("%-5s Num::modAbs() 2 of 2\n\n", (1 == A.words() && 0x034fb5e3 == A.word(0) && 26 == A.bits()) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::modAbs()\n");
    printf("(2048 bits modulo 256 bits with _loword = 0)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.modAbs(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::modAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::copy and Num::modAbs()\n");
    printf("(2048 bits modulo 256 bits with _loword = 4)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    for (i = 0; i < 4; B.setWord(i, 0), C.setWord(i, 0), i++);
    B._loword = 4;
    C._loword = 4;
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.modAbs(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::modAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::increment()\n\n");
    A.putLong(-3);
    A.increment();
    printf("%-5s Num::increment() 1 of 6\n", ((uint32_t)-1 == A._sign && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // (-3)++ = -2
    A.increment();
    printf("%-5s Num::increment() 2 of 6\n", ((uint32_t)-1 == A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // (-2)++ = -1
    A.increment();
    printf("%-5s Num::increment() 3 of 6\n", (!A._sign && 1 == A.bits() && 1 == A.words() && !A.word(0)) ? "OK" : "FAIL"); // (-1)++ = 0
    A.increment();
    printf("%-5s Num::increment() 4 of 6\n", (!A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // (0)++ = 1
    A.increment();
    printf("%-5s Num::increment() 5 of 6\n", (!A._sign && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // (1)++ = 2
    A.increment();
    printf("%-5s Num::increment() 6 of 6\n\n", (!A._sign && 2 == A.bits() && 1 == A.words() && 3 == A.word(0)) ? "OK" : "FAIL"); // (2)++ = 3

    printf("Measuring 1,000 iterations of Num::increment()\n");
    printf("(2048 bits incremented 1,000 times)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.increment(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::increment() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::decrement()\n\n");
    A.putWord(3);
    A.decrement();
    printf("%-5s Num::decrement() 1 of 6\n", (!A._sign && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // (3)-- = 2
    A.decrement();
    printf("%-5s Num::decrement() 2 of 6\n", (!A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // (2)-- = 1
    A.decrement();
    printf("%-5s Num::decrement() 3 of 6\n", (!A._sign && 1 == A.bits() && 1 == A.words() && !A.word(0)) ? "OK" : "FAIL"); // (1)-- = 0
    A.decrement();
    printf("%-5s Num::decrement() 4 of 6\n", ((uint32_t)-1 == A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // (0)-- = -1
    A.decrement();
    printf("%-5s Num::decrement() 5 of 6\n", ((uint32_t)-1 == A._sign && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // (-1)-- = -2
    A.decrement();
    printf("%-5s Num::decrement() 6 of 6\n\n", ((uint32_t)-1 == A._sign && 2 == A.bits() && 1 == A.words() && 3 == A.word(0)) ? "OK" : "FAIL"); // (-2)-- = -3

    printf("Measuring 1,000 iterations of Num::decrement()\n");
    printf("(2048 bits decremented 1,000 times)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.decrement(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::decrement() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::add()\n\n");
    A.putWord(0x5a5a5a5a);
    A.add(A);
    printf("%-5s Num::add() 1 of 10\n", (0xb4b4b4b4 == A.word(0) && 1 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 1-word --> no word overflow
    A.add(A);
    printf("%-5s Num::add() 2 of 10\n", (0x69696968 == A.word(0) && 1 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 1-word --> word overflow
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0x55555555);
    A.add(B);
    printf("%-5s Num::add() 3 of 10\n", (0xdf012344 == A.word(0) && 0x01234567 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 2-word --> no word overflow
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0xaaaaaaaa);
    A.add(B);
    printf("%-5s Num::add() 4 of 10\n", (0x34567899 == A.word(0) && 0x01234568 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 2-word --> word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0xffffffff);
    A._hiword = 3;
    B.putTwo();
    A.add(B);
    printf("%-5s Num::add() 5 of 10\n", (1 == A.word(0) && !A.word(1) && !A.word(2) && !A.word(3) && 1 == A.word(4) && 5 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + n-word --> n-word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0xffffffff);
    A._hiword = 3;
    B.putZero();
    B.setWord(0, 0x00000001);
    B.setWord(1, 0x00000001);
    B._hiword = 1;
    A.add(B);
    printf("%-5s Num::add() 6 of 10\n", (!A.word(0) && 1 == A.word(1) && !A.word(2) && !A.word(3) && 1 == A.word(4) && 5 == A.words() && !A._overflow) ? "OK" : "FAIL"); // n-word + n-word --> n-word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0x33333333);
    A.setWord(4, 0x22222222);
    A.setWord(5, 0x11111111);
    A._hiword = 5;
    B.putTwo();
    A.add(B);
    printf("%-5s Num::add() 7 of 10\n", (1 == A.word(0) && !A.word(1) && !A.word(2) && 0x33333334 == A.word(3) && 0x22222222 == A.word(4) && 0x11111111 == A.word(5) && 6 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + n-word --> word overflow, no increase in A.words()
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0x33333333);
    A.setWord(4, 0x22222222);
    A.setWord(5, 0x11111111);
    A._hiword = 5;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.add(B);
    printf("%-5s Num::add() 8 of 10\n", (!A.word(0) && 1 == A.word(1) && !A.word(2) && 0x33333334 == A.word(3) && 0x22222222 == A.word(4) && 0x11111111 == A.word(5) && 6 == A.words() && !A._overflow) ? "OK" : "FAIL"); // n-word + n-word --> n-word overflow, no increase in A.words()
    A.putZero();
    for (i = 0; i < num::words; A.setWord(i, 0xffffffff), i++);
    A._hiword = num::hiword;
    B.putTwo();
    A.add(B);
    printf("%-5s Num::add() 9 of 10\n", (1 == A.word(0) && 1 == A.words() && !A._overflow) ? "OK" : "FAIL"); // (-1) + 2 --> overflow
    A.putZero();
    for (i = 0; i < num::words; A.setWord(i, 0xffffffff), i++);
    A._hiword = num::hiword;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.add(B);
    printf("%-5s Num::add() 10 of 10\n\n", (!A.word(0) && 1 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // (-1) + n-word --> overflow 

    printf("Measuring 1,000 iterations of Num::add()\n");
    printf("(512-bits plus 128 bits)\n");
    A.putRandom(rand, 512);
    B.putRandom(rand, 128);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.add(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::add() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::sub()\n\n");
    A.putWord(0xffffffff);
    B.putWord(0xffffffff);
    A.sub(B);
    printf("%-5s Num::sub() 1 of 8\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1-word - same --> zero
    A.putWord(0xffffffff);
    B.putWord(0xdddddddd);
    A.sub(B);
    printf("%-5s Num::sub() 2 of 8\n", (1 == A.words() && 0x22222222 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1-word - 1-word --> positive value
    A.putZero();
    A.setWord(1, 1);
    A.setWord(0, 0x69696968);
    A._hiword = 1;
    B.copy(A);
    A.sub(B);
    printf("%-5s Num::sub() 3 of 8\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // n-word - same --> zero
    A.putZero();
    A.setWord(0, 0x69696968);
    A.setWord(1, 1);
    A._hiword = 1;
    B.putWord(0xb4b4b4b4);
    A.sub(B);
    printf("%-5s Num::sub() 4 of 8\n", (1 == A.words() && 0xb4b4b4b4 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // n-word - n-word --> positive value
    B.putWord(0x5a5a5a5a);
    A.sub(B);
    printf("%-5s Num::sub() 5 of 8\n", (1 == A.words() && 0x5a5a5a5a == A.word(0) && !A._hiword) ? "OK" : "FAIL"); // n-word - half-value --> 1-word value
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0x55555555);
    A.sub(B);
    printf("%-5s Num::sub() 6 of 8\n", (2 == A.words() && 0x3456789a == A.word(0) && 0x01234567 == A.word(1) && !A._overflow) ? "OK" : "FAIL"); // n-word - 1-word --> n-word
    A.putZero();
    A.setWord(0, 1);
    A.setWord(3, 1);
    A._hiword = 3;
    B.putTwo();
    A.sub(B);
    printf("%-5s Num::sub() 7 of 8\n", (3 == A.words() && 0xffffffff == A.word(0) && 0xffffffff == A.word(1) && 0xffffffff == A.word(2) && !A.word(3) && !A._overflow) ? "OK" : "FAIL"); // n-word - 1-word --> n-word w/fewer words
    A.putZero();
    A.setWord(0, 1);
    A.setWord(3, 1);
    A._hiword = 3;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.sub(B);
    printf("%-5s Num::sub() 8 of 8\n\n", (3 == A.words() && !A.word(0) && 0xffffffff == A.word(1) && 0xffffffff == A.word(2) && !A._overflow) ? "OK" : "FAIL"); // n-word - n-word --> n-word w/fewer words

    printf("Measuring 1,000,000 iterations of Num::sub()\n");
    printf("(512-bits minus 128 bits)\n");
    A.putRandom(rand, 512);
    B.putRandom(rand, 128);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.sub(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::sub() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mul()\n\n");
    A.putWord(93492);
    B.putWord(63861);
    A.mul(B);
    printf("%-5s Num::mul() 1 of 3\n", (2 == A.words() && 0x63de7cc4 == A.word(0) && 1 == A.word(1) && !A._overflow) ? "OK" : "FAIL");
    A.putString((uint8_t*)"5555555555");
    B.putString((uint8_t*)"4444444444");
    A.mul(B);
    printf("%-5s Num::mul() 2 of 3\n", (3 == A.words() && 0x6d600dd4 == A.word(0) && 0x56a9534c == A.word(1) && 1 == A.word(2) && !A._overflow) ? "OK" : "FAIL");
    A.mul(B);
    printf("%-5s Num::mul() 3 of 3\n\n", (4 == A.words() && 0xca3e8f30 == A.word(0) && 0xfd887986 == A.word(1) && 0x62964747 == A.word(2) && 1 == A.word(3) && !A._overflow) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::mul()\n");
    printf("(512 bits times 512 bits)\n");
    B.putRandom(rand, 512);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.mul(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::sub() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::div()\n\n");
    A.putZero();
    A.setWord(0, 0x63de7cc4);
    A.setWord(1, 1);
    A._hiword = 1;
    B.putWord(93492);
    A.div(B);
    printf("%-5s Num::div() 1 of 1\n\n", (1 == A.words() && 63861 == A.word(0) && !A.word(1) && !A._overflow) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::div()\n");
    printf("(2048 bits divided by 256 bits with _loword = 0)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.div(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::div() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mod()\n\n");
    A.putWord(88888888);
    B.putWord(12345);
    A.mod(B);
    printf("%-5s Num::mod() 1 of 2\n", (1 == A.words() && 4888 == A.word(0) && 13 == A.bits()) ? "OK" : "FAIL");
    A.putString((uint8_t*)"55555555555555555555");
    B.putString((uint8_t*)"444444444444");
    A.mod(B);
    printf("%-5s Num::mod() 2 of 2\n\n", (1 == A.words() && 0x034fb5e3 == A.word(0) && 26 == A.bits()) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::mod()\n");
    printf("(2048 bits modulo 256 bits with _loword = 0)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.mod(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::mod() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::montMul(), Num::montExp()\n\n");
    A.putWord(17);
    B.putWord(5);
    C.putWord(35);
    D.putWord(29);
    E.montExp(A, B, C);
    printf("%-5s Num::montExp() 1 of 2\n", (12 == E.word(0)) ? "OK" : "FAIL");
    E.montExp(E, D, C);
    printf("%-5s Num::montExp() 2 of 2\n\n", (17 == E.word(0)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::montExp() (17^5 mod 35)\n");
    A = 17;
    B = 5;
    C = 35;
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { E.montExp(A, B, C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::montExp() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::isPrime()\n\n");
    A.putZero();
    printf("%-5s Num::isPrime() 1 of 8\n", (!A.isPrime()) ? "OK" : "FAIL");
    A.putOne();
    printf("%-5s Num::isPrime() 2 of 8\n", (!A.isPrime()) ? "OK" : "FAIL");
    A.putTwo();
    printf("%-5s Num::isPrime() 3 of 8\n", (A.isPrime()) ? "OK" : "FAIL");
    A.putWord(3);
    printf("%-5s Num::isPrime() 4 of 8\n", (A.isPrime()) ? "OK" : "FAIL");
    A.putWord(997);
    printf("%-5s Num::isPrime() 5 of 8\n", (A.isPrime()) ? "OK" : "FAIL");
    A.putWord(2000);
    printf("%-5s Num::isPrime() 6 of 8\n", (!A.isPrime()) ? "OK" : "FAIL");
    A.putWord(55555);
    printf("%-5s Num::isPrime() 7 of 8\n", (!A.isPrime()) ? "OK" : "FAIL");
    A.putString((uint8_t*)"9572039759");
    printf("%-5s Num::isPrime() 8 of 8\n\n", (!A.isPrime()) ? "OK" : "FAIL");

    printf("Testing Num::putPrime()\n\n");
    for (j = 0; j < 6; j++) {
        A.putPrime(rand, (size_t)32 << j);
        printf("%-5s Num::putPrime(%u)\n", (A.isPrime()) ? "OK" : "FAIL", 32 << j);
    }
    printf("\n");

    printf("Measuring 100 iterations of Num::isPrime()\n");
    A.putPrime(rand, 512);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 100; i++) { A.isPrime(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::isPrime() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count() * 10);

    for (j = 0; j < 6; j++) {
        printf("Measuring 10 iterations of Num::putPrime(%u)\n", 32 << j);
        start = std::chrono::steady_clock::now();
        for (i = 0; i < 10; i++) { A.putPrime(rand, (size_t)32 << j); }
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        printf("Num::putPrime(%u) time: %0.4fms  avg: %0.6fms\n\n", 32 << j, elapsed.count() * 1000, elapsed.count() * 100);
    }

    printf("Testing Num::GCD()\n\n");
    X.putWord(383);
    Y.putWord(271);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 1 of 5\n", (1 == G.word(0)) ? "OK" : "FAIL");
    X.putWord(877);
    Y.putWord(557);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 2 of 5\n", (1 == G.word(0)) ? "OK" : "FAIL");
    X.putWord(1783);
    Y.putWord(1063);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 3 of 5\n", (1 == G.word(0)) ? "OK" : "FAIL");
    X.putWord(3041);
    Y.putWord(2903);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 4 of 5\n", (1 == G.word(0)) ? "OK" : "FAIL");
    X.putWord(768454923);
    Y.putWord(542167814);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 5 of 5\n\n", (1 == G.word(0)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::GCD()\n");
    printf("(512-bit prime, 512-bit prime)\n");
    X.putPrime(rand, 512);
    Y.putPrime(rand, 512);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { G.GCD(X, Y); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::GCD() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mulInvGCD()\n\n");
    X.putWord(383);                               //  m
    Y.putWord(271);                               //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 1 of 5\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");
    X.putWord(877);                               //  m
    Y.putWord(557);                               //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 2 of 5\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");
    X.putWord(1783);                              //  m
    Y.putWord(1063);                              //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 3 of 5\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");
    X.putWord(3041);                              //  m
    Y.putWord(2903);                              //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 4 of 5\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");
    X.putWord(768454923);                         //  m
    Y.putWord(542167814);                         //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 5 of 5\n\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::mulInvGCD()\n");
    printf("(512-bit prime, 512-bit prime )\n");
    X.putPrime(rand, 512);
    Y.putPrime(rand, 512);
    if (Y > X) {
        A = Y;
        Y = X;
        X = A;
    }
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { G.mulInvGCD(X, Y, D); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::mulInvGCD() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mulInvWord\n\n");
    i = Num::mulInvWord(3);
    printf("%-5s Num::mulInvWord(3) = %u\n", (i * 3 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(237);
    printf("%-5s Num::mulInvWord(237) = %u\n", (i * 237 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(4911);
    printf("%-5s Num::mulInvWord(4911) = %u\n", (i * 4911 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(5437);
    printf("%-5s Num::mulInvWord(5437) = %u\n", (i * 5437 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(38625);
    printf("%-5s Num::mulInvWord(38625) = %u\n", (i * 38625 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(373823);
    printf("%-5s Num::mulInvWord(373823) = %u\n", (i * 373823 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(7856321);
    printf("%-5s Num::mulInvWord(7856321) = %u\n", (i * 7856321 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(62489019);
    printf("%-5s Num::mulInvWord(62489019) = %u\n", (i * 62489019 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(0xCF977871);
    printf("%-5s Num::mulInvWord(3482810481L) = %u\n\n", (i * 0xcf977871 == 1) ? "OK" : "FAIL", i);

    printf("Measuring 1,000 iterations of Num::mulInvWord()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { Num::mulInvWord(0xcf977871); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::mulInvWord time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());
}

void testDSA()
{
}

void testRSA()
{
    size_t len;
    Random rnd;
    Num N, C, T, xp, xp1, xp2, p1;
    RSA rsa;
    uint8_t in[32];
    uint8_t out[256];
    uint8_t dec[32];

    printf("Testing RSA\n\n");
    printf("Testing RSA::create(1024)\n\n");
    rsa.Create(1024);
    N.putRandom(rnd, 512);
    C.montExp(N, rsa.E, rsa.N);
    T.montExp(C, rsa.D, rsa.N);
    printf("%-5s RSA::create() 1 of 1\n\n", (!N.compare(T) ? "OK" : "FAIL"));

    printf("Testing RSA::sign() and RSA::verify()\n\n");
    memcpy(in, "abcdefghijklmnopqrstuvwxyz01234\x00", 32);
    rsa.Sign(out, in, 32);
    len = 128;
    printf("%-5s RSA::sign() and verify() 1 of 1\n\n", rsa.Verify(dec, out, &len) ? "OK" : "FAIL");

    printf("Testing RSA::encrypt() and RSA::decrypt()\n\n");
    len = 32;
    rsa.Encrypt(out, in, &len);
    rsa.Decrypt(dec, out, &len);
    printf("%-5s RSA::encrypt() and decrypt() 1 of 1\n\n", !memcmp(in, dec, 32) ? "OK" : "FAIL");
}

void testAsymmetricEncryption()
{
    queryRun("DSA", testDSA);
    queryRun("RSA", testRSA);
}

void testCRC32()
{
}

void testZlib()
{
    uint8_t rec[4096] = { 0 };
    uint8_t cmp[4096] = { 0 };
    uint8_t dec[4096] = { 0 };
    z_stream z = { 0 };

    printf("Testing Zlib Compression\n\n");
    if (!_dump)
        printf("\n");
    size_t len = strlen(COMPRESS_RECORD);
    memcpy(rec, COMPRESS_RECORD, len);
    if (_dump) {
        printf("Test Data:\n");
        dumpMem(rec, len);
    }
    if (Z_OK != DeflateInit(&z)) {
        printf("FAIL  Unable to initialize ZLIB for compression\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    size_t totalIn = 0;
    size_t totalOut = 0;
    size_t in = 0;
    size_t out = 0;
    size_t loops = 0;
    do {
        z.next_in = &rec[in];
        z.avail_in = (uInt)(len - in);
        z.next_out = &cmp[out];
        z.avail_out = (uInt)(sizeof cmp - out);
        int zrc = DeflateNext(&z);
        if (Z_OK != zrc && Z_STREAM_END != zrc) {
            printf("FAIL  Unable to compress data\n");
            dumpMem((uint8_t*)&z, sizeof(z));
            break;
        }
        in = z.total_in;
        out = z.total_out;
        loops++;
    } while (in < len && loops < 100);
    if (_dump)
        printf("\n");
    printf("OK    (%zd) bytes compressed to (%zd) bytes in (%zd) iteration(s)\n", len, out, loops);
    z.next_in = 0;
    z.avail_in = 0;
    z.next_out = &cmp[out];
    z.avail_out = (uInt)(sizeof cmp - out);
    int zrc = DeflateFinal(&z);
    if (Z_OK != zrc && Z_STREAM_END != zrc) {
        printf("FAIL  Unable to finalize compression\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    zrc = DeflateEnd(&z);
    if (Z_OK != zrc) {
        printf("FAIL  Unable to release ZLIB resources\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    if (_dump) {
        printf("\nCompressed Data:\n");
        dumpMem(cmp, out);
    }
    len = out;
    memset(&z, 0, sizeof(z));
    if (Z_OK != InflateInit(&z)) {
        printf("FAIL  Unable to initialize ZLIB for decompression\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    totalIn = 0;
    totalOut = 0;
    in = 0;
    out = 0;
    loops = 0;
    do {
        z.next_in = &cmp[in];
        z.avail_in = (uInt)(len - in);
        z.next_out = &dec[out];
        z.avail_out = (uInt)(sizeof dec - out);
        zrc = InflateNext(&z);
        if (Z_OK != zrc && Z_STREAM_END != zrc) {
            printf("FAIL  Unable to decompress data\n");
            dumpMem((uint8_t*)&z, sizeof(z));
            break;
        }
        in = z.total_in;
        out = z.total_out;
        loops++;
    } while (in < len && loops < 100);
    if (_dump)
        printf("\n");
    printf("OK    (%zd) bytes decompressed to (%zd) bytes in (%zd) iteration(s)\n", len, out, loops);
    zrc = InflateEnd(&z);
    if (Z_OK != zrc) {
        printf("FAIL  Unable to release ZLIB resources\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    if (_dump) {
        printf("\nDecompressed Data:\n");
        dumpMem(dec, out);
    }
    printf("\n%-5s deflate() and inflate() 1 of 1\n\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");
}

void testCompression()
{
    queryRun("CRC-32", testCRC32);
    queryRun("ZLIB", testZlib);
}

void testBase64()
{
    size_t len, i;
    uint8_t rec[128] = { 0 };
    uint8_t enc[256] = { 0 };
    uint8_t dec[128] = { 0 };
    Random rand;

    printf("Testing Base64 Encoding\n");
    if (!_dump)
        printf("\n");
    for (i = 0; i < 112; i++) { rec[i] = (uint8_t)(rand.Rand()); }
    len = i;
    base64enc(enc, rec, &len);
    base64dec(dec, enc, &len);
    if (_dump) {
        printf("\n");
        printf("Plain:\n");
        dumpMem(rec, i);
        printf("Encoded:\n");
        dumpMem(enc, strlen((const char*)enc));
        printf("Decoded:\n");
        dumpMem(dec, i);
        printf("\n");
    }
    printf("%-5s Base64 1 of 4\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");

    memset(rec, 0, sizeof(rec));
    memset(enc, 0, sizeof(enc));

    for (i = 0; i < 113; i++) { rec[i] = (uint8_t)(rand.Rand()); }
    len = i;
    base64enc(enc, rec, &len);
    base64dec(dec, enc, &len);
    if (_dump) {
        printf("\n");
        printf("Plain:\n");
        dumpMem(rec, i);
        printf("Encoded:\n");
        dumpMem(enc, strlen((const char*)enc));
        printf("Decoded:\n");
        dumpMem(dec, i);
        printf("\n");
    }
    printf("%-5s Base64 2 of 4\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");

    memset(rec, 0, sizeof(rec));
    memset(enc, 0, sizeof(enc));

    for (i = 0; i < 114; i++) { rec[i] = (uint8_t)(rand.Rand()); }
    len = i;
    base64enc(enc, rec, &len);
    base64dec(dec, enc, &len);
    if (_dump) {
        printf("\n");
        printf("Plain:\n");
        dumpMem(rec, i);
        printf("Encoded:\n");
        dumpMem(enc, strlen((const char*)enc));
        printf("Decoded:\n");
        dumpMem(dec, i);
        printf("\n");
    }
    printf("%-5s Base64 3 of 4\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");

    memset(rec, 0, sizeof(rec));
    memset(enc, 0, sizeof(enc));

    for (i = 0; i < 115; i++) { rec[i] = (uint8_t)(rand.Rand()); }
    len = i;
    base64enc(enc, rec, &len);
    base64dec(dec, enc, &len);
    if (_dump) {
        printf("\n");
        printf("Plain:\n");
        dumpMem(rec, i);
        printf("Encoded:\n");
        dumpMem(enc, strlen((const char*)enc));
        printf("Decoded:\n");
        dumpMem(dec, i);
        printf("\n");
    }
    printf("%-5s Base64 4 of 4\n\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");
}

const char* x509_passphrase = "abcdefghijklmnopqrstuvwxyz";
RSA _rsa;
RSA _rsa_chk;
X509 _X;

void testX509()
{
    printf("Testing X.509 Encoding\n\n");
    size_t len = 4096;
    uint8_t* phr_enc = new uint8_t[len];
    uint8_t* phr_chk = new uint8_t[len];

    Passphrase phr;
    memset(phr_enc, 0, len);
    phr.Encode(phr_enc, x509_passphrase);
    FILE* file = fopen("test.phr", "w+b");
    fwrite(phr_enc, 1, strlen((char*)phr_enc), file);
    fclose(file);
    printf("OK    Encoded passphrase exported to test.phr\n");

    file = fopen("test.phr", "rb");
    len = 4096;
    memset(phr_enc, 0, 4096);
    fread(phr_enc, 1, len, file);
    fclose(file);

    memset(phr_chk, 0, 4096);
    if (!phr.Decode(phr_chk, (char*)phr_enc)) {
        printf("FAIL  Unable to decode passphrase\n\n");
        delete[] phr_enc;
        delete[] phr_chk;
        phr_enc = nullptr;
        phr_chk = nullptr;
        return;
    }
    if (strcmp((char*)phr_chk, x509_passphrase)) {
        printf("FAIL  Passphrase incorrectly decoded\n\n");
        delete[] phr_enc;
        delete[] phr_chk;
        phr_enc = nullptr;
        phr_chk = nullptr;
        return;
    }
    printf("OK    Passphrase decoded\n");
    delete[] phr_enc;
    phr_enc = nullptr;

    len = 4096;
    uint8_t* key_enc = new uint8_t[len];
    uint8_t* key_dec = new uint8_t[len];
    uint8_t* key_chk = new uint8_t[len];

    _rsa.Create(1024);
    printf("OK    Key-pair created\n");
    memset(key_dec, 0, 4096);
    _rsa.ExportKey(key_dec, &len);
    file = fopen("test.prv", "w+b");
    fwrite(key_dec, 1, len, file);
    fclose(file);
    printf("OK    Private key exported to test.prv\n");

    memset(key_enc, 0, 4096);
    _rsa.ExportEncryptedKey(key_enc, &len, phr_chk, strlen((char*)phr_chk));
    file = fopen("test.p8", "w+b");
    fwrite(key_enc, 1, len, file);
    fclose(file);
    printf("OK    Encrypted private key exported to test.p8\n");

    file = fopen("test.p8", "rb");
    len = 4096;
    memset(key_enc, 0, 4096);
    fread(key_enc, 1, len, file);
    fclose(file);

    uint8_t* imp = key_enc;
    _rsa_chk.Import(&imp, &len, phr_chk, strlen((char*)phr_chk));
    delete[] phr_chk;
    phr_chk = nullptr;

    if (_rsa.N != _rsa_chk.N) {
        printf("FAIL  Imported RSA key modulus differs\n\n");
        delete[] key_enc;
        delete[] key_chk;
        key_enc = nullptr;
        key_chk = nullptr;
        return;
    }
    if (_rsa.E != _rsa_chk.E) {
        printf("FAIL  Imported RSA key public exponent differs\n\n");
        delete[] key_enc;
        delete[] key_chk;
        key_enc = nullptr;
        key_chk = nullptr;
        return;
    }
    if (_rsa.D != _rsa_chk.D) {
        printf("FAIL  Imported RSA key private exponent differs\n\n");
        delete[] key_enc;
        delete[] key_chk;
        key_enc = nullptr;
        key_chk = nullptr;
        return;
    }
    printf("OK    Encrypted private key imported\n");

    memset(key_dec, 0, 4096);
    strcpy((char*)key_dec, "abcdefghijklmnopqrstuvwxyz01234");
    len = strlen((const char*)key_dec);
    memset(key_enc, 0, 4096);
    _rsa_chk.Encrypt(key_enc, key_dec, &len);

    memset(key_chk, 0, 4096);
    _rsa_chk.Decrypt(key_chk, key_enc, &len);
    printf("%-5s Encrypt/decrypt with imported key\n", !memcmp(key_dec, key_chk, len) ? "OK" : "FAIL");

    delete[] key_enc;
    delete[] key_chk;
    key_enc = nullptr;
    key_chk = nullptr;

    _X.PutIssuer("E=netcybr@proserio.com;O=Proserio;CN=NetCybrCA");
    _X.PutSerNo((uint8_t*)"1001");
    _X.PutSubject("E=netcybr@proserio.com;O=Proserio;CN=NetCybrCA");
    _X.PutNotBefore((uint8_t*)"20200101000000");
    _X.PutNotAfter((uint8_t*)"20300101000000");
    _X.PutPubKey(_rsa_chk);
    _X.PutPrvKey(_rsa_chk);
    _X._flags |= x509::flags::cacert;
    _X._pathLen = 3;
    _X.ExportCert(key_dec, &len);

    file = fopen("test.cer", "w+b");
    fwrite(key_dec, 1, len, file);
    fclose(file);
    printf("OK    Certificate exported to test.cer\n");

    delete[] key_dec;
    key_dec = nullptr;
    printf("\n");
}

void testEncoding()
{
    queryRun("Base64 Encoding", testBase64);
    queryRun("X.509 Encoding", testX509);
}

*/

void runTests()
{
    printf("\n");
    printf("sizeof(short)     %2zd bytes\n", sizeof(short));
    printf("sizeof(int)       %2zd bytes\n", sizeof(int));
    printf("sizeof(long)      %2zd bytes\n", sizeof(long));
    printf("sizeof(long long) %2zd bytes\n", sizeof(long long));
    printf("\n");

/*
    queryRun("Message Digest", testDigestAlgs);
    queryRun("Hashed MAC", testHMACAlgs);
    queryRun("Symmetric Encryption", testSymmetricEncryption);
    queryRun("Pseudo-Random", testRandom);
    queryRun("Large Integer", testInt);
    queryRun("Asymmetric Encryption", testAsymmetricEncryption);
    queryRun("Compression", testCompression);
    queryRun("Encoding", testEncoding);
*/

    printf("Tests Completed\n");
}

int usage()
{
    printf("Usage: testargo test [all] [dump]\n");
    return 0;
}

int __cdecl main(int argc, char* argv[])
{
    printf("Argo Test Program [0.X]\n");
    printf("Copyright 2010 ThatCodeBase. MIT License.\n");
    if (argc > 4 || (argc == 2 && !strcmp(argv[1], testargo::help)))
        return usage();
    char* args[4] = { 0 };
    for (int n = 0; n < argc; n++)
        args[n] = argv[n];
    if (1 == argc) {
        char cmd[256] = { 0 };
        fflush(stdin);
        fgets(cmd, sizeof cmd - 1, stdin);
        char* nexttok = cmd;
        //for (int n = 1; nexttok && n < 4; n++)
        //    args[n] = tokstrx(nexttok, " \t", " \t\n", &nexttok);
    }
    if (args[1] && !strcmp(args[1], testargo::test)) {
        for (int n = 2; n < 4 && args[n]; n++) {
            if (!strcmp(args[n], testargo::all))
                _all = true;
            else if (!strcmp(args[n], testargo::dump))
                _dump = true;
        }
        runTests();
    } else
        return usage();
    return 0;
}
