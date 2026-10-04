#include "api.h"
#include "ascii.h"

char* dupstr(const char* s)
{
    char* d = nullptr;
    if (s) {
        size_t len = strlen(s);
        if (d) {
            if (len) {
                memcpy(d, s, len);
            }
            d[len] = 0;
        }
    }
    return d;
}

void freeptr(uint8_t** ptr)
{
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = 0;
    }
}

void freestr(char** ptr)
{
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = 0;
    }
}

void setstr(char** ptr, const char* s)
{
    if (ptr && *ptr != s) {
        freestr(ptr);
        *ptr = dupstr(s);
    }
}
