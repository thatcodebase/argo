#include "uri.h"
#include "ascii.h"

URI::URI()
{
    Init();
}

URI::~URI()
{
    Reset();
}

void URI::Init()
{
    _addr = 0;
    _port = 0;
    _protocol = 0;
    _host = nullptr;
    _resource = nullptr;
    _user = nullptr;
    _password = nullptr;
}

void URI::Reset()
{
    freestr(&_host);
    freestr(&_resource);
    freestr(&_user);
    freestr(&_password);

    Init();
}

bool URI::Put(char *uri_s)
{
    if (!uri_s) {
        return false;
    }
    size_t len = strlen(uri_s);
    if (!len || len > 255) {
        return false;
    }
    char buf[256] = { 0 };
    strcpy(buf, uri_s);
    char *p = buf;
    char *t = buf;

    for (; *t && _colon != *t; t++);
    if (*t) {
        if (!memcmp("file://", p, 7)) {
            _protocol = uri::protocol::file;
            _port = 0;
            p = t + 3;
        } else if (!memcmp("http://", p, 7)) {
            _protocol = uri::protocol::http;
            _port = uri::port::http;
            p = t + 3;
        } else if (!memcmp("https://", p, 8)) {
            _protocol = uri::protocol::https;
            _port = uri::port::https;
            p = t + 3;
        } else {
            _protocol = uri::protocol::http;
            _port = uri::port::http;
        }
    } else {
        for (t = p = buf; *t && _at != *t; t++);
        if (*t) {
            _protocol = uri::protocol::smtp;
            _port = uri::port::smtp;
            p = t + 1;
        } else {
            _protocol = uri::protocol::file;
        }
    }

    if (uri::protocol::file == _protocol) {
        setstr(&_resource, p);
    } else {
        char *u, *w;
        for (u = 0, t = p; (*t) && (_at != *t); t++);
        if (*t) {
            *t = '\0';
            u = p;
            p = t + 1;
            for (w = 0, t = u; (*t) && (_colon != *t); t++);
            if (*t) {
                *t = '\0';
                w = t + 1;
                if (strlen(w)) {
                    _password = dupstr(w);
                }
            }
            if (strlen(u)) {
                _user = dupstr(u);
            }
        }
        char *r;
        for (r = 0, t = p; (*t) && (_slash != *t); t++);
        if (*t) {
            r = t;
            if (strlen(r)) {
                _resource = dupstr(r);
            }
            *t = '\0';
        }
        char *o, *h;
        for (o = 0, h = t = p; (*t) && (_colon != *t); t++);
        if (*t) {
            *t = '\0';
            o = t + 1;
            if (strlen(o)) {
                if (!sscanf(o, "%hi", &_port)) {
                    _port = 0;
                }
            }
        }
        if (strlen((const char *)h)) {
            _host = dupstr(h);
            if (uri::protocol::file != _protocol) {
                _addr = inet_addr(_host);
                if ((INADDR_NONE == _addr) || (!_addr)) {
                    struct hostent *host = gethostbyname(_host);
                    if (!host) {
                        return false;
                    }
                    _addr = *(unsigned int *)host->h_addr_list[0];
                }
                _addr = htonl(_addr);
            }
        }
    }
    return true;
}
