#include "channel.h"
#include "ascii.h"

#include <map>

namespace http {
    const char* day[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const char* month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    std::map<http::response, const char*> message = {
        { http::response::ok, "OK"},
        { http::response::badrequest, "Bad Request"}
    };
}
const char* ok_0 = \
"HTTP/%01u.%01u 200 OK\r\nDate: %s\r\nServer: Argo/0.X\r\n" \
"Content-type: text/html\r\nContent-Length: %zd\r\n\r\n";
const char* ok_1 = \
"<!DOCTYPE html><html><head>" \
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">" \
"<style type=\"text/css\">" \
"body{background-color:#fffffa;color:#2b2c30;margin:0;}" \
"div{padding:3px;font-family:Arial,sans-serif;font-size:1em;}" \
".titl{position:fixed;top:0;}" \
".copy{background-color:#2b2c30;color:#fffafa;position:fixed;bottom:0;width:50%;}" \
".rlbl{right:0;text-align:right;}" \
"</style><title>Argo 0.X</title></head><body>" \
"<div class=\"titl\">Argo 0.X Experimental</div>" \
"<div class=\"copy\">&copy; 2010 ThatCodeBase</div>" \
"<div class=\"copy rlbl\">";
const char* ok_2 = \
"</div></body></html>";

Channel::Channel()
{
    Init();
}

Channel::~Channel()
{
    Reset();
}

void Channel::Init()
{
    _next = nullptr;
    _prev = nullptr;
    _state = channel::state::ready;
    _method = http::method::unspecified;
    _expires = 0;
    _remain = 0;
    _plainTextVersion = 0;
    _plainTextSize = 0;
    _handShakeSize = 0;
    _httpMajor = 1;
    _httpMinor = 0;
    _tlsRecType = 0;
    _tlsHandShakeType = 0;
    _haveChangeCipherSpec = false;
}

void Channel::Reset()
{
    _uri.Reset();
    _sha256.Reset();
    _socket.Reset();
    _read.Reset();
    _write.Reset();
    Init();
}

void Channel::Read()
{
    if (!_read.Size()) {
        _read.Resize(channel::size);
    }
    _read.Front();
    size_t len = _read.Avail();
    if (_socket.Read(_read.Tail(), &len)) {
        _read.Extend(len);
    } else {
        Reset();
    }
}

void Channel::Write()
{
    size_t len = _write.Length();
    if (_socket.Write(_write.Head(), &len)) {
        _write.Discard(len);
    } else {
        Reset();
    }
}

void Channel::Service()
{
    if (time(0) > _expires) {
        _state = channel::state::done;
    }
    switch (_state) {
    case channel::state::connected:
        Connected();
        break;
    case channel::state::needfirstbytes:
        NeedFirstBytes();
        break;
    case channel::state::needplaintext:
        NeedPlainText();
        break;
    case channel::state::needhandshake:
        NeedHandShake();
        break;
    case channel::state::needrectypechange:
        NeedRecTypeChange();
        break;

    case channel::state::needrequest:
        NeedRequest();
        break;
    case channel::state::haverequest:
        HaveRequest();
        break;
    case channel::state::needheader:
        NeedHttpHeader();
        break;
    case channel::state::haveheader:
        HaveHttpHeader();
        break;
    case channel::state::needbody:
        NeedHttpBody();
        break;
    case channel::state::havebody:
        HaveHttpBody();
        break;
    case channel::state::done:
        Done();
        break;
    case channel::state::close:
    default:
        Close();;
    }
}

uint8_t* Channel::Prefetch(size_t remain)
{
    if (_write.Length()) {
        Write();
        return nullptr;
    }
    if (_remain < remain) {
        //  send alert: decode error handshake length too short
        return nullptr;
    }
    if (_read.Length() < remain) {
        Read();
        if (_read.Length() < remain) {
            return nullptr;
        }
    }
    _remain -= remain;
    return _read.Head();
}

void Channel::Connected()
{
    if (_socket.Readable()) {
        _read.Reset();
        _state = channel::state::needfirstbytes;
        NeedFirstBytes();
    }
}

void Channel::NeedFirstBytes()
{
    if (_read.Length() < 3) {
        Read();
        if (_read.Length() < 3) {
            return;
        }
    }
    uint8_t* p = _read.Head();
    if (tls::rec::handshake == *p) {
        _remain = 5;
        _state = channel::state::needplaintext;
        NeedPlainText();
    } else {
        _state = channel::state::needrequest;
        NeedRequest();
    }
}

void Channel::NeedPlainText()
{
    uint8_t* p = Prefetch(5);
    if (!p) {
        return;
    }
    _tlsRecType = *p;
    _plainTextVersion = (uint16_t) * (p + 1) << 8 | *(p + 2);
    if (_plainTextVersion < tls::ver::tls10 || _plainTextVersion > tls::ver::tls12) {
        SendAlert(tls::alertlevel::fatal, tls::alerttype::version);
        _state = channel::state::close;
        Close();
        return;
    }
    _plainTextSize = (uint16_t) * (p + 3) << 8 | *(p + 4);
    if (_plainTextSize > tls::max::plaintextsize) {
        SendAlert(tls::alertlevel::fatal, tls::alerttype::param);
        _state = channel::state::close;
        Close();
        return;
    }
    _read.Discard(5);
    switch (_tlsRecType) {
    case tls::rec::change:
        _remain = _plainTextSize;
        _state = channel::state::needrectypechange;
        NeedRecTypeChange();
        break;
    case tls::rec::alert:
        // handle alert
        _state = channel::state::close;
        Close();
        break;
    case tls::rec::handshake:
        if (!_haveChangeCipherSpec) {
            _remain = 4;
            _state = channel::state::needhandshake;
            NeedHandShake();
        } else {
            _remain = _plainTextSize;
            _state = channel::state::needdecryptedhandshake;
            NeedDecryptedHandshake();
        }
        break;
    case tls::rec::data:
        // handle data
        _state = channel::state::close;
        Close();
        break;
    default:
        SendAlert(tls::alertlevel::fatal, tls::alerttype::unexpected);
        _state = channel::state::close;
        Close();
    }
}

void Channel::SendAlert(const uint8_t level, const uint8_t desc)
{
    //  To-Do: Add encrypted alerts
    size_t len;
    uint8_t buf[512] = { 0 };
    uint8_t* p = buf;
    *p++ = tls::rec::alert;
    *p++ = 3;
    *p++ = 0;
    *p++ = 0;
    *p++ = 2;
    *p++ = level;
    *p++ = desc;
    len = p - buf;
    _write.Reset();
    _write.Append(buf, len);
}

void Channel::NeedHandShake()
{
    uint8_t* p = Prefetch(4);
    if (!p) {
        return;
    }
    _sha256.Update(p, 4);

}

void Channel::NeedRecTypeChange()
{
    size_t len = _plainTextSize;
    uint8_t* p = Prefetch(len);
    if (!p) {
        return;
    }
    _read.Discard(len);
    _haveChangeCipherSpec = true;
    _remain = 5;
    _state = channel::state::needplaintext;
    NeedPlainText();
}

void Channel::NeedDecryptedHandshake()
{
    _state = channel::state::close;
    Close();
}

void Channel::NeedRequest()
{
    if (_write.Length()) {
        Write();
        if (_write.Length()) {
            return;
        }
    }
    if (!_read.Length()) {
        Read();
        if (!_read.Length()) {
            return;
        }
    }
    uint8_t* p = _read.Head();
    uint8_t* q = _read.Tail();
    for (; p < q && _lf != *p; p++);
    if (_lf == *p) {
        _state = channel::state::haverequest;
        HaveRequest();
    } else {
        Read();
    }
}

void Channel::HaveRequest()
{
    uint8_t req[256] = { 0 };
    uint8_t* p = _read.Head();
    size_t len = strcspn((const char*)p, "\r");
    memcpy(req, p, len < 255 ? len : 255);

    uint8_t* q = p;
    for (; *q && _sp != *q; q++);
    if (q == p || _sp != *q) {
        BadRequest();
        return;
    }
    *q++ = 0;
    if (!CheckHttpMethod(p)) {
        BadRequest();
        return;
    }
    _read.Discard(q - p);
    for (p = q; *q && _sp != *q; q++);
    if (q == p || _sp != *q) {
        BadRequest();
        return;
    }
    *q++ = 0;
    if (!_uri.Put((char*)p)) {
        BadRequest();
        return;
    }
    _read.Discard(q - p);
    for (p = q; *q && _cr != *q; q++);
    if (q == p || _cr != *q) {
        BadRequest();
        return;
    }
    *q++ = 0;
    if (_lf != *q++) {
        BadRequest();
        return;
    }
    if (!CheckHttpVersion(p)) {
        BadRequest();
        return;
    }
    _read.Discard(q - p);
    _state = channel::state::needheader;
    NeedHttpHeader();
}

void Channel::BadRequest()
{
    PutHttpResponseString(http::response::badrequest);
}

void Channel::PutHttpResponseString(http::response response)
{
    char ver[24] = { 0 };
    snprintf(ver, sizeof ver, "%03u HTTP/1.0 ", (unsigned int)response);
    _write.Reset();
    _write.Append(ver);
    _write.Append(http::message[response]);
    PutHttpResponse();
}

void Channel::PutHttpResponse()
{
    _read.Reset();
    _state = channel::state::done;
    Done();
}

bool Channel::CheckHttpMethod(uint8_t* p)
{
    if (_G == *p && _E == *(p + 1) && _T == *(p + 2) && !*(p + 3)) {
        _method = http::method::get;
    } else if (_P == *p && _O == *(p + 1) && _S == *(p + 2) && _T == *(p + 3) && !*(p + 4)) {
        _method = http::method::post;
    } else if (_P == *p && _U == *(p + 1) && _T == *(p + 2) && !*(p + 3)) {
        _method = http::method::put;
    } else if (_H == *p && _E == *(p + 1) && _A == *(p + 2) && _D == *(p + 3) && !*(p + 4)) {
        _method = http::method::head;
    } else if (_O == *p && _P == *(p + 1) && _T == *(p + 2) && _I == *(p + 3) && _O == *(p + 4) && _N == *(p + 5) && _S == *(p + 6) && !*(p + 7)) {
        _method = http::method::options;
    } else if (_C == *p && _O == *(p + 1) && _N == *(p + 2) && _N == *(p + 3) && _E == *(p + 4) && _C == *(p + 5) && _T == *(p + 6) && !*(p + 7)) {
        _method = http::method::connect;
    } else if (_T == *p && _R == *(p + 1) && _A == *(p + 2) && _C == *(p + 3) && _E == *(p + 4) && !*(p + 5)) {
        _method = http::method::trace;
    } else {
        return false;
    }
    return true;
}

bool Channel::CheckHttpVersion(uint8_t* p)
{
    if ((_H != *p || _T != *(p + 1) || _T != *(p + 2) || _P != *(p + 3) || _slash != *(p + 4))
        || (_0 != *(p + 5) && _1 != *(p + 5)) || (_period != *(p + 6))
        || (_9 != *(p + 7) && _0 != *(p + 7) && _1 != *(p + 7)) || *(p + 8))
        return false;
    return true;
}

bool Channel::CheckHttpSupportedVersion(uint8_t* p)
{
    if (_0 == *(p + 5) && _9 == *(p + 7)) {
        _httpMajor = 0;
        _httpMinor = 9;
    } else if (_1 == *(p + 5) && _0 == *(p + 7)) {
        _httpMajor = 1;
        _httpMinor = 0;
    } else if (_1 == *(p + 5) && _1 == *(p + 7)) {
        _httpMajor = 1;
        _httpMinor = 1;
    } else {
        return false;
    }
    return true;
}

void Channel::NeedHttpHeader()
{
    if (_write.Length()) {
        Write();
        if (_write.Length()) {
            return;
        }
    }
    if (!_read.Length()) {
        Read();
        if (!_read.Length()) {
            return;
        }
    }
    uint8_t* p = _read.Head();
    uint8_t* q = _read.Tail();
    for (; (p < q) && (_lf != *p); p++);
    if (_lf == *p) {
        _state = channel::state::haveheader;
        HaveHttpHeader();
    }
}

void Channel::HaveHttpHeader()
{
    uint8_t* p = _read.Head();
    if (_cr == *p && _lf == *(p + 1)) {
        _state = channel::state::needbody;
        NeedHttpBody();
    } else {
        SaveHttpHeader(p);
        _state = channel::state::needheader;
    }
}

void Channel::SaveHttpHeader(uint8_t* p)
{
    uint8_t* q = p;
    for (; *q && _lf != *q; q++);
    _read.Discard(++q - p);
}

void Channel::NeedHttpBody()
{
    if (_socket.Readable()) {
        _read.Discard(_read.Length());
        Read();
    } else {
        _state = channel::state::havebody;
        HaveHttpBody();
    }
}

void Channel::HaveHttpBody()
{
    _write.Reset();
    time_t t = 0;
    time(&t);
    struct tm m = { 0 };
    memcpy(&m, gmtime(&t), sizeof(m));
    char date[30] = { 0 };
    sprintf(date, "%s, %u %s %u %02u:%02u:%02u GMT",
        http::day[m.tm_wday], m.tm_mday, http::month[m.tm_mon], m.tm_year + 1900,
        m.tm_hour, m.tm_min, m.tm_sec);
    char ip[INET6_ADDRSTRLEN] = { 0 };
    _socket.GetRemoteAddress(ip);
    char body[768] = { 0 };
    sprintf(body, "%s%s%s",
        ok_1, ip, ok_2);
    char hdr[256] = { 0 };
    sprintf(hdr, ok_0, _httpMajor, _httpMinor, date, strlen(body));
    _write.Append(hdr);
    _write.Append(body);
    _state = channel::state::close;
    Close();
}

void Channel::Done()
{
    if (_write.Length()) {
        Write();
        if (!_write.Length()) {
            Clear();
        }
    }
}

void Channel::Clear()
{
    _state = channel::state::ready;
    _expires = 0;
    _remain = 0;

    _method = http::method::unspecified;
    _plainTextVersion = 0;

    _httpMajor = 1;
    _httpMinor = 0;
    _tlsRecType = 0;

    _uri.Reset();
    _socket.Reset();
    _read.Reset();
    _write.Reset();
}

void Channel::Close()
{
    if (_write.Length()) {
        Write();
        if (_write.Length()) {
            return;
        }
    }

    _state = channel::state::ready;
    _method = http::method::unspecified;

    _expires = 0;
    _remain = 0;

    _plainTextVersion = 0;
    _plainTextSize = 0;
    _handShakeSize = 0;

    _httpMajor = 1;
    _httpMinor = 0;
    _tlsRecType = 0;
    _tlsHandShakeType = 0;

    _haveChangeCipherSpec = false;

    _uri.Reset();
    _sha256.Reset();

    _socket.Reset();
    _read.Reset();
    _write.Reset();
}
