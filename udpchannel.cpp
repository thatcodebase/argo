#include "udpchannel.h"

void UdpChannel::Read()
{
    if (!_read.Size()) {
        _read.Resize(udpchannel::size);
    }
    _read.Front();
    size_t len = _read.Avail();
    if (_socket.Get(_read.Tail(), &len)) {
        _read.Extend(len);
    } else {
        Reset();
    }
}

void UdpChannel::Write()
{
    size_t len = _write.Length();
    if (_socket.Put(_write.Head(), &len)) {
        _write.Discard(len);
    } else {
        Reset();
    }
}

void UdpChannel::Service()
{
    if (_write.Length()) {
        Write();
    }
    if (!_write.Length()) {
        Read();
    }
    if (_read.Length()) {
        _read.Discard(_read.Length());
    }
}