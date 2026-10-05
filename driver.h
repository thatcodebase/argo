#pragma once

#include "idriver.h"
#include "channel.h"
#include "udpchannel.h"

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace driver {
    enum {
        channels = 16
    };
}

class Driver final
    : public IDriver
{
    std::atomic<bool> _running;
    std::atomic<bool> _stopping;
    std::atomic<bool> _daemon;
    std::atomic<bool> _winsock;

    uint16_t _port;

    std::string _config;
    std::string _copyright;
    std::string _description;
    std::string _descriptor;
    std::string _display;
    std::string _model;
    std::string _name;
    std::string _registry;
    std::string _spec;
    std::string _title;
    std::string _usage;

    Channel* _first;
    Channel* _last;

#if defined(_WIN32)
    SC_HANDLE _hscm;
    SC_LOCK _lock;
    SERVICE_STATUS_HANDLE _handle;
    CRITICAL_SECTION _section;
    SERVICE_STATUS _status;
    SERVICE_TABLE_ENTRY _dispatch[2];

#endif
    Socket _v4tcp;
    Socket _v6tcp;

    UdpChannel _udpChannel4;
    UdpChannel _udpChannel6;

    Channel _channel[driver::channels];

    std::mutex _mutex;
    std::thread _thread;

    void Init();
    void Reset();
    bool Running();
    void Running(bool running);
    bool Stopping();
    bool Daemon();
    void Daemon(bool daemon);
    bool Winsock();
    void Winsock(bool winsock);
#if defined(_WIN32)
    bool OpenServiceManager();
    void Install(const char* name);
    void Uninstall(const char* name);
    void CloseServiceManager();
#endif
    bool Service(int argc, char* argv[]);
#if defined(_WIN32)
    bool GetRegistryValue(HKEY key, const char* name, char* buf, DWORD* size);
    void GetRegistryVars();
#endif
    void GetEnvVars();
    void GetFileArg(int argc, char* argv[]);
    void SetVar(unsigned int id, const char* val);
    void ParseLine(std::string& line);
    void GetFileVars();
    void GetArgVars(int argc, char* argv[]);
    bool GetModel();
    void Configure(int argc, char* argv[]);
    bool OpenAddress(Socket& tcp, bool v6 = false);
    bool OpenAddress(Socket& tcp, Socket& udp, bool v6 = false);
    void CloseAddress(Socket& tcp, Socket& udp);
    bool Initialize(int argc, char* argv[]);
    void Queue(Channel* channel);
    void GetClient();
    Channel* Dequeue();
    void ServiceChannel();
    void Mainline();
    void Finalize();
    void Run(int argc, char* argv[]);

public:
    Driver();
    ~Driver();
    void Stopping(bool stopping);
#if defined(_WIN32)
    void Handle(DWORD control);
    void Main(DWORD argc, LPSTR* argv);
#endif
    void Config(const char* config) override;
    void Copyright(const char* copyright) override;
    void Description(const char* description) override;
    void Display(const char* display) override;
    void LogBase(const char* base) override;
    void Name(const char* base) override;
    void Registry(const char* name) override;
    void Spec(const char* spec) override;
    void Title(const char* title) override;
    void Usage(const char* usage) override;

    bool Start(int argc, char* argv[]) override;
    void Stop() override;
    int Result() override;
};
