#pragma once

#include "idriver.h"

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

class Driver final
    : public IDriver
{
    std::atomic<bool> _running;
    std::atomic<bool> _stopping;
    std::atomic<bool> _daemon;
    std::atomic<bool> _winsock;

    std::string _name;
    std::string _title;
    std::string _copyright;

    std::mutex _mutex;
    std::thread _thread;

    void Init();
    void Reset();

    bool Running();
    void Running(bool running);
    bool Stopping();
    void Stopping(bool stopping);
    bool Daemon();
    void Daemon(bool daemon);
    bool Winsock();
    void Winsock(bool winsock);

    bool Service(int argc, char* argv[]);
    void Configure(int argc, char* argv[]);
    bool Initialize(int argc, char* argv[]);
    void GetClient();
    void ServiceChannel();
    void Mainline();
    void Finalize();

public:
    Driver();
    ~Driver();

    void Name(const char* base) override;
    void Title(const char* title) override;
    void Copyright(const char* copyright) override;

    void Run(int argc, char* argv[]);
    bool Start(int argc, char* argv[]) override;
    void Stop() override;
    int Result() override;
};