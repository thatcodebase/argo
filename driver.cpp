#include "api.h"
#include "driver.h"
#include "logger.h"

namespace driver {
    enum {
        stopwait = 100
    };
    namespace cond {
        enum {
            title = cond_base_driver,
            copyright,
            wsastartup,
            complete,
            servicestop,
            stopping,
            finalize
        };
    }
    namespace message {
        constexpr const char* title = "Title";
        constexpr const char* copyright = "Copyright";
        constexpr const char* complete = "Configuration completed";
        constexpr const char* servicestop = "Service stopping";
        constexpr const char* stopping = "Exiting main loop";
        constexpr const char* finalize = "Finalization completed";
    }
    constexpr const char* logsuffix = "log";
}

using namespace std;

Driver theDriver;

Driver::Driver()
{
    // Initialize members to default values.

    Init();
}

Driver::~Driver()
{
    // Release allocated storage and intialize members to default values.

    Reset();
}

void Driver::Init()
{
    // Initialize members to default values.

    _running.store(false, memory_order_relaxed);
    _stopping.store(false, memory_order_relaxed);
    _daemon.store(false, memory_order_relaxed);
    _winsock.store(false, memory_order_relaxed);
}

void Driver::Reset()
{
    // Release allocated storage.

    string().swap(_name);
    string().swap(_title);
    string().swap(_copyright);

    // Initialize members to default values.

    Init();
}

bool Driver::Running()
{
    return _running.load(memory_order_relaxed);
}

void Driver::Running(bool running)
{
    _running.store(running, memory_order_relaxed);
}

bool Driver::Stopping()
{
    return _stopping.load(memory_order_relaxed);
}

void Driver::Stopping(bool stopping)
{
    _stopping.store(stopping, memory_order_relaxed);
}

bool Driver::Daemon()
{
    return _daemon.load(memory_order_relaxed);
}

void Driver::Daemon(bool running)
{
    _daemon.store(running, memory_order_relaxed);
}

bool Driver::Winsock()
{
    return _winsock.load(memory_order_relaxed);
}

void Driver::Winsock(bool running)
{
    _winsock.store(running, memory_order_relaxed);
}

void Driver::Name(const char* name)
{
    lock_guard<mutex> lock(_mutex);
    if (name) {
        _name = name;
    } else {
        string().swap(_name);
    }
}

void Driver::Title(const char* title)
{
    lock_guard<mutex> lock(_mutex);
    if (title) {
        _title = title;
    } else {
        string().swap(_title);
    }
}

void Driver::Copyright(const char* copyright)
{
    lock_guard<mutex> lock(_mutex);
    if (copyright) {
        _copyright = copyright;
    } else {
        string().swap(_copyright);
    }
}

bool Driver::Service(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    return true;
}

void Driver::Configure(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    // Configure is called before any additional thread is started. So, we do
    // not need to provide for concurrency here.

    LoggerPrefix(_name.c_str());
    LoggerSuffix(driver::logsuffix);

    // Configuration is complete. So, spool any prelog messages into the
    // configured log path and file and close the prelog file.

    LoggerPrelog(false);
    inf("I%04d %s", driver::cond::complete, driver::message::complete);
}

bool Driver::Initialize(int argc, char* argv[])
{
    // Log the application title and copyright.

    wrt("I%04d %s", driver::cond::title, _title.empty() ? driver::message::title : _title.c_str());
    wrt("I%04d %s", driver::cond::copyright, _copyright.empty() ? driver::message::copyright : _copyright.c_str());
#if defined(_WIN32)

    // Initialize Windows sockets.

    WSADATA wsadata{ 0 };
    int rc = WSAStartup(WINSOCKVERSION, &wsadata);
    if (rc) {
        AppErr(driver::cond::wsastartup);
        return false;
    }
    Winsock(true);
#endif

    // Apply application configuration from registry, environment, etc.

    Configure(argc, argv);
    return true;
}

void Driver::GetClient()
{
    // Temporarily sleep here until sockets accept is implemented.

    this_thread::sleep_for(chrono::milliseconds(1));
}

void Driver::ServiceChannel()
{
}

void Driver::Mainline()
{
    // While we are not stopping check for any new connection and then service
    // the next channel.

    while (!Stopping()) {
        GetClient();
        ServiceChannel();
    }

    inf("I%04d %s", driver::cond::stopping, driver::message::stopping);
}

void Driver::Finalize()
{
#if defined(_WIN32)

    // Finalize Windows sockets.

    if (Winsock()) {
        WSACleanup();
        Winsock(false);
    }
#endif

    inf("I%04d %s", driver::cond::finalize, driver::message::finalize);
}

void Driver::Run(int argc, char* argv[])
{
    // We may be running on the main thread if we are a daemon or on a dedicated
    // thread if we are in the foreground and the main thread is busy handling
    // console input.

    Running(true);
    if (Initialize(argc, argv)) {
        Mainline();
    }
    Finalize();
    Running(false);
}

bool Driver::Start(int argc, char* argv[])
{
    //  Perform install, uninstall, or start the Windows service. If an install
    //  or uninstall was run or the Windows service dispatcher was called, then
    //  we can exit now indicating that the foreground app need not run.

    if (!Service(argc, argv)) {
        return false;
    }

    //  If Service returned true, we continue. Now if the "service" argument was
    //  passed on Linux or macOS, we are already forked and can enter the Run
    //  method on this task and then return false since there is no console.

    if (Daemon()) {
        Run(argc, argv);
        return false;
    }

    //  If Service returned true be we are not a daemon, start a background
    //  thread and call Run on it. Then return true to accept console input.

    try {
        _thread = std::thread([=] {
            Run(argc, argv);
        });
    } catch (...) {
        return false;
    }
    return true;
}

void Driver::Stop()
{
    // Signal that we are stopping so that the thread will exit.

    inf("I%04d %s", driver::cond::servicestop, driver::message::servicestop);
    Stopping(true);

    // Wait up to a limited time for the running condition to be set to false.

    for (int n = driver::stopwait; n && Running(); --n) {
        this_thread::sleep_for(chrono::milliseconds(10));
    }

    // If we have successfully exiting the running state, join the thread.

    if (!Running()) {
        if (_thread.joinable()) {
            _thread.join();
        }
    }
}

int Driver::Result()
{
    return AppErr();
}

IDriver& TheDriver()
{
    return theDriver;
}

IDriver* TheDriverPtr()
{
    return &theDriver;
}