#include "api.h"
#include "channel.h"
#include "driver.h"
#include "logger.h"

#include <fstream> // ifstream, getline

using namespace std;

namespace driver {
    enum {
        stopwait = 100,
        port = 4197
    };
    namespace arg {
        constexpr const char* configfile = "-f";
        constexpr const char* descriptor = "-d";
        constexpr const char* loglevel = "-l";
        constexpr const char* logpath = "-g";
        constexpr const char* logprefix = "-e";
        constexpr const char* logsuffix = "-s";
        constexpr const char* model = "-m";
        constexpr const char* port = "-p";
    }
    namespace env {
        constexpr const char* descriptor = "DESCRIPTOR";
        constexpr const char* loglevel = "LOGLEVEL";
        constexpr const char* logpath = "LOGPATH";
        constexpr const char* logprefix = "LOGPREFIX";
        constexpr const char* logsuffix = "LOGSUFFIX";
    }
    namespace setting {
        enum {
            configfile = 1,
            descriptor,
            loglevel,
            logpath,
            logprefix,
            logsuffix,
            model,
            port
        };
        namespace name {
            constexpr const char* configfile = "config-file";
            constexpr const char* descriptor = "descriptor";
            constexpr const char* loglevel = "log-level";
            constexpr const char* logpath = "log-path";
            constexpr const char* logprefix = "log-prefix";
            constexpr const char* logsuffix = "log-suffix";
            constexpr const char* model = "model";
            constexpr const char* port = "port";
        }
    }
    namespace cond {
        enum {
            servicestart = cond_base_driver,
            title,
            copyright,
            usage,

            //  Service intallation

            installing,
            access,
            opensc,
            lock,
            size,
            module,
            file,
            command,
            exists,
            display,
            create,
            key,
            value,
            closekey,
            close,
            unlock,
            closesc,
            installed,

            //  Service uninstallation

            uninstalling,
            missing,
            name,
            open,
            remove,
            uninstalled,

            //  Service dispatch

            console,
            dispatch,

            //  Linux/macOS daemon startup

            pipe1,
            alarm1,
            intr,
            fork,
            setsid,
            emptyset,
            addset,
            procmask,
            term,
            pipe2,
            alarm2,
            hup,
            null,
            stdin_,
            stdout_,
            stderr_,

            //  Windows startup

            wsastartup,

            //  Configuration

            regopenkeyex,
            reggetvalue,
            regsetting,
            regclosekey,
            envsetting,
            cfgsetting,
            argsetting,
            modelloaded,
            complete,

            //  Shutdown

            terminate,
            servicestop,
            stopping,
            finalize
        };
    }
    namespace message {
        constexpr const char* servicestart = "Service started";
        constexpr const char* title = "Title";
        constexpr const char* copyright = "Copyright";

        //  Service installation

        constexpr const char* installing = "Installing service";
        constexpr const char* access = "Administrative privilege is required";
        constexpr const char* opensc = "Unable to open service control manager";
        constexpr const char* lock = "LockServiceDatabase error";
        constexpr const char* size = "Registry name too long";
        constexpr const char* module = "GetModuleHandle error";
        constexpr const char* file = "GetModuleFileName error";
        constexpr const char* command = "Service command line too long";
        constexpr const char* exists = "Service already exists";
        constexpr const char* display = "Service display name in use";
        constexpr const char* create = "CreateService error";
        constexpr const char* key = "RegCreateKeyEx error";
        constexpr const char* value = "RegSetValueEx error";
        constexpr const char* closekey = "RegCloseKey error";
        constexpr const char* close = "CloseServiceHandle error";
        constexpr const char* unlock = "UnlockServiceDatabase error";
        constexpr const char* closesc = "CloseServiceHandle error";
        constexpr const char* installed = "Service installed";

        //  Service uninstallation

        constexpr const char* uninstalling = "Uninstalling service";
        constexpr const char* missing = "Service not found";
        constexpr const char* name = "Invalid service name";
        constexpr const char* open = "OpenService error";
        constexpr const char* remove = "DeleteService error";
        constexpr const char* uninstalled = "Service uninstalled";

        //  Service dispatch

        constexpr const char* console = "Service cannot start from console";
        constexpr const char* dispatch = "StartServiceCtrlDispatcher error";

        //  Linux/macOS Daemon dispatch

        constexpr const char* pipe1 = "sigaction(SIGPIPE)(1) error";
        constexpr const char* alarm1 = "sigaction(SIGALRM)(1) error";
        constexpr const char* intr = "sigaction(INT) error";
        constexpr const char* fork = "form error";
        constexpr const char* setsid = "setsid error";
        constexpr const char* emptyset = "sigemptyset error";
        constexpr const char* addset = "sigaddset error";
        constexpr const char* procmask = "sigprocmask error";
        constexpr const char* term = "sigaction(SIGTERM) error";
        constexpr const char* pipe2 = "sigaction(SIGPIPE)(2) error";
        constexpr const char* alarm2 = "sigaction(SIGALRM)(2) error";
        constexpr const char* hup = "sigaction(SIGHUP) error";
        constexpr const char* null = "open(/dev/null) error";
        constexpr const char* stdin_ = "dup2(STDIN) error";
        constexpr const char* stdout_ = "dup2(STDOUT) error";
        constexpr const char* stderr_ = "dup2(STDERR) error";

        //  Configuration

        constexpr const char* regopenkeyex = "RegOpenKeyEx error";
        constexpr const char* reggetvalue = "RegGetValue error";
        constexpr const char* regsetting = "I%04d Setting %s to (%s) from registry";
        constexpr const char* regclosekey = "RegCloseKey error";
        constexpr const char* envsetting = "I%04d Setting %s to (%s) from environment";
        constexpr const char* cfgsetting = "I%04d Setting %s to (%s) from config file";
        constexpr const char* argsetting = "I%04d Setting %s to (%s) from program arguments";
        constexpr const char* modelloaded = "Model loaded";
        constexpr const char* complete = "Configuration completed";

        //  Shutdown

        constexpr const char* servicestop = "Service stopping";
        constexpr const char* stopping = "Exiting main loop";
        constexpr const char* finalize = "Finalization completed";
    }
    constexpr const char* install = "install";
    constexpr const char* logsuffix = "log";
    constexpr const char* service = "service";
    constexpr const char* uninstall = "uninstall";
}

typedef struct setting {
    const char* str;
    uint32_t id;
} SETTING;

constexpr const SETTING app_settings[] = {
    {driver::setting::name::descriptor, driver::setting::descriptor},
    {driver::setting::name::loglevel, driver::setting::loglevel},
    {driver::setting::name::logpath, driver::setting::logpath},
    {driver::setting::name::logprefix, driver::setting::logprefix},
    {driver::setting::name::logsuffix, driver::setting::logsuffix},
    {0, 0}
};

Driver theDriver;

Driver::Driver()
{
    //  Initialize members to default values.

    Init();
}

Driver::~Driver()
{
    //  Release allocated storage and intialize members to default values.

    Reset();
}

void Driver::Init()
{
    //  Initialize members to default values.

    _running.store(false, memory_order_relaxed);
    _stopping.store(false, memory_order_relaxed);
    _daemon.store(false, memory_order_relaxed);
    _winsock.store(false, memory_order_relaxed);

    _port = driver::port;

    _first = nullptr;
    _last = nullptr;
#if defined(_WIN32)
    _hscm = 0;
    _lock = 0;
    _handle = 0;
    memset(&_section, 0, sizeof _section);
    memset(&_status, 0, sizeof _status);
    _dispatch[0] = { 0 };
    _dispatch[1] = { 0 };
#endif
}

void Driver::Reset()
{
    //  Release allocated storage.

    string().swap(_config);
    string().swap(_copyright);
    string().swap(_description);
    string().swap(_display);
    string().swap(_name);
    string().swap(_registry);
    string().swap(_spec);
    string().swap(_title);
    string().swap(_usage);

    //  Initialize members to default values.

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

void Driver::Config(const char* config)
{
    lock_guard<mutex> lock(_mutex);
    if (config) {
        _config = config;
    } else {
        string().swap(_config);
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

void Driver::Description(const char* description)
{
    lock_guard<mutex> lock(_mutex);
    if (description) {
        _description = description;
    } else {
        string().swap(_description);
    }
}

void Driver::Display(const char* display)
{
    lock_guard<mutex> lock(_mutex);
    if (display) {
        _display = display;
    } else {
        string().swap(_display);
    }
}

void Driver::LogBase(const char* base)
{
    LoggerBase(base);
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

void Driver::Registry(const char* registry)
{
    lock_guard<mutex> lock(_mutex);
    if (registry) {
        _registry = registry;
    } else {
        string().swap(_registry);
    }
}

void Driver::Spec(const char* spec)
{
    lock_guard<mutex> lock(_mutex);
    if (spec) {
        _spec = spec;
    } else {
        string().swap(_spec);
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

void Driver::Usage(const char* usage)
{
    lock_guard<mutex> lock(_mutex);
    if (usage) {
        _usage = usage;
    } else {
        string().swap(_usage);
    }
}

#if defined(_WIN32)
void Driver::Handle(DWORD control)
{
    switch (control) {
    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
        EnterCriticalSection(&_section);
        _status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        _status.dwCurrentState = SERVICE_STOP_PENDING;
        _status.dwWin32ExitCode = NO_ERROR;
        _status.dwServiceSpecificExitCode = 0;
        _status.dwCheckPoint = 0;
        _status.dwWaitHint = 0;
        SetServiceStatus(_handle, &_status);
        LeaveCriticalSection(&_section);
        Stopping(true);
        break;
    default:
        EnterCriticalSection(&_section);
        SetServiceStatus(_handle, &_status);
        LeaveCriticalSection(&_section);
    }
}
#endif

#if defined(_WIN32)
void WINAPI ServiceCtrlHandler(DWORD control)
{
    theDriver.Handle(control);
}
#endif

#if defined(_WIN32)
void Driver::Main(DWORD argc, LPSTR* argv)
{
    _handle = RegisterServiceCtrlHandler((LPCSTR)_name.c_str(), ServiceCtrlHandler);
    if (!_handle) {
        ExitProcess((UINT)-1);
        return;
    }
    InitializeCriticalSection(&_section);
    EnterCriticalSection(&_section);
    _status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    _status.dwCurrentState = SERVICE_RUNNING;
    _status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    _status.dwWin32ExitCode = NO_ERROR;
    _status.dwServiceSpecificExitCode = 0;
    _status.dwCheckPoint = 0;
    _status.dwWaitHint = 0;
    SetServiceStatus(_handle, &_status);
    LeaveCriticalSection(&_section);
    if (argc) {
        _name = argv[0];
    }
    inf("I%04d %s (%s)", driver::cond::servicestart, driver::message::servicestart, _name.c_str());
    Run(argc, argv);
    inf("I%04d %s (%s)", driver::cond::servicestop, driver::message::servicestop, _name.c_str());
    EnterCriticalSection(&_section);
    _status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    _status.dwCurrentState = SERVICE_STOPPED;
    _status.dwControlsAccepted = 0;
    _status.dwWin32ExitCode = NO_ERROR;
    _status.dwServiceSpecificExitCode = 0;
    _status.dwCheckPoint = 0;
    _status.dwWaitHint = 0;
    SetServiceStatus(_handle, &_status);
    LeaveCriticalSection(&_section);
    DeleteCriticalSection(&_section);
    ExitProcess(0);
}
#endif

#if defined(_WIN32)
void WINAPI ServiceMain(DWORD argc, LPSTR* argv)
{
    theDriver.Main(argc, argv);
}
#endif

#if defined(_WIN32)
bool Driver::OpenServiceManager()
{
    _hscm = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if (!_hscm) {
        OsErr(GetLastError());
        if (ERROR_ACCESS_DENIED == OsErr()) {
            AppErr(driver::cond::access);
            err("E%04d %s", driver::cond::access, driver::message::access);
        } else {
            AppErr(driver::cond::opensc);
            err("E%04d %s (%d)", driver::cond::opensc, driver::message::opensc, OsErr());
        }
        return false;
    }
    _lock = LockServiceDatabase(_hscm);
    if (!_lock) {
        OsErr(GetLastError());
        AppErr(driver::cond::lock);
        err("E%04d %s (%d)", driver::cond::lock, driver::message::lock, OsErr());
        CloseServiceHandle(_hscm);
        return false;
    }
    return true;
}
#endif

#if defined(_WIN32)
void Driver::Install(const char* name)
{
    char* p;
    long result;
    size_t h, pathLen, specLen, pathSpecLen;
    HMODULE module;
    SC_HANDLE hsvc;
    HKEY hkey;
    DWORD disposition;
    SERVICE_DESCRIPTION description;
    char buf[256] = { 0 };
    h = _registry.size() + _name.size() + 1;
    if (h > sizeof(buf)) {
        OsErr(0);
        AppErr(driver::cond::size);
        err("E%04d %s", driver::cond::size, driver::message::size);
        return;
    }
    module = GetModuleHandle(NULL);
    if (!module) {
        OsErr(GetLastError());
        AppErr(driver::cond::module);
        err("E%04d %s (%d)", driver::cond::module, driver::message::module, OsErr());
        return;
    }
    pathLen = GetModuleFileName(module, buf, sizeof(buf));
    if (!pathLen) {
        OsErr(GetLastError());
        AppErr(driver::cond::file);
        err("E%04d %s (%d)", driver::cond::file, driver::message::file, OsErr());
        return;
    }
    for (p = &buf[pathLen]; p > buf;) {
        --p;
        if (('\\' == *p) || ('/' == *p) || (':' == *p)) {
            p++;
            break;
        }
    }
    pathLen = (p - buf);
    specLen = _spec.size();
    pathSpecLen = pathLen + specLen + 2;
    if (pathSpecLen > sizeof(buf)) {
        AppErr(driver::cond::command);
        err("E%04d %s", driver::cond::command, driver::message::command);
        return;
    }
    strcpy(p, _spec.c_str());
    hsvc = CreateService(_hscm, name, _display.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, buf,
        NULL, NULL, NULL, NULL, NULL);
    if (!hsvc) {
        OsErr(GetLastError());
        if (ERROR_SERVICE_EXISTS == OsErr()) {
            AppErr(driver::cond::exists);
            err("E%04d %s (%s)", driver::cond::exists, driver::message::exists, name);
        } else if (ERROR_DUPLICATE_SERVICE_NAME == OsErr()) {
            AppErr(driver::cond::display);
            err("E%04d %s (%s)", driver::cond::display, driver::message::display, name);
        } else {
            AppErr(driver::cond::create);
            err("E%04d %s (%d)", driver::cond::create, driver::message::create, OsErr());
        }
        return;
    }
    description.lpDescription = (LPSTR)_description.c_str();
    ChangeServiceConfig2(hsvc, SERVICE_CONFIG_DESCRIPTION, &description);
    strcpy(buf, _registry.c_str());
    strcat(buf, name);
    result = RegCreateKeyEx(HKEY_LOCAL_MACHINE, buf, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &disposition);
    if (result != ERROR_SUCCESS) {
        OsErr(result);
        AppErr(driver::cond::key);
        err("E%04d %s (%d)", driver::cond::key, driver::message::key, OsErr());
        RegCloseKey(hkey);
        CloseServiceHandle(hsvc);
        return;
    }
    result = RegSetValueEx(hkey, "Description", 0, REG_SZ,
        (const BYTE*)_description.c_str(), (DWORD)_description.size() + 1);
    if (result != ERROR_SUCCESS) {
        OsErr(result);
        AppErr(driver::cond::value);
        err("E%04d %s (%d)", driver::cond::value, driver::message::value, OsErr());
        RegCloseKey(hkey);
        CloseServiceHandle(hsvc);
        return;
    }
    result = RegCloseKey(hkey);
    if (result != ERROR_SUCCESS) {
        OsErr(result);
        AppErr(driver::cond::closekey);
        err("E%04d %s (%d)", driver::cond::closekey, driver::message::closekey, OsErr());
        CloseServiceHandle(hsvc);
        return;
    }
    if (!CloseServiceHandle(hsvc)) {
        OsErr(GetLastError());
        AppErr(driver::cond::close);
        err("E%04d %s (%d)", driver::cond::close, driver::message::close, OsErr());
        return;
    }
    inf("I%04d %s (%s)", driver::cond::installed, driver::message::installed, name);
}
#endif

#if defined(_WIN32)
void Driver::Uninstall(const char* name)
{
    SC_HANDLE hsvc = (SC_HANDLE)0;
    hsvc = OpenService(_hscm, name, SERVICE_ALL_ACCESS);
    if (!hsvc) {
        OsErr(GetLastError());
        if (ERROR_SERVICE_DOES_NOT_EXIST == OsErr()) {
            AppErr(driver::cond::missing);
            err("E%04d %s (%s)", driver::cond::missing, driver::message::missing, name);
        } else if (ERROR_INVALID_NAME == OsErr()) {
            AppErr(driver::cond::name);
            err("E%04d %s (%s)", driver::cond::name, driver::message::name, name);
        } else {
            AppErr(driver::cond::open);
            err("E%04d %s (%d)", driver::cond::open, driver::message::open, OsErr());
        }
        return;
    }
    if (!DeleteService(hsvc)) {
        OsErr(GetLastError());
        AppErr(driver::cond::remove);
        err("E%04d %s (%d)", driver::cond::remove, driver::message::remove, OsErr());
        CloseServiceHandle(hsvc);
        return;
    }
    if (!CloseServiceHandle(hsvc)) {
        OsErr(GetLastError());
        AppErr(driver::cond::close);
        err("E%04d %s (%d)", driver::cond::close, driver::message::close, OsErr());
        return;
    }
    inf("I%04d %s (%s)", driver::cond::uninstalled, driver::message::uninstalled, name);
}
#endif

#if defined(_WIN32)
void Driver::CloseServiceManager()
{
    if (!UnlockServiceDatabase(_lock)) {
        if (!AppErr()) {
            OsErr(GetLastError());
            AppErr(driver::cond::unlock);
            err("E%04d %s (%d)", driver::cond::unlock, driver::message::unlock, OsErr());
        }
        CloseServiceHandle(_hscm);
        return;
    }
    if (!CloseServiceHandle(_hscm)) {
        if (!AppErr()) {
            OsErr(GetLastError());
            AppErr(driver::cond::closesc);
            err("E%04d %s (%d)", driver::cond::closesc, driver::message::closesc, OsErr());
        }
    }
}
#endif

#if defined(_WIN32)
BOOL WINAPI ServiceHandleTerm(DWORD fdwCtrlType)
{
    //  The Service method sets ServiceHandleTerm as the closure event handler.
    //  We are on the main thread here. We cannot log because theLogger has been
    //  destructed. We set _stopping to true so the service thread will exit.

    switch (fdwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        theDriver.Stopping(true);
        return TRUE;
    default:
        return FALSE;
    }
}
#else
void ServiceHandleSig(int sig)
{
    signal(sig, ServiceHandleSig);
}

void ServiceHandleTerm(int sig)
{
    theDriver.Stopping(true);
    signal(sig, ServiceHandleSig);
}
#endif

bool Driver::Service(int argc, char* argv[])
{
#if defined(_WIN32)
    if (argc > 1 && argv[1]) {

        //  The user may specify that the service be installed with a given
        //  name. If not specified, the name provided during configuration
        //  is used.

        const char* serviceName = _name.c_str();
        if (argc > 2 && argv[2]) {
            serviceName = argv[2];
        }
        if (!strcmp(argv[1], driver::service)) {

            //  The user may specify that the app be run as a service.

            _dispatch[0].lpServiceName = (char*)serviceName;
            _dispatch[0].lpServiceProc = ServiceMain;
            if (!StartServiceCtrlDispatcher(_dispatch)) {
                LoggerPrelog(false);
                wrt("I%04d %s", driver::cond::title, _title.empty() ? "Title" : _title.c_str());
                wrt("I%04d %s", driver::cond::copyright, _copyright.empty() ? "Copyright" : _copyright.c_str());
                OsErr(GetLastError());
                if (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT == OsErr()) {
                    AppErr(driver::cond::console);
                    err("E%04d %s", driver::cond::console, driver::message::console);
                } else {
                    AppErr(driver::cond::dispatch);
                    err("E%04d %s (%d)", driver::cond::dispatch, driver::message::dispatch, OsErr());
                }
            } else {
                LoggerConsole(false);
                _daemon = true;
            }
            return false;
        }
        if (!strcmp(argv[1], driver::install)) {

            //  The user may specify that the app be installed as a service.

            wrt("I%04d %s", driver::cond::title, _title.empty() ? "Title" : _title.c_str());
            wrt("I%04d %s", driver::cond::copyright, _copyright.empty() ? "Copyright" : _copyright.c_str());
            wrt("I%04d %s (%s)", driver::cond::installing, driver::message::installing, serviceName);
            if (OpenServiceManager()) {
                Install(serviceName);
                CloseServiceManager();
            }
            return false;
        }
        if (!strcmp(argv[1], driver::uninstall)) {

            //  The user may specify that the service be uninstalled.

            wrt("I%04d %s", driver::cond::title, _title.empty() ? "Title" : _title.c_str());
            wrt("I%04d %s", driver::cond::copyright, _copyright.empty() ? "Copyright" : _copyright.c_str());
            wrt("I%04d %s (%s)", driver::cond::uninstalling, driver::message::uninstalling, serviceName);
            if (OpenServiceManager()) {
                Uninstall(serviceName);
                CloseServiceManager();
            }
            return false;
        }
        wrt("I%04d %s", driver::cond::usage, _usage.empty() ? "Usage" : _usage.c_str());
        return false;
    }
    SetConsoleCtrlHandler(ServiceHandleTerm, TRUE);
#else
    int rc = 0;
    int nullFile = 0;
    sigset_t set = { 0 };
    struct sigaction act = { 0 };
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;
    rc = sigaction(SIGPIPE, &act, NULL);
    if (rc) {
        OsErr(errno);
        AppErr(driver::cond::pipe1);
        err("E%04d %s (%d)", driver::cond::pipe1, driver::message::pipe1, OsErr());
        return false;
    }
    rc = sigaction(SIGALRM, &act, NULL);
    if (rc) {
        OsErr(errno);
        AppErr(driver::cond::alarm1);
        err("E%04d %s (%d)", driver::cond::alarm1, driver::message::alarm1, OsErr());
        return false;
    }
    if ((argc < 2) || (strcmp(driver::service, argv[1]))) {
        memset(&act, 0, sizeof(act));
        act.sa_handler = ServiceHandleTerm;
        act.sa_flags = 0;
        rc = sigaction(SIGINT, &act, NULL);
        if (rc) {
            OsErr(errno);
            AppErr(driver::cond::intr);
            err("E%04d %s (%d)", driver::cond::intr, driver::message::intr, OsErr());
            return false;
        }
        return true;
    }
    _daemon = true;
    rc = fork();
    if (-1 == rc) {
        OsErr(errno);
        AppErr(driver::cond::fork);
        err("E%04d %s (%d)", driver::cond::fork, driver::message::fork, OsErr());
        return false;
    }
    if (rc) {
        exit(0);
    }
    rc = setsid();
    if (-1 == rc) {
        OsErr(errno);
        AppErr(driver::cond::setsid);
        err("E%04d %s (%d)", driver::cond::setsid, driver::message::setsid, OsErr());
        return false;
    }
    rc = sigemptyset(&set);
    if (rc) {
        OsErr(errno);
        AppErr(driver::cond::emptyset);
        err("E%04d %s (%d)", driver::cond::emptyset, driver::message::emptyset, OsErr());
        return false;
    }
    rc = sigaddset(&set, SIGINT);
    if (rc) {
        OsErr(errno);
        AppErr(driver::cond::addset);
        err("E%04d %s (%d)", driver::cond::addset, driver::message::addset, OsErr());
        return false;
    }
    rc = sigprocmask(SIG_UNBLOCK, &set, NULL);
    if (rc) {
        OsErr(errno);
        AppErr(driver::cond::procmask);
        err("E%04d %s (%d)", driver::cond::procmask, driver::message::procmask, OsErr());
        return false;
    }
    memset(&act, 0, sizeof(act));
    act.sa_handler = ServiceHandleTerm;
    act.sa_flags = 0;
    rc = sigaction(SIGINT, &act, NULL);
    if (rc) {
        OsErr(errno);
        AppErr(driver::cond::term);
        err("E%04d %s (%d)", driver::cond::term, driver::message::term, OsErr());
        return false;
    }
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;
    rc = sigaction(SIGPIPE, &act, NULL);
    if (rc) {
        OsErr(errno);
        AppErr(driver::cond::pipe2);
        err("E%04d %s (%d)", driver::cond::pipe2, driver::message::pipe2, OsErr());
        return false;
    }
    rc = sigaction(SIGALRM, &act, NULL);
    if (rc) {
        OsErr(errno);
        AppErr(driver::cond::alarm2);
        err("E%04d %s (%d)", driver::cond::alarm2, driver::message::alarm2, OsErr());
        return false;
    }
    rc = sigaction(SIGHUP, &act, NULL);
    if (rc) {
        OsErr(errno);
        AppErr(driver::cond::hup);
        err("E%04d %s (%d)", driver::cond::hup, driver::message::hup, OsErr());
        return false;
    }
    nullFile = ::open("/dev/null", O_RDWR);
    if (-1 == nullFile) {
        OsErr(errno);
        AppErr(driver::cond::null);
        err("E%04d %s (%d)", driver::cond::null, driver::message::null, OsErr());
        return false;
    }
    rc = dup2(nullFile, STDIN_FILENO);
    if (-1 == rc) {
        OsErr(errno);
        AppErr(driver::cond::stdin_);
        err("E%04d %s (%d)", driver::cond::stdin_, driver::message::stdin_, OsErr());
        return false;
    }
    rc = dup2(nullFile, STDOUT_FILENO);
    if (-1 == rc) {
        OsErr(errno);
        AppErr(driver::cond::stdout_);
        err("E%04d %s (%d)", driver::cond::stdout_, driver::message::stdout_, OsErr());
        return false;
    }
    rc = dup2(nullFile, STDERR_FILENO);
    if (-1 == rc) {
        OsErr(errno);
        AppErr(driver::cond::stderr_);
        err("E%04d %s (%d)", driver::cond::stderr_, driver::message::stderr_, OsErr());
        return false;
    }
#endif
    return true;
}

#if defined(_WIN32)
bool Driver::GetRegistryValue(HKEY key, const char* name, char* buf, DWORD* size)
{
    DWORD type = 0;
    long result = RegGetValue(key, NULL, name, RRF_RT_REG_SZ, &type, buf, size);
    if (result == ERROR_SUCCESS) {
        return true;
    }
    if (result == ERROR_FILE_NOT_FOUND) {
        *size = 0;
        return true;
    }
    OsErr(result);
    AppErr(driver::cond::reggetvalue);
    err("E%04d %s (%d)", driver::cond::reggetvalue, driver::message::reggetvalue, result);
    RegCloseKey(key);
    return false;
}
#endif

#if defined(_WIN32)
void Driver::GetRegistryVars()
{
    HKEY key = 0;
    std::string path = _registry + _name;
    long result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_QUERY_VALUE, &key);
    if (result != ERROR_SUCCESS) {
        if (result != ERROR_FILE_NOT_FOUND) {
            OsErr(result);
            AppErr(driver::cond::regopenkeyex);
            err("E%04d %s (%d)", driver::cond::regopenkeyex, driver::message::regopenkeyex, OsErr());
        }
        return;
    }
    char val[256]{ 0 };
    DWORD size = sizeof val;
    if (!GetRegistryValue(key, driver::setting::name::descriptor, val, &size)) {
        return;
    }
    if (size) {
        inf(driver::message::regsetting, driver::cond::regsetting, driver::setting::name::descriptor, val);
        _descriptor = val;
    }
    size = sizeof val;
    if (!GetRegistryValue(key, driver::setting::name::loglevel, val, &size)) {
        return;
    }
    if (size) {
        inf(driver::message::regsetting, driver::cond::regsetting, driver::setting::name::loglevel, val);
        LoggerLevel(val);
    }
    size = sizeof val;
    if (!GetRegistryValue(key, driver::setting::name::logpath, val, &size)) {
        return;
    }
    if (size) {
        inf(driver::message::regsetting, driver::cond::regsetting, driver::setting::name::logpath, val);
        LoggerPath(val);
    }
    size = sizeof val;
    if (!GetRegistryValue(key, driver::setting::name::logprefix, val, &size)) {
        return;
    }
    if (size) {
        inf(driver::message::regsetting, driver::cond::regsetting, driver::setting::name::logprefix, val);
        LoggerPrefix(val);
    }
    size = sizeof val;
    if (!GetRegistryValue(key, driver::setting::name::logsuffix, val, &size)) {
        return;
    }
    if (size) {
        inf(driver::message::regsetting, driver::cond::regsetting, driver::setting::name::logsuffix, val);
        LoggerSuffix(val);
    }
    result = RegCloseKey(key);
    if (result != ERROR_SUCCESS) {
        OsErr(result);
        AppErr(driver::cond::regclosekey);
        err("E%04d %s (%d)", driver::cond::regclosekey, driver::message::regclosekey, result);
    }
}
#endif

void Driver::GetEnvVars()
{
    const char* val = getenv(driver::env::descriptor);
    if (val) {
        inf(driver::message::envsetting, driver::cond::envsetting, driver::setting::name::descriptor, val);
        LoggerLevel(val);
    }
    val = getenv(driver::env::loglevel);
    if (val) {
        inf(driver::message::envsetting, driver::cond::envsetting, driver::setting::name::loglevel, val);
        LoggerLevel(val);
    }
    val = getenv(driver::env::logpath);
    if (val) {
        inf(driver::message::envsetting, driver::cond::envsetting, driver::setting::name::logpath, val);
        LoggerPath(val);
    }
    val = getenv(driver::env::logprefix);
    if (val) {
        inf(driver::message::envsetting, driver::cond::envsetting, driver::setting::name::logprefix, val);
        LoggerPrefix(val);
    }
    val = getenv(driver::env::logsuffix);
    if (val) {
        inf(driver::message::envsetting, driver::cond::envsetting, driver::setting::name::logsuffix, val);
        LoggerSuffix(val);
    }
}

void Driver::GetFileArg(int argc, char* argv[])
{
    for (int arg = 1; arg < argc; arg++) {
        if (!strcmp(argv[arg], driver::arg::configfile)) {
            if (++arg > argc) {
                continue;
            }
            inf(driver::message::argsetting, driver::cond::argsetting, driver::setting::name::configfile, argv[arg]);
            Config(argv[arg]);
        }
    }
}

void Driver::SetVar(unsigned int id, const char* val)
{
    switch (id) {
    case driver::setting::configfile:
        inf(driver::message::cfgsetting, driver::cond::cfgsetting, driver::setting::name::configfile, val);
        _config = val;
        break;
    case driver::setting::descriptor:
        inf(driver::message::cfgsetting, driver::cond::cfgsetting, driver::setting::name::descriptor, val);
        _descriptor = val;
        break;
    case driver::setting::loglevel:
        inf(driver::message::cfgsetting, driver::cond::cfgsetting, driver::setting::name::loglevel, val);
        LoggerLevel(val);
        break;
    case driver::setting::logpath:
        inf(driver::message::cfgsetting, driver::cond::cfgsetting, driver::setting::name::logpath, val);
        LoggerPath(val);
        break;
    case driver::setting::logprefix:
        inf(driver::message::cfgsetting, driver::cond::cfgsetting, driver::setting::name::logprefix, val);
        LoggerPrefix(val);
        break;
    case driver::setting::logsuffix:
        inf(driver::message::cfgsetting, driver::cond::cfgsetting, driver::setting::name::logsuffix, val);
        LoggerSuffix(val);
        break;
    case driver::setting::model:
        inf(driver::message::cfgsetting, driver::cond::cfgsetting, driver::setting::name::model, val);
        _model = val;
        break;
    case driver::setting::port:
        inf(driver::message::cfgsetting, driver::cond::cfgsetting, driver::setting::name::port, val);
        int port_n = atoi(val);
        port_n = port_n < 0 ? 0 : port_n > 65535 ? 65535 : port_n;
        _port = static_cast<uint16_t>(port_n);
        break;
    }
}

void Driver::ParseLine(std::string& line)
{
    std::string setting;
    std::string value;
    size_t loc = line.find_first_not_of(" \t");
    if (loc == std::string::npos) {
        return;
    }
    line.erase(0, loc);
    loc = line.find_first_of("=");
    if (loc == std::string::npos) {
        return;
    }
    setting = line.substr(0, loc);
    value = line.substr(loc);
    loc = setting.find_first_of(" \t");
    if (loc != std::string::npos) {
        setting.erase(loc);
    }
    loc = value.find_first_not_of("= \t");
    if (loc == std::string::npos) {
        return;
    }
    value.erase(0, loc);
    loc = value.find_first_of(" \t");
    if (loc != std::string::npos) {
        value.erase(loc);
    }
    for (int n = 0; app_settings[n].id; n++) {
        if (setting == app_settings[n].str) {
            SetVar(app_settings[n].id, value.c_str());
            break;
        }
    }
}

void Driver::GetFileVars()
{
    ifstream file(_config, ios::in);
    if (file.good()) {
        string str;
        while (getline(file, str)) {
            ParseLine(str);
        }
        file.close();
    }
}

void Driver::GetArgVars(int argc, char* argv[])
{
    if (argc < 2) {
        return;
    }
    int n = 1;
    if (!strcmp(argv[n], driver::service)) {
        n++;
    }
    while (n < argc) {
        if (!strcmp(argv[n], driver::arg::configfile)) {
            if (++n < argc) {
                Config(argv[n]);
            }
        } else if (!strcmp(argv[n], driver::arg::descriptor)) {
            if (++n < argc) {
                _descriptor = argv[n];
            }
        } else if (!strcmp(argv[n], driver::arg::loglevel)) {
            if (++n < argc) {
                LoggerLevel(argv[n]);
            }
        } else if (!strcmp(argv[n], driver::arg::logpath)) {
            if (++n < argc) {
                LoggerPath(argv[n]);
            }
        } else if (!strcmp(argv[n], driver::arg::logprefix)) {
            if (++n < argc) {
                LoggerPrefix(argv[n]);
            }
        } else if (!strcmp(argv[n], driver::arg::logsuffix)) {
            if (++n < argc) {
                LoggerSuffix(argv[n]);
            }
        } else if (!strcmp(argv[n], driver::arg::port)) {
            if (++n < argc) {
                int port_n = std::atoi(argv[n]);
                port_n = port_n < 0 ? 0 : port_n > 65535 ? 65535 : port_n;
                _port = static_cast<uint16_t>(port_n);
            }
        }
        n++;
    }
}

bool Driver::GetModel()
{
    return true;
}

void Driver::Configure(int argc, char* argv[])
{
    //  Configure is called before any additional thread is started. So, we do
    //  not need to provide for concurrency here.

    LoggerPrefix(_name.c_str());
    LoggerSuffix(driver::logsuffix);

    //  Set default port number for our sockets. This can be overridden in the
    //  configuration.

    _v4tcp.Port(driver::port);
    _v6tcp.Port(driver::port);
    _udpChannel4.Sock().Port(driver::port);
    _udpChannel6.Sock().Port(driver::port);

    //  Read and apply configuration settings from the registry, environment,
    //  configuration file and program arguments.

#if defined(_WIN32)
    GetRegistryVars();
#endif
    GetEnvVars();
    GetFileArg(argc, argv);
    GetFileVars();
    GetArgVars(argc, argv);
    GetModel();

    //  Configuration is complete. So, spool any prelog messages into the
    //  configured log path and file and close the prelog file.

    LoggerPrelog(false);
    inf("I%04d %s", driver::cond::complete, driver::message::complete);
}

bool Driver::OpenAddress(Socket& tcp, bool v6)
{
    if (!tcp.Stream(v6)) {
        return false;
    }
    if (!tcp.Bind()) {
        return false;
    }
    return (tcp.Listen());
}

bool Driver::OpenAddress(Socket& tcp, Socket& udp, bool v6)
{
    if (!tcp.Stream(v6)) {
        return false;
    }
    if (!tcp.Bind()) {
        return false;
    }
    if (!tcp.Listen()) {
        return false;
    }
    if (!udp.Datagram(v6)) {
        return false;
    }
    return udp.Bind();
}

void Driver::CloseAddress(Socket& tcp, Socket& udp)
{
    tcp.Shutdown();
    tcp.Close();
    udp.Close();
}

bool Driver::Initialize(int argc, char* argv[])
{
    //  Log the application title and copyright.

    wrt("I%04d %s", driver::cond::title, _title.empty() ? driver::message::title : _title.c_str());
    wrt("I%04d %s", driver::cond::copyright, _copyright.empty() ? driver::message::copyright : _copyright.c_str());
#if defined(_WIN32)

    //  Initialize Windows sockets.

    WSADATA wsadata{ 0 };
    int rc = WSAStartup(WINSOCKVERSION, &wsadata);
    if (rc) {
        AppErr(driver::cond::wsastartup);
        return false;
    }
    Winsock(true);
#endif

    //  Apply application configuration from registry, if runing on Windows, the
    //  environment settings, configuration file, and program arguments.

    Configure(argc, argv);

    //  Open TCP and UDP listeners for IPv4 and IPv6.

    if (!OpenAddress(_v4tcp, _udpChannel4.Sock())) {
        return false;
    }
    if (!OpenAddress(_v6tcp, _udpChannel6.Sock(), true)) {
        return false;
    }
    return true;
}

void Driver::Queue(Channel* channel)
{
    if (channel) {
        channel->Next(nullptr);
        channel->Prev(_last);
        if (_last) {
            _last->Next(channel);
        }
        _last = channel;
        if (!_first) {
            _first = channel;
        }
    }
}

void Driver::GetClient()
{
    for (int n = 0; n < driver::channels; ++n) {
        if (_channel[n].State() == channel::state::ready) {
            SOCKET client = _v4tcp.Accept();
            if (client) {
                _channel[n].RemoteAddress(_v4tcp);
            } else {
                client = _v6tcp.Accept();
                if (client) {
                    _channel[n].RemoteAddress(_v6tcp);
                }
            }
            if (client) {
                _channel[n].State(channel::state::connected);
                _channel[n].Sock(client);
                _channel[n].Expires(time(0) + 3600);
                Queue(&_channel[n]);
            }
            break;
        }
    }
}

Channel* Driver::Dequeue()
{
    Channel* channel = _first;
    if (channel) {
        if (channel->Prev()) {
            channel->Prev()->Next(channel->Next());
        }
        if (channel->Next()) {
            channel->Next()->Prev(channel->Prev());
        }
        _first = channel->Next();
        if (channel == _last) {
            _last = channel->Prev();
        }
    }
    return channel;
}

void Driver::ServiceChannel()
{
    //  We have one IPv4 and one IPv6 channel dedicated to UDP. Service each of
    //  these channels on each iteration since a connection is not relevant.

    _udpChannel4.Service();
    _udpChannel6.Service();

    //  For TCP, dequeue a channel not in the ready state in round-robin order.
    //  If one is found, service the channel. Return it to the queue only if
    //  the state is not ready. Ready channels are not queued because there is
    //  no work to perform on them.

    Channel* channel = Dequeue();
    if (channel) {
        channel->Service();
        if (channel->State() != channel::state::ready) {
            Queue(channel);
        }
    }
}

void Driver::Mainline()
{
    //  While we are not stopping check for any new connection and then service
    //  the next channel.

    while (!Stopping()) {
        GetClient();
        ServiceChannel();
    }

    inf("I%04d %s", driver::cond::stopping, driver::message::stopping);
}

void Driver::Finalize()
{
    //  Shutdown and close TCP and UDP listeners on both IPv4 and IPv6.

    CloseAddress(_v4tcp, _udpChannel4.Sock());
    CloseAddress(_v6tcp, _udpChannel6.Sock());
#if defined(_WIN32)

    //  Finalize Windows sockets.

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
    // Perform install, uninstall, or start the Windows service. If an install
    // or uninstall was run or the Windows service dispatcher was called, then
    // we can exit now indicating that the foreground app need not run.

    if (!Service(argc, argv)) {
        return false;
    }

    // If Service returned true, we continue. Now if the "service" argument was
    // passed on Linux or macOS, we are already forked and can enter the Run
    // method on this thread and then return false since there is no console.

    if (Daemon()) {
        Run(argc, argv);
        return false;
    }

    // If Service returned true be we are not a daemon, start a background
    // thread and call Run on it. Then return true to accept console input.

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
