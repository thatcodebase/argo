#include "api.h"
#include "logger.h"

#include <fstream> // ofsstream::app
#include <iostream>

using namespace std;

Logger theLogger;

Logger::Logger()
{
	Init();
}

Logger::~Logger()
{
	Reset();
}

void Logger::Init()
{
    _appErr = app::cond::ok;
    _osErr = 0;
    _level = logger::level::info;

    _prelog = true;
    _console = true;

    _suffix = logger::suffix;
}

void Logger::Reset()
{
    string().swap(_path);
    string().swap(_prefix);
    string().swap(_base);
    string().swap(_suffix);

    Init();
}

int Logger::AppErr()
{
    return _appErr.load(memory_order_relaxed);
}

void Logger::AppErr(int appErr)
{
    int ok = app::cond::code::ok;
    _appErr.compare_exchange_strong(ok, appErr, memory_order_relaxed);
}

int Logger::OsErr()
{
    return _osErr.load(memory_order_relaxed);
}

void Logger::OsErr(int osErr)
{
    _osErr.store(osErr, memory_order_relaxed);
}

unsigned int Logger::Level()
{
    return _level.load(memory_order_relaxed);
}

void Logger::Level(unsigned int level)
{
    _level.store(level, memory_order_relaxed);
}

bool Logger::Console()
{
    return _console.load(memory_order_relaxed);
}

void Logger::Console(bool console)
{
    _console.store(console, memory_order_relaxed);
}

bool Logger::Prelog()
{
    return _prelog.load(memory_order_relaxed);
}

void Logger::Prelog(bool prelog)
{
    _prelog.store(prelog, memory_order_relaxed);
}

void Logger::Path(const char* path)
{
    lock_guard<mutex> lock(_mutex);
    if (path) {
        _path = path;
    } else {
        string().swap(_path);
    }
}

void Logger::Prefix(const char* prefix)
{
    lock_guard<mutex> lock(_mutex);
    if (prefix) {
        _prefix = prefix;
    } else {
        string().swap(_prefix);
    }
}

void Logger::Base(const char* base)
{
    lock_guard<mutex> lock(_mutex);
    if (base) {
        _base = base;
    } else {
        string().swap(_base);
    }
}

void Logger::Suffix(const char* suffix)
{
    lock_guard<mutex> lock(_mutex);
    if (suffix) {
        _suffix = suffix;
    } else {
        string().swap(_suffix);
    }
}

void Logger::Write(const char* msg)
{
    if (!msg) {
        return;
    }

    lock_guard<mutex> lock(_mutex);

    time_t t = time(0);
    tm* tm = gmtime(&t);
    if (!tm) {
        return;
    }

    char filetime[9]{};
    char datetime[21]{};
    strftime(filetime, sizeof filetime, "%Y%m%d", tm);
    strftime(datetime, sizeof datetime, "%Y.%m.%d %H:%M:%S ", tm);

    if (_console) {
        cout << msg << std::endl;
    }
    if (_prelog) {
        ofstream prelog(logger::prelog, ofstream::app);
        if (prelog.is_open()) {
            prelog << datetime << msg << endl;
            prelog.close();
        }
        return;
    }

    string spec;
    if (!_path.empty()) {
        spec = _path + "/";
    }
    if (!_prefix.empty()) {
        spec += _prefix + ".";
    }
    if (!_base.empty()) {
        spec += _base;
    } else {
        spec += filetime;
    }
    if (!_suffix.empty()) {
        spec += "." + _suffix;
    }

    ofstream logfile(spec, ofstream::app);
    if (logfile.is_open()) {
        ifstream prelog(logger::prelog, ofstream::in);
        if (prelog.is_open()) {
            logfile << prelog.rdbuf();
            prelog.close();
            remove(logger::prelog);
        }
        logfile << datetime << msg << endl;
        logfile.close();
    }
}

int AppErr()
{
    return theLogger.AppErr();
}

void AppErr(int appErr)
{
    theLogger.AppErr(appErr);
}

void LoggerConsole(bool console)
{
    theLogger.Console(console);
}

void LoggerPrelog(bool prelog)
{
    theLogger.Prelog(prelog);
}

void LoggerPath(const char* path)
{
    theLogger.Path(path);
}

void LoggerPrefix(const char* prefix)
{
    theLogger.Prefix(prefix);
}

void LoggerBase(const char* base)
{
    theLogger.Base(base);
}

void LoggerSuffix(const char* suffix)
{
    theLogger.Suffix(suffix);
}

void LoggerWrite(unsigned int level, const char* format, ...)
{
    if (theLogger.Level() >= level) {
        va_list arglist;
        va_start(arglist, format);
        char msg[logger::max::size]{ 0 };
        vsnprintf(msg, sizeof(msg) - 1, format, arglist);
        va_end(arglist);
        theLogger.Write(msg);
    }
}
