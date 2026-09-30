#pragma once

#include <atomic>
#include <mutex>
#include <string>

namespace app {
    namespace cond {
        enum code {
            ok = 0
        };
    }
}

namespace logger {
    namespace level {
        enum {
            write = 0,
            error,
            warning,
            info,
            summary,
            detail,
            trace,
            debug
        };
    }
    namespace max {
        enum
        {
            size = 512
        };
    }
    constexpr const char* prelog = "prelog";
    constexpr const char* suffix = "log";
}

#define wrt(...) LoggerWrite(logger::level::write, __VA_ARGS__)
#define inf(...) LoggerWrite(logger::level::info, __VA_ARGS__)

class Logger final
{
    std::atomic<int> _appErr;
    std::atomic<int> _osErr;

    std::atomic<unsigned int> _level;

    std::atomic<bool> _console;
    std::atomic<bool> _prelog;

    std::string _path;
    std::string _prefix;
    std::string _base;
    std::string _suffix;

    std::mutex _mutex;

public:
	Logger();
	~Logger();
	void Init();
	void Reset();

    int AppErr();
    void AppErr(int appErr);
    int OsErr();
    void OsErr(int osErr);

    unsigned int Level();
    void Level(unsigned int level);
    bool Console();
    void Console(bool console);
    bool Prelog();
    void Prelog(bool prelog);

    void Path(const char* path);
    void Prefix(const char* prefix);
    void Base(const char* base);
    void Suffix(const char* suffix);

    void Write(const char* msg);
};

int AppErr();
void AppErr(int appErr);

void LoggerConsole(bool console);
void LoggerPrelog(bool prelog);

void LoggerPath(const char* path);
void LoggerPrefix(const char* prefix);
void LoggerBase(const char* base);
void LoggerSuffix(const char* suffix);
void LoggerWrite(unsigned int level, const char* format, ...);
