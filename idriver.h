#pragma once

#include "iapi.h"

struct IDriver
{
    virtual void Config(const char* config) = 0;
    virtual void Copyright(const char* copyright) = 0;
    virtual void Description(const char* description) = 0;
    virtual void Display(const char* display) = 0;
    virtual void LogBase(const char* base) = 0;
    virtual void Name(const char* name) = 0;
    virtual void Registry(const char* name) = 0;
    virtual void Spec(const char* spec) = 0;
    virtual void Title(const char* title) = 0;
    virtual void Usage(const char* usage) = 0;

    virtual bool Start(int argc, char* argv[]) = 0;
    virtual void Stop() = 0;
    virtual int Result() = 0;
};

EXPORT IDriver& TheDriver();
EXPORT IDriver* TheDriverPtr();