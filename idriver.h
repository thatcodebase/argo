#pragma once

#include "iapi.h"

struct IDriver
{
    virtual void Name(const char* name) = 0;
    virtual void Title(const char* title) = 0;
    virtual void Copyright(const char* copyright) = 0;

    virtual bool Start(int argc, char* argv[]) = 0;
    virtual void Stop() = 0;

    virtual int Result() = 0;
};

EXPORT IDriver& TheDriver();
EXPORT IDriver* TheDriverPtr();