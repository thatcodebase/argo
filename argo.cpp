#include "idriver.h"
#include "argo.h"

#include <iostream>
#include <string>

using namespace std;

int __cdecl main(int argc, char* argv[])
{
    IDriver& driver = TheDriver();

    driver.Name(app::name);
    driver.Title(app::title);
    driver.Copyright(app::copyright);

    if (driver.Start(argc, argv)) {
        string line;
        while (getline(cin, line)) {
            if (line == app::command::exit) {
                break;
            }
        }
        driver.Stop();
    }
    return driver.Result();
}