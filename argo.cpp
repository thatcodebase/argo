#include "idriver.h"
#include "argo.h"

#include <iostream>
#include <string>

using namespace std;

//  Program control enters at main after any global instances in the library are
//  constructed. The program prefers stdcall on 32-bit but main must be __cdecl.

int __cdecl main(int argc, char* argv[])
{
    //  The singleton Driver is constructed in the Argo library. Obtain a
    //  reference to it and set its members to application-layer values.

    IDriver& driver = TheDriver();

    //  Set driver variables specific to the application.

    driver.Config(app::config);
    driver.Copyright(app::copyright);
    driver.Description(app::description);
    driver.Display(app::display);
    driver.Name(app::name);
    driver.Registry(app::registry);
    driver.Spec(app::spec);
    driver.Title(app::title);
    driver.Usage(app::usage);

    //  Library initialization only returns true if the program completes
    //  configuration and will run in the foreground. If the program will
    //  run as a service or daemon, the background process will have been
    //  forked and this parent process may exit. Start also returns false
    //  if an error occurred during initialization.

    if (driver.Start(argc, argv)) {
        string line;
        while (getline(cin, line)) {
            if (line == app::command::exit) {
                break;
            }
        }
        driver.Stop();
    }

    //  The program will exit returning any result code maintained in the
    //  library. But, global instance destructors are called on exit from
    //  main.

    return driver.Result();
}