### Argo on Windows
#### Download Argo
Clone the Argo repository using git to create a local copy.
```
C:> cd repos
C:\repos> git clone https://gitub.com/thatcodebase/argo.git
```
#### Build Argo
##### Build using MSBuild
Open the "x64 Native Tools Command Prompt" as an Administrator for your version and edition of Visual Studio.

Run the make.bat script with the "clean" parameter to remove any previously created artifacts.  
Then run make.bat with no parameters to build x64 and Win32 artifacts for both Debug and Release configurations.  
Running make.bat with the "install" parameter will rebuild, if necessary, and then copy program artifacts into C:\Windows\System32.  
```
C:\repos\argo> make clean
C:\repos\argo> make
C:\repos\argo> make install
```
##### Build using CMake
Create a build folder and change directories into it.  
```
C:\repos\argo> rmdir /s /q build
C:\repos\argo> mkdir build && cd build
C:\repos\argo\build>
```
Run CMake to generate the build scripts and Windows projects.  
Run CMake to build and install.  
This can only be done as Administrator.  
Note: CMake installs to C:\Program Files (x86)\argo\bin.  
Update the system PATH environment variable as needed.
```
C:\repos\argo\build> cmake ..
C:\repos\argo\build> cmake --build . --config Debug --target install
```
#### Run Argo
##### Run Argo in the Foreground
Use the "where argo" command to confirm the location of the Argo executable.  
```
C:\repos\argo> where argo
C:\Windows\System32\argo.exe
```

##### Run Argo as a Service
###### Install Service
Use the "sc query argo" command to confirm that the Argo service is not installed.
```
C:\repos\argo> sc query argo
[SC] EnumQueryServicesStatus:OpenService FAILED 1060:

The specified service does not exist as an installed service.
```
Run Argo with the "install" parameter to install Argo as a service.  
This can only be done as an Administrator.  
```
C:\repos\argo> argo install
I1001 Argo 0.X Experimental
I1002 Copyright 2010 ThatCodeBase. All rights reserved.
I1004 Installing service (argo)
I1021 Service installed (argo)
```
###### Start the Service
Use the "sc start argo" command to start the Argo service.
```
C:\repos\argo> sc start argo
SERVICE_NAME: argo
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 10396
        FLAGS              :
```
Use the "sc query argo" command to confirm the Argo service is running.  
```
C:\repos\argo> sc query argo
SERVICE_NAME: argo
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
Use the "netstat -an | findstr 1143" command to confirm that Argo is listening for connections.  
```
C:\repos\argo> netstat -an | findstr 1143
  TCP    0.0.0.0:1143           0.0.0.0:0              LISTENING
  TCP    [::1]:1143             [::]:0                 LISTENING
  UDP    0.0.0.0:1143           *:*
  UDP    [::1]:1143             *:*
```
Browse to http://127.0.0.1:1143/  

###### Stop the Service
Use the "sc stop argo" command to stop the service.
```
C:\repos\argo> sc stop argo
SERVICE_NAME: argo
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
Use the "sc query argo" command to confirm the service is stopped.
```
C:\repos\argo> sc query argo
SERVICE_NAME: argo
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
###### Uninstall the Service
Use the "argo uninstall" command to uninstall the Argo service
```
C:\repos\argo> argo uninstall
I1001 Argo 0.X Experimental
I1002 Copyright 2010 ThatCodeBase. All rights reserved.
I1022 Uninstalling service (argo)
I1027 Service uninstalled (argo)
```
Use the "sc query argo" command to confirm the service is uninstalled.
```
C:\repos\argo> sc query argo
[SC] EnumQueryServicesStatus:OpenService FAILED 1060:

The specified service does not exist as an installed service.
```
### Run the Test Program
Run the test program, prompting between test groups: "testargo test"  
Run the test program without prompting: "testargo test all"
Run the test program without prompting, displaying all output: "testargo test all dump"
```
C:\repos\argo> testargo test
C:\repos\argo> testargo test all
C:\repos\argo> testargo test all dump
```
