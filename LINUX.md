### Argo on Linux
#### Update Prerequisites
Before building Argo, update your Linux components, install development tools and remove unnecessary packages.
##### Debian or Ubuntu
```
$ sudo apt update
$ sudo apt upgrade
$ sudo apt install build-essential
$ sudo apt autoremove
```
##### Fedora
```
$ sudo dnf update
$ sudo dnf install @development-tools
```
##### Oracle
```
$ sudo yum update
$ sudo yum upgrade
$ sudo yum groupinstall "Development Tools"
```
#### Download Argo
Clone the Argo repository using git to create a local copy.
```
$ cd ~/repos
$ git clone https://github.com/thatcodebase/argo.git
```
#### Build Argo
##### Build using CMake
```
$ cd ~/repos/argo
$ rm -rf build && mkdir build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
$ make
$ sudo make install
$ sudo ldconfig
$ make clean
```
#### Run Argo
##### Run Argo in the Foreground
```
$ which argo
$ argo
```

##### Run Argo as a Service
###### Install Service
Argo as a service runs from /usr/bin and /usr/lib so that test builds can still install to /usr/local/bin and /usr/local/lib.
Be aware, though, that /usr/local/lib might take precedence depending on path settings.
```
$ cd ~/repos/argo
$ sudo mkdir /var/opt/argo
$ sudo cp libargo.so /usr/lib
$ sudo cp argo /usr/bin
$ sudo cp argo.service /lib/systemd/system/
$ sudo cp argo.conf /etc/modules-load.d/
$ sudo systemctl daemon-reload
$ sudo systemctl enable argo
```
###### Service Operation
Check the output of "systemctl status argo" to note which signal was sent to terminate the service.
This could be SIGTERM or SIGINT, even though ava.service specifies that SIGINT should be sent (kill -2).
```
$ sudo systemctl start argo
$ sudo systemctl status argo
$ netstat -an | grep 1143
$ sudo systemctl stop argo
$ netstat -an | grep 1143
$ sudo more /var/opt/argo/*.log
```

###### Remove Service
```
$ sudo systemctl stop argo
$ sudo systemctl disable argo
$ sudo rm /etc/modules-load.d/argo.conf
$ sudo rm /lib/systemd/system/argo.service
$ sudo systemctl daemon-reload
$ sudo rm /usr/bin/argo
$ sudo rm /usr/lib/libargo.so
$ sudo rm -rf /var/opt/argo
```
#### Debug Argo
##### Debugging Using Vistual Studio Code
To have root privilege debugging using VS Code, log in to Linux as an administrator. The first time GDB is run, either stand-alone or from within Visual Studio Code, copy .gdbinit into your user's home folder (~) so the GDB will be configured to pass the SIGINT signal to the app.
```
$ cd ~/repos/argo
$ cp .gdbinit ~
$ code .
```

##### Debugging using GDB
Start GDB with the "--tui" option to run the debugger with a "Textual User Interface".
```
$ cd ~/repos/argo
$ gdb --tui argo
```
