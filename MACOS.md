### Argo on macOS
#### Download
```
% cd ~\repos
% git clone https://github.com/thatcodebase/argo.git
% cd argo
```
#### Build using Make
```
% cd ~/repos/argo
% make
% sudo make install
% make clean
```

#### Build using CMake
```
% cd ~/repos/argo
% rm -rf cmake
% mkdir cmake && cd cmake
% cmake -DCMAKE_BUILD_TYPE=Debug ..
% make
% sudo make install
```
