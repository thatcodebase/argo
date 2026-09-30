# Argo

## About

Argo is a multi-protocol communication service written in C++ for Linux, macOS, Windows, iOS and Android.

## Repository Structure
```
windows ----+---- v141 ----+---- argo.props                 VS 2017 properties, solution, projects
            |              +---- argo.sln
            |              +---- argo.vcxproj
            |              +---- argo.vcxproj.filters
            |              +---- argo.vcxproj.user
            |              +---- libargo.vcxproj
            |              +---- libargo.vcxproj.filters
            |              +---- libargo.vcxproj.user
            |              +---- testargo.vcxproj
            |              +---- testargo.vcxproj.filters
            |              +---- testargo.vcxproj.user
            +---- v142 ----+---- (same files as above)      VS 2019 properties, solution, projects
            +---- v143 ----+---- (same files as above)      VS 2022 properties, solution, projects
            +---- v145 ----+---- argo.slnx                  VS 2026 properties, solution, projects
                           +---- (remaining files as above)
.editorconfig
.gdbinit
.gitignore
argo.cfg
argo.conf
argo.json
CMakeLists.txt
LICENSE
LINUX.md
README.md
WINDOWS.md
(additional source code files)
```

## Build

### Build on Windows

#### Build on Windows with Visual Studio 2026

1. Open windows\v145\argo.slnx.
2. Use Ctrl+Shift+B to build.

#### Build on Windows with MSBuild

1. Open an x64 Native Tools Command Prompt for VS 2026 as Administrator.
2. Navigate to the folder where you have cloned the repo.
3. Use MSBuild to build either Debug or Release configurations.

```
C:\Windows\System32> cd C:\repos\argo
C:\repos\beryl> MSBuild windows\v145\argo.slnx /p:Configuration=Debug   /p:Platform=x64 /p:OutDir=..\build\Debug\
C:\repos\beryl> MSBuild windows\v145\argo.slnx /p:Configuration=Release /p:Platform=x64 /p:OutDir=..\build\Release\
```
