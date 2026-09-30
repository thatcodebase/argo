@echo off
if "%1" == "clean" (
	if exist Win32 rmdir /s /q Win32
	if exist x64 rmdir /s /q x64
	if exist test.* del /f test.*
	exit /b
)
Setlocal
msbuild -m argo.sln /p:Configuration=Debug /p:Platform=x64
msbuild -m argo.sln /p:Configuration=Release /p:Platform=x64
msbuild -m argo.sln /p:Configuration=Debug /p:Platform=x86
msbuild -m argo.sln /p:Configuration=Release /p:Platform=x86
Endlocal
if "%1" == "install" (
	copy x64\Release\libargo.dll C:\Windows\system32
	copy x64\Release\argo.exe C:\Windows\system32
	copy x64\Release\testargo.exe C:\Windows\system32
	copy argo.json C:\Windows\system32
	copy argo.cfg C:\Windows\system32
)
exit /b
