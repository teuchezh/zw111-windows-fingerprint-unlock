@echo off
REM Build with Visual Studio: run from "x64 Native Tools Command Prompt for VS".
setlocal
if not exist build mkdir build
set CL_FLAGS=/nologo /O2 /EHsc /std:c++17 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /W3 /MT
set LIBS=ole32.lib oleaut32.lib uuid.lib secur32.lib advapi32.lib crypt32.lib bcrypt.lib setupapi.lib shlwapi.lib gdi32.lib shell32.lib user32.lib

cl %CL_FLAGS% /LD /Fe:build\ZwCredProv.dll credprov\Dll.cpp credprov\Provider.cpp credprov\Credential.cpp credprov\helpers.cpp common\serial.cpp common\config.cpp common\proto.cpp /link /DEF:credprov\ZwCredProv.def %LIBS%
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe:build\zwsetup.exe setup\zwsetup.cpp common\serial.cpp common\config.cpp common\proto.cpp /link %LIBS%
if errorlevel 1 goto :fail

rc /nologo /fo build\gui_res.res gui\zwsetup-gui.rc
if errorlevel 1 goto :fail
cl %CL_FLAGS% /Fe:build\zwsetup-gui.exe gui\main.cpp common\serial.cpp common\config.cpp common\proto.cpp build\gui_res.res /link /SUBSYSTEM:WINDOWS %LIBS% comctl32.lib
if errorlevel 1 goto :fail
del /q build\gui_res.res 2>nul

del /q *.obj 2>nul
echo.
echo OK: build\ZwCredProv.dll  build\zwsetup.exe  build\zwsetup-gui.exe
exit /b 0
:fail
echo BUILD FAILED
exit /b 1
