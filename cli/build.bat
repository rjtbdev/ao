@echo off
rem Build cli tools in-tree so #include "../host/ao_client.h" resolves.
rem Output: hook_tool.exe, syscall_monitor.exe in this directory.
setlocal

call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
if errorlevel 1 (
    echo failed to set up VS environment
    exit /b 1
)

cd /d "%~dp0"

rem Assemble the hypercall stub from host\ into a local .obj
ml64 /nologo /c ..\host\ao_call.asm /Fo ao_call.obj
if errorlevel 1 exit /b 1

cl /nologo /O2 /W3 hook_tool.c ao_call.obj /link /out:hook_tool.exe >build_hook.log 2>&1
set HOOK_RC=%ERRORLEVEL%

cl /nologo /O2 /W3 syscall_monitor.c ao_call.obj /link /out:syscall_monitor.exe >build_sc.log 2>&1
set SC_RC=%ERRORLEVEL%

if %HOOK_RC% NEQ 0 (
    echo === hook_tool build FAILED ===
    type build_hook.log
    exit /b 1
)
if %SC_RC% NEQ 0 (
    echo === syscall_monitor build FAILED ===
    type build_sc.log
    exit /b 1
)

echo OK
dir /b hook_tool.exe syscall_monitor.exe
exit /b 0
