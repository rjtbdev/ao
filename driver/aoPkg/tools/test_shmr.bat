@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
cd /d "C:\Users\riley\Projects\canopy\edk2"
cl /nologo /EHsc /Fe:test_shmr.exe test_shmr.cpp
if errorlevel 1 goto :eof
echo.
test_shmr.exe
