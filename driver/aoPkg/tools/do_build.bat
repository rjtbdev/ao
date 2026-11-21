@echo off
rem Build ao.efi out-of-tree against an existing EDK2 checkout.
rem
rem AO_DIR    = absolute path to ao/driver (contains aoPkg\)
rem EDK2_DIR  = absolute path to the EDK2 workspace
rem Output   .efi lands in %EDK2_DIR%\Build\aoPkg\NOOPT_VS2026\X64\ao.efi

set "AO_DIR=C:\Users\riley\projects\ao\driver"
set "EDK2_DIR=C:\Users\riley\Projects\canopy\edk2"

call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64
cd /d "%EDK2_DIR%"
call "%EDK2_DIR%\edksetup.bat"
set "EDK_TOOLS_BIN=%EDK2_DIR%\BaseTools\Bin\Win64"
set "PATH=%EDK_TOOLS_BIN%;%PATH%"
set "NASM_PREFIX=C:\Users\riley\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin\"

rem Make EDK2 look for aoPkg at AO_DIR (out-of-tree package location)
set "PACKAGES_PATH=%AO_DIR%;%EDK2_DIR%"

build -t VS2026 -a X64 -b NOOPT -p aoPkg\aoPkg.dsc 2>&1
