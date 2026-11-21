@echo off
:: build_ovmf.bat — builds OVMF_CODE.fd and OVMF_VARS.fd from edk2 source
:: Output lands in aoPkg\tools\ next to this script and run_qemu.bat
::
:: Run ONCE before run_qemu.bat. Takes ~2 min.

setlocal
set ROOT=C:\Users\riley\Projects\canopy\edk2
set TOOLS=%~dp0

call "%ROOT%\edksetup.bat" Rebuild >nul 2>&1
call "%ROOT%\edksetup.bat"

echo [*] Building OVMF (X64, NOOPT)...
build -p OvmfPkg\OvmfPkgX64.dsc ^
      -a X64 ^
      -b NOOPT ^
      -t VS2026 ^
      -n 8

if %errorlevel% neq 0 (
    echo [!] OVMF build failed. Check output above.
    exit /b 1
)

set OVMF_OUT=%ROOT%\Build\OvmfX64\NOOPT_VS2026\FV
copy /y "%OVMF_OUT%\OVMF_CODE.fd" "%TOOLS%OVMF_CODE.fd"
copy /y "%OVMF_OUT%\OVMF_VARS.fd" "%TOOLS%OVMF_VARS.fd"

echo.
echo [*] Done. OVMF images copied to:
echo     %TOOLS%OVMF_CODE.fd
echo     %TOOLS%OVMF_VARS.fd
echo.
echo Now run: run_qemu.bat
