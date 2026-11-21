@echo off
:: run_qemu.bat — boots ao inside QEMU with GDB stub on :1234
:: Usage: run_qemu.bat [path\to\OVMF_CODE.fd] [path\to\OVMF_VARS.fd]
::
:: QEMU catches triple faults instead of rebooting your real machine.
:: Attach GDB (or WinDbg via gdbserver) to localhost:1234.
::
:: Quick GDB session (from WSL or any GDB):
::   gdb
::   (gdb) target remote localhost:1234
::   (gdb) set architecture i386:x86-64
::   (gdb) hbreak *0x0         <- host exception IDT entry if needed
::   (gdb) c
::
:: When the HV triple-faults, QEMU stops and GDB catches it.
:: Print registers: (gdb) info registers
:: Print stack:     (gdb) x/16gx $rsp

setlocal

set QEMU=qemu-system-x86_64
set BUILD=C:\Users\riley\Projects\canopy\edk2\Build\aoPkg\NOOPT_VS2026\X64

:: OVMF — use args if provided, else look for local copies
set OVMF_CODE=%~1
set OVMF_VARS=%~2
if "%OVMF_CODE%"=="" set OVMF_CODE=%~dp0OVMF_CODE.fd
if "%OVMF_VARS%"=="" set OVMF_VARS=%~dp0OVMF_VARS.fd

if not exist "%OVMF_CODE%" (
    echo [!] OVMF_CODE.fd not found at: %OVMF_CODE%
    echo     Run build_ovmf.bat first, or copy OVMF_CODE.fd here.
    exit /b 1
)

:: FAT image with our EFIs on it (created fresh each run)
set DISK=%TEMP%\shmr_test.img
echo [*] Creating FAT disk image...
if exist "%DISK%" del /f /q "%DISK%"

:: Use qemu-img to make a 64MB FAT image
qemu-img create -f raw "%DISK%" 64M >nul
:: Format and copy files via mformat/mcopy if available, else warn
where mformat >nul 2>&1
if %errorlevel%==0 (
    mformat -i "%DISK%"@@0 -F ::
    mcopy -i "%DISK%"@@0 "%BUILD%\ao.efi"    ::ao.efi
    mcopy -i "%DISK%"@@0 "%BUILD%\TriggerCrash.efi" ::TriggerCrash.efi
    mcopy -i "%DISK%"@@0 "%BUILD%\ReadScratch.efi"  ::ReadScratch.efi
    echo [*] Disk image built with mtools.
) else (
    echo [!] mtools not found — copy EFIs to a FAT USB or pre-built disk image instead.
    echo     Install mtools: winget install GnuWin32.Mtools
)

echo [*] Starting QEMU (GDB stub on :1234, QEMU monitor on :4444)...
echo     Attach GDB: target remote localhost:1234
echo     QEMU monitor: telnet localhost 4444
echo.

%QEMU% ^
  -machine q35,accel=whpx,kernel-irqchip=off ^
  -cpu EPYC,+svm,+x2apic ^
  -smp 4,cores=4 ^
  -m 4G ^
  -drive if=pflash,format=raw,readonly=on,file="%OVMF_CODE%" ^
  -drive if=pflash,format=raw,file="%OVMF_VARS%" ^
  -drive format=raw,file="%DISK%",if=none,id=hd0 ^
  -device virtio-blk-pci,drive=hd0 ^
  -serial stdio ^
  -monitor telnet:localhost:4444,server,nowait ^
  -gdb tcp::1234 ^
  -S ^
  -no-reboot ^
  -d cpu_reset,guest_errors ^
  -D %TEMP%\qemu_shmr.log

echo.
echo [*] QEMU exited. Log at: %TEMP%\qemu_shmr.log
