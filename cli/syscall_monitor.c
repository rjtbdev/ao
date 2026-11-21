/*
 * syscall_monitor.c — usermode tool that uses the ao HV to log every
 * syscall a target process makes, in real time.
 *
 * Build:
 *   ml64 /c ao_call.asm
 *   cl /O2 syscall_monitor.c ao_call.obj /link /out:syscall_monitor.exe
 *
 * Usage:
 *   syscall_monitor.exe <process name>          (e.g. "target.exe")
 *   syscall_monitor.exe --all                   (log all processes)
 *   syscall_monitor.exe --cr3 0x1A3F000         (log specific CR3)
 *
 * Press Ctrl+C to stop.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../host/ao_client.h"

static const char* syscall_name(uint32_t num)
{
    switch (num) {
    case 0x0006: return "NtClose";
    case 0x0012: return "NtDeviceIoControlFile";
    case 0x0018: return "NtAllocateVirtualMemory";
    case 0x001A: return "NtFreeVirtualMemory";
    case 0x0023: return "NtQueryInformationProcess";
    case 0x0025: return "NtQueryInformationThread";
    case 0x002B: return "NtOpenProcess";
    case 0x002E: return "NtQuerySystemInformation";
    case 0x0034: return "NtCreateFile";
    case 0x0036: return "NtQueryVirtualMemory";
    case 0x0037: return "NtReadVirtualMemory";
    case 0x003A: return "NtWriteVirtualMemory";
    case 0x003D: return "NtSetInformationThread";
    case 0x0050: return "NtCreateSection";
    case 0x0055: return "NtCreateThreadEx";
    case 0x0077: return "NtProtectVirtualMemory";
    case 0x00C7: return "NtQueryInformationFile";
    case 0x00D4: return "NtSetInformationFile";
    case 0x00DC: return "NtReadFile";
    case 0x0008: return "NtWriteFile";
    case 0x004E: return "NtOpenSection";
    case 0x0028: return "NtMapViewOfSection";
    case 0x002A: return "NtUnmapViewOfSection";
    case 0x001E: return "NtQueryObject";
    case 0x0019: return "NtWaitForSingleObject";
    case 0x000B: return "NtWaitForMultipleObjects";
    case 0x002C: return "NtOpenThread";
    case 0x004C: return "NtSuspendThread";
    case 0x0052: return "NtResumeThread";
    case 0x0057: return "NtGetContextThread";
    case 0x0150: return "NtSetContextThread";
    case 0x00C6: return "NtDuplicateObject";
    default:     return NULL;
    }
}

static volatile int g_running = 1;

static BOOL WINAPI ctrl_handler(DWORD type)
{
    (void)type;
    g_running = 0;
    return TRUE;
}

int main(int argc, char** argv)
{
    uint64_t filter_cr3 = 0;
    const char* proc_name = NULL;
    int log_all = 0;
    int unsafe = 0;
    int argi = 1;

    if (argc < 2) {
        fprintf(stderr, "usage: %s [--unsafe] <process name> | --all | --cr3 <hex>\n", argv[0]);
        fprintf(stderr, "       %s --status  (print hook/log state and exit)\n", argv[0]);
        fprintf(stderr, "       --unsafe: install the actual NPT hook (may crash the system)\n");
        fprintf(stderr, "       without --unsafe: SAFE MODE (control plane only, no syscall capture)\n");
        return 1;
    }

    if (strcmp(argv[argi], "--status") == 0) {
        if (!ao_present()) {
            fprintf(stderr, "error: ao hypervisor not detected\n");
            return 1;
        }
        ao_syscall_status s;
        memset(&s, 0, sizeof(s));
        uint64_t sr = ao_syscall_log_status(&s);
        if (sr != 0) {
            fprintf(stderr, "error: status hypercall failed (rc=%lld)\n",
                    (long long)(int64_t)sr);
            return 1;
        }
        printf("ao syscall logger status:\n");
        printf("  log_allocated       : %u\n", s.log_allocated);
        printf("  active              : %u\n", s.active);
        printf("  count (buffered)    : %u\n", s.count);
        printf("  dropped             : %u\n", s.dropped);
        printf("  filter_cr3          : 0x%016llX\n", (unsigned long long)s.filter_cr3);
        printf("  kernel_lstar        : 0x%016llX\n", (unsigned long long)s.kernel_lstar);
        printf("  kernel_cstar        : 0x%016llX\n", (unsigned long long)s.kernel_cstar);
        printf("  kernel_cr3          : 0x%016llX\n", (unsigned long long)s.kernel_cr3);
        printf("  syscall_gpa_64      : 0x%016llX  %s\n",
               (unsigned long long)s.syscall_gpa_64,
               s.syscall_gpa_64 ? "(hooked)" : "(NOT hooked)");
        printf("  syscall_gpa_32      : 0x%016llX  %s\n",
               (unsigned long long)s.syscall_gpa_32,
               s.syscall_gpa_32 ? "(hooked)" : "(NOT hooked)");
        printf("  hook_count          : %u  (total NPT hooks live)\n", s.hook_count);
        printf("  exec_flip_count     : %u  (NPFs that flipped a CPU to exec NCr3)\n",
               s.exec_flip_count);
        printf("  n_cpus              : %u\n", s.n_cpus);
        printf("  n_cpus_on_exec_ncr3 : %u\n", s.n_cpus_on_exec_ncr3);
        return 0;
    }

    if (strcmp(argv[argi], "--unsafe") == 0) {
        unsafe = 1;
        argi++;
        if (argi >= argc) {
            fprintf(stderr, "error: --unsafe needs a target (<process> | --all | --cr3 <hex>)\n");
            return 1;
        }
    }

    if (strcmp(argv[argi], "--all") == 0) {
        log_all = 1;
    } else if (strcmp(argv[argi], "--cr3") == 0) {
        if (argi + 1 >= argc) {
            fprintf(stderr, "error: --cr3 requires a hex value\n");
            return 1;
        }
        filter_cr3 = strtoull(argv[argi + 1], NULL, 16);
    } else {
        proc_name = argv[argi];
    }

    if (!ao_present()) {
        fprintf(stderr, "error: ao hypervisor not detected\n");
        return 1;
    }
    printf("[+] ao HV present\n");

    if (proc_name != NULL) {
        filter_cr3 = ao_get_process_cr3(proc_name);
        if (filter_cr3 == 0 || filter_cr3 == AO_NOT_PRESENT) {
            fprintf(stderr, "error: process '%s' not found (cr3=0x%llx)\n",
                    proc_name, (unsigned long long)filter_cr3);
            return 1;
        }
        printf("[+] %s CR3 = 0x%llx\n", proc_name, (unsigned long long)filter_cr3);
    }

    if (log_all) filter_cr3 = 0;

    uint64_t rc;
    if (unsafe) {
        printf("[!] UNSAFE: installing NPT hook. Press Ctrl+C or let it crash.\n");
        rc = ao_syscall_log_start_unsafe(filter_cr3);
    } else {
        rc = ao_syscall_log_start(filter_cr3);
    }
    int64_t rc_signed = (int64_t)rc;
    if (rc_signed < 0) {
        fprintf(stderr, "error: syscall_log_start failed (rc=%lld)\n", (long long)rc_signed);
        return 1;
    }
    if (!unsafe && rc == 1) {
        printf("[!] SAFE MODE: ring buffer allocated but NPT hook NOT installed.\n");
        printf("[!] Pass --unsafe to install the actual hook.\n");
    } else if (unsafe && rc == 1) {
        printf("[+] UNSAFE: 64-bit hook installed. 32-bit (CSTAR) unavailable —\n");
        printf("    WoW64 processes will not appear via the x86 path (they may\n");
        printf("    still appear via the x64 WoW64 thunks).\n");
    } else {
        printf("[+] syscall logging started (filter CR3 = 0x%llx)\n",
               (unsigned long long)filter_cr3);
    }
    printf("[+] press Ctrl+C to stop\n\n");
    printf("%-6s %-4s %-8s %-40s %-18s %-18s\n",
           "CPU", "BITS", "SYSCALL", "NAME", "RET_ADDR", "ARG1");
    printf("------ ---- -------- ---------------------------------------- "
           "------------------ ------------------\n");

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    ao_syscall_entry buf[256];
    uint64_t total = 0;

    while (g_running) {
        uint64_t n = ao_syscall_log_read(buf, 256);
        if (n == 0 || n == AO_NOT_PRESENT) {
            Sleep(10);
            continue;
        }

        for (uint64_t i = 0; i < n; i++) {
            const char* name = syscall_name(buf[i].syscall_num);
            const char* bits = (buf[i].flags & AO_SYSCALL_FLAG_32BIT) ? "x86" : "x64";
            printf("%-6u %-4s 0x%04X   %-40s 0x%016llX 0x%016llX\n",
                   buf[i].cpu_index,
                   bits,
                   buf[i].syscall_num,
                   name ? name : "(unknown)",
                   (unsigned long long)buf[i].ret_addr,
                   (unsigned long long)buf[i].arg1);
            total++;
        }
        fflush(stdout);
    }

    ao_syscall_log_stop();
    printf("\n[+] stopped. %llu syscalls captured.\n", (unsigned long long)total);
    return 0;
}
