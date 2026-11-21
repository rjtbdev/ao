/*
 * hook_tool.c  —  usermode CLI for the ao process-hook scripting layer.
 *
 * You sig-scan from here (or pass an already-resolved VA), then install a
 * hook with an inline script. A couple of built-in recipes are provided so
 * you can get something running without writing opcodes by hand; add your
 * own recipe in the switch block at the bottom.
 *
 * Build:
 *   ml64 /c ao_call.asm
 *   cl /O2 hook_tool.c ao_call.obj /link /out:hook_tool.exe
 *
 * Usage:
 *   hook_tool.exe status
 *       dump the hook table + per-slot stats
 *   hook_tool.exe log
 *       drain the PH_OP_LOG debug ring once and print
 *   hook_tool.exe unregister <slot>
 *       remove one hook
 *   hook_tool.exe clear
 *       mark every hook inactive
 *
 *   hook_tool.exe install <process> <va_hex> <recipe> [recipe args...]
 *       resolve the process CR3, install a hook at va_hex that runs
 *       <recipe>. See the recipe list below.
 *
 *   hook_tool.exe sigscan <process> <module> <pattern> <mask>
 *       scan <module> inside <process>'s memory for <pattern> (hex bytes,
 *       no separators or 0x prefix) with <mask> ('x'=match, '?'=wildcard).
 *       Prints matching VA(s). Does not install anything.
 *
 * Recipes:
 *   force_eax <value>         — set EAX=value, RETSKIP 1 (for ret-site hooks)
 *   force_eax_cont <value>    — set EAX=value, then run the original insn (for mid-function hooks)
 *   mul_eax <factor>          — EAX = EAX * factor, RETSKIP 1
 *   add_eax <delta>           — EAX = EAX + delta,  RETSKIP 1
 *   clamp_eax <max>           — if EAX>max: EAX=max, RETCONT otherwise
 *   log_args                  — LOG ARG1, ARG2; RETCONT
 *   log_eax_edx               — LOG EAX, EDX; RETCONT
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "../host/ao_client.h"

// Max ph_insn's in one recipe (must stay <= PH_SCRIPT_MAX_INSNS=64).
#define RECIPE_MAX_INSNS 32

static void die(const char* msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(1);
}

static const char* fault_name(uint32_t r)
{
    switch (r) {
    case PH_FAULT_NONE:         return "none";
    case PH_FAULT_BAD_OPCODE:   return "bad_opcode";
    case PH_FAULT_BAD_OPERAND:  return "bad_operand";
    case PH_FAULT_READ_FAILED:  return "read_failed";
    case PH_FAULT_WRITE_FAILED: return "write_failed";
    case PH_FAULT_CYCLE_LIMIT:  return "cycle_limit";
    case PH_FAULT_BAD_JUMP:     return "bad_jump";
    case PH_FAULT_WRITE_RO_REG: return "write_ro_reg";
    default: return "?";
    }
}

static int do_status(void)
{
    ph_status s;
    memset(&s, 0, sizeof(s));
    uint64_t rc = ao_ph_status(&s);
    if ((int64_t)rc < 0) { fprintf(stderr, "status failed: %lld\n", (long long)(int64_t)rc); return 1; }
    printf("ao process-hook status:\n");
    printf("  num_active     : %u\n", s.num_active);
    printf("  dispatch_count : %llu\n", (unsigned long long)s.dispatch_count);
    printf("  fault_count    : %llu\n", (unsigned long long)s.fault_count);
    printf("\n");
    printf("  %-4s %-6s %-18s %-18s %-10s %-6s %-12s %s\n",
           "slot", "active", "cr3", "va", "hits", "insns", "fault", "fault_pc");
    printf("  ---- ------ ------------------ ------------------ ---------- ------ ------------ --------\n");
    for (uint32_t i = 0; i < PH_MAX_HOOKS; ++i) {
        const ph_status_entry* e = &s.entries[i];
        printf("  %-4u %-6u 0x%016llX 0x%016llX %-10llu %-6u %-12s %u\n",
               i, e->active,
               (unsigned long long)e->target_cr3,
               (unsigned long long)e->target_va,
               (unsigned long long)e->hits,
               e->insn_count,
               fault_name(e->last_fault_reason),
               e->last_fault_pc);
    }
    return 0;
}

static int do_log(void)
{
    ph_log_entry buf[256];
    uint64_t n = ao_ph_log_read(buf, 256);
    if (n == 0) { printf("(no log entries)\n"); return 0; }
    printf("drained %llu entries:\n", (unsigned long long)n);
    printf("  %-18s %-18s %-18s %-18s\n", "cr3", "va", "a", "b");
    printf("  ------------------ ------------------ ------------------ ------------------\n");
    for (uint64_t i = 0; i < n; ++i) {
        printf("  0x%016llX 0x%016llX 0x%016llX 0x%016llX\n",
               (unsigned long long)buf[i].cr3,
               (unsigned long long)buf[i].va,
               (unsigned long long)buf[i].a,
               (unsigned long long)buf[i].b);
    }
    return 0;
}

// ---- recipes -------------------------------------------------------------

static uint32_t recipe_force_eax(ph_insn* out, uint32_t value, uint32_t ret_bytes)
{
    uint32_t n = 0;
    out[n++] = PH_LOADI(PH_R0, value);
    out[n++] = PH_MOV(PH_GR_EAX, PH_R0);
    out[n++] = PH_RETSKIP(ret_bytes);
    out[n++] = PH_HALT();
    return n;
}

static uint32_t recipe_force_eax_cont(ph_insn* out, uint32_t value)
{
    uint32_t n = 0;
    out[n++] = PH_LOADI(PH_R0, value);
    out[n++] = PH_MOV(PH_GR_EAX, PH_R0);
    out[n++] = PH_RETCONT();
    out[n++] = PH_HALT();
    return n;
}

static uint32_t recipe_mul_eax(ph_insn* out, uint32_t factor, uint32_t ret_bytes)
{
    uint32_t n = 0;
    out[n++] = PH_LOADI(PH_R0, factor);
    out[n++] = PH_MUL(PH_R1, PH_GR_EAX, PH_R0);
    out[n++] = PH_MOV(PH_GR_EAX, PH_R1);
    out[n++] = PH_RETSKIP(ret_bytes);
    out[n++] = PH_HALT();
    return n;
}

static uint32_t recipe_add_eax(ph_insn* out, uint32_t delta, uint32_t ret_bytes)
{
    uint32_t n = 0;
    out[n++] = PH_LOADI(PH_R0, delta);
    out[n++] = PH_ADD(PH_R1, PH_GR_EAX, PH_R0);
    out[n++] = PH_MOV(PH_GR_EAX, PH_R1);
    out[n++] = PH_RETSKIP(ret_bytes);
    out[n++] = PH_HALT();
    return n;
}

static uint32_t recipe_clamp_eax(ph_insn* out, uint32_t max_val)
{
    uint32_t n = 0;
    out[n++] = PH_LOADI(PH_R0, max_val);
    out[n++] = PH_CMP(PH_GR_EAX, PH_R0);
    out[n++] = PH_JLT(2);                 // if EAX < max, skip clamp
    out[n++] = PH_MOV(PH_GR_EAX, PH_R0);
    out[n++] = PH_LOG(PH_GR_EAX, PH_R0);  // record the clamp event
    out[n++] = PH_RETCONT();
    out[n++] = PH_HALT();
    return n;
}

static uint32_t recipe_log_args(ph_insn* out)
{
    uint32_t n = 0;
    out[n++] = PH_LOG(PH_GR_ARG1, PH_GR_ARG2);
    out[n++] = PH_RETCONT();
    out[n++] = PH_HALT();
    return n;
}

static uint32_t recipe_log_eax_edx(ph_insn* out)
{
    uint32_t n = 0;
    out[n++] = PH_LOG(PH_GR_EAX, PH_GR_EDX);
    out[n++] = PH_RETCONT();
    out[n++] = PH_HALT();
    return n;
}

static int do_install(int argc, char** argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: install <process> <va_hex> <recipe> [args]\n");
        return 1;
    }
    const char* proc = argv[2];
    uint64_t va = strtoull(argv[3], NULL, 16);
    const char* recipe = argv[4];

    uint64_t cr3 = ao_get_process_cr3(proc);
    if (cr3 == 0 || cr3 == AO_NOT_PRESENT) { die("process not found"); }
    printf("[+] %s cr3 = 0x%llx\n", proc, (unsigned long long)cr3);
    printf("[+] target va = 0x%llx\n", (unsigned long long)va);

    ph_insn script[RECIPE_MAX_INSNS];
    uint32_t n = 0;

    if (strcmp(recipe, "force_eax") == 0) {
        if (argc < 6) die("force_eax needs <value> [ret_bytes default 1]");
        uint32_t v    = (uint32_t)strtoul(argv[5], NULL, 0);
        uint32_t rb   = (argc >= 7) ? (uint32_t)strtoul(argv[6], NULL, 0) : 1;
        n = recipe_force_eax(script, v, rb);
    } else if (strcmp(recipe, "force_eax_cont") == 0) {
        if (argc < 6) die("force_eax_cont needs <value>");
        uint32_t v    = (uint32_t)strtoul(argv[5], NULL, 0);
        n = recipe_force_eax_cont(script, v);
    } else if (strcmp(recipe, "mul_eax") == 0) {
        if (argc < 6) die("mul_eax needs <factor> [ret_bytes default 1]");
        uint32_t f    = (uint32_t)strtoul(argv[5], NULL, 0);
        uint32_t rb   = (argc >= 7) ? (uint32_t)strtoul(argv[6], NULL, 0) : 1;
        n = recipe_mul_eax(script, f, rb);
    } else if (strcmp(recipe, "add_eax") == 0) {
        if (argc < 6) die("add_eax needs <delta> [ret_bytes default 1]");
        uint32_t d    = (uint32_t)strtoul(argv[5], NULL, 0);
        uint32_t rb   = (argc >= 7) ? (uint32_t)strtoul(argv[6], NULL, 0) : 1;
        n = recipe_add_eax(script, d, rb);
    } else if (strcmp(recipe, "clamp_eax") == 0) {
        if (argc < 6) die("clamp_eax needs <max>");
        uint32_t m    = (uint32_t)strtoul(argv[5], NULL, 0);
        n = recipe_clamp_eax(script, m);
    } else if (strcmp(recipe, "log_args") == 0) {
        n = recipe_log_args(script);
    } else if (strcmp(recipe, "log_eax_edx") == 0) {
        n = recipe_log_eax_edx(script);
    } else {
        fprintf(stderr, "unknown recipe: %s\n", recipe);
        return 1;
    }

    uint64_t rc = ao_ph_register(cr3, va, script, n);
    if ((int64_t)rc < 0) { fprintf(stderr, "register failed: %lld\n", (long long)(int64_t)rc); return 1; }
    printf("[+] installed hook in slot %llu (%u insns)\n", (unsigned long long)rc, n);
    return 0;
}

// ---- sig scan ------------------------------------------------------------

static int hexchar(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_pattern(const char* hex, uint8_t* out, uint32_t max)
{
    uint32_t n = 0;
    while (*hex && n < max) {
        while (*hex == ' ' || *hex == '\t') hex++;
        if (!*hex) break;
        int hi = hexchar(*hex++); if (hi < 0) return -1;
        int lo = hexchar(*hex++); if (lo < 0) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

static int sig_scan_range(uint64_t cr3, uint64_t start_va, uint64_t end_va,
                          const uint8_t* pat, const char* mask, uint32_t plen,
                          uint64_t* match_out)
{
    // Read page-by-page via ao_read_mem. Carry a trailing window across
    // page boundaries so patterns crossing a 4KB line still match.
    uint8_t window[8192];
    uint64_t va = start_va & ~0xFFFULL;
    uint32_t carry = 0;

    while (va < end_va) {
        uint64_t chunk = 0x1000;
        if (chunk > end_va - va) chunk = end_va - va;

        uint64_t rc = ao_read_mem(cr3, va, chunk, window + carry);
        if ((int64_t)rc < 0) {
            // skip unreadable page
            va += 0x1000;
            carry = 0;
            continue;
        }

        uint32_t have = carry + (uint32_t)chunk;
        if (have >= plen) {
            for (uint32_t i = 0; i + plen <= have; ++i) {
                int ok = 1;
                for (uint32_t j = 0; j < plen; ++j) {
                    if (mask[j] == '?') continue;
                    if (window[i + j] != pat[j]) { ok = 0; break; }
                }
                if (ok) {
                    *match_out = (va - carry) + i;
                    return 1;
                }
            }
            // slide: keep last (plen-1) bytes as carry
            carry = plen - 1;
            memmove(window, window + have - carry, carry);
        } else {
            carry = have;
        }
        va += 0x1000;
    }
    return 0;
}

// Repeatedly read <size> bytes at <va>, print only when the value CHANGES.
// Useful for finding "which field is pause" — run this, then toggle pause
// in-game; the address that flips is yours.
// Prints "t=<ms> HEX=<...>" per change. Ctrl+C to stop.
static int do_watch(int argc, char** argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: watch <process> <va_hex> <size> [interval_ms=50] [duration_s=60]\n");
        return 1;
    }
    const char* proc = argv[2];
    uint64_t va = strtoull(argv[3], NULL, 16);
    uint32_t size = (uint32_t)strtoul(argv[4], NULL, 0);
    uint32_t interval_ms = (argc >= 6) ? (uint32_t)strtoul(argv[5], NULL, 0) : 50;
    uint32_t duration_s  = (argc >= 7) ? (uint32_t)strtoul(argv[6], NULL, 0) : 60;
    if (size == 0 || size > 256) { fprintf(stderr, "size 1..256\n"); return 1; }

    uint64_t cr3 = ao_get_process_cr3(proc);
    if (cr3 == 0 || cr3 == AO_NOT_PRESENT) {
        fprintf(stderr, "error: process '%s' not found\n", proc); return 1;
    }
    printf("[+] watching cr3=0x%llx va=0x%llx size=%u every %ums for %us\n",
           (unsigned long long)cr3, (unsigned long long)va, size, interval_ms, duration_s);

    uint8_t prev[256] = {0};
    uint8_t cur[256]  = {0};
    DWORD t_start = GetTickCount();
    int first = 1;
    int changes = 0;
    while ((GetTickCount() - t_start) < duration_s * 1000) {
        uint64_t rc = ao_read_mem(cr3, va, size, cur);
        if ((int64_t)rc < 0) {
            printf("t=%lu  READ_FAIL rc=%lld\n",
                   (unsigned long)(GetTickCount() - t_start), (long long)(int64_t)rc);
            Sleep(interval_ms);
            continue;
        }
        if (first || memcmp(prev, cur, size) != 0) {
            printf("t=%lu  HEX=",(unsigned long)(GetTickCount() - t_start));
            for (uint32_t i = 0; i < size; i++) printf("%02x", cur[i]);
            printf("\n");
            fflush(stdout);
            memcpy(prev, cur, size);
            first = 0;
            changes++;
        }
        Sleep(interval_ms);
    }
    printf("[+] done. %d distinct values observed.\n", changes);
    return 0;
}

// Report EVERY sigscan match within the range (not just the first).
// Helps diagnose "sig isn't unique" without having to add a new matcher.
static int do_sigscan_all(int argc, char** argv)
{
    if (argc < 6) {
        fprintf(stderr, "usage: sigscan_all <process> <module> <pattern_hex> <mask> [scan_mb=16] [max_hits=32]\n");
        return 1;
    }
    const char* proc = argv[2];
    const char* mod  = argv[3];
    const char* pat_hex = argv[4];
    const char* mask = argv[5];
    uint32_t scan_mb = (argc >= 7) ? (uint32_t)strtoul(argv[6], NULL, 0) : 16;
    uint32_t max_hits = (argc >= 8) ? (uint32_t)strtoul(argv[7], NULL, 0) : 32;
    if (scan_mb == 0) scan_mb = 16;

    uint64_t cr3 = ao_get_process_cr3(proc);
    if (cr3 == 0 || cr3 == AO_NOT_PRESENT) { die("process not found"); }
    uint64_t base = ao_find_module_base(proc, mod);
    if (base == 0 || base == AO_NOT_PRESENT) { die("module not found"); }
    printf("[+] %s cr3=0x%llx  %s base=0x%llx  scan=%u MB  max_hits=%u\n",
           proc, (unsigned long long)cr3, mod, (unsigned long long)base, scan_mb, max_hits);

    uint8_t pat[512];
    int plen = parse_pattern(pat_hex, pat, sizeof(pat));
    if (plen <= 0) die("bad pattern hex");
    if ((int)strlen(mask) != plen) die("mask length != pattern length");

    uint64_t start = base;
    uint64_t end   = base + ((uint64_t)scan_mb * 1024 * 1024);
    // sig_scan_range rounds start_va DOWN to a page boundary internally,
    // then restarts matching from that page start. So we can't just pass
    // `found+1` back in (it rounds back to the same page). Instead, scan
    // page-by-page and reset carry each time, tracking all hits per page.
    uint32_t hits = 0;
    uint64_t last_found = 0;
    for (uint64_t page = start & ~0xFFFULL; page < end && hits < max_hits; page += 0x1000) {
        // Scan a 2-page window to cross boundaries, starting at `page`.
        uint64_t window_end = page + 0x2000;
        if (window_end > end) window_end = end;
        uint64_t search_start = page;
        while (search_start < page + 0x1000 && hits < max_hits) {
            uint64_t found = 0;
            if (!sig_scan_range(cr3, search_start, window_end, pat, mask, (uint32_t)plen, &found)) break;
            if (found >= page + 0x1000) break;  // in next page, handled by outer loop
            if (found <= last_found && hits > 0) { search_start = last_found + 1; continue; }
            printf("[+] MATCH[%u]: 0x%llx\n", hits, (unsigned long long)found);
            hits++;
            last_found = found;
            search_start = found + 1;
        }
    }
    printf("[+] total matches: %u (cap=%u)\n", hits, max_hits);
    return hits > 0 ? 0 : 2;
}

// One-shot: resolve CR3 for <process>, read <size> bytes at <va>, print hex.
// Output format is one line: "VA=0x... SIZE=... HEX=aabbccdd..." so Python
// shelling out can parse trivially.
static int do_read(int argc, char** argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: read <process> <va_hex> <size>\n");
        fprintf(stderr, "  <process>  e.g. osu!.exe\n");
        fprintf(stderr, "  <va_hex>   e.g. 0x02B367A5 or 02B367A5\n");
        fprintf(stderr, "  <size>     decimal, 1..4096\n");
        return 1;
    }
    const char* proc = argv[2];
    uint64_t va = strtoull(argv[3], NULL, 16);
    uint32_t size = (uint32_t)strtoul(argv[4], NULL, 0);
    if (size == 0 || size > 4096) {
        fprintf(stderr, "error: size must be 1..4096 (got %u)\n", size);
        return 1;
    }
    uint64_t cr3 = ao_get_process_cr3(proc);
    if (cr3 == 0 || cr3 == AO_NOT_PRESENT) {
        fprintf(stderr, "error: process '%s' not found (cr3=0x%llx)\n",
                proc, (unsigned long long)cr3);
        return 1;
    }
    uint8_t buf[4096];
    uint64_t rc = ao_read_mem(cr3, va, size, buf);
    if ((int64_t)rc < 0) {
        fprintf(stderr, "error: ao_read_mem failed (rc=%lld) va=0x%llx size=%u\n",
                (long long)(int64_t)rc, (unsigned long long)va, size);
        return 1;
    }
    printf("VA=0x%llX SIZE=%u HEX=", (unsigned long long)va, size);
    for (uint32_t i = 0; i < size; i++) printf("%02x", buf[i]);
    printf("\n");
    return 0;
}

static int do_sigscan(int argc, char** argv)
{
    if (argc < 6) {
        fprintf(stderr, "usage: sigscan <process> <module> <pattern_hex> <mask> [scan_mb=16]\n");
        fprintf(stderr, "  pattern: hex bytes (e.g. 558BEC83EC10)\n");
        fprintf(stderr, "  mask:    'x' = match, '?' = wildcard. Same length as pattern.\n");
        fprintf(stderr, "  scan_mb: how many MB past the module base to scan (default 16).\n");
        fprintf(stderr, "           If your target's JIT heap lives far past the image base,\n");
        fprintf(stderr, "           bump this to 256 or more.\n");
        return 1;
    }
    const char* proc = argv[2];
    const char* mod  = argv[3];
    const char* pat_hex = argv[4];
    const char* mask = argv[5];
    uint32_t scan_mb = (argc >= 7) ? (uint32_t)strtoul(argv[6], NULL, 0) : 16;
    if (scan_mb == 0) scan_mb = 16;

    uint64_t cr3 = ao_get_process_cr3(proc);
    if (cr3 == 0 || cr3 == AO_NOT_PRESENT) { die("process not found"); }
    uint64_t base = ao_find_module_base(proc, mod);
    if (base == 0 || base == AO_NOT_PRESENT) { die("module not found in process"); }
    printf("[+] %s cr3=0x%llx  %s base=0x%llx  scan=%u MB\n",
           proc, (unsigned long long)cr3, mod, (unsigned long long)base, scan_mb);

    uint8_t pat[512];
    int plen = parse_pattern(pat_hex, pat, sizeof(pat));
    if (plen <= 0) die("bad pattern hex");
    if ((int)strlen(mask) != plen) die("mask length != pattern length");

    uint64_t found = 0;
    uint64_t start = base;
    uint64_t end   = base + ((uint64_t)scan_mb * 1024 * 1024);
    if (sig_scan_range(cr3, start, end, pat, mask, (uint32_t)plen, &found)) {
        printf("[+] MATCH: 0x%llx\n", (unsigned long long)found);
        return 0;
    }
    printf("[!] not found in 0x%llx..0x%llx\n",
           (unsigned long long)start, (unsigned long long)end);
    return 2;
}

//
// One-shot: sigscan, apply byte offset, then install a hook at the resulting
// VA. Usage: install_sig <process> <module> <pattern_hex> <mask> <offset_hex> <scan_mb> <recipe> [recipe args]
//
// See docs/case-studies/<target>.md for real sig/offset/recipe triples.
// The install_sig command is deliberately generic — no target names or
// patterns are embedded here. Example invocation shape:
//   hook_tool install_sig <process.exe> <module.dll> <pattern_hex> <mask> \
//       <offset_hex> <scan_mb> <recipe> [recipe args]
//
static int do_install_sig(int argc, char** argv)
{
    if (argc < 9) {
        fprintf(stderr, "usage: install_sig <process> <module> <pattern_hex> <mask> <offset_hex> <scan_mb> <recipe> [args]\n");
        return 1;
    }
    const char* proc    = argv[2];
    const char* mod     = argv[3];
    const char* pat_hex = argv[4];
    const char* mask    = argv[5];
    uint64_t    offset  = strtoull(argv[6], NULL, 0);
    uint32_t    scan_mb = (uint32_t)strtoul(argv[7], NULL, 0);
    if (scan_mb == 0) scan_mb = 16;

    uint64_t cr3 = ao_get_process_cr3(proc);
    if (cr3 == 0 || cr3 == AO_NOT_PRESENT) die("process not found");
    uint64_t base = ao_find_module_base(proc, mod);
    if (base == 0 || base == AO_NOT_PRESENT) die("module not found in process");
    printf("[+] %s cr3=0x%llx  %s base=0x%llx  scan=%u MB  offset=0x%llx\n",
           proc, (unsigned long long)cr3, mod, (unsigned long long)base, scan_mb,
           (unsigned long long)offset);

    uint8_t pat[512];
    int plen = parse_pattern(pat_hex, pat, sizeof(pat));
    if (plen <= 0) die("bad pattern hex");
    if ((int)strlen(mask) != plen) die("mask length != pattern length");

    uint64_t found = 0;
    uint64_t start = base;
    uint64_t end   = base + ((uint64_t)scan_mb * 1024 * 1024);
    if (!sig_scan_range(cr3, start, end, pat, mask, (uint32_t)plen, &found)) {
        fprintf(stderr, "[!] sig not found in 0x%llx..0x%llx\n",
                (unsigned long long)start, (unsigned long long)end);
        return 2;
    }
    uint64_t hook_va = found + offset;
    printf("[+] sig match @ 0x%llx -> hook VA 0x%llx\n",
           (unsigned long long)found, (unsigned long long)hook_va);

    //
    // Build the script from argv[8..] using the same recipe switch as the
    // install subcommand. Keep in sync with do_install's recipe parsing.
    //
    const char* recipe = argv[8];
    ph_insn script[RECIPE_MAX_INSNS];
    uint32_t n = 0;
    if (strcmp(recipe, "force_eax") == 0) {
        if (argc < 10) die("force_eax needs <value> [ret_bytes default 1]");
        uint32_t v  = (uint32_t)strtoul(argv[9], NULL, 0);
        uint32_t rb = (argc >= 11) ? (uint32_t)strtoul(argv[10], NULL, 0) : 1;
        n = recipe_force_eax(script, v, rb);
    } else if (strcmp(recipe, "force_eax_cont") == 0) {
        if (argc < 10) die("force_eax_cont needs <value>");
        uint32_t v = (uint32_t)strtoul(argv[9], NULL, 0);
        n = recipe_force_eax_cont(script, v);
    } else if (strcmp(recipe, "mul_eax") == 0) {
        if (argc < 10) die("mul_eax needs <factor> [ret_bytes default 1]");
        uint32_t f  = (uint32_t)strtoul(argv[9], NULL, 0);
        uint32_t rb = (argc >= 11) ? (uint32_t)strtoul(argv[10], NULL, 0) : 1;
        n = recipe_mul_eax(script, f, rb);
    } else if (strcmp(recipe, "add_eax") == 0) {
        if (argc < 10) die("add_eax needs <delta> [ret_bytes default 1]");
        uint32_t d  = (uint32_t)strtoul(argv[9], NULL, 0);
        uint32_t rb = (argc >= 11) ? (uint32_t)strtoul(argv[10], NULL, 0) : 1;
        n = recipe_add_eax(script, d, rb);
    } else if (strcmp(recipe, "clamp_eax") == 0) {
        if (argc < 10) die("clamp_eax needs <max>");
        uint32_t m = (uint32_t)strtoul(argv[9], NULL, 0);
        n = recipe_clamp_eax(script, m);
    } else if (strcmp(recipe, "log_args") == 0) {
        n = recipe_log_args(script);
    } else if (strcmp(recipe, "log_eax_edx") == 0) {
        n = recipe_log_eax_edx(script);
    } else {
        fprintf(stderr, "unknown recipe: %s\n", recipe);
        return 1;
    }

    uint64_t rc = ao_ph_register(cr3, hook_va, script, n);
    if ((int64_t)rc < 0) {
        fprintf(stderr, "register failed: %lld\n", (long long)(int64_t)rc);
        return 1;
    }
    printf("[+] installed hook in slot %llu (%u insns)\n",
           (unsigned long long)rc, n);
    return 0;
}

static int do_diag_ncr3(void)
{
    ph_diag_ncr3 d;
    memset(&d, 0, sizeof(d));
    uint64_t rc = ao_ph_diag_ncr3(&d);
    if ((int64_t)rc < 0) { fprintf(stderr, "diag ncr3 failed: %lld\n", (long long)(int64_t)rc); return 1; }
    printf("NCr3 state (CPU %u):\n", d.cpu_index);
    printf("  g_ShadowNcr3Pa     : 0x%016llx\n", (unsigned long long)d.shadow_ncr3_pa);
    printf("  g_ReadNcr3Pa       : 0x%016llx\n", (unsigned long long)d.read_ncr3_pa);
    printf("  g_ExecNcr3Pa       : 0x%016llx\n", (unsigned long long)d.exec_ncr3_pa);
    printf("  VMCB.NCr3 (active) : 0x%016llx\n", (unsigned long long)d.vmcb_ncr3);
    printf("  NptMode            : %u (0=read, 1=exec)\n", d.npt_mode);
    printf("  NCr3UpdatePending  : %u\n", d.ncr3_update_pending);
    printf("  NCr3PendingValue   : 0x%016llx\n", (unsigned long long)d.ncr3_pending_value);
    return 0;
}

static const char* walk_stop_str(uint32_t s)
{
    switch (s) {
    case 1: return "NOT_PRESENT";
    case 2: return "1GB_LEAF";
    case 3: return "2MB_LEAF";
    case 4: return "4KB_PTE";
    default: return "?";
    }
}

static int do_diag_walk(int argc, char** argv)
{
    if (argc < 4) { fprintf(stderr, "usage: diag_walk <process|0> <va_hex>\n"); return 1; }
    uint64_t cr3 = 0;
    if (strcmp(argv[2], "0") != 0) {
        cr3 = ao_get_process_cr3(argv[2]);
        if (cr3 == 0 || cr3 == AO_NOT_PRESENT) die("process not found");
    }
    uint64_t va = strtoull(argv[3], NULL, 16);
    ph_diag_walk d;
    memset(&d, 0, sizeof(d));
    uint64_t rc = ao_ph_diag_walk(cr3, va, &d);
    if ((int64_t)rc < 0) { fprintf(stderr, "diag walk failed: %lld\n", (long long)(int64_t)rc); return 1; }
    printf("NPT walk for VA 0x%llx (cr3 0x%llx):\n", (unsigned long long)va, (unsigned long long)cr3);
    printf("  resolved gpa4k : 0x%016llx\n", (unsigned long long)d.gpa4k);
    printf("  indices        : pml4=%u pdpt=%u pd=%u pt=%u\n",
           d.pml4_idx, d.pdpt_idx, d.pd_idx, d.pt_idx);
    printf("  stop_level     : %u (%s)\n", d.stop_level, walk_stop_str(d.stop_level));
    printf("  pml4e          : 0x%016llx  present=%llu nx=%llu\n",
           (unsigned long long)d.pml4e, (unsigned long long)(d.pml4e & 1), (unsigned long long)((d.pml4e >> 63) & 1));
    printf("  pdpte          : 0x%016llx  present=%llu nx=%llu leaf=%llu\n",
           (unsigned long long)d.pdpte, (unsigned long long)(d.pdpte & 1), (unsigned long long)((d.pdpte >> 63) & 1), (unsigned long long)((d.pdpte >> 7) & 1));
    printf("  pde            : 0x%016llx  present=%llu nx=%llu leaf=%llu\n",
           (unsigned long long)d.pde, (unsigned long long)(d.pde & 1), (unsigned long long)((d.pde >> 63) & 1), (unsigned long long)((d.pde >> 7) & 1));
    printf("  pte            : 0x%016llx  present=%llu nx=%llu\n",
           (unsigned long long)d.pte, (unsigned long long)(d.pte & 1), (unsigned long long)((d.pte >> 63) & 1));
    return 0;
}

static int do_diag_hookmeta(void)
{
    ph_diag_hookmeta d;
    memset(&d, 0, sizeof(d));
    uint64_t rc = ao_ph_diag_hookmeta(&d);
    if ((int64_t)rc < 0) { fprintf(stderr, "diag hookmeta failed: %lld\n", (long long)(int64_t)rc); return 1; }
    printf("HookMeta: hook_count=%u shadow_used=%u\n", d.hook_count, d.shadow_used);
    uint32_t n = d.hook_count < PH_DIAG_HOOKMETA_MAX ? d.hook_count : PH_DIAG_HOOKMETA_MAX;
    for (uint32_t i = 0; i < n; ++i) {
        printf("  [%u] active=%u  gpa4k=0x%016llx  original_pfn=0x%llx  shadow_pfn=0x%llx\n",
               i,
               d.entries[i].active,
               (unsigned long long)d.entries[i].gpa4k,
               (unsigned long long)d.entries[i].original_pfn,
               (unsigned long long)d.entries[i].shadow_pfn);
    }
    return 0;
}

static int do_diag_counters(void)
{
    ph_diag_counters d;
    memset(&d, 0, sizeof(d));
    uint64_t rc = ao_ph_diag_counters(&d);
    if ((int64_t)rc < 0) { fprintf(stderr, "diag counters failed: %lld\n", (long long)(int64_t)rc); return 1; }
    printf("PH NPF/dispatch counters:\n");
    printf("  npf_inst_fetch  : %u   (inst-fetch NPFs that hit the PH branch)\n", d.npf_inst_fetch);
    printf("  gpa_match       : %u   (... whose gpa4K matched an active entry)\n", d.gpa_match);
    printf("  rip_match       : %u   (... AND whose VA == guestRip)\n", d.rip_match);
    printf("  cr3_match       : %u   (... AND whose CR3 matched)\n", d.cr3_match);
    printf("  dispatch        : %u   (RunProcessHookScript ran)\n", d.dispatch);
    printf("  stray           : %u   (fetch on hooked page but no claim)\n", d.stray);
    printf("  bp_count        : %u   (#BP intercepts total)\n", d.bp_count);
    printf("  bp_owned        : %u   (... claimed by an active hook)\n", d.bp_owned);
    printf("  bp_reinject     : %u   (... re-injected as native int3)\n", d.bp_reinject);
    printf("  last_guest_rip  : 0x%016llx\n", (unsigned long long)d.last_guest_rip);
    printf("  last_guest_cr3  : 0x%016llx\n", (unsigned long long)d.last_guest_cr3);
    printf("  last_gpa4k      : 0x%016llx\n", (unsigned long long)d.last_gpa4k);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  hook_tool status\n"
            "  hook_tool log\n"
            "  hook_tool unregister <slot>\n"
            "  hook_tool clear\n"
            "  hook_tool install <process> <va_hex> <recipe> [args]\n"
            "  hook_tool read <process> <va_hex> <size>\n"
            "  hook_tool watch <process> <va_hex> <size> [interval_ms=50] [duration_s=60]\n"
            "  hook_tool sigscan <process> <module> <hex_pattern> <mask> [scan_mb=16]\n"
            "  hook_tool sigscan_all <process> <module> <hex_pattern> <mask> [scan_mb=16] [max_hits=32]\n"
            "  hook_tool install_sig <process> <module> <hex_pattern> <mask> <offset_hex> <scan_mb> <recipe> [args]\n"
            "  hook_tool diag_ncr3\n"
            "  hook_tool diag_walk <process|0> <va_hex>\n"
            "  hook_tool diag_hookmeta\n"
            "  hook_tool diag_counters\n"
            "recipes: force_eax, force_eax_cont, mul_eax, add_eax, clamp_eax, log_args, log_eax_edx\n");
        return 1;
    }

    if (!ao_present()) die("ao HV not detected");

    if (strcmp(argv[1], "status") == 0)         return do_status();
    if (strcmp(argv[1], "log") == 0)            return do_log();
    if (strcmp(argv[1], "install") == 0)        return do_install(argc, argv);
    if (strcmp(argv[1], "read") == 0)           return do_read(argc, argv);
    if (strcmp(argv[1], "watch") == 0)          return do_watch(argc, argv);
    if (strcmp(argv[1], "sigscan") == 0)        return do_sigscan(argc, argv);
    if (strcmp(argv[1], "sigscan_all") == 0)    return do_sigscan_all(argc, argv);
    if (strcmp(argv[1], "install_sig") == 0)    return do_install_sig(argc, argv);
    if (strcmp(argv[1], "diag_ncr3") == 0)      return do_diag_ncr3();
    if (strcmp(argv[1], "diag_walk") == 0)      return do_diag_walk(argc, argv);
    if (strcmp(argv[1], "diag_hookmeta") == 0)  return do_diag_hookmeta();
    if (strcmp(argv[1], "diag_counters") == 0)  return do_diag_counters();
    if (strcmp(argv[1], "unregister") == 0) {
        if (argc < 3) die("unregister needs slot");
        uint64_t rc = ao_ph_unregister((uint32_t)strtoul(argv[2], NULL, 0));
        printf("unregister rc=%lld\n", (long long)(int64_t)rc);
        return (int64_t)rc < 0 ? 1 : 0;
    }
    if (strcmp(argv[1], "clear") == 0) {
        uint64_t rc = ao_ph_clear();
        printf("clear rc=%lld\n", (long long)(int64_t)rc);
        return (int64_t)rc < 0 ? 1 : 0;
    }

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}
