#pragma once
#include <Windows.h>
#include <stdint.h>

//
// Must match AO_HYPERCALL_MAGIC / AO_CMD_* in Host.c.
//
#define AO_MAGIC          0x56484F41UL    // "AOHV"
#define AO_NOT_PRESENT    UINT64_MAX

#define AO_CMD_PING       0
#define AO_CMD_READ_MEM   1
#define AO_CMD_GET_CR3    2
#define AO_CMD_VA_TO_PA   3
#define AO_CMD_DIAG_CR3    4
#define AO_CMD_DIAG_LSTAR  5
#define AO_CMD_DIAG_BASE   6
#define AO_CMD_DIAG_PSYS   7
#define AO_CMD_DIAG_PEOFF  8
#define AO_CMD_DIAG_EXPDIR 9
#define AO_CMD_DIAG_NNAMES 10
#define AO_CMD_LIST_PROCS    11
#define AO_CMD_GET_PROC_BASE 12
#define AO_CMD_WRITE_GPA     13
#define AO_CMD_ALLOC_SHADOW  14
#define AO_CMD_NPT_HOOK      15
#define AO_CMD_NCR3_SWITCH_READ 16
#define AO_CMD_FIND_MODULE      17
#define AO_CMD_READ_GPA         23
#define AO_CMD_CLEAR_HOOKS      30
#define PROC_ENTRY_SIZE        24   // ImageFileName[16] + DirectoryTableBase[8]

#ifdef __cplusplus
extern "C" {
#endif

//
// Raw UD2 hypercall — implemented in ao_call.asm.
// RAX = (AO_MAGIC << 32) | cmd is built by the asm stub.
// If the hypervisor is not present, UD2 raises STATUS_ILLEGAL_INSTRUCTION.
// Use AO_HYPERCALL() for the SEH-wrapped version.
//
uint64_t ao_call(uint32_t cmd, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);

#ifdef __cplusplus
}
#endif

//
// SEH wrapper — returns AO_NOT_PRESENT if hypervisor is absent.
//
static inline uint64_t
AO_HYPERCALL(uint32_t cmd, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    __try {
        return ao_call(cmd, a0, a1, a2, a3);
    } __except (GetExceptionCode() == STATUS_ILLEGAL_INSTRUCTION
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        return AO_NOT_PRESENT;
    }
}

static inline int ao_present(void) {
    return AO_HYPERCALL(AO_CMD_PING, 0, 0, 0, 0) != AO_NOT_PRESENT;
}

#define ao_hypercall AO_HYPERCALL

static inline uint64_t
ao_va_to_pa(uint64_t cr3, uint64_t va)
{
    return AO_HYPERCALL(AO_CMD_VA_TO_PA, cr3, va, 0, 0);
}

static inline uint64_t
ao_read_mem(uint64_t target_cr3, uint64_t target_va, uint64_t size, void *out_buf)
{
    return AO_HYPERCALL(AO_CMD_READ_MEM, target_cr3, target_va, size, (uint64_t)(uintptr_t)out_buf);
}

static inline uint64_t
ao_get_process_cr3_nth(const char *process_name, uint32_t skip)
{
    return AO_HYPERCALL(AO_CMD_GET_CR3,
                          (uint64_t)(uintptr_t)process_name, (uint64_t)skip, 0, 0);
}

static inline uint64_t
ao_get_process_cr3(const char *process_name)
{
    return ao_get_process_cr3_nth(process_name, 0);
}

static inline uint64_t
ao_get_process_base_nth(const char *process_name, uint32_t skip)
{
    return AO_HYPERCALL(AO_CMD_GET_PROC_BASE,
                          (uint64_t)(uintptr_t)process_name, (uint64_t)skip, 0, 0);
}

static inline uint64_t
ao_get_process_base(const char *process_name)
{
    return ao_get_process_base_nth(process_name, 0);
}

static inline uint64_t
ao_alloc_shadow(void)
{
    return AO_HYPERCALL(AO_CMD_ALLOC_SHADOW, 0, 0, 0, 0);
}

static inline uint64_t
ao_write_gpa(uint64_t dest_gpa, const void *src_buf, uint64_t size)
{
    return AO_HYPERCALL(AO_CMD_WRITE_GPA,
                          dest_gpa,
                          (uint64_t)(uintptr_t)src_buf,
                          size, 0);
}

// Returns the shadow page GPA on success (write hook bytes there via
// ao_write_gpa AFTER this call), or AO_NOT_PRESENT / -1 on failure.
static inline uint64_t
ao_npt_hook(uint64_t target_gpa)
{
    return AO_HYPERCALL(AO_CMD_NPT_HOOK, target_gpa, 0, 0, 0);
}

static inline uint64_t
ao_clear_hooks(void)
{
    return AO_HYPERCALL(AO_CMD_CLEAR_HOOKS, 0, 0, 0, 0);
}

static inline uint64_t
ao_find_module_base_nth(const char *process_name, uint32_t skip, const char *dll_name)
{
    return AO_HYPERCALL(AO_CMD_FIND_MODULE,
                          (uint64_t)(uintptr_t)process_name,
                          (uint64_t)(uintptr_t)dll_name,
                          (uint64_t)skip, 0);
}

static inline uint64_t
ao_find_module_base(const char *process_name, const char *dll_name)
{
    return ao_find_module_base_nth(process_name, 0, dll_name);
}

static inline uint64_t
ao_read_gpa(uint64_t gpa, void *buf, uint64_t size)
{
    return AO_HYPERCALL(AO_CMD_READ_GPA, gpa, (uint64_t)(uintptr_t)buf, size, 0);
}

// Enumerate running processes into caller buffer.
// Returns number of entries written (each PROC_ENTRY_SIZE bytes).
static inline uint64_t
ao_list_procs(void *buf, uint64_t max_procs)
{
    return AO_HYPERCALL(AO_CMD_LIST_PROCS,
                          (uint64_t)(uintptr_t)buf, max_procs, 0, 0);
}

#define AO_CMD_SYSCALL_LOG_START        24
#define AO_CMD_SYSCALL_LOG_STOP         25
#define AO_CMD_SYSCALL_LOG_READ         26
#define AO_CMD_SYSCALL_LOG_START_UNSAFE 27
#define AO_CMD_SYSCALL_LOG_STATUS       28

#pragma pack(push, 1)
typedef struct {
    uint32_t log_allocated;
    uint32_t active;
    uint32_t count;
    uint32_t dropped;
    uint64_t filter_cr3;
    uint64_t kernel_lstar;
    uint64_t kernel_cstar;
    uint64_t kernel_cr3;
    uint64_t syscall_gpa_64;
    uint64_t syscall_gpa_32;
    uint32_t hook_count;
    uint32_t exec_flip_count;
    uint32_t n_cpus;
    uint32_t n_cpus_on_exec_ncr3;
} ao_syscall_status;   // 80 bytes, matches SYSCALL_LOG_STATUS
#pragma pack(pop)

static inline uint64_t
ao_syscall_log_status(ao_syscall_status* out)
{
    return AO_HYPERCALL(AO_CMD_SYSCALL_LOG_STATUS, (uint64_t)(uintptr_t)out, 0, 0, 0);
}

#pragma pack(push, 1)
typedef struct {
    uint64_t cr3;
    uint32_t syscall_num;
    uint16_t cpu_index;
    uint16_t flags;         // bit 0: 0 = 64-bit syscall path, 1 = 32-bit (CSTAR / WoW64)
    uint64_t ret_addr;
    uint64_t arg1;
} ao_syscall_entry;   // 32 bytes, matches SYSCALL_LOG_ENTRY
#pragma pack(pop)

#define AO_SYSCALL_FLAG_32BIT 0x0001

// Start syscall logging — SAFE mode. Just allocates ring buffer and records
// state; no NPT hook is installed, no syscalls will be captured. Useful for
// verifying the control plane works end-to-end. Returns 1 (safe).
static inline uint64_t
ao_syscall_log_start(uint64_t filter_cr3)
{
    return AO_HYPERCALL(AO_CMD_SYSCALL_LOG_START, filter_cr3, 0, 0, 0);
}

// Start syscall logging — UNSAFE mode. Installs the NPT hook on KiSystemCall64
// and enables TF single-step flip-back via #DB interception. This is the
// mechanism that actually captures syscalls. Returns 0 on success.
// filter_cr3=0 logs all processes; nonzero logs only that CR3.
static inline uint64_t
ao_syscall_log_start_unsafe(uint64_t filter_cr3)
{
    return AO_HYPERCALL(AO_CMD_SYSCALL_LOG_START_UNSAFE, filter_cr3, 0, 0, 0);
}

static inline uint64_t
ao_syscall_log_stop(void)
{
    return AO_HYPERCALL(AO_CMD_SYSCALL_LOG_STOP, 0, 0, 0, 0);
}

// Drain up to max_count entries into buf. Returns number of entries copied.
static inline uint64_t
ao_syscall_log_read(ao_syscall_entry *buf, uint32_t max_count)
{
    return AO_HYPERCALL(AO_CMD_SYSCALL_LOG_READ,
                          (uint64_t)(uintptr_t)buf, (uint64_t)max_count, 0, 0);
}

// ============================================================================
// Process-hook scripting layer.
// ============================================================================

#define AO_CMD_PH_REGISTER      40
#define AO_CMD_PH_UNREGISTER    41
#define AO_CMD_PH_STATUS        42
#define AO_CMD_PH_LOG_READ      43
#define AO_CMD_PH_CLEAR         44
#define AO_CMD_PH_SET_CFG       49
#define AO_CMD_PH_GET_CFG       50

// Diagnostic hypercalls for the process-hook NPT path.
#define AO_CMD_PH_DIAG_WALK     45  // walk active NCr3 for a (cr3, va); return 4 PTEs
#define AO_CMD_PH_DIAG_NCR3     46  // return g_Shadow/Read/Exec NCr3 PAs + VMCB.NCr3
#define AO_CMD_PH_DIAG_HOOKMETA 47  // dump SHARED_SVM_DATA.HookMeta.Hooks[]
#define AO_CMD_PH_DIAG_COUNTERS 48  // fine-grained NPF/dispatch counters

#define PH_MAX_HOOKS              8
#define PH_SCRIPT_MAX_INSNS       128

// Script register encoding (matches ao.h PH_* constants).
#define PH_R0   0x00
#define PH_R1   0x01
#define PH_R2   0x02
#define PH_R3   0x03
#define PH_R4   0x04
#define PH_R5   0x05
#define PH_R6   0x06
#define PH_R7   0x07
#define PH_R8   0x08
#define PH_R9   0x09
#define PH_R10  0x0A
#define PH_R11  0x0B
#define PH_R12  0x0C
#define PH_R13  0x0D
#define PH_R14  0x0E
#define PH_R15  0x0F
#define PH_GR_EAX     0x10
#define PH_GR_ECX     0x11
#define PH_GR_EDX     0x12
#define PH_GR_EBX     0x13
#define PH_GR_ESP     0x14
#define PH_GR_EBP     0x15
#define PH_GR_ESI     0x16
#define PH_GR_EDI     0x17
#define PH_GR_EIP     0x18
#define PH_GR_EFLAGS  0x19
#define PH_GR_ARG1    0x20
#define PH_GR_ARG2    0x21
#define PH_GR_ARG3    0x22
#define PH_GR_ARG4    0x23
#define PH_GR_ARG5    0x24
#define PH_GR_ARG6    0x25
#define PH_GR_ARG7    0x26
#define PH_GR_ARG8    0x27
#define PH_CFG0       0x30
#define PH_CFG1       0x31
#define PH_CFG2       0x32
#define PH_CFG3       0x33
#define PH_CFG4       0x34
#define PH_CFG5       0x35
#define PH_CFG6       0x36
#define PH_CFG7       0x37
#define PH_CFG8       0x38
#define PH_CFG9       0x39
#define PH_CFG10      0x3A
#define PH_CFG11      0x3B
#define PH_CFG12      0x3C
#define PH_CFG13      0x3D
#define PH_CFG14      0x3E
#define PH_CFG15      0x3F

// Opcode encoding (matches ao.h PH_OP_*).
#define PH_OP_NOP        0x00
#define PH_OP_LOADI      0x01
#define PH_OP_MOV        0x02
#define PH_OP_ADD        0x03
#define PH_OP_SUB        0x04
#define PH_OP_MUL        0x05
#define PH_OP_AND        0x06
#define PH_OP_OR         0x07
#define PH_OP_XOR        0x08
#define PH_OP_SHL        0x09
#define PH_OP_SHR        0x0A
#define PH_OP_CMP        0x0B
#define PH_OP_JMP        0x0C
#define PH_OP_JEQ        0x0D
#define PH_OP_JNE        0x0E
#define PH_OP_JLT        0x0F
#define PH_OP_JGT        0x10
#define PH_OP_READ1      0x11
#define PH_OP_READ2      0x12
#define PH_OP_READ4      0x13
#define PH_OP_WRITE1     0x14
#define PH_OP_WRITE2     0x15
#define PH_OP_WRITE4     0x16
#define PH_OP_LOG        0x17
#define PH_OP_RETCONT    0x18
#define PH_OP_RETSKIP    0x19
#define PH_OP_RETRET     0x1A
#define PH_OP_HALT       0x1B
#define PH_OP_CALL       0x1C

#define PH_FAULT_NONE            0
#define PH_FAULT_BAD_OPCODE      1
#define PH_FAULT_BAD_OPERAND     2
#define PH_FAULT_READ_FAILED     3
#define PH_FAULT_WRITE_FAILED    4
#define PH_FAULT_CYCLE_LIMIT     5
#define PH_FAULT_BAD_JUMP        6
#define PH_FAULT_WRITE_RO_REG    7

#pragma pack(push, 1)
typedef struct {
    uint8_t  op;
    uint8_t  dst;
    uint8_t  a;
    uint8_t  b;
    uint32_t imm;
} ph_insn;        // 8 bytes
#pragma pack(pop)

// Script-builder macros. Build a C initializer list of ph_insn entries.
#define PH_NOP()                 ((ph_insn){ PH_OP_NOP,    0,     0,     0,     0 })
#define PH_LOADI(dst, imm)       ((ph_insn){ PH_OP_LOADI,  (dst), 0,     0,     (uint32_t)(imm) })
#define PH_MOV(dst, src)         ((ph_insn){ PH_OP_MOV,    (dst), (src), 0,     0 })
#define PH_ADD(dst, a, b)        ((ph_insn){ PH_OP_ADD,    (dst), (a),   (b),   0 })
#define PH_SUB(dst, a, b)        ((ph_insn){ PH_OP_SUB,    (dst), (a),   (b),   0 })
#define PH_MUL(dst, a, b)        ((ph_insn){ PH_OP_MUL,    (dst), (a),   (b),   0 })
#define PH_AND(dst, a, b)        ((ph_insn){ PH_OP_AND,    (dst), (a),   (b),   0 })
#define PH_OR(dst, a, b)         ((ph_insn){ PH_OP_OR,     (dst), (a),   (b),   0 })
#define PH_XOR(dst, a, b)        ((ph_insn){ PH_OP_XOR,    (dst), (a),   (b),   0 })
#define PH_SHL(dst, a, imm)      ((ph_insn){ PH_OP_SHL,    (dst), (a),   0,     (uint32_t)(imm) })
#define PH_SHR(dst, a, imm)      ((ph_insn){ PH_OP_SHR,    (dst), (a),   0,     (uint32_t)(imm) })
#define PH_CMP(a, b)             ((ph_insn){ PH_OP_CMP,    0,     (a),   (b),   0 })
#define PH_JMP(delta)            ((ph_insn){ PH_OP_JMP,    0,     0,     0,     (uint32_t)(delta) })
#define PH_JEQ(delta)            ((ph_insn){ PH_OP_JEQ,    0,     0,     0,     (uint32_t)(delta) })
#define PH_JNE(delta)            ((ph_insn){ PH_OP_JNE,    0,     0,     0,     (uint32_t)(delta) })
#define PH_JLT(delta)            ((ph_insn){ PH_OP_JLT,    0,     0,     0,     (uint32_t)(delta) })
#define PH_JGT(delta)            ((ph_insn){ PH_OP_JGT,    0,     0,     0,     (uint32_t)(delta) })
#define PH_READ1(dst, a, disp)   ((ph_insn){ PH_OP_READ1,  (dst), (a),   0,     (uint32_t)(disp) })
#define PH_READ2(dst, a, disp)   ((ph_insn){ PH_OP_READ2,  (dst), (a),   0,     (uint32_t)(disp) })
#define PH_READ4(dst, a, disp)   ((ph_insn){ PH_OP_READ4,  (dst), (a),   0,     (uint32_t)(disp) })
#define PH_WRITE1(a, b, disp)    ((ph_insn){ PH_OP_WRITE1, 0,     (a),   (b),   (uint32_t)(disp) })
#define PH_WRITE2(a, b, disp)    ((ph_insn){ PH_OP_WRITE2, 0,     (a),   (b),   (uint32_t)(disp) })
#define PH_WRITE4(a, b, disp)    ((ph_insn){ PH_OP_WRITE4, 0,     (a),   (b),   (uint32_t)(disp) })
#define PH_LOG(a, b)             ((ph_insn){ PH_OP_LOG,    0,     (a),   (b),   0 })
#define PH_RETCONT()             ((ph_insn){ PH_OP_RETCONT, 0,    0,     0,     0 })
#define PH_RETSKIP(insn_bytes)   ((ph_insn){ PH_OP_RETSKIP, 0,    0,     0,     (uint32_t)(insn_bytes) })
#define PH_RETRET(stacksize)     ((ph_insn){ PH_OP_RETRET,  0,    0,     0,     (uint32_t)(stacksize) })
#define PH_HALT()                ((ph_insn){ PH_OP_HALT,    0,    0,     0,     0 })

// PH_CALL — call a cdecl function in the guest at the VA held in `fn_reg`.
// `retval_reg` receives EAX on return (0 = discard). `n_args` is 0..4.
// Up to 4 argument operand encodings (each a PH_R*/PH_GR_*) are packed into
// the Imm field, one per byte, little-endian: arg0 = byte 0, arg1 = byte 1, ...
#define PH_CALL(retval_reg, fn_reg, n_args, a0, a1, a2, a3)         \
    ((ph_insn){ PH_OP_CALL, (uint8_t)(retval_reg), (uint8_t)(fn_reg), \
                (uint8_t)(n_args),                                   \
                (uint32_t)((uint32_t)(uint8_t)(a0)                   \
                         | ((uint32_t)(uint8_t)(a1) << 8)            \
                         | ((uint32_t)(uint8_t)(a2) << 16)           \
                         | ((uint32_t)(uint8_t)(a3) << 24)) })

// Zero-arg call convenience.
#define PH_CALL0(retval_reg, fn_reg) \
    PH_CALL((retval_reg), (fn_reg), 0, 0, 0, 0, 0)
#define PH_CALL1(retval_reg, fn_reg, a0) \
    PH_CALL((retval_reg), (fn_reg), 1, (a0), 0, 0, 0)
#define PH_CALL2(retval_reg, fn_reg, a0, a1) \
    PH_CALL((retval_reg), (fn_reg), 2, (a0), (a1), 0, 0)
#define PH_CALL3(retval_reg, fn_reg, a0, a1, a2) \
    PH_CALL((retval_reg), (fn_reg), 3, (a0), (a1), (a2), 0)
#define PH_CALL4(retval_reg, fn_reg, a0, a1, a2, a3) \
    PH_CALL((retval_reg), (fn_reg), 4, (a0), (a1), (a2), (a3))

#pragma pack(push, 1)
typedef struct {
    uint64_t cr3;
    uint64_t va;
    uint64_t a;
    uint64_t b;
} ph_log_entry;   // 32 bytes
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t active;
    uint64_t target_cr3;
    uint64_t target_va;
    uint64_t hits;
    uint32_t insn_count;
    uint32_t last_fault_reason;
    uint32_t last_fault_pc;
} ph_status_entry;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t         num_active;
    uint64_t         dispatch_count;
    uint64_t         fault_count;
    ph_status_entry  entries[PH_MAX_HOOKS];
} ph_status;      // 340 bytes
#pragma pack(pop)

// Install a hook. target_cr3=0 matches any process. Returns slot (0..7) or -1.
static inline uint64_t
ao_ph_register(uint64_t target_cr3, uint64_t target_va,
                    const ph_insn *script, uint32_t insn_count)
{
    return AO_HYPERCALL(AO_CMD_PH_REGISTER,
                             target_cr3, target_va,
                             (uint64_t)(uintptr_t)script,
                             (uint64_t)insn_count);
}

static inline uint64_t
ao_ph_unregister(uint32_t slot)
{
    return AO_HYPERCALL(AO_CMD_PH_UNREGISTER, (uint64_t)slot, 0, 0, 0);
}

static inline uint64_t
ao_ph_clear(void)
{
    return AO_HYPERCALL(AO_CMD_PH_CLEAR, 0, 0, 0, 0);
}

// Write a per-hook config slot. Returns 0 on success, -1 on error.
static inline uint64_t
ao_ph_set_cfg(uint32_t slot, uint32_t cfg_idx, uint32_t value)
{
    return AO_HYPERCALL(AO_CMD_PH_SET_CFG,
                             (uint64_t)slot, (uint64_t)cfg_idx,
                             (uint64_t)value, 0);
}

// Read a per-hook config slot. Returns the UINT32 value on success, or
// (uint64_t)-1 on error (hooks not initialized or slot/cfg out of range).
// NOTE: callers that need to distinguish "value 0xFFFFFFFF" from "error"
// should compare against AO_NOT_PRESENT (= (uint64_t)-1).
static inline uint64_t
ao_ph_get_cfg(uint32_t slot, uint32_t cfg_idx)
{
    return AO_HYPERCALL(AO_CMD_PH_GET_CFG,
                             (uint64_t)slot, (uint64_t)cfg_idx, 0, 0);
}

// Returns bytes written on success (340), -1 on error.
static inline uint64_t
ao_ph_status(ph_status *out)
{
    return AO_HYPERCALL(AO_CMD_PH_STATUS,
                             (uint64_t)(uintptr_t)out, 0, 0, 0);
}

// Returns number of entries drained into buf.
static inline uint64_t
ao_ph_log_read(ph_log_entry *buf, uint32_t max_count)
{
    return AO_HYPERCALL(AO_CMD_PH_LOG_READ,
                             (uint64_t)(uintptr_t)buf,
                             (uint64_t)max_count, 0, 0);
}

// ---- diagnostics ---------------------------------------------------------

#pragma pack(push, 1)
typedef struct ph_diag_walk {
    uint64_t gpa4k;        // 4KB-aligned GPA used for the walk (input)
    uint64_t pml4e;        // raw 64-bit PML4 entry
    uint64_t pdpte;        // raw PDPT entry
    uint64_t pde;          // raw PD entry (or 2MB leaf)
    uint64_t pte;          // raw PT entry (or 0 if PDE was a 2MB leaf)
    uint32_t stop_level;   // 4 = reached PT, 3 = 2MB leaf, 2 = 1GB leaf, 1 = not present
    uint32_t pml4_idx;
    uint32_t pdpt_idx;
    uint32_t pd_idx;
    uint32_t pt_idx;
    uint32_t pad;
} ph_diag_walk;            // 64 bytes

typedef struct ph_diag_ncr3 {
    uint64_t shadow_ncr3_pa;
    uint64_t read_ncr3_pa;
    uint64_t exec_ncr3_pa;
    uint64_t vmcb_ncr3;    // this CPU's current VMCB.ControlArea.NCr3
    uint32_t npt_mode;     // this CPU's States.Guest.NptMode
    uint32_t cpu_index;
    uint32_t ncr3_update_pending;  // this CPU's pending-flip flag
    uint32_t pad;
    uint64_t ncr3_pending_value;
} ph_diag_ncr3;            // 56 bytes

typedef struct ph_diag_hookmeta_entry {
    uint64_t gpa4k;
    uint64_t original_pfn;
    uint64_t shadow_pfn;
    uint32_t active;
    uint32_t pad;
} ph_diag_hookmeta_entry;  // 32 bytes

#define PH_DIAG_HOOKMETA_MAX 32
typedef struct ph_diag_hookmeta {
    uint32_t hook_count;
    uint32_t shadow_used;
    uint64_t pad;
    ph_diag_hookmeta_entry entries[PH_DIAG_HOOKMETA_MAX];
} ph_diag_hookmeta;        // 16 + 32*32 = 1040 bytes

// Fine-grained NPF/dispatch counters. Inspect after install+run to see
// WHERE the dispatch path is failing when hits=0:
//
//   npf_inst_fetch > 0 but gpa_match == 0 → fetch NPFs are firing but NOT on
//      our hooked page. The install's gpa4K disagrees with the GPA the CPU
//      actually faults on.
//   gpa_match > 0 but rip_match == 0 → NPFs ARE landing on our hooked page,
//      but the faulting RIP is not the registered hook VA. Either a prologue
//      fetch (most common — install the hook on a later byte) OR the entry's
//      TargetVa is wrong.
//   rip_match > 0 but cr3_match == 0 → right instruction, wrong process.
//      Hook was installed with a CR3 that doesn't match the executing one.
//   cr3_match / dispatch > 0 → hook IS firing. If PROCESS_HOOK table's
//      HitCount is still 0, the problem is in RunProcessHookScript / RETCONT.
//
typedef struct ph_diag_counters {
    uint32_t npf_inst_fetch;
    uint32_t gpa_match;
    uint32_t rip_match;
    uint32_t cr3_match;
    uint32_t dispatch;
    uint32_t stray;
    uint32_t bp_count;       // total #BP intercepts handled
    uint32_t bp_owned;       // ...claimed by an active PH entry
    uint32_t bp_reinject;    // ...re-injected to the guest (native int3)
    uint32_t pad;
    uint64_t last_guest_rip;
    uint64_t last_guest_cr3;
    uint64_t last_gpa4k;
} ph_diag_counters;        // 60 bytes
#pragma pack(pop)

// Walk NPT for (target_cr3, target_va). If target_cr3==0, caller-resolved.
// Which NPT tree we walk is reported via ph_diag_ncr3.
static inline uint64_t
ao_ph_diag_walk(uint64_t target_cr3, uint64_t target_va, ph_diag_walk *out)
{
    return AO_HYPERCALL(AO_CMD_PH_DIAG_WALK,
                             target_cr3, target_va,
                             (uint64_t)(uintptr_t)out, 0);
}

static inline uint64_t
ao_ph_diag_ncr3(ph_diag_ncr3 *out)
{
    return AO_HYPERCALL(AO_CMD_PH_DIAG_NCR3,
                             (uint64_t)(uintptr_t)out, 0, 0, 0);
}

static inline uint64_t
ao_ph_diag_hookmeta(ph_diag_hookmeta *out)
{
    return AO_HYPERCALL(AO_CMD_PH_DIAG_HOOKMETA,
                             (uint64_t)(uintptr_t)out, 0, 0, 0);
}

static inline uint64_t
ao_ph_diag_counters(ph_diag_counters *out)
{
    return AO_HYPERCALL(AO_CMD_PH_DIAG_COUNTERS,
                             (uint64_t)(uintptr_t)out, 0, 0, 0);
}
