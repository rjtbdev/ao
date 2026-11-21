# Case study: osu!stable

**Target.** osu!stable, as of 2026-era builds.
**Downstream code.** `new-era/` — all working tools that use these sigs
live there, not in ao.

## What the target is

- Windows x86 (32-bit), WoW64 under 64-bit Windows.
- .NET 4.x + OpenTK + a native self-protection layer (`oa.dll`).
- Managed IL is partially virtualized with Eazfuscator: sensitive methods'
  IL bodies are replaced by stubs that invoke an Eaz runtime VM. The real
  method logic exists only as Eaz opcodes in a blob; the stubs are what
  the CLR JITs.
- The native layer has a second VM (custom, implemented in `oa.dll`'s
  `.text`) that virtualizes integrity-check routines. The running
  integrity check reads call stacks and verifies return addresses belong
  to legit modules (StackSampling). It also uses raw syscalls (by
  number, bypassing imports) to query thread/process state.
- Does NOT scan for hypervisors. Does NOT scan for `0xCC` or page hashes
  in a way that blocks Option 7 (our hook doesn't change the page bytes).
- DOES catch injected DLLs, remote threads, DR-register-based breakpoints,
  and anything that modifies osu!'s memory visibly.

## What does NOT work (approaches to avoid)

- Anything that modifies bytes in osu's address space is detectable by
  the StackSampling checker (return addresses must live in legit
  modules). Don't `VirtualAllocEx` a scratch page + redirect EIP into it.
- Anything that opens a HANDLE to osu! with write access leaves an
  artifact. Opening with `PROCESS_VM_READ` only is fine.
- Hardware breakpoints in osu!'s thread contexts — detectable with
  `NtGetContextThread`.
- In-process DLL injection — detected by the integrity VM.

## Sigs

All sigs are AOB (array-of-bytes) patterns with `?` wildcards, as in
the AQN format. Each entry gives the AOB, the resolution recipe
(how to turn a match location into the actual field VA or function
address at this session's ASLR layout), what the field is used for,
and a verified-against note.

**ASLR note:** osu! ASLRs on every launch. None of the addresses below
are stable VAs — they must be re-resolved at attach time by scanning
the running process and reading the displacement out of the matched
instruction.

### Field sigs (data)

Resolution convention: scan for AOB → `match_va` + `target_offset` =
pointer to the 4-byte displacement that holds the field's session VA.
Read 4 bytes there to get the field address.

#### time — current beatmap time (int32 ms)

- AOB: `74 12 a1 ? ? ? ? 2b 05 ? ? ? ? a3`
- AQN resolve: `t += 0x23; osu_data.time = *(u32*)(t + 1);`
- target_offset: **0x24**
- Layout: instruction at match+0x23 is `A3 xx xx xx xx` (`mov [imm32], eax`),
  so the 4-byte imm at insn+1 is our field VA.
- Verified against: hemlock-era osu!stable (2026 builds). Last verified
  by this project: NEVER — needs live re-verification before use.

#### is_paused + play_mode — one byte paused flag, derived play_mode

- AOB: `02 75 0e 80 3d ? ? ? ? 00 75 05 e9`
- AQN resolve: `osu_data.is_paused = *(u8**)(t + 5);`
- target_offset: **0x5**
- Layout: instruction `80 3D xx xx xx xx 00` (`cmp byte ptr [imm32], 0`),
  4-byte imm at match+5 is the `is_paused` field VA.
- Derived: `play_mode_va = is_paused_va - 0x21` (adjacent static field,
  no separate sig needed).
- Verified against: see time note.

#### mode + running_gamemode — pointer to active osu_GameMode

- AOB: `89 45 f0 a1 ? ? ? ? a3 ? ? ? ? a1`
- AQN resolve: `t += 0x12; osu_data.mode = *(size_t*)(t + 1); osu_data.running_gamemode = *(size_t*)(t + 7);`
- target_offsets: **0x13** (mode), **0x19** (running_gamemode)
- Layout: at match+0x12 we have two `a1 xx xx xx xx` / `a3 xx xx xx xx`
  patterns referencing the two fields.
- running_gamemode is a POINTER to a pointer; deref once to get the
  active `osu_GameMode_Player`, which has `hitobject_manager` at a
  field offset (see osu_def struct layout below).
- Verified against: see time note.

### Function sigs (code)

Resolution convention: AOB matches a short prologue near the call.
Resolve via displacement-math specific to each.

#### mouse_apply_handler — cursor position capture point

- AOB: `d9 c1 d9 1c 24 d9 5d ? d9 5d ? ff 15`
- AQN resolve: `t = find(...) + 0xd; OSU_set_MousePosition = **(_osufunc_vec2**)t; t += 0xf; while (*(u16*)t != 0x15FF) ++t; OSU_SetCursorHandlerPositions = **(_osufunc_vec2**)(t + 2);`
- AQN hooks the enclosing function and captures `handler->position` as
  `osu_data.raw_mouse_pos`. No static field holds live cursor; needs
  a PH hook to capture into CFG slots at runtime.
- Verified against: see time note.

#### keyboard_get_state — keyboard-state read site

- AOB: `e8 ? ? ? ? 33 f6 8b 5f 04 3b f3 73 ? f6 44 37 08 80`
- AQN resolve: `t = find(...) + 1; OSU_GetKeyboardState = (_osufunc_GetKeyboardState)RJMP_REBASE(t); *(int*)t = int(__GetKeyboardState) - int(t + 4);`
- AQN DLL-injects and trampolines the call-site. From ao we instead use
  a PH hook that `PH_OP_CALL`s the real function, then `PH_WRITE1`
  stamps the K1/K2 binding bytes in the returned buffer. See the
  "Keyboard injection via ao" section below for the design.
- Verified against: see time note.

#### keybinding_aob — K1/K2 byte index lookup

- AOB: `ff 15 ? ? ? ? 89 ? ? 8d ? ? 50 8b 0d ? ? ? ? 8b 55 ? ? ? ff`
- AQN resolve: `t = find(...); osu_data.keybinding_ptr = *(u32*)(t + 0xF);`
- Resolves a pointer-to-struct that contains the K1/K2 virtual-key
  codes (chars `'Z'` and `'X'` by default). Deref chain from AQN's
  `update_keybinds()`:
  - `t = *(u32*)keybinding_ptr; t = *(u32*)(t + 8);`
  - `binding.K1 = *(int*)(t + 0x14); binding.K2 = *(int*)(t + 0x24);`
- Verified against: see time note.

#### ar_write — approach-rate preempt-interval write site

- AOB:
  ```
  DD050000000083EC08DD1C24DD050000000083EC08DD1C24DD050000000083EC08DD1C24
  8BCE8B018B4000FF5000DD5DE0F20F1045E0F20F2CC089461C
  ```
  (long sig, 61 bytes; the final `89 46 1C` is the write instruction
  `mov [esi+0x1C], eax`.)
- Mask includes AR-compute wildcard displacements.
- target_offset: **0x3A** from match to the `mov [esi+0x1C], eax` opcode.
- Recipe (CFG-driven): `MOV EAX, CFG1` if `CFG0 != 0`, then `RETCONT`
  (the original 3-byte `mov` runs with the new EAX; preempt gets
  written to `[esi+0x1C]`).
- CFG1 is an integer preempt in ms; user-mode computes it from the UI's
  float AR value.
- Working hook example: `new-era/tools/osu-menu/`.

### Struct layout notes

From AQN's `osu_def.h` (snapshot, offsets subject to drift across osu!
versions — verify at use):

- `osu_GameMode_Player` (inherits `osu_GameMode`) has
  `osu_Hitobject_Manager* hitobject_manager` at an offset. The chain is:
  1. Read `[running_gamemode_va]` → gives active `osu_GameMode_Player*`.
  2. Read `[that + HOM_OFFSET]` → gives `osu_Hitobject_Manager*`.
  3. From the manager you can reach `get_top_note()`, `pre_empt`,
     `hit_object_radius`, etc.
- `HOM_OFFSET` is NOT currently resolved by ao's tools; downstream
  code paths (see `new-era/relax/live/hemlock_reader.py` stubs) note
  this as TBD.

## Hook recipes using these sigs

### AR override (working, in production)

Tool: `new-era/tools/osu-menu/`. Install flow:

1. `ao_get_process_cr3("osu!.exe")`
2. `ao_find_module_base("osu!.exe", "osu!.exe")`
3. sigscan for `ar_write` AOB in the module
4. `install_va = match_va + 0x3A`
5. Register script (`force_eax_cont 450` or CFG-driven variant):
   ```c
   PH_CMP(PH_CFG0 + 0, PH_R0_literal_0),
   PH_JEQ(+2),
   PH_MOV(PH_GR_EAX, PH_CFG0 + 1),
   PH_RETCONT(),
   PH_HALT(),
   ```
6. `ao_ph_set_cfg(slot, 0, 1)` to enable, `ao_ph_set_cfg(slot, 1, preempt_ms)`
   to set the value.

### In-game GL overlay (working)

Tool: `new-era/tools/osu-overlay/`.

- Target: `gdi32!SwapBuffers` (the 6-byte `jmp dword ptr [...]` forwarder
  into `gdi32full!SwapBuffers`). Resolve via `EnumProcessModulesEx(LIST_MODULES_32BIT)`
  + PE-parse of `C:\Windows\SysWOW64\gdi32.dll` for the export's RVA.
- **Shared-DLL hazard:** CR3 filter MUST be set to osu!'s CR3 because
  gdi32 is a shared system DLL — the physical page backing SwapBuffers
  is in every process. Without the filter the hook fires for every
  process in the OS.
- Recipe: chain native `glMatrixMode`, `glPushMatrix`, `glLoadIdentity`,
  `glDisable(GL_DEPTH_TEST)`, `glEnable(GL_BLEND)`, `glBlendFunc(...)`,
  `glColor4f(...)`, `glBegin(GL_QUADS)`, 4×`glVertex2f`, `glEnd`,
  `glPopMatrix`, `glPopMatrix`, then `PH_RETCONT()`. Resolve all VAs
  from `C:\Windows\SysWOW64\opengl32.dll` + osu!'s 32-bit module base.
- Script fires AT the `jmp` (first byte of SwapBuffers). After the
  CALL chain, `RETCONT` arms the single-step flip, the shadow page
  runs the real `jmp` (byte-identical), gdi32full's SwapBuffers runs,
  screen presents, our quad is in the frame.
- Projection caveat: osu!'s GL projection is some non-default ortho we
  don't fully reset. Drawing in NDC `[-1, +1]` ends up somewhere other
  than full-screen. For HUD/menu purposes this is fine; for ESP (coords
  tied to game space) we'd want to probe osu!'s projection or hook
  further up the render pipeline.

### Keyboard injection via ao (designed, not yet implemented)

Target: `keyboard_get_state` sig (see above).

Design: PH script on the call site. Steps:
1. `PH_OP_CALL` the real `OSU_GetKeyboardState` with the guest's own
   `ECX` (the `state*` buffer pointer).
2. On return, check `CFG0` / `CFG1`:
   - If `CFG0 != 0`, stamp `128` or `0` into `[state + binding.K1]`
     via `PH_WRITE1`.
   - Likewise CFG1 → `[state + binding.K2]`.
3. `PH_RETSKIP 5` to skip the original call (we already made it).

CFG layout:
- CFG0 = K1 action (0 = pass-through, 1 = force press, 2 = force release)
- CFG1 = K2 action (same)
- CFG2 = `binding.K1` byte index (resolved once at install time via
  `keybinding_aob` + the deref chain above)
- CFG3 = `binding.K2` byte index

User-mode writes CFG0 / CFG1 each frame from the inference loop
(`new-era/relax/live/`). Needs two PH slots total if cursor is also
captured via its own hook; still well inside the 8-slot limit.

### Score submission (not implemented, design notes only)

- osu!stable's score submit flow goes through an Eazfuscator-virtualized
  managed method. The native stub is what the CLR JITs, so sig-scanning
  for the original IL's compiled form won't work on the live binary.
- Hookable options:
  1. Hook the stub entry (get called args before the Eaz VM starts).
  2. Hook the Eaz VM dispatcher (noisy, fires for every virtualized
     method).
  3. Hook the HTTP send at the WinINet / WinHTTP / `HttpClient.Send`
     level — not virtualized, easy to find.
- Blocking submission with `PH_RETSKIP` or `PH_HALT` on the stub
  prevents the method from running; the submit never happens.
- Modifying submission content requires finding where the score struct
  is built in managed memory and writing to those offsets before the
  stub is invoked. Also note: ppy server does its own validation so
  this is of limited value.

## Lessons / rejected approaches

- **`0xCC` byte-trap in a shadow page:** detectable by osu!'s integrity
  routine via a simple polling scanner. Removed early. Option 7 (bytes
  unchanged) replaces it.
- **Hardware breakpoints:** detectable via `NtGetContextThread`.
- **In-process DLL injection (AQN-style):** detected by the StackSampling
  integrity VM as a non-legit module in the call stack. ao's out-of-
  process hooking avoids this entirely.
- **Modifying code in-place in osu's memory:** same detection vector.
  Never do it. Option 7's shadow-page model is specifically what makes
  the modification invisible to in-process scanners.

## References

- AQN source for sig patterns (snapshot in the repo's scratchpad at
  time of writing): `AQN_nologin-master/init.h`, `osu_def.h`,
  `modules/aim_assist.h`, `modules/autobot.h`.
- Project memory IDs (internal to this working session):
  `project_aqn_osu_sigs_and_offsets`, `feedback_hv_hook_shared_dll_hazard`,
  `project_detection_mechanism_found`, `project_hemlock_option7_hook_working`,
  `project_hv_gl_overlay_day2_working`.
