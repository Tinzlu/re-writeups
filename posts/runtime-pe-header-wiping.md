# When a Binary Erases Its Own PE Header

*A short field note on runtime header wiping: how to confirm it happened, what it breaks, and why it is weaker protection than it looks.*

---

## TL;DR

Some Windows samples zero out their own PE header in memory after startup. It defeats naive memory dumping — a dump taken after the wipe has no `MZ` signature and most dumpers refuse to rebuild it.

It is easy to **observe** and easy to **defeat**. The header still exists on disk, and the loader has already mapped everything the process needs before the wipe happens.

---

## 1. What the technique does

On process start, the PE header occupies the first page (or pages) of the mapped image at the module base. Some samples call `VirtualProtect(PAGE_READWRITE)` on that region and write zeros over it — commonly the first 4 KB.

Effects:

| Artifact | After wipe |
|---|---|
| `MZ` signature at module base | gone |
| `e_lfanew` → `PE\0\0` | gone |
| Section table | gone |
| Import directory | gone (the imports were already resolved) |
| Export directory | gone (exports already bound) |

The process keeps running normally. Anything that reads the header *after* the wipe — a dumper, a scanner, an integrity check — sees a region of zeros.

## 2. How to confirm it (without guessing)

The check is four numbers and one byte comparison:

1. **Enumerate modules** and get the module base address.
2. **Read the first bytes** at that address, in-process (or via a debugger with read access).
3. **Compare** against the header you expect: `4D 5A` (`MZ`) at offset 0, and `50 45 00 00` (`PE\0\0`) at `e_lfanew`.
4. **Record how much was zeroed**, not just "it was zeroed".

In one observed sample the result was unambiguous:

```
process   : CrackMe.exe (32-bit)
pid       : 7012
base      : 0x7ff743560000
header    : 4096 / 4096 bytes are 0x00
MZ?       : False
```

A full 4 KB page of zeros at a valid module base is not a coincidence, and it is not a corrupted image — the module still exported a working entry point.

## 3. Why it is weaker than it looks

Three reasons, in order of importance:

**The disk image is untouched.** The wipe happens in memory. The file on disk still has a perfectly valid header, section table, and directory entries. Anything that starts from the file — static analysis, signature scanning, re-running under a debugger with an entry breakpoint — is unaffected.

**The loader already did the work.** By the time the wipe runs, the imports are bound, the sections are mapped at their RVAs, and the entry point has executed. The header was only ever needed for mapping and rebasing. Removing it afterwards costs the attacker one dump-time reconstruction step at most.

**The wipe itself is a detectable event.** Zeroing 4 KB at a module base is a `VirtualProtect` + `memset` pattern. On a typical workload, that is a bright signal.

## 4. Reconstruction options (defensive reading)

If you need to analyze a dump taken after the wipe, the reliable path is not to repair the dump — it is to **avoid taking the dump late**:

- Break at the entry point (or before the wipe) and dump from memory at that moment.
- Dump from the mapped image while suspended, then reconstruct the header from the on-disk file.
- Map the on-disk file at the recorded base and use it as the header source for the memory dump.

All three only need the **base address** and the **original file** — both of which an analyst legitimately has when auditing their own product.

## 5. What this means for vendors

Header wiping is a speed bump aimed at one class of tool. It does not protect:

- the code (unchanged, readable, still executing),
- the strings (still in memory),
- the license logic (still deciding),
- the on-disk binary (still intact).

If your threat model is "casual user with a dumper", a header wipe plus a packer raises the effort slightly. If your threat model is a determined analyst, the wipe is noise — and the **detection** of the wipe is itself a signal telling the analyst where to look.

Better investments, in this author's view:

1. **Make failure non-local.** A check whose failure path is a single branch is a one-patch target regardless of header state.
2. **Bind to something an attacker cannot copy for free** — server-side validation, hardware identity, or per-unit provisioning — rather than to binary layout.
3. **Measure instead of assuming.** If you ship an anti-tamper feature, record how long it took an external evaluator to get past it. A header wipe typically costs minutes.

## 6. Limits

- One sample, one platform (Windows 10 x64, 32-bit target). Other implementations may wipe more than the first page, or do it in stages.
- The observed wipe is at 4,096 bytes; whether that is a page-size decision or a deliberate constant is not established.
- No claim is made about the sample's license enforcement beyond the fact that the module kept running with a zeroed header.

---

*Method: in-process module enumeration + direct memory read of the module base, compared byte-for-byte against the file's header. Numbers above are from a single recorded run.*
