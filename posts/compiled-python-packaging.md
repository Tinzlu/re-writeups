# Compiled Python Is Not Obfuscated Python

*A first-30-minutes checklist for PyInstaller and Nuitka binaries — what each one actually hides, and what it does not.*

---

## TL;DR

Compiling Python to a frozen executable or to native code changes **packaging**, not semantics. In practice:

- **PyInstaller** appends a CArchive to a native bootloader. The application's `.pyc` files sit inside it, often recoverable in minutes.
- **Nuitka** compiles Python to C, then to machine code. There is no `.pyc` to recover — but the program's structure (module names, function names, strings, import graph) usually survives.

The failure mode I see most often is a team assuming "we used Nuitka, so the source is safe" while shipping a build that still contains readable strings, module names, and a full Python runtime.

---

## 1. PyInstaller: the archive is the program

PyInstaller builds a native bootloader, then appends a **CArchive** after it in the same file. If you know where the cookie is, you know where everything is.

### Detection

The CArchive ends with a cookie. For PyInstaller 2.1 and later the magic is:

```
4D 45 49 0C 0B 0A 0B 0E     ("MEI" + 4 version bytes)
```

Older builds use `MEI\x01\x02\x03\x04\x05\x06`. The cookie structure is:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic |
| 8 | 4 | package length (big-endian) |
| 12 | 4 | TOC offset (big-endian) |
| 16 | 4 | TOC length (big-endian) |
| 20 | 4 | Python version (e.g. 311) |

The most reliable place to look is the **PE overlay** (`get_overlay_data_start_offset()` in `pefile`), scanning backwards from EOF. Scanning the whole file works too, but the overlay is where the bootloader puts it.

### Extraction

Once the cookie is parsed, the TOC gives a list of `(name, offset, length)` entries — the modules, data files, and shared libraries. Modules are stored **without a `pyc` header**, so each entry needs a header rebuilt from the archive's own Python version before it will load in a decompiler.

The practical consequence: an unmodified PyInstaller build is not a barrier. Published extractors handle the common case; the only added work is repairing headers and handling renamed entries.

### What actually raises the cost

| Measure | Effect |
|---|---|
| `--key` (bytecode encryption) | Modules cannot be decrypted without the key. This is real protection, not obfuscation — keep the key off the client side. |
| Appending junk / shifting the cookie | Breaks naive extractors, not analysis. Minutes. |
| Custom bootloader changes | Raises effort until the analyst recognizes the pattern. Hours at most. |
| Moving logic server-side | Actually removes the asset. |

The last row is the only structural fix.

## 2. Nuitka: no bytecode, but plenty of structure

Nuitka translates Python to C, then compiles it. There is no `.pyc` archive to extract, and decompiling C back to idiomatic Python is not a solved problem.

That does **not** mean the program is opaque. What typically survives in a Nuitka build:

- **Module and function names**, frequently as strings in the binary and in symbol tables (unless stripped).
- **String literals**, in the same encodings as the original source.
- **The import graph**, visible through the compiled modules and their initialisation calls.
- **The Python runtime**, which is linked into the distribution (or shipped alongside as DLLs).
- **Runtime markers**: Nuitka sets a `__compiled__` attribute on compiled modules and functions specifically so program code can test whether it is running compiled. It deliberately does *not* set `sys.frozen` — so a binary looking for `sys.frozen` will mis-identify a Nuitka build.

For an auditor, the first question is not "what is the source" but "what is the structure": entry point, module init chain, and the strings that name the sensitive operations.

### Distribution layout matters

A Nuitka standalone build ships the compiled modules plus dependencies. If the build uses `--onefile`, the payload is repacked, and locating the real PE inside the resource section is the first step — the same class of work as any installer-style unpacking. If it ships as a folder, the analysis starts immediately.

### What raises the cost in Nuitka

| Measure | Effect |
|---|---|
| Strip symbols, disable name preservation | Removes the cheapest structural map |
| Encrypt or obfuscate string constants before compilation | Survives into the binary; requires the analyst to recover the deobfuscation routine |
| Move secrets out of the binary | Same conclusion as PyInstaller |

## 3. The checklist I actually run first

For any frozen Python binary, in this order:

1. **Identify the packer.** PyInstaller cookie near EOF or in overlay; Nuitka markers (`__compiled__`, `.pyd`/`.so` module set, linked CPython); py2exe resource; zipapp `PYZ\0`.
2. **Get the module list** — from the TOC (PyInstaller) or from the shipped module files (Nuitka).
3. **Search the readable strings for the sensitive nouns**: endpoint hostnames, license keywords, crypto algorithm names, error messages with variable names.
4. **Locate the entry module** and walk its initialisation order.
5. **Only then** decide whether source-level recovery is worth the effort.

Steps 1–3 take minutes and, in my experience, answer the question most clients actually have ("what can a competitor learn about our product?") without any decompilation at all.

## 4. What this means for vendors shipping Python

- **Compilation is packaging.** It stops accidental source access and naive extraction. It does not stop a competent analyst, and it does not protect secrets.
- **Never ship a key with the encrypted bytecode.** `--key` without server-side key delivery is theater.
- **Treat strings as data leaves.** If a hostname or a license keyword is in the binary, it is public.
- **Design the check to fail well.** The interesting question is not whether the check can be found, but what happens downstream when it fails — a single `jne` is a one-byte patch.

## 5. Limits

- The PyInstaller cookie structure above is version-dependent; the format described applies to 2.1+ with the 8-byte magic.
- Nuitka's emission details vary by version and by `--onefile`/`--standalone`; the markers listed are the ones that survived in builds I examined.
- This post intentionally contains no extraction tooling and no worked bypass. It is a description of what the packaging does, for teams deciding whether their current setup meets their threat model.

---

*Method: static inspection of PE/ELF layout and embedded archive structures; behavior confirmed by looking at strings, symbol presence, and module layout. No proprietary build is named or included.*
