# Reverse engineering notes

Field notes on software protection: what holds, what does not, and what it costs to find out.

I audit licensing and anti-tamper designs for software vendors — usually after someone has already shipped a cracked build, sometimes before.

## What I look at

- **License enforcement**: offline activation, tamper-evident license files, dongle and container models (CodeMeter / AxProtector), revocation and replacement flows.
- **Binary protection**: what a packer or protector actually changes versus what it only appears to change.
- **Frozen and compiled Python**: PyInstaller, Nuitka, py2exe — what survives compilation and what a competitor can read.
- **Tamper evidence**: runtime integrity checks, header and section manipulation, anti-dump techniques.

## Write-ups

1. **[Anatomy of a Wibu AxProtector-Protected .NET Assembly](posts/axprotector-dotnet-audit.md)** — 7,303 methods, 4,647 encrypted (63.6%). Where the encryption ratio leaks the vendor's threat model, and why the license decision is not where you think it is.
2. **[When a Binary Erases Its Own PE Header](posts/runtime-pe-header-wiping.md)** — how to confirm runtime header wiping with four numbers, and why it is a speed bump rather than a wall.
3. **[Compiled Python Is Not Obfuscated Python](posts/compiled-python-packaging.md)** — a first-30-minutes checklist for PyInstaller and Nuitka builds, and what actually raises the cost.

## How I work

- Written reports, not calls — everything documented, with reproducible observations.
- Findings labeled **confirmed** (reproduced) versus **inferred** (structural evidence, not proven).
- No exploitation tooling delivered; the deliverable is an assessment and a fix list.
- Authorized-target work only, with a written scope.

## Contact

Available for audits, second opinions on an existing protection design, and pre-release reviews.

- GitHub: [@Tinzlu](https://github.com/Tinzlu)
- Email: `tin@tinzlu.com`

*Based in Shanghai (UTC+8). Written English; async by default.*
