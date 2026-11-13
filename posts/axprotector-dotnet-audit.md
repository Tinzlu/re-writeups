# Anatomy of a Wibu AxProtector-Protected .NET Assembly

*A structural audit of a commercial medical-device UI library (vendor and product anonymized): what the protector encrypts, what it leaves readable, and where the design leaks information.*

---

## TL;DR

A 7,303-method .NET assembly protected with Wibu AxProtector .NET had **4,647 method bodies encrypted (63.6%)** while the protector's own runtime remained 100% plaintext. Two plaintext artifacts — the runtime's static index table and the `License` type — are enough to reconstruct the overall protection model without decrypting a single protected method.

For vendors: the encryption ratio is not the weak point. **The uniformity of the ratio is.** When every namespace cluster sits within a few points of the same number, an attacker learns which parts you consider valuable before touching the code.

---

## 1. What was measured

| Property | Value |
|---|---|
| Assemblies | 1 main UI control library |
| Total types | 1,131 |
| Total methods (with bodies) | 7,303 |
| Methods encrypted | 4,647 (63.6%) |
| Types under `com.wibu.xpm.AxpNet` | 140 |
| Protector methods encrypted | 0 |

Method bodies were classified by parsing the CLR metadata tables directly (ECMA-335): `MethodDef.RVA` → file offset, then inspecting the body header. AxProtector replaces the body of a protected method with a small native stub rather than storing a valid tiny/fat header, so the protected/unprotected split is determinable statically, without executing anything.

Protected method bodies in this build share a recognizable payload prologue before the stub hands off to the native runtime — matching AxProtector's model where each method is decrypted on first access, gated by a license check.

## 2. The encryption is layered, and the layers tell a story

Encryption rate by namespace (only namespaces with ≥100 methods shown):

| Namespace | Methods | Encrypted | Rate |
|---|---|---|---|
| `...Controls.ImageViews` | 917 | 708 | **77%** |
| `...Controls.RESP` | 391 | 298 | 76% |
| `...Controls.ECG` | 593 | 437 | 74% |
| `...Controls.VolumeControls` | 167 | 123 | 74% |
| `...Controls.SimulatedECG` | 116 | 86 | 74% |
| `...Controls.Images` | 694 | 477 | 69% |
| `App.Image.SurviewLines` | 216 | 152 | 70% |
| Root namespace `App.UI.Controls` | 2,392 | 1,531 | 64% |
| `...Controls.ProtocolEditor` | 141 | 75 | **53%** |
| Unnamespaced / internal | 679 | 234 | 34% |

Two observations:

1. **The most-protected code is waveform and vital-sign rendering** (ECG, RESP, ImageViews). The least-protected business module is the protocol editor. The vendor's own threat model is therefore visible in the ratio: they believe the signal-processing and display pipeline is the asset, not the device protocol glue.
2. **The protector runtime itself is 0% encrypted**, which is unavoidable — it must execute — but it also means the entire dispatch layer is available for static reading.

## 3. Two plaintext entry points

### 3.1 `pp::.cctor` — a 18,761-instruction static initializer

The runtime type `pp` contains 92 methods; 88 have bodies. Its static constructor is by far the largest method in the assembly:

| Instruction | Count | Note |
|---|---|---|
| `ldc.i4` | 9,304 | constant loads |
| `ldsfld` | 4,650 | field reads |
| `stelem.i4` | **4,647** | **exactly the encrypted-method count** |
| `stsfld` | 67 | |
| `newarr` | 14 | chunked allocation |
| `call` | 8 | |

The shape is a chunked table fill: allocate an array (first chunk length 2,528), emit constants one by one, store the chunk into a static field, repeat. Sentinel constants such as `0x12345678`, `int.MaxValue`, `77528` and `2000` are interleaved with what are presumably method indices.

The 1:1 match between `stelem.i4` count and encrypted-method count is strong evidence that this table is the runtime's **method index / state table** — the structure the native side walks to locate and rewrite protected bodies. (Element semantics not proven; see §6.)

### 3.2 `License` — 25 methods, all plaintext, Wibu semantics intact

`com.wibu.xpm.AxpNet.License` is fully readable, with non-obfuscated field names:

| Field | Type | Meaning |
|---|---|---|
| `FirmCode` | uint32 | vendor identifier |
| `ProductCode` | uint32 | product identifier |
| `FeatureCode` | uint32 | feature toggles |
| 20+ single-letter fields | u32/i4/value types | internal state, counters, flags |

Methods such as `get_UsedCopyProtectionSystem` and `ToString` remain named; the rest are `a`/`b`/`c`-style.

**The interesting part is who calls it.** Inbound reference counts to `License` members:

| Caller | Calls |
|---|---|
| `com.wibu.xpm.AxpNet.a7::a` | 16 |
| `License` itself | 9 |
| `pp::a` / `pp::J` | 3 / 3 |

The license decision does not live in `License`. It converges on `a7`. That single fact shortens any legitimate audit considerably: to understand *when* a check fails, start from `a7`'s 16 inbound edges, not from the data type.

## 4. What this means defensively

If you ship AxProtector .NET, the audit above is what an evaluator sees **before** defeating anything:

- **Ratios leak intent.** A cluster at 77% and another at 53% tells an attacker where to spend effort. Consider encrypting uniformly, or deliberately encrypting decoys at the same rate as the real asset.
- **The runtime is the map.** Any protector that keeps a plaintext index table (it must, to dispatch) gives a complete inventory of protected methods. This is not a flaw to be fixed; it is a reason not to rely on method-count secrecy.
- **Check convergence matters more than check density.** Sixteen call sites funneling into one decision function is easier to reason about than sixteen independent checks — for the attacker *and* for you. If you need stronger guarantees, spread the decision (e.g., data-dependent paths that fail differently), and make failure non-local.

## 5. What this is *not*

This analysis stops at structure: type layout, method counts, encryption ratios, call-edge topology. It does not decrypt method bodies, does not touch keys, and does not provide a bypass path. The purpose is to describe how the protection is shaped, which is the same information a vendor needs to evaluate it.

## 6. Limits

- Element semantics of the `pp::.cctor` table are inferred from count correspondence, not proven by execution.
- `pp::N` (1,012 instructions, native library loader) was identified but not traced.
- `a7`'s decision logic was not analyzed — deliberately out of scope.
- One assembly, one version. Cross-version stability of the ratios is unknown.

---

*Method: CLR metadata parsed with a custom ECMA-335 reader (MethodDef RVA → file offset → body header). No execution of the protected assembly was required for any number in this post.*
