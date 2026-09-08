# Is `Block_Cipher_df` with Kalyna the best available? — cost analysis and remaining code items

**Subject:** `KalynaBCDF_2805`, cross-platform variant (2026-09-08), mode `KALYNA_512_512`
**Measured on:** the project's own `kalyna.c` / `tables.c`, g++ 11.4 `-O2`, single core
**Companion documents:** `block_cipher_df_verification.md` (correctness), `NIST_SP800-90B_conformance_review.md` (conformance)

---

> ### Correction (2026-09-08): every timing below assumes an **optimized** build
>
> All figures in this document were measured with `g++ -O2`. The project's Visual Studio build is
> `Debug|x64` (the only executable present is `x64/Debug/KalynaBCDF.exe`), and unoptimized builds are
> **~11× slower** for this code — not the usual 2–3× — because `MultiplyGF` is called 9 216 times per
> block encipherment and none of those calls inline at `/Od`.
>
> | build | per 64-byte output | 64 MB target |
> |---|---|---|
> | observed Debug run | 8 320 µs | **139 min** |
> | `-O0` | 7 652 µs | 127.5 min |
> | `-O1` / `-O2` | ~693 µs | 11.6 min |
>
> Note also that `Release|x64` in `KalynaBCDF.vcxproj` sets `FunctionLevelLinking`,
> `IntrinsicFunctions` and `WholeProgramOptimization` but **never sets `<Optimization>`**, so `cl.exe`
> falls back to `/Od` and `/GL` is ignored. Selecting the Release configuration is therefore not
> sufficient on its own — add `<Optimization>MaxSpeed</Optimization>` explicitly.
>
> The MDS T-table patch of §2 helps an unoptimized build disproportionately, since it removes those
> calls outright: `-O0` drops from 127.5 min to **1.7 min**, `-O2` from 11.6 min to **1.0 min**.

## 1. Short answer

**Within `Block_Cipher_df`, yes — almost.** The implementation is correct (verified separately) and
does no unnecessary work, with one exception: the entropy pool is 11 bytes smaller than it could be at
*identical* cipher cost (§4). That is the only structural gain left inside the construction.

**But the constraint itself is expensive.** Two independent levers sit outside it, and they multiply:

| Change | Cost per 64-byte output | Speed-up | Affects entropy assessment? |
|---|---|---|---|
| current code, as measured | 694 µs | — | — |
| table-driven `MultiplyGF` in `kalyna.c` | 122 µs | **5.7×** | no |
| … and CBC-MAC/CMAC instead of `Block_Cipher_df` | 38.6 µs | **18× total** | no |

For the mode-4 target of 64 MB that is **11.6 minutes → 2.0 minutes → 39 seconds**.

The critical point for your validation write-up: **none of this trades against entropy.** All three
options have the same `n_out` = 512, the same `n_w` = 512, and therefore the same `h_out` ceiling of
511.488 bits. The choice is cost and which standard you cite — not extraction quality.

---

## 2. Where the time goes

`block_cipher_df` performs, per conditioned output, exactly **13 `KalynaEncipher` + 2
`KalynaKeyExpand`** (instrumented count, mode 4). The timing model closes to the measurement:

```
13 × 44.63 µs (encipher) + 2 × 57.44 µs (key expand) = 695 µs   vs   694 µs measured
```

So there is no hidden overhead — the cost *is* the primitive calls. Note that `KalynaKeyExpand` is
only 1.3 × an encipherment, so the two re-keyings account for ~17 %; the dominant term is the 13
encipherments.

Why 13, when a direct MAC over the same 300 bytes needs 5:

- `S = L‖N‖pool‖0x80` padded = 320 B = 5 blocks; each BCC pass also prepends the 16-byte `IV` block → **6 blocks per pass**.
- Step 9 must produce `keylen + outlen` = 1024 bits of `temp`, which at 512 bits per BCC output means **2 passes** → 12 encipherments.
- Step 13 contributes 1 more.

Two BCC passes is the floor: `keylen + outlen > outlen` always, in every mode. So `Block_Cipher_df`
reads the entropy pool **twice** by construction, where a MAC reads it once. That is the 3.1×.

### The primitive is the bigger lever

`MatrixMultiply` calls `MultiplyGF` — an 8-iteration bitwise carry-less multiply — 8 × 8 × 8 = **512
times per round**, across 18 rounds. That is ~74 000 inner iterations per 512-bit block. Replacing it
with a 64 KB precomputed `gf_tab[256][256]` (a ten-line change confined to `kalyna.c`, no interface
change) measured:

| | encipher | key expand | per output |
|---|---|---|---|
| bitwise `MultiplyGF` | 44.63 µs | 57.44 µs | 694 µs |
| table `MultiplyGF` | 7.79 µs | 10.17 µs | 122 µs |

**5.7×, for free, with zero effect on output values.** A full T-table treatment (folding `SubBytes`
into the MDS layer, 64 lookups+XORs per round) would go further, but the 64 KB table is the
high-value/low-risk step and it is where I would start. `WordsToBytes` was a suspect and is
innocent — it is a cast, not an allocation.

---

## 3. Mode choice — your current selection is right

Per-mode measurement (table-driven GF, so the comparison is about the construction, not the
primitive):

| Mode | pool | `n_out` | encipherments | µs / output | **µs per output bit** |
|---|---|---|---|---|---|
| 128/128 | 75 B | 128 | 15 | 24.6 | **0.193** |
| 128/256 | 150 B | 256 | 35 | 71.7 | 0.280 |
| 256/256 | 150 B | 256 | 13 | 53.2 | **0.208** |
| 256/512 | 300 B | 512 | 35 | 161.7 | 0.316 |
| **512/512** | 300 B | 512 | **13** | 123.3 | **0.241** |

The modes with `keylen = 2 × outlen` (128/256, 256/512) need **three** BCC passes rather than two, so
they cost ~30 % more per output bit than their square counterparts. `KALYNA_512_512` is the right
choice among the 512-bit-output modes — 0.241 vs 0.316 µs/bit against 256/512 — and it is also the
mode that avoids the `n_w` argument of the conformance review's G4 entirely.

---

## 4. The one free win inside `Block_Cipher_df`

`concat_len = 4 + 4 + pool + 1`, then zero-padded up to a block boundary. At `pool = 300` that is
309 → **320**, so **11 bytes of the final block are padding you are paying for and not using**.
Raising the pool to 311 fills them with noise instead, at *identical* cipher cost:

| Mode | pool now | `h_in` now | max pool at same cost | `h_in` then | gain |
|---|---|---|---|---|---|
| 128/128 | 75 B | 150.1 bits | **87 B** | 174.1 bits | **+16.0 %** |
| 128/256 | 150 B | 300.2 | 151 B | 302.2 | +0.7 % |
| 256/256 | 150 B | 300.2 | 151 B | 302.2 | +0.7 % |
| 256/512 | 300 B | 600.4 | **311 B** | 622.4 | +3.7 % |
| **512/512** | 300 B | 600.4 | **311 B** | 622.4 | **+3.7 %** |

Mode 4 gains 22 bits of input entropy per output for nothing; mode 0 gains 16 %. This does not raise
`h_out` (already capped at 511.488 by the 0.999 rule), but it widens the margin above `n_out`, which
is exactly the margin that protects you if `H` is ever revised downward — the failure case flagged as
G10. Cheap insurance.

Worth pairing with the `static_assert` from G10 so pool and `H` stay coupled.

---

## 5. If you are willing to leave `Block_Cipher_df`

**Калина-512/512-CMAC-512** (ДСТУ 7624 §8) or CBC-MAC (SP 800-90B App. F) conditions the same 300-byte
pool in **5 encipherments and zero key expansions** — the key is fixed, so the schedule is computed
once at start-up instead of twice per pool. Measured 39.5 µs vs 123.3 µs, i.e. **3.1×** cheaper, and:

- identical `n_out` = `n_w` = 512, so §3.1.5.2 assessment and the 511.488-bit ceiling are unchanged;
- **removes the G5 deviation entirely** — no extension of SP 800-90A's 32-byte step-8 constant past
  `0x1F`, because CMAC is specified end-to-end in your own national standard;
- easier §3.2.3(5) argument: 90B lists CMAC and CBC-MAC as vetted *constructions*, so you argue only
  about the primitive, not the mode.

The cost: CMAC is **keyed**, so §3.2.3(3)–(4) stop being vacuous — the key must be fixed before any
output and must not also be an input. Trivial with a hardcoded key, but a reviewer will ask about it,
whereas `Block_Cipher_df` is classified unkeyed and the question never arises.

There is no entropy-quality argument either way. Both rely on the cipher being a good PRP rather than
on a leftover-hash-lemma bound, since the "key" is public in both cases — so §3.2.3(5) item 3 needs
the same mathematical evidence whichever you pick.

**My read:** if the audience is a ДСТУ scheme, CMAC is the cleaner story and 3.1× faster. If you want
to keep the SP 800-90A lineage — and it is already verified spec-faithful — keep `Block_Cipher_df`,
take the free pool-size win, and put the 64 KB GF table in. That last one alone gets you most of the
available speed without touching the construction or the argument.

---

## 6. Remaining code items in the cross-platform variant

Correctness-neutral, but they matter for portability and for the ДСТУ §4.3 obligation.

### 6.1 `#include "tables.c"` — the `#ifndef __linux__` is treating a symptom

`tables.c` defines `mds_matrix`, `mds_inv_matrix`, `sboxes_enc`, `sboxes_dec` with **external
linkage**, and the vcxproj compiles it as its own translation unit (confirmed: not
`ExcludedFromBuild`). Including it *as well* into `KalynaBCDF.cpp` therefore defines each array twice.

I reproduced both halves:

- **On Linux** it is a hard error — `multiple definition of 'sboxes_dec'`, `'sboxes_enc'`,
  `'mds_inv_matrix'`. Hence your `#ifndef`.
- **On Windows** it links only because MSVC decorates C++ globals, so the C++ copy in
  `KalynaBCDF.obj` and the C copy in `tables.obj` get different symbol names. The Windows binary
  carries **two copies** of the tables (~4 KB), and `KalynaEncipher` uses the C one while the included
  copy is dead weight. Harmless today because `KalynaBCDF.cpp` never touches the tables directly, but
  it is an ODR trap.

Fix, and the `#ifdef` disappears with it:

```c
#include "tables.h"      /* not tables.c — it is already in both builds */
```

Verified: one copy of `mds_matrix` in the binary, links clean on Linux, and Windows loses the
duplicate.

### 6.2 `__linux__` is the wrong platform test

`#ifndef __linux__ → #include <windows.h>` means **macOS, FreeBSD and musl-based Linux all take the
Windows branch** and fail. The property you are testing is "is this Windows", so test that:

```c
#if defined(_WIN32)
#include <windows.h>
#endif
```

Same for the console-code-page calls, which are the only thing `windows.h` is still needed for.

### 6.3 `kalyna.h`: `typedef __uint64_t uint64_t;`

`__uint64_t` is a glibc-internal identifier — reserved to the implementation, absent on musl, macOS
and the BSDs. The header uses `uint8_t`/`uint64_t` in its own struct, so the portable fix is the
standard one (C99; MSVC has shipped it since 2010, so the Visual Studio build is unaffected):

```c
#include <stdint.h>      /* replaces both typedef branches */
```

### 6.4 MSVC pragmas are unguarded, and one is now dead

`#pragma comment(lib, "bcrypt.lib")` survives although `<bcrypt.h>` and the `BCryptGenRandom` calls
are gone — it still forces the link. Both pragmas also draw warnings from GCC/Clang:

```c
#if defined(_MSC_VER)
#pragma warning(disable:4996)
#endif
```

and delete the `bcrypt.lib` line.

### 6.5 Carried over from the earlier reviews

Restating only, since these are your calls to make: output still opens `"ab"`, so successive runs
concatenate into one file with no visible boundary — the hazard is to the `h'` measurement, not to the
bytes (conformance review G7). No sanitisation of `pool`, `S`, `IV_S`, `temp`, `K`, `X` or the
pool-derived round-key schedule (ДСТУ 7624 §4.3, G11a/G13). And the five one-line
`static_assert`/guards from `block_cipher_df_verification.md` §5.2–5.6 — the `(keylen+outlen) %
outlen` one is the one I would not skip, since an AES-192-shaped configuration overflows `temp` by 8
bytes and nothing in the source says why that cannot happen.

---

## 7. Priority

| # | Action | Effort | Payoff |
|---|---|---|---|
| 0 | add `<Optimization>MaxSpeed</Optimization>` to `Release\|x64` and build Release | 1 line of XML | **~11×** — this is the single largest factor and costs nothing |
| 1 | MDS T-tables in `kalyna.c` (`kalyna_mds_tables.patch`) | ~50 lines | **11.9×** at `-O2`, **75×** at `-O0`, output identical |
| 2 | pool 300 → 311 (mode 4) | 1 constant | +22 bits `h_in` free; margin against `H` revision |
| 3 | `#include "tables.h"`, drop the `#ifndef` | 2 lines | removes ODR trap + 4 KB duplication |
| 4 | `_WIN32` instead of `__linux__`; `<stdint.h>` in `kalyna.h`; guard pragmas | ~6 lines | actually portable, not just Windows+glibc |
| 5 | the `static_assert` set | 5 lines | closes the latent overflows |
| 6 | consider Калина-512/512-CMAC-512 | redesign | further 3.1×; removes the G5 deviation |

Items 1–5 keep `Block_Cipher_df` exactly as verified. Item 6 is the architectural question, and the
only one that changes what you cite.

---

*Method: primitive calls counted by instrumenting `KalynaEncipher`/`KalynaKeyExpand` around the
project's own `BCC()`/`block_cipher_df()` extracted verbatim; timings are means over 20 000
conditioning operations (200 000 for the bare encipher) via `CLOCK_MONOTONIC`; the linkage behaviour
in §6.1 was reproduced by building both arrangements. Speed changes were checked to leave output
values unchanged.*
