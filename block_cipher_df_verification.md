# Verification of `block_cipher_df` / `BCC` — Kalyna instantiation of SP 800-90A §10.3.2

**Subject:** `KalynaBCDF.cpp` (original variant), functions `BCC()`, `block_cipher_df()`,
`u32_to_bytes()`, with `kalyna.c` / `tables.c` as the `Block_Encrypt` primitive
**Against:** SP 800-90A Rev. 1 §10.3.2–10.3.3; ДСТУ 7624:2014 §5.2–5.5; SP 800-90B Table 1, §3.2.3(2)
**Date:** 2026-09-07

---

## 1. Verdict

**The algorithm is correct.** `block_cipher_df()` and `BCC()` implement SP 800-90A §10.3.2/§10.3.3
faithfully, the Kalyna substitution for `Block_Encrypt` is done correctly including the cases where
key length ≠ block length, and the internal buffers, alignment and types are all sound **for the five
configurations `params.h` defines**. No functional defect was found.

Everything in §5 below is a *latent* robustness issue: the code is safe today because of exact
arithmetic coincidences in the five Kalyna geometries, not because it checks. Those invariants are
undocumented and unenforced, and one of them is genuinely easy to violate — an AES-192-shaped
configuration overflows a stack buffer by 8 bytes (§5.2). Worth pinning down before anyone adds a
mode.

---

## 2. The verification chain

Four independent links, so a shared misreading cannot hide in any one of them.

| # | Claim | Method | Result |
|---|---|---|---|
| 1 | My reading of §10.3.2 is the standard's | Drove a full CTR_DRBG (§10.2.1) from it and compared against **published CAVP `aes_128_use_df_pr` vectors** | `int_returnedbits` = `d4988a46804cdba359025752661cea5b` **MATCH**; `returnedbits` = `cf01ac2231068efcce56ea240f3843c6` **MATCH** |
| 2 | The project's construction is what AES would need | Transcribed the C control flow, substituted AES, compared against a spec-only implementation over 200 random lengths × AES-128/192/256 | all agree |
| 3 | The Kalyna instantiation is correct | Wrote a **second** `Block_Cipher_df` from the standard's pseudocode only (heap buffers sized from arguments, not from `ENT_POOL_SIZE`), calling the project's own `KalynaEncipher`/`KalynaKeyExpand`; compared against the project's functions compiled **verbatim** | **975 / 975** input lengths agree, across all five modes |
| 4 | The primitive itself is right | Project's `kalyna.c` against the DSTU 7624 Kalyna-128/128 reference vector | key `000102…0F`, pt `101112…1F` → `81BF1C7D779BAC20E1C9EA39B4D2AD06` **MATCH**, decipher round-trip OK |

Link 3 per mode: 75 (128/128), 150 (128/256), 150 (256/256), 300 (256/512), 300 (512/512) — every
input length from 1 byte up to that mode's pool size.

Link 1 matters most for your validation package: it means the reference reading is anchored to
externally published values, not just to my own interpretation.

---

## 3. Step-by-step conformance to §10.3.2

| Step | Standard | Implementation | ✔ |
|---|---|---|---|
| 1 | error if `nbits > max_number_of_bits` (512) | `if (no_of_bits_to_return > KEY_BITLEN) return 1;` — stricter than 512 in every mode | ✔ |
| 2 | `L = len(input_string)/8`, 32-bit | `u32_to_bytes(L, input_len / 8)`, big-endian | ✔ |
| 3 | `N = nbits/8`, 32-bit | `u32_to_bytes(N, no_of_bits_to_return / 8)` | ✔ |
| 4 | `S = L ‖ N ‖ input_string ‖ 0x80` | four `memcpy`s in that order | ✔ |
| 5 | zero-pad `S` to a multiple of `outlen` | `(BLOCK_LEN - concat_len % BLOCK_LEN) % BLOCK_LEN` | ✔ |
| 6 | `temp = Null` | `temp[KEY_LEN + BLOCK_LEN]`, `tempLen = 0` | ✔ |
| 7 | `i = 0`, 32-bit | `int i = 0`, emitted via `u32_to_bytes` | ✔ |
| 8 | `K = leftmost(0x000102…1D1E1F, keylen)` | `initialKey[64]` = `0x00…0x3F`, `memcpy(K, …, nk*8)` | ✔ + **documented deviation** (see §4.3) |
| 9 | while `len(temp) < keylen+outlen`: `IV = i ‖ 0^(outlen−32)`; `temp ‖= BCC(K, IV‖S)`; `i++` | `IV` = 4-byte `i` then `memset(IV+4, 0, nb*8−4)`; `BCC(…, temp + nb*8*i)`; `tempLen += BLOCK_LEN` | ✔ |
| 10 | `K = leftmost(temp, keylen)` | `memcpy(K, temp, nk*8)` + `KalynaKeyExpand` | ✔ |
| 11 | `X = select(temp, keylen+1, keylen+outlen)` | `memcpy(X, temp + nk*8, nb*8)` | ✔ |
| 12 | `temp = Null` | `new_temp[KEY_LEN]`, `tempBitlen = 0` | ✔ |
| 13 | while `len(temp) < nbits`: `X = Block_Encrypt(K, X)`; `temp ‖= X` | `KalynaEncipher((uint64_t*)X, ctx, (uint64_t*)X)` then `memcpy` | ✔ |
| 14–15 | `requested_bits = leftmost(temp, nbits)` | `memcpy(requested_bits, new_temp, nbits/8)` | ✔ |

`BCC()` against §10.3.3: chaining value initialised to `0^outlen` ✔; `n = len(data)/outlen` ✔;
`input_block = chaining_value ⊕ block_i` ✔; `chaining_value = Block_Encrypt(Key, input_block)` ✔;
returns the final chaining value ✔.

The `IV` byte order deserves a note because it is easy to get backwards: the standard puts the 32-bit
`i` in the **leftmost** bits and zero-pads to the right. `memcpy(IV, I_to32, 4)` followed by
`memset(IV + 4, 0, …)` is exactly that. ✔

---

## 4. The Kalyna substitution

### 4.1 `Block_Encrypt` semantics

§10.3.3 defines `Block_Encrypt` as "a basic encryption operation … equivalent to an encryption
operation on a single block of data using the ECB mode". `KalynaEncipher` is the ДСТУ 7624 §5 base
transform (базове перетворення / проста заміна) — the raw keyed permutation, no mode, no IV, no
padding. That is the correct correspondent. ✔

The standard's own note that "the presence of these derivation functions in this Recommendation does
not implicitly approve these functions for any other application" is worth keeping in view: it is
also why substituting the primitive is a documentation matter rather than a licence — see the main
review's G1–G4.

### 4.2 Key length independent of block length

This is where an AES-shaped implementation most often breaks, because AES-128 has `keylen == outlen`
and the bug stays invisible. Kalyna offers `keylen = 2 × outlen` in two modes, so step 9 must run a
number of times that depends on both:

| Mode | `outlen` | `keylen` | step-9 iterations | step-13 iterations |
|---|---|---|---|---|
| 128/128 | 16 | 16 | 2 | 1 |
| 128/256 | 16 | 32 | 3 | 2 |
| 256/256 | 32 | 32 | 2 | 1 |
| 256/512 | 32 | 64 | 3 | 2 |
| 512/512 | 64 | 64 | 2 | 1 |

All correct, and link 3 exercises every one of them. The `nb`/`nk` split is honoured throughout —
`nb*8` where a *block* is meant, `nk*8` where a *key* is meant, never confused. ✔

### 4.3 Step-8 constant

SP 800-90A defines the constant only as far as `0x00 01 … 1D 1E 1F` (32 bytes), AES-256 being the
largest key it contemplates. `initialKey[64]` continues the natural sequence to `0x3F` for
Kalyna-512. This is the only place the implementation goes beyond the standard's text. It is the
obvious extension and is self-consistent, but it is a deviation and must be stated as one — no CAVP
vectors can exist at that key length, which is why the KAT in §2 link 4 and your own published
vectors have to stand in for them (SP 800-90B §3.2.3(2)).

### 4.4 Data representation and endianness

The implementation casts `uint8_t*` buffers to `uint64_t*` at the `KalynaEncipher` boundary. On a
little-endian host, byte *k* of the array becomes byte *k* mod 8 of word *k* div 8, least-significant
first — which is precisely the column-major, little-endian state fill that ДСТУ 7624 §5.2 (Figure 1)
and §3.2 mandate. Link 4 proves this empirically: the published DSTU vector is expressed as a byte
string and the implementation reproduces it exactly.

So the byte-string semantics are correct **and follow the base standard's own convention** rather
than working around it. The dependency is on host endianness, not on the standard: on a big-endian
host the casts would transpose bytes within each word and the cipher would be wrong. Every current
target (x86-64, ARM in LE mode) is fine. Document the assumption; see §5.7.

One consequence worth stating explicitly in your write-up: the *construction* — padding, chaining,
`L`/`N`/`IV` encoding, key derivation — operates on byte strings identically to the AES
instantiation (link 2 proves this). The only thing that differs from an AES-based
`Block_Cipher_df` is the primitive. That is the cleanest way to frame the substitution for a reviewer.

---

## 5. Internal functions and data

### 5.1 Buffer bounds — all exact, no slack

Computed for all five modes:

| Mode | `S` need/cap | `IV_S` need/cap | `temp` written/cap | `new_temp` written/cap | BCC block/buf |
|---|---|---|---|---|---|
| 128/128 | 96 / 203 | 112 / 203 | 32 / 32 | 16 / 16 | 16 / 64 |
| 128/256 | 160 / 278 | 176 / 278 | 48 / 48 | 32 / 32 | 16 / 64 |
| 256/256 | 160 / 278 | 192 / 278 | 64 / 64 | 32 / 32 | 32 / 64 |
| 256/512 | 320 / 428 | 352 / 428 | 96 / 96 | 64 / 64 | 32 / 64 |
| 512/512 | 320 / 428 | 384 / 428 | 128 / 128 | 64 / 64 | 64 / 64 |

`S` and `IV_S` carry comfortable headroom. **`temp`, `new_temp` and the BCC buffers are filled
exactly to capacity** — correct, but with zero margin, which is what makes §5.2–5.4 worth writing
down.

### 5.2 (latent) `temp` overflows if `keylen + outlen` is not a whole number of blocks

Step 9 loops on `tempLen < KEY_LEN + BLOCK_LEN` and advances `tempLen += BLOCK_LEN`, writing a full
block each time at `temp + BLOCK_LEN*i`. If `(KEY_LEN + BLOCK_LEN) % BLOCK_LEN != 0` the last
iteration writes past the end. All five Kalyna modes divide exactly, so the code is safe.

The counterexample is concrete rather than hypothetical: an **AES-192** shape (`keylen` 24,
`outlen` 16 → 40 bytes, 2.5 blocks) makes the loop write 48 bytes into a 40-byte buffer — **an 8-byte
stack overflow**. I confirmed this by instrumenting the transcription. Kalyna has no 192-bit key so
it cannot arise here, but the invariant is invisible in the source.

```c
static_assert((KEY_LEN + BLOCK_LEN) % BLOCK_LEN == 0,
              "keylen + outlen must be a whole number of blocks");
```

### 5.3 (latent) `new_temp` overflows if `nbits` is not a whole number of blocks

Step 13 writes `BLOCK_LEN` at a time into `new_temp[KEY_LEN]` while `tempBitlen < nbits`. With
`nbits = KEY_BITLEN` and `KEY_BITLEN % BLOCK_BITLEN == 0` in every mode this fills exactly. A caller
passing, say, 384 bits in the 512/512 mode would write 512 bits into a 512-bit buffer — safe — but
288 bits in the 128/256 mode writes 384 into 256. Since the parameter is a runtime argument while the
buffer is sized by a macro, guard it:

```c
static_assert(KEY_BITLEN % BLOCK_BITLEN == 0, "keylen must be a whole number of blocks");
/* and at runtime: */
if (no_of_bits_to_return % BLOCK_BITLEN) return 1;
```

### 5.4 (latent) `S` / `IV_S` are sized from a macro but filled from an argument

`S[ENT_POOL_SIZE + 128]` and `IV_S[ENT_POOL_SIZE + 128]`, but the length actually copied comes from
the `input_len` **parameter**. Nothing checks the two against each other. Today both call sites are
safe (`ENT_POOL_SIZE` from `main`, 38 bytes from `BlockCipherDFMode`), but the function's signature
advertises an arbitrary length it cannot honour. Add:

```c
if (input_len / 8 > ENT_POOL_SIZE) return 1;   /* buffer is sized for the pool */
```

### 5.5 (latent) `BCC` assumes `outlen ≤ 512` bits

`chaining_value[64]` and `input_block[64]` exactly fit the 512-bit block, and `outbytes` comes from
the `outlen` argument with no guard. Fine for DSTU 7624 (512 bits is its maximum), but a one-line
check costs nothing given the buffers have no margin.

Also `n = data_bitlen / outlen` truncates silently: a `data_bitlen` that is not a multiple of `outlen`
would drop a trailing partial block rather than erroring. Steps 4–5 plus the `IV` prefix guarantee a
multiple, so this is unreachable — but §10.3.3 states the multiple as a precondition, so asserting it
documents the contract.

### 5.6 (minor) The same quantities are sourced two different ways

Within one function, block and key sizes come sometimes from the context and sometimes from macros —
`ctx->nb * 8` and `ctx->nk * 8` in steps 9–11, `BLOCK_LEN` / `KEY_LEN` / `BLOCK_BITLEN` /
`KEY_BITLEN` in the buffer declarations and loop bounds. They agree because `main` builds `ctx` from
the same macros, so this is not a bug. But it means correctness depends on an invariant that is never
checked, and buffer arithmetic is exactly where a mismatch would go unnoticed. Either assert the
agreement once on entry, or pick one source:

```c
if (ctx->nb * 8 != BLOCK_LEN || ctx->nk * 8 != KEY_LEN) return 1;
```

### 5.7 Alignment — correct, including the subtle cases

`KalynaEncipher`/`KalynaKeyExpand` take `uint64_t*`, so every buffer that reaches them through a cast
must be 8-byte aligned. Audit:

- `alignas(8)` and cast: `S`, `IV_S`, `IV`, `temp`, `K`, `X`, `chaining_value`, `input_block` ✔
- **not** aligned but never cast — only `memcpy` targets: `new_temp`, `feed` (both call sites), `pool`,
  `L`, `N`, `initialKey` ✔

`pool` is the one to notice: it is a plain global `uint8_t[ENT_POOL_SIZE]` passed as `input_string`,
but it is only ever `memcpy`d into `S`, so its alignment is irrelevant. Correct as written.

In-place use at step 13 — `KalynaEncipher((uint64_t*)X, ctx, (uint64_t*)X)` — is safe: the reference
core copies the plaintext into `ctx->state` before writing anything to the output buffer.

### 5.8 Re-keying is leak-free

`KalynaKeyExpand` is called twice on the same context (step 8's constant, then step 10's derived key).
It `malloc`s one scratch `kt` and `free`s it before returning, and does not touch `ctx->round_keys`
allocation — those were allocated once by `KalynaInit`. So re-keying in place neither leaks nor
reallocates. ✔ Confirmed by reading `kalyna.c`.

### 5.9 (minor) Types

- `int tempBitlen` compared against `uint32_t no_of_bits_to_return` — signed/unsigned comparison.
  Harmless at these magnitudes; produces a warning at `-Wextra` / `/W4`.
- `u32_to_bytes(L, input_len / 8)` narrows `size_t` → `uint32_t`. The standard specifies `L` as a
  32-bit integer, so the narrowing is intended; it only misbehaves for inputs ≥ 4 GiB, which the
  buffer sizes preclude anyway.
- The step-1 guard tests against the `KEY_BITLEN` macro rather than the standard's literal 512 or
  `ctx->nk * 64`. Stricter in every mode, so correct — but it is the same macro-vs-context split as
  §5.6.

### 5.10 Cosmetic

`memset(chaining_value, 0, outlen/8)` is redundant after `= { 0 }`. `uint8_t val[1] = {0x80}` plus a
1-byte `memcpy` could be a direct assignment. `initialKey[64]` is rebuilt on the stack on every call —
roughly a million times per 64 MB run; `static const` would hoist it. None of these affect
correctness.

---

## 6. Summary

Nothing needs fixing for the code to be correct in its current configuration. What is worth doing:

| Item | Kind | Why |
|---|---|---|
| §5.2 `static_assert` on `(keylen+outlen) % outlen` | 1 line | prevents a real 8-byte stack overflow in an AES-192-shaped config |
| §5.3 guard `nbits % BLOCK_BITLEN` | 1 line + assert | `new_temp` is filled to exact capacity |
| §5.4 check `input_len/8 <= ENT_POOL_SIZE` | 1 line | the signature promises more than the buffers allow |
| §5.6 assert `ctx` agrees with the macros | 1 line | buffer maths depends on an unchecked invariant |
| §5.5 assert `outlen <= 512` and the multiple-of-outlen precondition | 2 lines | BCC buffers have zero margin |
| §4.3 document the step-8 extension | prose | the only departure from the standard's text |
| §4.4 document the little-endian assumption | prose | correct per ДСТУ §5.2, but host-dependent |

For the validation package, §2 is the reusable part: it is the evidence SP 800-90B §3.2.3(2) asks
for, and link 1 is what makes it stand up independently of my reading.

---

*Method: the project's `BCC()`/`block_cipher_df()`/`u32_to_bytes()` were extracted mechanically from
`KalynaBCDF.cpp` and compiled verbatim against a second implementation written only from the SP
800-90A pseudocode, using the project's own Kalyna as the primitive, for every input length from 1 to
the pool size in all five modes. The reading of §10.3.2 used for that comparison was first validated
by reproducing published CAVP CTR_DRBG AES-128 `use_df` vectors.*

*Sources: NIST SP 800-90A Rev. 1 and NIST SP 800-90B (project knowledge base); ДСТУ Калина draft
(project knowledge base); CAVP `aes_128_use_df_pr` vectors as embedded in the OpenSSL test suite.*
