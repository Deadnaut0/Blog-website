---
title: "IMPOSSIBLE ESCAPE - CTF Writeup"
date: 2026-04-11
draft: false
description: "Cryptography challenge writeup"
tags: ["Cryptography"]
categories: ["Writeups"]
---


**Challenge Name:** IMPOSSIBLE ESCAPE  
**Category:** Cryptography  
**CTF:** CyberSummit V4.0 CTF  
**Description:** integrity: unknown encryption: "trust me bro" Someone built a crypto system so convoluted they thought it was safe. They were wrong. Recover the plaintext.  
> Flag Format:CyberTrace{flag}  

**Connection:** `nc 48.199.16.26 9993`  

---

## Initial Reconnaissance

The first thing we did was connect to the service and write down exactly what it returned.

```text
nc 48.199.16.26 9993
⠀⣤⣤⠀⠀⠀⠀⠀⠀⢠⣤⠀⠀⠀⠀⠀⠀⠀⠀⣤⡄⠀⠀⠀⠀⠀⠀⣤⣤⠀
⠀⣿⣿⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⠀⢸⣿⠀⣠⣾⣿⣿⣷⣄⠀⣿⡇⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⠀⢸⣿⠀⣿⣿⣿⣿⣿⣿⠀⣿⡇⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⠀⢸⣿⠀⣿⣿⣿⣿⣿⣿⠀⣿⡇⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⠀⢸⣿⠀⣿⣿⣿⣿⣿⣿⠀⣿⡇⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⠀⢸⣿⠀⢿⣿⣿⣿⣿⡿⠀⣿⡇⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⣙⣛⣛⣋⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⠀⠸⠿⠀⣿⣿⣿⣿⣿⣿⠀⠿⠇⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⢠⣶⡖⠂⠈⢻⣿⣿⡿⠁⠐⢲⣶⡄⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡟⠛⠃⢸⣿⣿⡇⠘⠛⢻⣿⣿⠀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⢀⠘⢿⣿⠟⢁⣼⣿⣿⣷⡀⠻⣿⡿⠃⡀⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⣸⡇⢠⣤⠀⣿⣿⣿⣿⣿⣿⠀⣤⡄⢸⣇⠀⠀⠀⠀⣿⣿⠀
⠀⣿⣿⠀⠀⠀⠀⣿⡇⢸⣿⠀⣿⣿⣿⣿⣿⣿⠀⣿⡇⢸⣿⠀⠀⠀⠀⣿⣿⠀
⠀⠛⠛⠀⠀⠀⠀⠛⠃⠘⠛⠀⠛⠛⠛⠛⠛⠛⠀⠛⠃⠘⠛⠀⠀⠀⠀⠛⠛⠀

=== IMPOSSIBLE ESCAPE CRYPTO NODE ===
A modulus rotates every 5 connections. You have 90 seconds.
Send plaintext guess as hex after recovering it.

{
  "epoch": 10,
  "n": "0x5e1db4bbe9bfecb77141fcb1fca8a0d3b18aed10a57d89122c512204b0aa47f5fef8020f014cdf0b5f6b20da5fd06bfeb1fa7b8695f6a99f57815257a4bd19ad4aec892bb3f737e258fe94346923ed13998e9b14e20573b6cb839401c725caadcc6f72c6d8f60bd6ca4e1ea8b6cdf7bff228579d6aff7aabb7a39e7d8c324003",
  "e": 65537,
  "wrapped_nonce": "0x1af1c350b3a86b1ea6166cf83a96fc1588ad3d199ffcaad5e0ac5dfd8c477caa48d2fa311373205a34f0566f00cd104acbbe25a586c629093dc6488b8e81242b44370c430e8e4fe0db0c95cb76bc7c4f4a0933eaa86b1a95cdd33cde4576092acaca418da2eb4f2d5c38ad84aa01b35e096ac3a85c85376934f0e6b1f6394dd0",
  "timing_leaks": [
    73417,
    102546,
    11247,
    155886,
    251019,
    238554,
    62459,
    73481,
    47527,
    7285,
    80783,
    99099,
    177836,
    88617,
    39308,
    170726,
    76482,
    54008,
    39913,
    227643,
    104563,
    261893,
    78103,
    73093
  ],
  "leak_bits": 18,
  "ciphertext_chunks": [
    "cfd87481254cd8112fb31ed20459d30c73b2d95a4cf468fcf94c0dca5420df3d6f1d3188a146236df44b128993cd434e",
    "cd3fc2c39f84dbaead54febb2cfb8c955318fea1cad08c80b97f3f028e30cc63a330b5786e81d711fdd780bea127ce43",
    "f89ecdf0c921798e70415ea8a339a6434bfb7047f93f8d19ded728bc54c764c7b4115e2393e3e557faae21e3ee38d518",
    "b007e12d6529f91497193c1fd4d6541342ee69ef99f8aaae04c8df43680c158441f9ce696a02584393f8a2aa5f0377b2",
    "7193169cf208f690baba4730e7991e53950cfe35da8365da5850b8c11977a88f04a14018dae707d43c19281fb963596c",
    "a6b62d68a6502aeb82e9c25d253def647e4dc917e51320b1dd139a751c3548f111b6321d1dfbfe90ec1d98092e246019",
    "f70ba95c6bc397c5a6a1fc0432c73365de896d0f17da045ad0d5b6d159e916fa0a2c94e2f52b5beb5a88dd1413c56cc9",
    "4cccf653bdd19b926483f03f83fcfe31c593f477c0a672ceb4bd6da2ca1d9b7e697f91206523f4e2dfff410af7161a9f",
    "1304a2c7d86a7f4d9ac50ff41e676eebcb4b5aaf4be328410423367456c1553d883b3eb5c5a3b7e67e6d609da6f3cc0e",
    "54656c9f22e1b351a4848712f8becd8a9ede4a8f4f5b4bde3881a37b94835b3d0b077510771ee8600bbc5f902591ea70",
    "89e03d1612cd08547b399bbff48dafc875591e05021f781144e968d7a54145f408dcc575970e8454c627cdf409cebf3b",
    "26b12625458c9ced074984d28ff4edf689d74d5cbc1bb96d405007bc1ba04bbd5ef550557123dfb7b219a4cc37b32317",
    "0538dd3a1aa113975e555a3b65dffe75812dd1d20d8d1f1e1339ae4820183047ce0467d8fa6b59e241ac2782af4757d9",
    "5e5b3619930409e1588e9aef1d662ec88adf9ccc41397b2c332673c62ac7cb86f15cb99c357a7032d48c20b7ddada589",
    "ac240d5036297b3c56c555cb76dd4c18508a1144eaf17e73b69917696f3563e213f6b964b6721407dfdacfdd76ad7f1e",
    "3defb067f0f23d046cd321d10f26d93707b386dd1e7a335f835baaf09377d07cc2706af6a54a77acb97414dc72a11ac9",
    "d5ded34bd9fc8e439585b83ca602c1379a12bf5ed633364c254aa4d538551e20592f3b71372f2ba01d93859a85fdfd59",
    "b3e34ca047efffdf36692d4295fc56a863928615e362bd34a1ad5e2c8be83346364782b45a74a499eb85541f1bfa2952",
    "c6780584cd574f9bf938fda0e6d3516e0a5c5c0a4d7b693f7b57b6423c6d60771ee5136708a4b0bc1a6004a406fd2032",
    "a96e5a172aee65b2aa9ee7d609426e7ca3581607fb7868c5e23197054e4fdf3ec5a834258d72ee1886039c6189c308c3",
    "dd9e5bcf71f8131ec6d326c84f6cba62cc05b52c6fc4da07f8569a4ece0f880577fbe299e5718ad0d0f63caea7cd389c",
    "fd99792ca96e5b5ca056383b69f87690c5f39fb6fde7f9cf80ba647417021f444dab3e5332bc987aa8d7010c0b1ba98a",
    "509f10b6529c629a2ca0ab76338fcbf998db52b9dc6b5bfe2a0b3b3b3bdeacc54139b6eaf6da505247322c607e9813e2",
    "cc03e46c2882ae678ec4d94dc20ae1e6ae54bd34e19b2df71f095af3aae9dd81f9543dbdac8c40d8b17e6688a103f391",
    "5bc8d1c0c91b0d0d211b1c5a7d0502e07ec273342c8e5c47d10e74ace1ec9bdfbffbfc447c15640faf909e6aee0b9944",
    "fc7ab3110799431b1fde35a3471c76c926a3fc48c29962fb677db99d0173f3970ad28d48ff15fd07a9877c6a9aff5b74",
    "175cf15a044791dc84dd35875d6c9f5d5fd25af3b5c82097bbe752830ba388c7022457255ff53d65674abc1ee077f434",
    "c1dafcbc8211fce41f7fa5bd5ba96484a9cbc27d526eaac862c51ddab0672ba19fb7345e3d0dae73bc"
  ],
  "plaintext_len": 1337,
  "sg_blocks": [
    "6b6d43e2f31a067f607d26320dcdb720",
    "8f3261ccea83d1c10e3efd6482937a92",
    "48c0a0fdee4b38de0a25ec40d7cad78e",
    "b7b37e426b971d4ec4d78f724f796e2f",
    "37d508e546ae4145e8d0de9e33aa045f",
    "b1b70f4d87033b59089446b1555c737e"
  ],
  "sg_leak_offset": 2048,
  "sg_key_offset": 4096,
  "notes": {
    "tbbs_A": "0xd1342543de82ef95",
    "tbbs_B": "0x9e3779b97f4a7c15",
    "tbbs_high": "0xa5c37e1902400000",
    "tbbs_unknown_bits": 22,
    "prime_words": 8
  }
}

plaintext_hex> 
```

That told us the important thing immediately: the live JSON is the real handout, and the solver has to be able to parse it.

The only offline file we were given was `challenge_core_handout.py`. That file is enough to understand the construction, the PRNG constants, and the encryption pipeline, but it intentionally redacts the LFSR taps/state.

The relevant contents of that file were:

```python
#!/usr/bin/env python3

from __future__ import annotations

import hashlib
from typing import List

from Crypto.Cipher import AES

MASK64        = (1 << 64) - 1
RSA_E         = 65537
RSA_BITS      = 1024
PRIME_WORDS   = 8
LEAK_BITS     = 18
LEAK_COUNT    = 24
PLAINTEXT_LEN = 1337

TBBS_A            = 0xD1342543DE82EF95
TBBS_B            = 0x9E3779B97F4A7C15
TBBS_UNKNOWN_BITS = 22
TBBS_HIGH         = 0xA5C37E1902400000

SG_L             = 79
SG_TAPS          = ???
SG_STATE         = ???
SG_LEAK_OFFSET   = 2048
SG_LEAK_BLOCKS   = 6
SG_BLOCK_SIZE    = 16
SG_KEY_OFFSET    = 4096
KEY_MATERIAL_LEN = 512

class TBBS:
    def __init__(self, seed: int):
        self.state = seed & MASK64

    def next_word(self) -> int:
        self.state = (self.state * TBBS_A + TBBS_B) & MASK64
        return self.state

def build_prime(words: List[int], tweak: int) -> int:
    x = 0
    for w in words:
        x = (x << 64) | w
    x ^= tweak
    x |= (1 << 511)
    x |= 1
    return next_prime(x)

def lfsr_bits(n_bits: int, state: int = SG_STATE, taps: int = SG_TAPS) -> List[int]:
    mask  = (1 << SG_L) - 1
    state &= mask
    taps  &= mask

    out = []
    for _ in range(n_bits):
        bit      = state & 1
        out.append(bit)
        feedback = (state & taps).bit_count() & 1
        state    = ((state >> 1) | (feedback << (SG_L - 1))) & mask
    return out

def derive_aes_key(d: int, sg_stream: List[int]) -> bytes:
    raise NotImplementedError("REDACTED")
```

From that file we extracted the core facts:

- RSA is used with `e = 65537`.
- The modulus rotates every 5 connections.
- Prime generation is driven by a 64-bit affine generator called TBBS.
- The TBBS seed has a fixed high mask and only 22 unknown low bits.
- Each connection leaks the top 18 bits of 24 consecutive TBBS outputs.
- The plaintext is wrapped in AES-CTR.
- The AES key is derived from RSA private exponent bits and an LFSR side stream.

What the file did **not** give us was the LFSR taps and state. That was the clue that the intended solve was not to reconstruct the LFSR from a static spec, but to recover it from the leaked stream blocks.

---

## Thinking Process

The obvious-looking parts were RSA and AES, but neither of those were the real weakness. The real weak spots were the two places where the system leaked internal state:

1. The top bits of the **TBBS** states.
2. The consecutive **LFSR** output blocks.

Once we noticed that, the whole challenge collapsed into state recovery.

The reason the TBBS leak matters is that the seed space is tiny: only 22 bits are unknown. That is brute-force territory, especially when each candidate can be rejected quickly with 24 leaked prefixes.

The reason the LFSR leak matters is that consecutive linear output is exactly what Berlekamp-Massey is built for. We do not need the taps or the initial state from the handout because the six blocks already contain enough information to recover the recurrence.

So the solve path was not "break RSA" or "solve a lattice problem." It was:

- `recover the TBBS seed,`
- `replay the RSA key generation`
- `recover the LFSR recurrence from the side stream`
- `rebuild the AES key`
- `decrypt the ciphertext.`

---

## Challenge Flow

The encryption pipeline is basically:

1. Seed a 64-bit affine generator with a masked secret.
2. Leak the top 18 bits of 24 states.
3. Use the next 16 TBBS words to build `p`.
4. Use the next 16 TBBS words to build `q`.
5. Compute RSA private exponent `d`.
6. Use another TBBS word as the AES-CTR nonce.
7. Generate an LFSR stream and combine it with even-indexed bits of `d`.
8. Hash the combined material with SHA-256 to get the AES key.
9. Encrypt the plaintext with AES-CTR.

So the solve is:

```text
timing leaks -> TBBS seed -> p,q -> d -> nonce -> LFSR recurrence -> AES key -> plaintext
```

---

## Exploit Strategy

### 1. Recover the TBBS seed

TBBS is affine modulo `2^64`:

```math
S_{i+1} = (A S_i + B) \bmod 2^{64}
```

Only the low 22 bits of the seed are unknown because the high bits are fixed by the handout. That makes seed recovery easy enough to brute-force:

- Try all `2^22` low-bit candidates.
- Advance the generator 24 steps.
- Compare the leaked top 18 bits each time.
- The one candidate that matches all leaks is the correct seed.

This sounds like a lot, but `2^22` is small for a filtered brute force, especially because most candidates die on the first few leaks.

### 2. Rebuild RSA primes and private key

Once the seed is known, we just replay the generator exactly:

- Skip the 24 leak states.
- Pull the next 8 words for `p`.
- Pull the next 8 words for `q`.
- Apply the same `build_prime()` logic as the challenge.
- Check that `p * q == n` from the handout.
- Compute:

```math
\varphi(n) = (p-1)(q-1)
```

and then:

```math
d = e^{-1} \bmod \varphi(n)
```

With `d` known, we can also decrypt the RSA-wrapped nonce.

### 3. Recover the LFSR stream from `sg_blocks`

The `sg_blocks` are six consecutive 16-byte chunks from a linear bitstream. That is exactly what Berlekamp-Massey likes.

Steps:

- Convert the leaked bytes into bits.
- Run Berlekamp-Massey to get the shortest linear recurrence.
- Extend the stream forward until we reach the window used for key derivation.

This is the important part: we do not need the redacted taps or state from `challenge_core_handout.py`. The leaked blocks are enough to recover the recurrence directly.

### 4. Rebuild the AES key

The key derivation uses:

- the even-indexed bits of `d`
- a same-length window from the LFSR stream

Those two bitstrings are interleaved, packed into bytes, and hashed with SHA-256.

So once `d` and the stream window are known, the key is deterministic.

### 5. Decrypt the ciphertext

The nonce is RSA-wrapped in the handout.

Recover it with:

```math
nonce = wrapped\_nonce^d \bmod n
```

Then use AES-CTR with the recovered key and nonce to decrypt the ciphertext.

At that point the plaintext contains the flag.

---

## Why This Works Reliably

This challenge looks layered and overdesigned, but every layer is deterministic and replayable.

Key observations:

- The seed search is tiny because only 22 bits are unknown.
- The RSA primes are generated from a replayable PRNG stream.
- The LFSR side channel is linear, so BM recovers it cleanly.
- The AES key is built from data we can fully reconstruct.

So the exploit is not a lattice nightmare. It is a careful state-reconstruction problem with a clean end-to-end script.

---

## Solver Workflow

The actual solving script we used is split into two parts:

- `solve/solve.py` contains the crypto logic.
- `solve/live_solve.py` is the one-command network wrapper that connects to the service, saves the JSON handout, runs the solver, and submits the answer.

### Core solver (`solve/solve.py`)

```python
#!/usr/bin/env python3
"""Exploit solver for the Impossible Escape crypto challenge."""

from __future__ import annotations

import json
import importlib.util
import sys
from pathlib import Path
from typing import List, Tuple

from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parents[1]

CORE_PATH = ROOT / "chall" / "challenge_core.py"
CORE_SPEC = importlib.util.spec_from_file_location("challenge_core", CORE_PATH)
if CORE_SPEC is None or CORE_SPEC.loader is None:
    raise RuntimeError("failed to load challenge_core module")

challenge_core = importlib.util.module_from_spec(CORE_SPEC)
sys.modules["challenge_core"] = challenge_core
CORE_SPEC.loader.exec_module(challenge_core)

KEY_D_EVEN_BITS = challenge_core.KEY_D_EVEN_BITS
LEAK_BITS = challenge_core.LEAK_BITS
MASK64 = challenge_core.MASK64
PRIME_WORDS = challenge_core.PRIME_WORDS
RSA_E = challenge_core.RSA_E
SG_BLOCK_SIZE = challenge_core.SG_BLOCK_SIZE
SG_LEAK_BLOCKS = challenge_core.SG_LEAK_BLOCKS
TBBS = challenge_core.TBBS
TBBS_A = challenge_core.TBBS_A
TBBS_B = challenge_core.TBBS_B
build_prime = challenge_core.build_prime
bits_to_bytes = challenge_core.bits_to_bytes
interleave_bits = challenge_core.interleave_bits


def load_handout(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def recover_seed(timing_leaks: List[int], high: int, unknown_bits: int) -> int:
    space = 1 << unknown_bits
    for low in range(space):
        state = high | low
        ok = True
        for leak in timing_leaks:
            state = (state * TBBS_A + TBBS_B) & MASK64
            if (state >> (64 - LEAK_BITS)) != leak:
                ok = False
                break
        if ok:
            return high | low
    raise RuntimeError("seed not found")


def regenerate_primes(seed: int, leak_count: int) -> Tuple[int, int]:
    gen = TBBS(seed)
    for _ in range(leak_count):
        gen.next_word()

    p_words = [gen.next_word() for _ in range(PRIME_WORDS)]
    q_words = [gen.next_word() for _ in range(PRIME_WORDS)]

    p = build_prime(p_words, tweak=0xC0FFEE12345)
    q = build_prime(q_words, tweak=0xBADF00DCAFE)
    if p == q:
        q += 2
        while True:
            if challenge_core.is_probable_prime(q):
                break
            q += 2
    return p, q


def berlekamp_massey(bits: List[int]) -> List[int]:
    c = [0] * len(bits)
    b = [0] * len(bits)
    c[0] = 1
    b[0] = 1
    l = 0
    m = -1

    for n in range(len(bits)):
        d = bits[n]
        for i in range(1, l + 1):
            d ^= c[i] & bits[n - i]
        if d == 0:
            continue

        t = c[:]
        shift = n - m
        for i in range(len(bits) - shift):
            c[i + shift] ^= b[i]

        if 2 * l <= n:
            l = n + 1 - l
            m = n
            b = t

    return c[: l + 1]


def extend_with_recurrence(bits: List[int], poly: List[int], total_len: int) -> List[int]:
    l = len(poly) - 1
    out = bits[:]
    while len(out) < total_len:
        n = len(out)
        nxt = 0
        for i in range(1, l + 1):
            nxt ^= poly[i] & out[n - i]
        out.append(nxt)
    return out


def bytes_to_bits(data: bytes) -> List[int]:
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def derive_key_from_d_and_sg(d: int, sg_bits: List[int], sg_key_offset_rel: int) -> bytes:
    d_even = [((d >> (2 * i)) & 1) for i in range(KEY_D_EVEN_BITS)]
    sg_window = sg_bits[sg_key_offset_rel : sg_key_offset_rel + KEY_D_EVEN_BITS]
    material = bits_to_bytes(interleave_bits(d_even, sg_window))

    import hashlib

    return hashlib.sha256(material).digest()


def solve(handout_path: Path) -> bytes:
    data = load_handout(handout_path)

    notes = data["notes"]
    high = int(notes["tbbs_high"], 16)
    unknown_bits = int(notes["tbbs_unknown_bits"])
    timing = [int(x) for x in data["timing_leaks"]]

    seed = recover_seed(timing, high, unknown_bits)
    p, q = regenerate_primes(seed, leak_count=len(timing))

    n = int(data["n"], 16)
    if p * q != n:
        raise RuntimeError("prime regeneration mismatch")

    phi = (p - 1) * (q - 1)
    d = pow(RSA_E, -1, phi)

    wrapped_nonce = int(data["wrapped_nonce"], 16)
    nonce_int = pow(wrapped_nonce, d, n)
    nonce = nonce_int.to_bytes(8, "big")

    sg_blob = b"".join(bytes.fromhex(x) for x in data["sg_blocks"])
    expected = SG_LEAK_BLOCKS * SG_BLOCK_SIZE
    if len(sg_blob) != expected:
        raise RuntimeError("unexpected sg block length")

    sg_bits = bytes_to_bits(sg_blob)
    poly = berlekamp_massey(sg_bits)

    leak_offset = int(data["sg_leak_offset"])
    key_offset = int(data["sg_key_offset"])
    if key_offset < leak_offset:
        raise RuntimeError("key offset before leak offset is unsupported")

    rel = key_offset - leak_offset
    needed = rel + KEY_D_EVEN_BITS
    sg_full = extend_with_recurrence(sg_bits, poly, needed)

    key = derive_key_from_d_and_sg(d, sg_full, rel)

    if "ciphertext" in data:
        ct_hex = data["ciphertext"]
    elif "ciphertext_chunks" in data:
        ct_hex = "".join(data["ciphertext_chunks"])
    else:
        raise RuntimeError("missing ciphertext field in handout")

    ciphertext = bytes.fromhex(ct_hex)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext


def main() -> None:
    default = ROOT / "dlist" / "handout.json"
    handout = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    pt = solve(handout)

    marker = b"CyberTrace{"
    i = pt.find(marker)
    if i == -1:
        print("[!] flag marker not found")
        print(pt[:200])
        return

    j = pt.find(b"}", i)
    if j == -1:
        print("[!] malformed flag")
        print(pt[i : i + 120])
        return

    print(pt[i : j + 1].decode())


if __name__ == "__main__":
    main()
```

### One-shot live wrapper (`solve/live_solve.py`)

```python
#!/usr/bin/env python3
"""One-shot remote solver for the hosted Impossible Escape challenge."""

from __future__ import annotations

import argparse
import importlib.util
import json
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOLVE_PATH = ROOT / "solve" / "solve.py"


def load_solver_module():
    spec = importlib.util.spec_from_file_location("ie_solve", SOLVE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load solve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def recv_until_prompt(sock: socket.socket, prompt: bytes) -> bytes:
    buf = b""
    while prompt not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def extract_handout(text: str) -> dict:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise RuntimeError("could not parse JSON handout from server output")
    return json.loads(text[start : end + 1])


def extract_flag(plaintext: bytes) -> str:
    marker = b"CyberTrace{"
    i = plaintext.find(marker)
    if i == -1:
        raise RuntimeError("flag marker not found in plaintext")
    j = plaintext.find(b"}", i)
    if j == -1:
        raise RuntimeError("malformed flag in plaintext")
    return plaintext[i : j + 1].decode("utf-8", errors="strict")


def main() -> None:
    parser = argparse.ArgumentParser(description="Live solver for Impossible Escape")
    parser.add_argument("--host", default="127.0.0.1", help="challenge host")
    parser.add_argument("--port", type=int, default=5001, help="challenge port")
    parser.add_argument(
        "--save-handout",
        default=str(ROOT / "dlist" / "live_handout.json"),
        help="path to save parsed handout JSON",
    )
    args = parser.parse_args()

    solve_module = load_solver_module()

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(30)
        raw = recv_until_prompt(sock, b"plaintext_hex> ")
        text = raw.decode("utf-8", errors="ignore")

        handout = extract_handout(text)
        handout_path = Path(args.save_handout)
        handout_path.parent.mkdir(parents=True, exist_ok=True)
        handout_path.write_text(json.dumps(handout, indent=2), encoding="utf-8")

        plaintext = solve_module.solve(handout_path)
        sock.sendall(plaintext.hex().encode() + b"\n")

        result = sock.recv(4096).decode("utf-8", errors="ignore").strip()
        flag = extract_flag(plaintext)

    print(result)
    print(flag)
    print(f"saved handout: {handout_path}")


if __name__ == "__main__":
    main()
```

### Final Execution

```bash
python3 solve/live_solve.py --host 48.199.16.26 --port 9993
correct: exfil succeeded
CyberTrace{7h1s_1S_M7_F1N4L_St4ND_S0_En5o7_Wh1L3_It_L4s7388}
```

---

## Final Flag

```text
CyberTrace{7h1s_1S_M7_F1N4L_St4ND_S0_En5o7_Wh1L3_It_L4s7388}
```

---

## Key Notes

- The seed space is only `2^22`, so brute force is completely practical.
- Berlekamp-Massey is the intended way to recover the stream recurrence from `sg_blocks`.
