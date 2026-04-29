---
title: "RNG FOR THE WIN - CTF Writeup"
date: 2026-04-11
draft: false
description: "Cryptography challenge writeup"
tags: ["Cryptography"]
categories: ["Writeups"]
---



**Challenge Name:** RNG FOR THE WIN  
**Category:** Cryptography  
**CTF:** CyberSummit V4.0 CTF  
**Description:** You are given a remote service. It leaks LEAK_COUNT lines; each line is the top LEAK_BITS bits of a 64-bit output from a hidden 128-bit RNG state. Then it gives one ciphertext hex string.  
**Connection:** `nc 48.199.16.26 9997`  

---

## Initial Reconnaissance

First step was to connect and inspect behavior:

```bash
nc 48.199.16.26 9997
```

Observed pattern:

1. Banner and intro text.
2. Many lines of indexed leaks like:
   - `[000] abcdef`
   - `[001] 012345`
3. One long hex ciphertext line.
4. Prompt: `Submit flag:`

Given files:

- `chall.py`  

From `chall.py`, we can confirm:

- Internal state is 128-bit split into two 64-bit words.
- RNG update is xorshift-like and fully linear over GF(2).
- Leaks are truncated outputs (top 24 bits of each 64-bit output).
- Ciphertext is generated from future RNG outputs using SHA-256 blocks, then XOR with flag.

This immediately suggests a state recovery attack instead of brute force.

---

## Challenge Overview

The critical weakness is linearity.

Even though each leak reveals only 24 bits, the underlying transition and output are linear bit operations (`xor`, shifts, word moves). For a linear PRNG, each observed output bit can be written as a linear equation in the unknown initial state bits.

Let the unknown initial state be a 128-bit vector:

```text
S_0 \in \{0,1\}^{128}
```

Each leaked bit gives an equation:

```text
a_i \cdot S_0 = b_i \pmod 2
```

With enough leaks, we build an overdetermined linear system and solve by Gaussian elimination over GF(2). Once `S0` is known, we replay the RNG to the post-leak point, regenerate keystream, and decrypt ciphertext.

---

## What We Found During Analysis

This section is the practical thought process that leads from "looks random" to a full break.

### 1) Why brute force was never an option

The hidden state is 128 bits.

```text
2^{128} \approx 3.4 \times 10^{38}
```

That rules out guessing the seed directly, even with heavy pruning.

### 2) Why truncation looked scary at first

Each output is 64 bits, but we only see top 24 bits. So each step hides 40 bits. At a glance this seems secure because each sample is incomplete.

The key realization: incomplete linear equations are still equations. If we collect enough of them, hidden bits do not matter anymore.

### 3) The turning point: recognizing pure GF(2) behavior

In `chall.py`, all state mixing uses shifts and XORs.

- No modular multiplication.
- No S-box/non-linear substitution.
- No carries from addition in the state transition.

That means each output bit is an affine/linear function of initial state bits over GF(2). This is exactly what Gaussian elimination can solve.

### 4) Why SHA-256 did not save the challenge

Ciphertext generation uses SHA-256 on each RNG output block, which is cryptographically strong.

But SHA-256 is applied after the weak part. Once we recover the RNG state at the point where keystream blocks are generated, we can compute the exact same SHA-256 inputs and recreate the stream byte-for-byte.

So the break path is:

1. Recover state from truncated leaks.
2. Replay RNG.
3. Recompute SHA-256 blocks.
4. XOR with ciphertext.

### 5) Sanity checks that confirmed the attack path

Before writing the full solver, we validated:

- Leak format is stable and parseable (`[idx] hex`).
- Number of leak bits is enough to overconstrain the 128 unknowns.
- Flag format prefix (`CyberTrace{`) can be used as a correctness oracle if multiple candidates exist.

These checks prevented wasting time on wrong assumptions.

---

## Detailed Exploit

### Step 1: Parse and normalize observations

We parse every leak line and the ciphertext line from the netcat transcript. Each leak is a 24-bit integer.

Then we expand each leak into individual bits in MSB-to-LSB order. If `LEAK_COUNT = 170`, then total equations are:

```text
170 \times 24 = 4080
```

That is far more equations than the 128 unknown state bits.

### Step 2: Build linear equations without symbolic math libraries

Instead of manually deriving equations on paper, we use basis simulation.

Idea:

- Treat initial state as 128 unknown basis bits.
- For each basis bit, set only that bit to 1 and all others to 0.
- Run the same RNG update and leak extraction as the challenge.
- Record which observed leak bits become 1.

For basis bit `j`, this gives one column of the matrix `A`.

After iterating all 128 basis states, we obtain:

$$
A \in \{0,1\}^{m \times 128},\quad b \in \{0,1\}^{m}
$$

where `m` is total leaked bits.

### Step 3: Solve `A x = b` over GF(2)

We run Gaussian elimination with XOR row operations.

Important implementation detail:

- Rows are stored as Python integers where bit `k` is coefficient of unknown `x_k`.
- Row elimination becomes fast bitwise XOR.

Possible outcomes:

1. Inconsistent system: no solution (should not happen if parsing is correct).
2. Unique solution: ideal case.
3. Multiple solutions (free variables): enumerate a bounded subset, then validate with flag prefix.

### Step 4: Move state to encryption phase

Recovered state corresponds to the start (before leak rounds). The challenge consumes one RNG step per leak line.

So we replay exactly `LEAK_COUNT` steps to align with keystream generation point.

This alignment step is critical. Off-by-one here gives total garbage plaintext.

### Step 5: Rebuild keystream and decrypt

For each needed block:

1. Advance RNG.
2. Compute:

$$
 ext{SHA256}(\text{rnd\_u64} || \text{counter\_u32} || \text{domain\_sep})
$$

1. Concatenate blocks, truncate to ciphertext length.
2. XOR with ciphertext.

If plaintext starts with `CyberTrace{`, candidate is correct.

### Step 6: Submit recovered flag

The solver sends plaintext back on the same socket and prints server response (`correct`).

---

## Common Pitfalls We Avoided

- Bit order confusion (MSB-first vs LSB-first in leak expansion).
- Wrong state split (`s0` low 64 vs high 64 bits).
- Forgetting to advance RNG through leak rounds before decrypting.
- Parsing accidental hex strings that are not ciphertext.
- Assuming unique solution without checking free variables.

---

## Full Solver Code

```python
#!/usr/bin/env python3
import argparse
import hashlib
import re
import socket

MASK64 = (1 << 64) - 1
LEAK_BITS = 24
FLAG_PREFIX = b"CyberTrace{"  # Used to validate recovered plaintext.


def xs128_step(s0: int, s1: int) -> tuple[int, int, int]:
    x = s0
    y = s1
    s0 = y
    x ^= (x << 23) & MASK64
    x ^= x >> 17
    x ^= y
    x ^= y >> 26
    s1 = x & MASK64
    out = (s0 ^ s1) & MASK64
    return s0, s1, out


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def keystream(s0: int, s1: int, n: int) -> tuple[bytes, int, int]:
    out = bytearray()
    counter = 0
    while len(out) < n:
        s0, s1, rnd = xs128_step(s0, s1)
        block = hashlib.sha256(
            rnd.to_bytes(8, "big") + counter.to_bytes(4, "big") + b"|rng_for_the_win|"
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:n]), s0, s1


def parse_text(text: str) -> tuple[list[int], bytes]:
    leaks: list[int] = []
    ct: bytes | None = None
    for line in text.splitlines():
        m = re.search(r"\[(\d+)\]\s*([0-9a-fA-F]+)", line)
        if m:
            leaks.append(int(m.group(2), 16))
        if re.fullmatch(r"[0-9a-fA-F]{16,}", line.strip()):
            ct = bytes.fromhex(line.strip())
    if not leaks or ct is None:
        raise ValueError("Could not parse leaks/ciphertext from input")
    return leaks, ct


def read_remote(host: str, port: int) -> tuple[list[int], bytes, socket.socket]:
    s = socket.create_connection((host, port))
    data = bytearray()
    while b"Submit flag:" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    leaks, ct = parse_text(data.decode(errors="ignore"))
    return leaks, ct, s


def leaks_to_bits(leaks: list[int]) -> list[int]:
    bits: list[int] = []
    for leak in leaks:
        for i in range(LEAK_BITS - 1, -1, -1):
            bits.append((leak >> i) & 1)
    return bits


def gen_outputs_for_basis(var_idx: int, count: int) -> list[int]:
    if var_idx < 64:
        s0 = 1 << var_idx
        s1 = 0
    else:
        s0 = 0
        s1 = 1 << (var_idx - 64)

    outs: list[int] = []
    for _ in range(count):
        s0, s1, rnd = xs128_step(s0, s1)
        outs.append(rnd)
    return outs


def build_linear_system(leaks: list[int]) -> tuple[list[int], list[int]]:
    nvars = 128
    bits = leaks_to_bits(leaks)
    m = len(bits)
    rows = [0] * m
    rhs = bits[:]

    for var in range(nvars):
        outs = gen_outputs_for_basis(var, len(leaks))
        row_idx = 0
        for rnd in outs:
            top = rnd >> (64 - LEAK_BITS)
            for b in range(LEAK_BITS - 1, -1, -1):
                if (top >> b) & 1:
                    rows[row_idx] |= 1 << var
                row_idx += 1

    return rows, rhs


def solve_gf2(rows: list[int], rhs: list[int], nvars: int) -> tuple[int, list[int]]:
    m = len(rows)
    where = [-1] * nvars
    r = 0

    for c in range(nvars):
        pivot = -1
        for i in range(r, m):
            if (rows[i] >> c) & 1:
                pivot = i
                break
        if pivot == -1:
            continue

        rows[r], rows[pivot] = rows[pivot], rows[r]
        rhs[r], rhs[pivot] = rhs[pivot], rhs[r]
        where[c] = r

        for i in range(m):
            if i != r and ((rows[i] >> c) & 1):
                rows[i] ^= rows[r]
                rhs[i] ^= rhs[r]

        r += 1
        if r == m:
            break

    for i in range(m):
        if rows[i] == 0 and rhs[i] == 1:
            raise RuntimeError("Inconsistent linear system")

    sol = 0
    for c in range(nvars):
        if where[c] != -1 and rhs[where[c]]:
            sol |= 1 << c

    free_vars = [c for c in range(nvars) if where[c] == -1]
    return sol, free_vars


def recover_state(leaks: list[int], ct: bytes) -> tuple[int, int, bytes]:
    rows, rhs = build_linear_system(leaks)
    base_sol, free_vars = solve_gf2(rows, rhs, 128)

    candidates = [base_sol]
    if free_vars:
        # Usually full rank with this many leaks. If not, enumerate a bounded subset.
        limit = min(1 << min(len(free_vars), 16), 1 << 16)
        candidates = []
        for mask in range(limit):
            cand = base_sol
            for i, v in enumerate(free_vars[:16]):
                if (mask >> i) & 1:
                    cand ^= 1 << v
            candidates.append(cand)

    for cand in candidates:
        s0 = cand & MASK64
        s1 = (cand >> 64) & MASK64

        for _ in leaks:
            s0, s1, _ = xs128_step(s0, s1)

        stream, _, _ = keystream(s0, s1, len(ct))
        pt = xor_bytes(ct, stream)
        if pt.startswith(FLAG_PREFIX):
            return cand, s0, pt

    raise RuntimeError("No valid plaintext found")


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve RNG FOR THE WIN")
    parser.add_argument("--host", help="Remote host")
    parser.add_argument("--port", type=int, help="Remote port")
    parser.add_argument("--transcript", help="Path to saved challenge transcript")
    args = parser.parse_args()

    if args.host and args.port:
        leaks, ct, sock = read_remote(args.host, args.port)
        state, _, pt = recover_state(leaks, ct)
        print(f"[+] recovered state: {state:032x}")
        print(f"[+] flag: {pt.decode(errors='replace')}")
        sock.sendall(pt + b"\n")
        print(sock.recv(1024).decode(errors="ignore").strip())
        sock.close()
        return 0

    if args.transcript:
        with open(args.transcript, "r", encoding="utf-8") as f:
            text = f.read()
        leaks, ct = parse_text(text)
        state, _, pt = recover_state(leaks, ct)
        print(f"[+] recovered state: {state:032x}")
        print(f"[+] flag: {pt.decode(errors='replace')}")
        return 0

    parser.error("Provide either --host/--port or --transcript")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

---

## Running the Exploit

```bash
python3 solve.py --host 48.199.16.26 --port 9997
```

Expected output:

```text
[+] recovered state: <128-bit-hex>
[+] flag: CyberTrace{1_K53W_Y0u_W3re_H34E_B3f0r33!!_MEE33$}
correct
```

---

## Final Flag

```text
CyberTrace{1_K53W_Y0u_W3re_H34E_B3f0r33!!_MEE33$}
```

---

## Key Notes

- Truncation alone does not secure a linear `PRNG` if enough samples are leaked.
- `Xorshift-style` generators are fast but not cryptographically secure.
- Post-processing with `SHA-256` does not help if attacker can recover preimage `RNG` outputs/state first.
- Overdetermined linear systems over `GF(2)` are practical and very effective in CTF RNG challenges.
- Reliable parsing and careful bit-order handling are often the difference between a broken and working exploit.
