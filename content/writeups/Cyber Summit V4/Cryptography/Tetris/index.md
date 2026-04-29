---
title: "Tetris - CTF Writeup"
date: 2026-04-11
draft: false
description: "Cryptography challenge writeup"
tags: ["Cryptography"]
categories: ["Writeups"]
---



**Challenge Name:** Tetris  
**Category:** Cryptography  
**CTF:** CyberSummit V4.0 CTF  
**Description:** A custom Tetris telemetry format leaks sparse bits from each internal RNG output word, but many entries are dropped or flipped. The same RNG instance then drives a stream cipher that encrypted the flag. The oracle enforces per-connection sample budget and request rate limits, so optimize where you spend queries. Use repeated SAMPLE queries to denoise and reconstruct reliable equations, then recover the internal RNG state and decrypt.  

**Connection:** `nc 48.199.16.26 9994`

---

## Initial Reconnaissance

First step was connecting to the service and recording exactly what it exposes.

```text
$ printf 'HELP\nHANDOUT\n' | nc 48.199.16.26 9994
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠂⡀⠀⠀⠀⠀⠀⣰⡖⠀⣦⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠄⠀⡾⠁⠀⡇⠀⠀⠀⢀⣴⡟⠁⠀⣸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏⠀⢸⠁⢠⢤⠇⠀⠀⣠⡾⠋⠀⠀⣠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢀⡇⠀⢸⡾⣀⡤⠞⠉⠀⠤⠤⠴⠿⠤⠤⠤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡀⠀⣧⢸⡇⢀⡼⠋⠉⠀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠷⠦⣄⣀⡀⠀⠀⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⡴⠚⠋⠉⠛⠉⠉⣿⡾⠧⠀⠀⠀⠀⠀⠉⠉⣉⠉⠓⠲⢤⣠⣄⠀⠀⠀⠳⣶⣶⣖⡛⠉⠉⠉⠉⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⠞⠁⠀⠀⣠⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠑⠲⣤⣉⠀⠉⠛⠲⠤⣄⣀⠀⠉⣉⣛⣿⠿⠟⠁⠀⠀⠀
⠀⠀⠀⠀⠀⣴⠃⠀⣀⡴⠋⠁⠀⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠈⠳⣝⠂⠀⠀⠀⠀⠈⠉⠛⠦⢤⣀⡀⠀⠀⠀⠀⠀
⢀⣀⣀⣀⡤⠤⠚⠋⠀⠀⠀⠀⢰⠃⠀⠀⢀⠀⠀⠀⠀⠀⢄⠀⠀⠀⢴⡆⠀⠹⣆⠀⠈⢧⠀⠀⢠⠀⠀⠐⢦⣀⣠⠤⢭⢽⣿⡶⠶⠄
⠈⠉⠉⠁⠀⠀⠀⢀⡞⠃⠀⠀⣾⠀⠀⠀⢸⡄⠀⠀⠀⠀⢸⠠⡆⠀⢸⡇⠀⡀⠹⣆⠀⠀⢷⡀⠸⡶⣔⣄⢦⡙⢾⣆⠉⠉⠉⠁⠀⠀
⠀⠀⠀⠀⠀⢀⡴⣿⠁⠀⠀⠀⣿⠀⠀⠀⠸⡇⠀⡇⠀⠀⢸⡀⣷⠀⢸⡇⡄⢹⠀⢹⣦⡀⠀⢣⠀⣧⣌⢿⡆⠳⡌⢿⡄⠀⠀⠀⠀⠀
⠀⠀⠀⣠⢶⣿⢾⡇⠀⣾⠀⠀⣿⠀⢀⠀⣀⢹⡄⢿⡀⠀⠈⡇⢿⡆⢰⡇⡇⠀⣧⠈⡇⢳⡄⠈⢧⣿⡘⣆⠹⣄⠹⡄⢷⡀⠀⠀⠀⠀
⠀⣷⡻⠗⠋⠀⡾⠀⠀⢿⠀⠀⢻⠀⠈⢧⠙⡌⢧⠘⣧⠀⠀⣧⠸⣷⠀⣿⣽⡀⠘⡄⢿⠀⠙⢆⠈⣟⡇⠙⣆⢿⣳⡻⡈⣧⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢠⠇⣼⠀⢸⡀⠀⠈⢧⠀⠸⡄⣧⡘⡆⠹⣧⠀⢿⣤⢿⡀⢹⠘⢧⠀⢧⠘⣆⣤⢼⣦⢸⣧⣀⠘⣎⡿⡟⢧⢸⡄⠀⠀⠀
⠀⠀⠀⠀⠀⣾⣰⢧⡄⠀⢧⠀⠀⠸⡄⠀⢷⢸⣷⣿⣆⠘⢧⣸⡉⠉⢧⢸⠀⠈⣧⣼⣤⡇⠀⢀⣰⣾⣿⠸⡆⠘⢷⡹⡜⣿⡇⠀⠀⠀
⠀⠀⠀⠀⢰⣿⢿⣟⣶⠀⠈⢧⡀⠀⢻⡀⠸⡜⡇⠹⡞⢦⣠⣿⣿⣿⣿⣾⣄⠀⠘⢿⣷⣧⣾⣿⣿⣿⣿⣤⡜⣆⠈⢷⡄⠀⠀⠀⠀⠀
⠀⠀⢀⣴⡟⢁⣞⣾⡏⢸⣦⡶⢿⣄⡀⣇⣀⣇⣇⣀⣸⣤⣿⣿⣿⣿⣿⣿⣞⣷⣤⣤⣼⣿⣿⣿⣿⣿⣿⣿⣇⠈⠳⣌⣹⡆⠀⠀⠀⠀
⠀⠀⠀⠉⠠⠿⠋⣾⣣⣿⣿⢀⣿⡦⣙⢾⡛⢿⠛⠛⠛⢻⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠉⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣿⠋⢹⠹⣞⠉⡽⢿⠁⠀⠀⠀⠀⠀⠀⠘⠻⠿⠿⠿⠿⠋⠀⠀⠀⠀⠉⠛⠻⠿⠿⠛⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠠⡾⠁⠀⠘⣿⢻⣟⠁⠞⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⠀⠀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣌⣧⡈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠏⣿⠁⠙⢦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡇⠀⠀⠈⠛⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠤⠤⠤⡤⠀⠀⠀⣰⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣼⡇⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢦⣀⡼⠃⠀⢀⣴⡟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠘⢦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⢀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣷⣦⣀⡀⠀⠀⠀⠹⣿⡶⢦⣄⣀⠀⠀⠀⠀⢀⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣀⠀⠀⠙⠾⣿⣿⠭⣛⡶⠒⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣽⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⠈⠻⣿⣿⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣼⣿⣿⣿⣷⣦⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣷⣶⣽⡛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣝⡿⢿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⣾⡿⠋⠀⠈⠹⢿⣿⣿⠟⢿⣿⣿⣏⣹⣿⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣰⠟⠛⠁⠀⠀⠀⢀⠈⠁⠀⠄⠀⠀⠀⠙⢻⣿⣿⣿⣿⣷⡿⣿⣿⡿⢿⣿⣿⡿⢟⢿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
Commands: HELP | HANDOUT | HANDOUT_FULL | SAMPLE <round> <bit> <count>

> {"commands": {"HELP": "show protocol help", "HANDOUT": "return compact handout JSON", "HANDOUT_FULL": "return full handout JSON", "SAMPLE <round> <bit> <count>": "return fresh noisy observations (0/1)"}, "limits": {"sample_rps": 24, "per_connection_budget": 20000, "sample_count_limits": [1, 512]}}

> {
  "name": "Tetromino Cipher: Invisible Garbage Master",
  "flavor": "Public telemetry is decoy-only. Real leakage is noisy and must be denoised via oracle queries.",
  "telemetry_schema": "decoy",
  "rounds": 220,
  "leak_bit_positions": [0,1,2,5,6,11,12,13,14],
  "drop_rate": 0.58,
  "flip_rate": 0.24,
  "oracle_protocol": {
    "transport": "tcp",
    "commands": ["HELP","HANDOUT","SAMPLE <round> <bit> <count>"],
    "sample_count_limits": [1,512],
    "sample_rps": 24,
    "per_connection_budget": 20000
  },
  "ciphertext_hex": "4d2ddf129743b9cddc88e69fff5b6bc4994af01cd81029eb72e3f6a2d8c6dbe2126bda32074abd7749883dee0725ff2bb0c8",
  "notes": [
    "The same PRNG instance generated both telemetry and encryption keystream.",
    "Ciphertext was produced immediately after the last telemetry round.",
    "Telemetry fields are thematic decoys and do not directly encode leak bit positions.",
    "The handout leaks are intentionally corrupted and incomplete.",
    "The hosted oracle returns fresh noisy observations for selected round/bit pairs."
  ],
  "telemetry_entries": 220,
  "leaked_rows": 220
}
```

### What this tells us immediately

1. The challenge is oracle-first.
2. We have strict rate/budget limits.
3. We only need core fields (`rounds`, `leak_bit_positions`, `ciphertext_hex`) for solving.
4. Telemetry is decoy; real exploitable signal comes from `SAMPLE`.

---

## Challenge Overview

The internal flow is:

1. Hidden PRNG emits one 32-bit word each round.
2. Oracle leaks sparse bit positions from each word, but with noise.
3. After telemetry rounds, the same PRNG continues to produce keystream.
4. Flag is XOR-encrypted with that keystream.

So the objective becomes:

```
recover initial PRNG state -> regenerate keystream -> decrypt ciphertext
```

---

## Exploit

### Step 1: Build a linear model over GF(2)

The PRNG transition is xor/shift based, so output bits are linear combinations of the 128 unknown initial state bits.

If initial state vector is $x \in GF(2)^{128}$, each denoised leak gives one equation:

`a_i \cdot x = b_i`

where:

- `a_i` is derived by symbolic stepping,
- `b_i` is the denoised observed bit.

### Step 2: Query and denoise under limits

For selected rounds and each leak position, query:

- `SAMPLE <round> <bit> <count>`

Use majority vote over returned samples to estimate true bit.

Used parameters:

- `TARGET_ROUNDS = 50`
- `SAMPLES_PER_EQUATION = 41`

These are enough to get reliable equations while staying under budget.

### Step 3: Solve GF(2) linear system

Run `Gaussian elimination in GF(2)` to recover the full `128-bit PRNG state`.

### Step 4: Decrypt

- Advance recovered state by `rounds`.
- Generate keystream bytes.
- XOR with `ciphertext_hex`.

Recovered plaintext contains the flag.

---

## Solver Code

```python
#!/usr/bin/env python3
"""Organizer solve script for the Tetromino Cipher challenge."""

from __future__ import annotations

import json
import socket
import statistics
import time
from pathlib import Path

MASK32 = 0xFFFFFFFF
N_BITS = 128
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
TARGET_ROUNDS = 50
SAMPLES_PER_EQUATION = 41


def shift_left(vec: list[int], n: int) -> list[int]:
    if n == 0:
        return vec[:]
    return [0] * n + vec[:-n]


def shift_right(vec: list[int], n: int) -> list[int]:
    if n == 0:
        return vec[:]
    return vec[n:] + [0] * n


def xor_vec(*vecs: list[int]) -> list[int]:
    out = [0] * len(vecs[0])
    for v in vecs:
        for i, x in enumerate(v):
            out[i] ^= x
    return out


def init_symbolic_state() -> tuple[list[int], list[int], list[int], list[int]]:
    regs = []
    for reg_idx in range(4):
        reg = []
        for bit in range(32):
            var_id = reg_idx * 32 + bit
            reg.append(1 << var_id)
        regs.append(reg)
    return regs[0], regs[1], regs[2], regs[3]


def step_symbolic(state: tuple[list[int], list[int], list[int], list[int]]) -> tuple[tuple[list[int], list[int], list[int], list[int]], list[int]]:
    s0, s1, s2, s3 = state
    t = xor_vec(s0, shift_left(s0, 11))
    new_s3 = xor_vec(s3, shift_right(s3, 19), t, shift_right(t, 8))
    new_state = (s1, s2, s3, new_s3)
    return new_state, new_s3


def step_concrete(state: tuple[int, int, int, int]) -> tuple[tuple[int, int, int, int], int]:
    s0, s1, s2, s3 = state
    t = (s0 ^ ((s0 << 11) & MASK32)) & MASK32
    s0, s1, s2 = s1, s2, s3
    s3 = (s3 ^ (s3 >> 19) ^ t ^ (t >> 8)) & MASK32
    return (s0, s1, s2, s3), s3


def solve_linear_system(rows: list[int], rhs: list[int], nvars: int) -> list[int]:
    m = len(rows)
    rows = rows[:]
    rhs = rhs[:]

    pivot_col_for_row: list[int] = []
    row_i = 0

    for col in range(nvars):
        pivot = -1
        for r in range(row_i, m):
            if (rows[r] >> col) & 1:
                pivot = r
                break

        if pivot == -1:
            continue

        rows[row_i], rows[pivot] = rows[pivot], rows[row_i]
        rhs[row_i], rhs[pivot] = rhs[pivot], rhs[row_i]

        for r in range(m):
            if r != row_i and ((rows[r] >> col) & 1):
                rows[r] ^= rows[row_i]
                rhs[r] ^= rhs[row_i]

        pivot_col_for_row.append(col)
        row_i += 1
        if row_i == m:
            break

    for r in range(m):
        if rows[r] == 0 and rhs[r]:
            raise ValueError("Inconsistent linear system")

    solution = [0] * nvars
    for r, col in enumerate(pivot_col_for_row):
        solution[col] = rhs[r]

    return solution


def bits_to_state(bits: list[int]) -> tuple[int, int, int, int]:
    words = []
    for reg_idx in range(4):
        w = 0
        for bit in range(32):
            if bits[reg_idx * 32 + bit]:
                w |= 1 << bit
        words.append(w)
    return tuple(words)  # type: ignore[return-value]


def recover_state(leaked_bits: list[dict[str, int]], leak_positions: list[int]) -> tuple[int, int, int, int]:
    sym_state = init_symbolic_state()
    rows: list[int] = []
    rhs: list[int] = []

    for i, row in enumerate(leaked_bits):
        sym_state, sym_out = step_symbolic(sym_state)
        for bit_pos in leak_positions:
            rows.append(sym_out[bit_pos])
            rhs.append(int(row[str(bit_pos)]))

    sol_bits = solve_linear_system(rows, rhs, N_BITS)
    state = bits_to_state(sol_bits)

    # Sanity-check the recovered state against all leaked telemetry bits.
    check_state = state
    for row in leaked_bits:
        check_state, out = step_concrete(check_state)
        for bit_pos in leak_positions:
            if ((out >> bit_pos) & 1) != int(row[str(bit_pos)]):
                raise ValueError("Recovered state failed verification")

    return state


def decrypt_from_state(state: tuple[int, int, int, int], rounds: int, ciphertext: bytes) -> bytes:
    cur = state
    for _ in range(rounds):
        cur, _ = step_concrete(cur)

    ks = bytearray()
    while len(ks) < len(ciphertext):
        cur, out = step_concrete(cur)
        ks.extend(out.to_bytes(4, "little"))

    return bytes(c ^ k for c, k in zip(ciphertext, ks))


def recv_until_prompt(sock: socket.socket) -> str:
    buf = bytearray()
    while not buf.endswith(b"> "):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Disconnected while waiting for prompt")
        buf.extend(chunk)
    return buf.decode(errors="replace")


def send_cmd(sock: socket.socket, cmd: str) -> dict:
    sock.sendall((cmd + "\n").encode())
    data = recv_until_prompt(sock)

    # Remove trailing prompt marker and decode first JSON object (compact or pretty-printed).
    payload = data[:-2] if data.endswith("> ") else data
    decoder = json.JSONDecoder()
    start = payload.find("{")
    while start != -1:
        try:
            obj, _ = decoder.raw_decode(payload[start:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
        start = payload.find("{", start + 1)

    raise ValueError(f"No JSON response for command: {cmd}")


def sample_with_retry(sock: socket.socket, round_idx: int, bit: int, count: int) -> dict:
    while True:
        resp = send_cmd(sock, f"SAMPLE {round_idx} {bit} {count}")
        if "error" not in resp:
            return resp

        if resp["error"] == "rate limit exceeded":
            retry_after_ms = int(resp.get("retry_after_ms", 50))
            time.sleep(max(0.01, retry_after_ms / 1000.0))
            continue

        raise RuntimeError(f"oracle error: {resp}")


def fetch_handout_and_truth(host: str, port: int, samples_per_bit: int) -> tuple[dict, list[dict[str, int]]]:
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(20)
        recv_until_prompt(sock)

        handout = send_cmd(sock, "HANDOUT")
        rounds = int(handout["rounds"])
        leak_positions = [int(x) for x in handout["leak_bit_positions"]]
        rounds_to_query = min(TARGET_ROUNDS, rounds)

        denoised_rows: list[dict[str, int]] = []
        for r in range(rounds_to_query):
            row: dict[str, int] = {}
            for b in leak_positions:
                resp = sample_with_retry(sock, r, b, samples_per_bit)
                vals = [int(x) for x in resp["samples"]]
                # Majority vote is enough at this noise level and gives high reliability.
                row[str(b)] = int(round(statistics.mean(vals)))
            denoised_rows.append(row)

        return handout, denoised_rows


def main() -> None:
    handout, leaked_bits = fetch_handout_and_truth(DEFAULT_HOST, DEFAULT_PORT, SAMPLES_PER_EQUATION)

    rounds = int(handout["rounds"])
    leak_positions = [int(x) for x in handout["leak_bit_positions"]]
    ciphertext = bytes.fromhex(handout["ciphertext_hex"])

    recovered_state = recover_state(leaked_bits, leak_positions)
    flag = decrypt_from_state(recovered_state, rounds, ciphertext)

    print("[+] recovered initial state:", [hex(x) for x in recovered_state])
    print("[+] flag:", flag.decode())


if __name__ == "__main__":
    main()
```

---

## Final Execution

Command used to solve the remote service with the local solver:

```bash
python - <<'PY'
import importlib.util
from pathlib import Path

p = Path('solve/solve.py').resolve()
spec = importlib.util.spec_from_file_location('solve_mod', p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.DEFAULT_HOST = '48.199.16.26'
mod.DEFAULT_PORT = 9994
mod.main()
PY
```

Output:

```text
[+] recovered initial state: ['0x8c0ffee1', '0xdead10cc', '0xa17c9e51', '0x51f15eed']
[+] flag: CyberTrace{Y0uuu_Kn0W_73TR1S_W4S_My_F4V0R1Te_G8m3}
```

---

## Final Flag

```text
CyberTrace{Y0uuu_Kn0W_73TR1S_W4S_My_F4V0R1Te_G8m3}
```

---

## Key Notes

- You do not need to reverse the decoy telemetry fields.
- The exploitable surface is noisy sparse bit leakage from `SAMPLE`.
- This is a linear-state recovery problem over GF(2).
- Respect rate limits and budget; `use retry + majority voting`.
- Once state is recovered, decryption is deterministic and immediate.
