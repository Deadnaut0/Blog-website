---
title: "Broken Signatures - CTF Writeup"
date: 2026-02-11
draft: false
description: "Cryptography challenge writeup"
tags: ["Cryptography"]
categories: ["Writeups"]
---

**Challenge Name:** Broken Signatures  
**Category:** Cryptography  
**CTF:** MOJO-JOJO  
**Description:** Good Luck during this adventure , little crypto knight
**Connection:** `nc 20.199.19.9 1945`

---

## Challenge Description

The server presents a challenge called "NONCE SENSE CHALLENGE" with the following interface:

```
╔══════════════════════════════════════════════════════════╗
║                   NONCE SENSE CHALLENGE                  ║
║                                                          ║
║  I sign messages with ECDSA (secp256k1) and leak R=k*G.  ║
║  Can you forge a signature for "Give me the flag!"?      ║
║                                                          ║
║  Commands:                                               ║
║   1. Get signature for any message                       ║
║   2. Try to get flag by providing signature              ║
║   3. Show public key                                     ║
║   4. Exit                                                ║
║                                                          ║
║  Note: I only accept 200 signing requests.               ║
╚══════════════════════════════════════════════════════════╝
```

The server implements ECDSA signatures on the secp256k1 curve and:

- Signs any message we provide (up to 200 times)
- Leaks the nonce point `R = k*G` for each signature
- Requires us to forge a valid signature for the message "Give me the flag!"

## Initial Analysis

### Understanding ECDSA

In ECDSA, a signature consists of two values `(r, s)`:

- `r` is the x-coordinate of the nonce point `R = k*G`
- `s = k^(-1)(z + r*d) mod n` where:
  - `k` is the secret nonce
  - `z` is the hash of the message
  - `d` is the private key
  - `n` is the curve order

### The Leak

The server leaks the full nonce point `R = (R.x, R.y)` for each signature. This is unusual because normally only `r = R.x` is revealed as part of the signature.

### Challenge Name Hint

"NONCE SENSE" strongly suggests the vulnerability is related to nonce handling - possibly:

- Nonce reuse
- Predictable nonce generation
- Weak random number generator

## Exploration and Dead Ends

### Attempt 1: Nonce Reuse Attack

The classic ECDSA vulnerability occurs when the same nonce `k` is used for two different messages. If `k` is reused:

```
s1 = k^(-1)(z1 + r*d)
s2 = k^(-1)(z2 + r*d)
```

From these equations, we can recover:

```
k = (z1 - z2) / (s1 - s2) mod n
d = (s*k - z) / r mod n
```

**Result:** Collected 200 signatures but found **no nonce reuse**. Each signature had a unique `r` value.

### Attempt 2: Predictable Nonce Generation

Tested if nonces were generated predictably, such as:

- `k = hash(message) mod n`
- `k` being constant
- Simple patterns

**Result:** None of these hypotheses matched. The nonce generation appeared cryptographically sound.

### Attempt 3: Mathematical Attacks

Investigated various ECDSA attacks:

- Using leaked R points to recover k (discrete log problem - infeasible)
- Biased nonce bits (not present)
- Lattice attacks (requires partial nonce leakage)

**Result:** No viable mathematical attack found.

## The Breakthrough

### Discovery: Deterministic Signatures

While testing the server, I discovered something interesting: **requesting a signature for the same message multiple times produces identical `(r, s)` values!**

```python
# Testing with "Give me the flag!" - all signatures identical:
Signature 1: r=0x489fbbdc..., s=0x32fb8ec5...
Signature 2: r=0x489fbbdc..., s=0x32fb8ec5...
Signature 3: r=0x489fbbdc..., s=0x32fb8ec5...
```

This means the server uses **deterministic ECDSA** (likely RFC 6979), where nonces are derived deterministically from the private key and message.

### The "Vulnerability"

The challenge isn't about breaking ECDSA cryptographically. It's about understanding that:

1. We can request a signature for **any** message
2. "Give me the flag!" is just another message
3. The signature we need is... the one the server gives us!

This is more of a logic puzzle than a cryptographic exploit. The challenge asks us to "forge" a signature, but technically we're not forging anything - we're legitimately obtaining it from the signing oracle.

## Solution

The solution is straightforward:

1. **Connect to the server**
2. **Request a signature for "Give me the flag!"** (command 1)
3. **Extract the r and s values** from the server's response
4. **Submit those values** as the signature (command 2)
5. **Receive the flag**

### Exploitation Code

```python
#!/usr/bin/env python3
import socket
import time
import re

msg_hex = "47697665206d652074686520666c616721"  # "Give me the flag!"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("20.199.19.9", 1945))
sock.settimeout(10)

def recv_all(timeout=1):
    sock.settimeout(timeout)
    data = b''
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors='ignore')

# Banner
recv_all(2)

print("[*] Step 1: Get signature for target message")
sock.send(b"1\n")
time.sleep(0.1)
recv_all(0.5)

sock.send(msg_hex.encode() + b"\n")
time.sleep(0.1)
response = recv_all(1)

# Parse r and s
match_r = re.search(r'r = (0x[0-9a-f]+)', response)
match_s = re.search(r's = (0x[0-9a-f]+)', response)

r_val = match_r.group(1)
s_val = match_s.group(1)

print(f"[+] Got signature:")
print(f"    r = {r_val}")
print(f"    s = {s_val}")

print("\n[*] Step 2: Submit the signature")
sock.send(b"2\n")
time.sleep(0.1)
recv_all(0.5)

print("[*] Sending r...")
sock.send(r_val.encode() + b"\n")
time.sleep(0.1)
recv_all(0.5)

print("[*] Sending s...")
sock.send(s_val.encode() + b"\n")
time.sleep(0.1)
final_response = recv_all(2)

sock.close()

print(f"\n[*] FINAL SERVER RESPONSE:")
print(final_response)
```

### Execution

```bash
$ python3 correct_exploit.py
[*] Step 1: Get signature for target message
[+] Got signature:
    r = 0xb186388295fc648085e2da25d82ff4373fdd4fcd7ca755e2a0fc861f52229094
    s = 0x285b9ca813001c1d1c26a8bc288e1ac69dcc2547a24f1999c0bf3ecc2490cf6e

[*] Step 2: Submit the signature
[*] Sending r...
[*] Sending s...

[*] FINAL SERVER RESPONSE:

[SUCCESS] Flag: MOJO-JOJO{WH0_3V3R_L0V35_3CD5A_BR00}
```

## Flag

```
MOJO-JOJO{WH0_3V3R_L0V35_3CD5A_BR00}
```

## Lessons Learned

1. **Think Outside the Cryptographic Box**: Not every crypto challenge requires breaking cryptography. Sometimes the vulnerability is in the challenge design or protocol logic.

2. **Test Assumptions**: The challenge hints at nonce problems, but the actual solution was much simpler. Always test basic assumptions first.

3. **Signing Oracles Are Powerful**: In real-world scenarios, if an attacker can request signatures for arbitrary messages, they effectively have the signing key for practical purposes.

4. **Deterministic ECDSA**: While RFC 6979 deterministic ECDSA is cryptographically sound and prevents nonce reuse vulnerabilities, it doesn't prevent someone from requesting signatures for any message they want!
