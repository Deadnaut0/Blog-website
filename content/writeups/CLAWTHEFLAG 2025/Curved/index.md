---
title: "Curved - CTF Writeup"
date: 2025-12-27
draft: false
description: "Cryptography challenge writeup"
tags: ["Cryptography", "Easy"]
categories: ["Writeups"]
---

**Challenge Name:** Curved  
**Category:** Cryptography  
**CTF:** ClawTheFlag  
**Difficulty:** Easy  
**Description:** *Just An other ecc challenge*  

---

## TL;DR
The curve was **anomalous**: its group order equals the prime field size ($\#E(\mathbb{F}_p) = p$). This enables **Smart's attack**, letting us solve the ECDLP in linear time, recover Bob's private key, derive the shared secret, and decrypt the flag.

## Challenge Artefacts
- Script: `server.py` (provided)
```python

import json
import os
import hashlib
from random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from sage.all import EllipticCurve, GF

SECRET_FLAG = b'Cybears{fake_flag}'


prime_mod = 98525254601464748798796659245875458879425316953529501999447929215987731776997
coeff_a = 0x1c456bfc3fabba99a737d7fd127eaa9661f7f02e9eb2d461d7398474a93a9b87
coeff_b = 0x8b429f4b9d14ed4307ee460e9f8764a1f276c7e5ce3581d8acd4604c2f0ee7ca


curve = EllipticCurve(GF(prime_mod), [coeff_a, coeff_b])



base_point = curve.gens()[0]
gx, gy = base_point.xy()

def gen_key():
    priv = randint(1, curve.order() - 1)
    pub = base_point * priv
    return pub, priv

def calc_shared(pub_key, priv_key):
    point = pub_key * priv_key
    return point.xy()[0]

def enc(secret):

    bob_pub, bob_priv = gen_key()
    bx, by = bob_pub.xy()


    alice_pub, alice_priv = gen_key()


    secret_value = calc_shared(bob_pub, alice_priv)
    key = hashlib.sha1(str(secret_value).encode()).digest()[:16]


    iv_bytes = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
    ciphertext_bytes = cipher.encrypt(pad(secret, 16))


    payload = {
        "iv": iv_bytes.hex(),
        "encrypted_flag": ciphertext_bytes.hex(),
        "bob_public_key": {"x": hex(bx), "y": hex(by)},
        "alice_public_key": {"x": hex(alice_pub.xy()[0]), "y": hex(alice_pub.xy()[1])},
        "generator": {"x": hex(gx), "y": hex(gy)}
    }
    return json.dumps(payload, indent=4)
    
output_json = enc(SECRET_FLAG)
print(output_json)

# output
# data = {
#     "iv": "ee3991136f084b6b54fc03ea87d3309f",
#     "encrypted_flag": "a234a9b4e3140566f365660a6ad70af524d0c57819e8d5d52a80c0964e58583ffed62a06f14ea378ba773c831cb0a65d",
#     "bob_public_key": {
#         "x": "0x499fa531c6e4c3726147ed0fd9c6529f1a12f0c783ff90747de9d82299aa20fb",
#         "y": "0x7f05d4fbab1b838661327e03a2077a7b1397038d56d74aae8d49749c393d2ea6"
#     },
#     "alice_public_key": {
#         "x": "0x2404dc8f95e9203581f79188dada1f6738a7caf88d31a540d9e5c37f73d4f0cb",
#         "y": "0x2b3233a83e1ed08cdc55ed47887ac04aa6a24881f03646f12047c6e0e50ec8f6"
#     },
#     "generator": {
#         "x": "0xad474d1a2709090faaf4ebf6ede7cb71c8917c60519ab581818716b9ad5969ae",
#         "y": "0x3fc125df9f61ac41fd36e257e31d0e8d33434ca32127d32ff40a53a41c7ab374"
#     }
# }

```
- Output JSON (public info):
  - `iv`: `ee3991136f084b6b54fc03ea87d3309f`
  - `encrypted_flag`: `a234...0a65d`
  - `bob_public_key`: `(0x499f..., 0x7f05...)`
  - `alice_public_key`: `(0x2404..., 0x2b32...)`
  - `generator`: `(0xad47..., 0x3fc1...)`


## Understanding the Scheme
- Elliptic curve over $\mathbb{F}_p$ with parameters `coeff_a`, `coeff_b`, and generator `G`.
- Key exchange: both parties generate ephemeral keys; shared secret is the x-coordinate of `alice_priv * bob_pub`.
- AES-CBC encryption uses key = SHA1(shared_x) truncated to 16 bytes; IV is random.

## Finding the Vulnerability
1. Compute curve discriminant to ensure non-singular (it is non-singular).
2. Compute group order: `order = curve.order()`.
3. Observation: `order == p`. Such curves are called **anomalous curves**.
4. Anomalous curves are vulnerable to **Smart's attack**, which reduces ECDLP to a linear-time computation via a p-adic lift.

### Why Smart's Attack Works
- For an anomalous curve, there is an isomorphism from the curve group to $(\mathbb{Z}/p\mathbb{Z}, +)$ obtained via a p-adic logarithm.
- After lifting points to $\mathbb{Q}_p$, the discrete log `n` for `Q = nP` is recovered from p-adic coordinates of `pP` and `pQ`.

## Exploitation Steps
1. **Set up the curve** in Sage with the given parameters and public points.
2. **Run Smart's attack** to solve for Bob's private key `k_B` from `bob_pub = k_B * G`.
3. **Derive shared secret**: `S = k_B * alice_pub`; use the x-coordinate `S.x`.
4. **Derive AES key**: `key = SHA1(str(S.x))[:16]`.
5. **Decrypt** the ciphertext with AES-CBC using the provided IV.

## Key Scripts (high level)
- `smart_attack.sage`: Implements Smart's attack for the anomalous curve, outputs `SECRET_VALUE = S.x`.
- `decrypt.py`: Uses `SECRET_VALUE` to derive AES key and decrypt the flag.

## Solver (step-by-step)

1. Run Smart's attack to recover the shared secret x-coordinate:

```bash
sage smart_attack.sage
```

```sage
from sage.all import *

# Given parameters
p = 98525254601464748798796659245875458879425316953529501999447929215987731776997
a = 0x1c456bfc3fabba99a737d7fd127eaa9661f7f02e9eb2d461d7398474a93a9b87
b = 0x8b429f4b9d14ed4307ee460e9f8764a1f276c7e5ce3581d8acd4604c2f0ee7ca

# Output data
gx = int("0xad474d1a2709090faaf4ebf6ede7cb71c8917c60519ab581818716b9ad5969ae", 16)
gy = int("0x3fc125df9f61ac41fd36e257e31d0e8d33434ca32127d32ff40a53a41c7ab374", 16)

bob_x = int("0x499fa531c6e4c3726147ed0fd9c6529f1a12f0c783ff90747de9d82299aa20fb", 16)
bob_y = int("0x7f05d4fbab1b838661327e03a2077a7b1397038d56d74aae8d49749c393d2ea6", 16)

alice_x = int("0x2404dc8f95e9203581f79188dada1f6738a7caf88d31a540d9e5c37f73d4f0cb", 16)
alice_y = int("0x2b3233a83e1ed08cdc55ed47887ac04aa6a24881f03646f12047c6e0e50ec8f6", 16)

# Create curve
F = GF(p)
E = EllipticCurve(F, [a, b])

G = E(gx, gy)
bob_pub = E(bob_x, bob_y)
alice_pub = E(alice_x, alice_y)

print(f"Curve order: {E.order()}")
print(f"Prime p: {p}")
print(f"Anomalous: {E.order() == p}")

# Smart's Attack for anomalous curves
def smart_attack(P, Q, p):
    """
    Smart's attack on anomalous curves.
    Given P and Q = n*P, returns n.
    """
    E = P.curve()
    
    # Lift curve to Qp (p-adic field)
    Qp_field = Qp(p, 2)  # precision 2
    
    # Get curve coefficients
    a4 = ZZ(E.a4())
    a6 = ZZ(E.a6())
    
    # Create curve over Qp
    Ep = EllipticCurve(Qp_field, [a4, a6])
    
    # Hensel lift a point from E to Ep
    def hensel_lift(Pt):
        x_val = ZZ(Pt.xy()[0])
        y_val = ZZ(Pt.xy()[1])
        
        # y^2 = x^3 + a4*x + a6
        # We need y' such that y'^2 ≡ x^3 + a4*x + a6 (mod p^2)
        # Using Newton's method: y' = y + t*p where t = (rhs - y^2)/(2*y*p)
        
        rhs = x_val^3 + a4 * x_val + a6
        
        # t = (rhs - y_val^2) / (2 * y_val * p)
        # We need this mod p
        numerator = (rhs - y_val^2) // p  # This should be an integer
        denominator = 2 * y_val
        t = ZZ(Mod(numerator, p) * Mod(denominator, p)^(-1))
        
        y_lifted = y_val + t * p
        
        return Ep(Qp_field(x_val), Qp_field(y_lifted))
    
    # Lift points
    P_lift = hensel_lift(P)
    Q_lift = hensel_lift(Q)
    
    # Compute p * P_lift and p * Q_lift
    pP = p * P_lift
    pQ = p * Q_lift
    
    # Get coordinates
    x_pP = pP.xy()[0]
    y_pP = pP.xy()[1]
    x_pQ = pQ.xy()[0]
    y_pQ = pQ.xy()[1]
    
    # The discrete log is: n = φ(Q) / φ(P) where φ is the p-adic log
    # For anomalous curves: φ(P) = -x(pP) / y(pP)
    # So n = (x(pQ)/y(pQ)) / (x(pP)/y(pP)) = x(pQ)*y(pP) / (x(pP)*y(pQ))
    
    phi_P = -x_pP / y_pP
    phi_Q = -x_pQ / y_pQ
    
    n = phi_Q / phi_P
    
    return ZZ(n) % p

print("\nRunning Smart's attack...")
bob_priv = smart_attack(G, bob_pub, p)
print(f"Bob's private key: {bob_priv}")

# Verify
if bob_priv * G == bob_pub:
    print("Verification: bob_priv * G == bob_pub ✓")
else:
    print("WARNING: Verification failed!")
    # Try negative
    bob_priv = p - bob_priv
    if bob_priv * G == bob_pub:
        print(f"Corrected Bob's private key: {bob_priv}")
        print("Verification after correction: ✓")

# Calculate shared secret
shared_point = bob_priv * alice_pub
shared_x = ZZ(shared_point.xy()[0])
print(f"\nShared secret x-coordinate: {shared_x}")

print(f"\n=== FOR DECRYPTION ===")
print(f"SECRET_VALUE = {shared_x}")

```
Expected important output:

```
Bob's private key: <...>
Verification: bob_priv * G == bob_pub ✓
Shared secret x-coordinate: 70195069208381892934585902848485094050700408152976961917545624632484143189611
=== FOR DECRYPTION ===
SECRET_VALUE = 70195069208381892934585902848485094050700408152976961917545624632484143189611
```

2. Decrypt with AES-CBC using that secret:

```bash
python decrypt.py
```

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Data from the challenge
iv = bytes.fromhex("ee3991136f084b6b54fc03ea87d3309f")
encrypted_flag = bytes.fromhex("a234a9b4e3140566f365660a6ad70af524d0c57819e8d5d52a80c0964e58583ffed62a06f14ea378ba773c831cb0a65d")

# Shared secret x-coordinate from Smart's attack
SECRET_VALUE = 70195069208381892934585902848485094050700408152976961917545624632484143189611

# Derive key (same as in server.py)
key = hashlib.sha1(str(SECRET_VALUE).encode()).digest()[:16]

# Decrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(encrypted_flag), 16)

print(f"FLAG: {plaintext.decode()}")

```
Expected output:

```
FLAG: cybears{...}
```

## Math Notes (compact)
- Anomalous condition: $\#E(\mathbb{F}_p) = p$.
- Smart's attack recovers $n$ where $Q = nP$ via
  $$n \equiv \frac{-x(pQ)/y(pQ)}{-x(pP)/y(pP)} \pmod p.$$

## Final Flag
```
cybears{YOUR_ATTACK_IS_TOO_SMART!!!!}
```

## Takeaways
- Never use anomalous curves in ECC; they collapse ECDLP hardness.
- Always validate curve parameters and group order; use standardized safe curves.
- Do not rely on home-rolled curves without security proofs or standard review.
