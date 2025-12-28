---
title: "Rng - CTF Writeup"
date: 2025-12-27
draft: false
description: "Cryptography challenge writeup"
tags: ["Cryptography", "Hard"]
categories: ["Writeups"]
---

**Challenge Name:** Rng  
**Category:** Cryptography  
**CTF:** ClawTheFlag  
**Difficulty:** Hard  
**Description:** *I love rng , who doesn't ? (im lying)*  

---

## Challenge Overview

We're given a DSA (Digital Signature Algorithm) implementation where the nonces are generated using a Linear Congruential Generator (LCG). However, there's a critical vulnerability: the LCG outputs are truncated by discarding the lower 32 bits before being used as nonces.

### Files Provided

- `src.sage` - The challenge source code showing how signatures are generated
```sage
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

def gen_challenge():
    q = random_prime(2^160 - 1, False, 2^159)
    
    t = 2^864 // q
    if t % 2 != 0: t += 1
    
    while True:
        p = t * q + 1
        if p.is_prime():
            break
        t += 2
        
    e = (p - 1) // q
    while True:
        h = randint(2, p - 1)
        g = power_mod(h, e, p)
        if g != 1:
            break
            
    x = randint(1, q - 1)
    y = power_mod(g, x, p)
    
    a = randint(2, q - 1)
    b = randint(1, q - 1)
    
    signatures = []
    msgs = [b"Welcome to the challenge", b"This is a signed message", b"Hope U can Solve this"]
    
    state = randint(1, q - 1)
    
    hidden_bits = 32
    mask = (1 << hidden_bits) - 1
    
    for msg in msgs:
        state = (a * state + b) % q
        
        k = state >> hidden_bits
        
        if k == 0: k = 1 
        
        m_hash = int(hashlib.sha1(msg).hexdigest(), 16)
        
        r = power_mod(g, k, p) % q
        if r == 0: continue
        
        k_inv = inverse_mod(k, q)
        s = (k_inv * (m_hash + x * r)) % q
        if s == 0: continue
        
        signatures.append({
            'msg': msg.decode(),
            'h': m_hash,
            'r': r,
            's': s
        })
        
    FLAG = b"Cybears{REDACTED}"
    key = hashlib.sha256(str(x).encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    
    output = []
    output.append("=== Public Parameters ===")
    output.append(f"p = {p}")
    output.append(f"q = {q}")
    output.append(f"g = {g}")
    output.append(f"y = {y}")
    output.append(f"a = {a}")
    output.append(f"b = {b}")
    output.append("")
    output.append("=== Signatures ===")
    for i, sig in enumerate(signatures):
        output.append(f"Msg {i}: {sig['msg']}")
        output.append(f"r: {sig['r']}")
        output.append(f"s: {sig['s']}")
        output.append("")
        
    output.append("=== Encrypted Flag ===")
    output.append(f"iv = {iv.hex()}")
    output.append(f"ciphertext = {ciphertext.hex()}")
    
    with open("out.txt", "w") as f:
        f.write("\n".join(output))
        

if __name__ == "__main__":
    gen_challenge()

```

- `out.txt` - Output file containing public parameters, three signatures, and an encrypted flag
```txt
=== Public Parameters ===
p = 123003155723136208567847447683223664415731869180715065944930703618254955521953492303010368693540149343822709050322214299552689203876695953600699775494388206142090885899729347827083318884583758435450548517566916661303540194105874846318704235833742951730395387893
q = 1351421998290697311075336828328868237101534073971
g = 33281778595201387261293626747615008705518327664613367247692358327331920321800338423029474043243916236688059227689255073131577344900473973707320419626540150438125115514005329631925252477669281215047423532322256514575254413979623373756671730097875278551744512292
y = 3307176365914197161077112919302114465012288764080495710556781650276230163105901770805655058452596531663862930554036441352621088291225804501623324989790865151454288524834303112917325796231214885559000730116030759472981610816425452002018684702872269406185707624
a = 1133017228114262159970528021801337885090356344787
b = 936311987844784871482813416133128695274329562672

=== Signatures ===
Msg 0: Welcome to the challenge
r: 915875771377874108142817390807358778656074043192
s: 702187177606022918474498802326245196106161318996

Msg 1: This is a signed message
r: 399768373000447995442743550681355809407336352895
s: 1326361401622173194474654662518094360274404497842

Msg 2: Hope U can Solve this
r: 1106708731356503672778052636855852639695964424325
s: 514444627373315433335058189992763090727319953242

=== Encrypted Flag ===
iv = 084e4fb08250493e6fbbcbf4b16f31c8
ciphertext = e2ffb4339675cca22ae6770e68a26b0e5ae2421ca10cd597ce3a033f08083cfb642253d27ee29ae5ab928fed7816aae76e9ea4795a3bb91f5a9df08d1a1dd539

```

## Analysis

### The Vulnerability

Looking at the source code, we can identify the key vulnerability:

```python
state = randint(1, q - 1)  # Initial random state

hidden_bits = 32
mask = (1 << hidden_bits) - 1

for msg in msgs:
    state = (a * state + b) % q  # LCG update
    
    k = state >> hidden_bits  # Only use upper bits as nonce!
    
    # DSA signature generation
    r = power_mod(g, k, p) % q
    k_inv = inverse_mod(k, q)
    s = (k_inv * (m_hash + x * r)) % q
```

The problem is that:
1. **Nonces are predictable**: They follow an LCG: `state_i = (a * state_{i-1} + b) mod q`
2. **Partial information leakage**: Only the upper bits are used: `k_i = state_i >> 32`
3. **Known LCG parameters**: Both `a` and `b` are publicly revealed in the output

### Why This Is Exploitable

In standard DSA, if you can recover or predict the nonce `k`, you can recover the private key `x` from the signature equation:

```
s = k^(-1) * (h + x * r) mod q
=> x = (s * k - h) * r^(-1) mod q
```

Here, we have:
- Three consecutive signatures using three consecutive LCG states
- The LCG parameters `a` and `b` are known
- Each nonce `k_i` is related to its state: `k_i = state_i >> 32`

This means `state_i = k_i * 2^32 + u_i` where `u_i` are the unknown lower 32 bits (0 ≤ u_i < 2^32).

## Attack Strategy

### Step 1: Set Up the Problem

From the DSA signature equations, we know:
```
s_i * k_i ≡ h_i + x * r_i (mod q)
```

Where `k_i` are the truncated nonces. Rearranging:
```
k_i = (h_i + x * r_i) * s_i^(-1) (mod q)
```

From the LCG relation:
```
state_{i+1} = a * state_i + b (mod q)
```

Substituting `state_i = k_i * B + u_i` (where B = 2^32):
```
k_{i+1} * B + u_{i+1} = a * (k_i * B + u_i) + b (mod q)
```

### Step 2: Eliminate the Private Key

To create a system independent of `x`, we combine two consecutive signature equations:

From signatures 0 and 1:
```
k_0 = (h_0 + x*r_0) * s_0^(-1) (mod q)
k_1 = (h_1 + x*r_1) * s_1^(-1) (mod q)
```

Substituting into the LCG equation and rearranging:
```
x * (r_1*s_1^(-1)*B - a*r_0*s_0^(-1)*B) ≡ a*h_0*s_0^(-1)*B - h_1*s_1^(-1)*B + b + (a*u_0 - u_1) (mod q)
```

Let's denote:
- `A_01 = r_1*s_1^(-1)*B - a*r_0*s_0^(-1)*B (mod q)`
- `C_01 = a*h_0*s_0^(-1)*B - h_1*s_1^(-1)*B + b (mod q)`
- `δ_01 = a*u_0 - u_1`

Then: `x * A_01 ≡ C_01 + δ_01 (mod q)`

Similarly for signatures 1 and 2:
- `x * A_12 ≡ C_12 + δ_12 (mod q)`

### Step 3: Lattice Attack to Find Hidden Bits

For both equations to give the same `x`, we need:
```
δ_01 * A_12 - δ_12 * A_01 ≡ C_12*A_01 - C_01*A_12 (mod q)
```

Expanding in terms of the hidden bits:
```
a*u_0*A_12 - u_1*(A_12 + a*A_01) + u_2*A_01 ≡ target (mod q)
```

This is a linear equation in small unknowns `(u_0, u_1, u_2)` where each `u_i < 2^32`. We can solve this using **lattice reduction**!

We construct a lattice where the short vector reveals the hidden bits:

```
L = [
    [q,                            0, 0, 0],
    [a*A_12 mod q,                 1, 0, 0],
    [-(A_12 + a*A_01) mod q,       0, 1, 0],
    [A_01 mod q,                   0, 0, 1]
]
```

Using LLL reduction and CVP (Closest Vector Problem) with Babai's algorithm, we find the vector closest to `(target, 0, 0, 0)`, which gives us `(target, u_0, u_1, u_2)`.

### Step 4: Recover the Private Key

Once we have the hidden bits `u_0, u_1, u_2`, we can compute:
```
x = (C_01 + a*u_0 - u_1) * A_01^(-1) (mod q)
```

### Step 5: Decrypt the Flag

The flag is encrypted with AES-CBC using a key derived from the private key:
```python
key = SHA256(str(x))
```

## Solution

### Complete Solver Script

```sage
# Rng CTF Challenge Solver
import hashlib

# Parse the output file
with open("out.txt", "r") as f:
    lines = f.read().strip().split('\n')

# Extract public parameters
p = Integer(lines[1].split(' = ')[1])
q = Integer(lines[2].split(' = ')[1])
g = Integer(lines[3].split(' = ')[1])
y = Integer(lines[4].split(' = ')[1])
a = Integer(lines[5].split(' = ')[1])  # LCG parameter
b = Integer(lines[6].split(' = ')[1])  # LCG parameter

# Extract signatures (remember: 0-indexed)
r1 = Integer(lines[10].split(': ')[1])
s1 = Integer(lines[11].split(': ')[1])
r2 = Integer(lines[14].split(': ')[1])
s2 = Integer(lines[15].split(': ')[1])
r3 = Integer(lines[18].split(': ')[1])
s3 = Integer(lines[19].split(': ')[1])

# Compute message hashes
msgs = [b"Welcome to the challenge", b"This is a signed message", b"Hope U can Solve this"]
h1 = Integer(int(hashlib.sha1(msgs[0]).hexdigest(), 16))
h2 = Integer(int(hashlib.sha1(msgs[1]).hexdigest(), 16))
h3 = Integer(int(hashlib.sha1(msgs[2]).hexdigest(), 16))

signatures = [(h1, r1, s1), (h2, r2, s2), (h3, r3, s3)]

print("=== LCG-DSA Attack ===\n")

hidden_bits = 32
B = 2^hidden_bits  # B = 2^32
n = 3  # Number of signatures

h0, r0, s0 = signatures[0]
h1, r1, s1 = signatures[1]
h2, r2, s2 = signatures[2]

# Compute modular inverses of signature values
s0_inv = inverse_mod(s0, q)
s1_inv = inverse_mod(s1, q)
s2_inv = inverse_mod(s2, q)

# Compute coefficients A and C for the linear system
# For signatures 0-1:
A_01 = (r1*s1_inv*B - a*r0*s0_inv*B) % q
C_01 = (a*h0*s0_inv*B - h1*s1_inv*B + b) % q

# For signatures 1-2:
A_12 = (r2*s2_inv*B - a*r1*s1_inv*B) % q
C_12 = (a*h1*s1_inv*B - h2*s2_inv*B + b) % q

# Compute the target value for our lattice attack
target = (C_12*A_01 - C_01*A_12) % q

print(f"Target value: {target}")
print(f"Setting up lattice to solve for hidden bits...\n")

# Build a 4x4 lattice to solve for (u_0, u_1, u_2)
# We need: a*u_0*A_12 - u_1*(A_12 + a*A_01) + u_2*A_01 ≡ target (mod q)
dim = 4
L = Matrix(ZZ, dim, dim)

L[0, 0] = q
L[1, 0] = (a * A_12) % q
L[1, 1] = 1
L[2, 0] = (-(A_12 + a*A_01)) % q
L[2, 2] = 1
L[3, 0] = A_01 % q
L[3, 3] = 1

# Apply LLL reduction
print("Applying LLL reduction...")
L_LLL = L.LLL()
print("LLL complete!\n")

# Babai's nearest plane algorithm for CVP
def babai(L_LLL, target):
    """Find the closest lattice vector to target using Babai's algorithm"""
    G = L_LLL.gram_schmidt()[0]
    t_cur = target
    coeffs = []
    for i in range(L_LLL.nrows()-1, -1, -1):
        c = (t_cur * G[i]) / (G[i] * G[i])
        c = round(c)
        coeffs.insert(0, c)
        t_cur = t_cur - c * L_LLL[i]
    
    v = sum(coeffs[i] * L_LLL[i] for i in range(L_LLL.nrows()))
    return v

# Solve CVP
t = vector(ZZ, [target, 0, 0, 0])
closest = babai(L_LLL, t)

print(f"Closest vector found: {closest}\n")

# Extract the hidden bits from the solution
u_0 = abs(closest[1])
u_1 = abs(closest[2])
u_2 = abs(closest[3])

print(f"Recovered hidden bits:")
print(f"  u_0 = {u_0}")
print(f"  u_1 = {u_1}")
print(f"  u_2 = {u_2}")

# Verify they're in valid range (< 2^32)
if u_0 < B and u_1 < B and u_2 < B:
    print("✓ Hidden bits are valid!\n")
    
    # Compute the private key x
    delta_01 = (a*u_0 - u_1) % q
    x = ((C_01 + delta_01) * inverse_mod(A_01, q)) % q
    
    # Verify with the second equation
    delta_12 = (a*u_1 - u_2) % q
    x_check = ((C_12 + delta_12) * inverse_mod(A_12, q)) % q
    
    if x == x_check:
        print("✓ Private key verified with both equations!")
        
        # Final verification: check all signatures and LCG relations
        print("\nVerifying all signatures and LCG relations...")
        
        k_0 = ((h0 + x*r0) * inverse_mod(s0, q)) % q
        k_1 = ((h1 + x*r1) * inverse_mod(s1, q)) % q
        k_2 = ((h2 + x*r2) * inverse_mod(s2, q)) % q
        
        state_0 = k_0*B + u_0
        state_1 = k_1*B + u_1
        state_2 = k_2*B + u_2
        
        # Check LCG relations
        lcg_check_1 = (a*state_0 + b) % q == state_1
        lcg_check_2 = (a*state_1 + b) % q == state_2
        
        if lcg_check_1 and lcg_check_2:
            print("✓ All LCG relations verified!")
            print("\n" + "="*50)
            print("SUCCESS!")
            print("="*50)
            print(f"\nPrivate key (x): {x}\n")
            
            # Save the private key
            with open("private_key.txt", "w") as f:
                f.write(str(x))
            print("Private key saved to private_key.txt")
        else:
            print("✗ LCG verification failed")
    else:
        print("✗ Private key verification failed")
else:
    print("✗ Hidden bits out of valid range")
```

### Decryption Script

```python
# decrypt_flag.py
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Read the recovered private key
with open("private_key.txt", "r") as f:
    x = int(f.read().strip())

# Parse the encrypted flag from output file
with open("out.txt", "r") as f:
    lines = f.read().strip().split('\n')

iv = bytes.fromhex(lines[22].split(' = ')[1])
ciphertext = bytes.fromhex(lines[23].split(' = ')[1])

# Derive the AES key from the private key
key = hashlib.sha256(str(x).encode()).digest()

# Decrypt the flag
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), 16)

print(f"Flag: {plaintext.decode()}")
```

## Running the Solution

```bash
# Run the Sage solver to recover the private key
sage solve_final.sage

# Decrypt the flag using the recovered key
python3 decrypt_flag.py
```

## Flag

```
Cybears{lil_bit_truncated_lil_bit_signature_and_thats_the_flag}
```

## Key Takeaways

1. **Never use predictable RNGs for cryptographic nonces**: Even with a cryptographically secure LCG, truncating the output leaks information.

2. **Bit truncation is dangerous**: Discarding the lower 32 bits of a 160-bit value creates a Hidden Number Problem that can be solved with lattice techniques.

3. **Lattice attacks are powerful**: When you have linear equations with small unknowns over a modulus, lattice reduction (LLL) combined with CVP solving can recover those unknowns.

4. **DSA requires truly random nonces**: Any bias, predictability, or partial information leakage in DSA nonces can lead to complete private key recovery.

## References

- [The Hidden Number Problem](https://en.wikipedia.org/wiki/Hidden_number_problem)
- [Lattice Attacks on DSA Schemes](https://eprint.iacr.org/2019/023.pdf)
- [Recovering Cryptographic Keys from Partial Information](https://www.iacr.org/archive/crypto2003/27290019/27290019.pdf)
- [LLL Algorithm](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)

---

