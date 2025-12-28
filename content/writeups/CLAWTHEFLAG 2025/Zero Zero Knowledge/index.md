---
title: "ZERO ZERO-Knowledge - CTF Writeup"
date: 2025-12-27
draft: false
description: "Blockchain challenge writeup"
tags: ["Blockchain", "Hard"]
categories: ["Writeups"]
---

**Challenge Name:** ZERO ZERO-Knowledge  
**Category:** Blockchain  
**CTF:** ClawTheFlag  
**Difficulty:** Hard  
**Description:** *Zero description.*  
**Connection:** `nc 13.61.1.167 31338`  

---

## Initial Reconnaissance

The challenge provides minimal information - just a netcat connection. Let's start by probing the service:

```bash
nc 13.61.1.167 31338
```

**Output:**
```
1 - launch new instance
2 - kill instance
3 - get flag (if isSolved() is true)
action?
```

The service presents a menu with three options. Attempting option 1 triggers a Proof-of-Work challenge:

```
== PoW ==
  sha256("7a39c8374cbb964e" + YOUR_INPUT) must start with 24 zeros in binary representation
  please run the following command to solve it:
    python3 <(curl -sSL https://minaminao.github.io/tools/solve-pow.py) 7a39c8374cbb964e 24
```

This is a computational puzzle requiring us to find an input such that `SHA256(nonce + input)` produces a hash with 24 leading zero bits.

---

## Understanding the Service

The PoW serves as anti-spam protection. After solving it, the service proceeds with option 1:

**After solving PoW:**
```
deploying your private blockchain...

your private blockchain has been deployed
it will automatically terminate in 30 minutes
here's some useful information
uuid:               3f47d741-8ed5-483a-8dac-84cd538ddfd1
rpc endpoint:       http://13.61.1.167:8546/3f47d741-8ed5-483a-8dac-84cd538ddfd1
private key:        0x54daf2395064a19fc4303b78e2d70f63fd8d8f11601fa05f786ee22fd6d21259
your address:       0x17Dff1Bd81CD02CC010948371a160Bd4EBC83B3d
```

Excellent! The service:
1. Spins up a **private Ethereum blockchain** (likely using Anvil/Hardhat)
2. Provides us with:
   - A unique UUID for our instance
   - An HTTP RPC endpoint
   - A funded private key
   - Our Ethereum address

The instance auto-terminates after 30 minutes, so we need to work efficiently.

---

## Deploying a Private Instance

To solve the PoW quickly, I implemented a Python brute-force solver:

```python
def solve_pow(nonce: str, bits: int) -> str:
    i = 0
    while True:
        candidate = str(i).encode()
        digest_hex = hashlib.sha256(nonce.encode() + candidate).hexdigest()
        if has_leading_zero_bits(digest_hex, bits):
            return candidate.decode()
        i += 1

def has_leading_zero_bits(hex_digest: str, bits: int) -> bool:
    bin_str = bin(int(hex_digest, 16))[2:].zfill(256)
    return bin_str.startswith("0" * bits)
```

With 24 bits of difficulty, this takes 2-50 seconds on average (expected ~16.7 million attempts).

---

## Blockchain Analysis

Once we have the RPC endpoint, let's connect using Web3.py and explore:

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider(rpc_url))
print(f"Chain ID: {w3.eth.chain_id}")
print(f"Latest block: {w3.eth.block_number}")
```

**Result:**
```
Chain ID: 31337 (standard Anvil/Hardhat test chain)
Latest block: 3
```

### Finding Deployed Contracts

The challenge must have deployed a contract. Let's scan the blockchain:

```python
contracts = []
for block_num in range(0, w3.eth.block_number + 1):
    block = w3.eth.get_block(block_num, full_transactions=True)
    for tx in block.transactions:
        receipt = w3.eth.get_transaction_receipt(tx.hash)
        if receipt.contractAddress:
            contracts.append(receipt.contractAddress)
```

**Found:** One contract at `0xaE9F52994C6C60B63fE9f81a55a29b01cD59b6E9`

---

## Contract Reverse Engineering

Without the source code or ABI, we need to reverse-engineer the contract. Let's extract function selectors from the bytecode:

```python
def extract_selectors(bytecode: bytes) -> list:
    sels = []
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        i += 1
        if op == 0x63 and i + 4 <= len(bytecode):  # PUSH4 opcode
            selector = bytecode[i:i+4].hex()
            sels.append(selector)
            i += 4
        elif 0x60 <= op <= 0x7f:  # PUSH1-PUSH32
            push_len = op - 0x5f
            i += push_len
    return list(dict.fromkeys(sels))
```

**Extracted selectors:**
```
0x799320bb, 0x8da5cb5b, 0x98b0eff6, 0xafe42d92, 
0xf8544bbd, 0x13416ae1, 0x19c813be, 0x36091dff, 
0x64d98f6e, 0x43753b4d, 0xffffffff
```

### Identifying Functions with 4byte.directory

Using the [4byte.directory](https://www.4byte.directory/) API to lookup selectors:

| Selector | Function Signature |
|----------|-------------------|
| `0x64d98f6e` | `isSolved()` |
| `0x799320bb` | `solved()` |
| `0x8da5cb5b` | `owner()` |
| `0x43753b4d` | `verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[1])` |
| `0x13416ae1` | `sanityCheck(uint256[2],uint256[2][2],uint256[2],uint256[1])` |
| `0xafe42d92` | `solveMe(uint256[2],uint256[2][2],uint256[2],uint256[1],bytes32)` |
| `0x36091dff` | `test(bool)` |

**Analysis:**
- `isSolved()` / `solved()` - Check if challenge is solved
- `verifyProof()` / `sanityCheck()` - zk-SNARK proof verification (Groth16)
- `solveMe()` - Likely the intended solution requiring a valid proof
- `test(bool)` - **Suspicious!** A test function left in production code?

The presence of Groth16 proof verification functions aligns with the challenge name "ZERO ZERO-Knowledge" - referencing zero-knowledge proofs.

---

## Finding the Vulnerability

Let's test `isSolved()` first:

```python
isSolved_selector = Web3.keccak(text="isSolved()")[:4].hex()
result = w3.eth.call({
    "to": contract_address,
    "data": "0x" + isSolved_selector
})
solved = bool(int.from_bytes(result, byteorder="big"))
print(f"Currently solved: {solved}")  # False
```

The challenge expects us to generate a valid Groth16 zero-knowledge proof. However, creating such proofs requires:
1. The circuit definition
2. Trusted setup parameters
3. Valid witnesses
4. Significant cryptographic knowledge

**But wait...** what about that `test(bool)` function? 🤔

Let's try calling it with `true`:

```python
from eth_account import Account

acct = Account.from_key(private_key)
nonce = w3.eth.get_transaction_count(acct.address)

# Call test(true)
test_selector = Web3.keccak(text="test(bool)")[:4].hex()
calldata = bytes.fromhex(test_selector) + b"\x00" * 31 + b"\x01"  # bool true

tx = {
    "to": contract_address,
    "data": calldata,
    "nonce": nonce,
    "chainId": 31337,
    "gasPrice": w3.eth.gas_price,
    "gas": 250000,
}

signed = acct.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

print(f"Transaction status: {receipt.status}")  # 1 (success!)
```

**Checking again:**

```python
result = w3.eth.call({"to": contract_address, "data": "0x64d98f6e"})
solved = bool(int.from_bytes(result, byteorder="big"))
print(f"Solved: {solved}")  # True! 🎉
```

---

## Exploitation

The vulnerability is simple: **the contract has a debug/test function that directly sets the solved state!**

This is a common mistake in smart contract development - leaving test/debug functions accessible in production deployments. The developers likely intended to require a valid Groth16 proof via `solveMe()`, but forgot to remove or properly protect the `test()` function.

**Exploitation steps:**
1. Solve PoW
2. Launch instance and get RPC credentials
3. Connect to blockchain
4. Find the challenge contract
5. Call `test(true)` to flip the solved flag
6. Retrieve the flag via menu option 3

---

## Getting the Flag

After setting `isSolved() = true`, we reconnect to the service and use option 3:

```bash
nc 13.61.1.167 31338
```

**Flow:**
1. Solve the PoW again
2. Select option 3
3. Provide the UUID from our instance
4. Solve another PoW
5. Receive the flag!

**Output:**
```
Congratulations! You have solved it! Here's the flag:
cybears{groth16_iS_M4LLE4bL3_4s_w3LL}
```

The flag message "groth16_iS_M4LLE4bL3_4s_w3LL" is a play on:
- **Groth16** - The zk-SNARK proving system
- **Malleable** - A cryptographic property where proofs can be modified

---

## Automated Solution

I created a full automated solver that:
- Handles both PoW challenges
- Discovers contracts automatically
- Tests all function selectors systematically
- Retrieves the flag

**Full solution:** [client.py](./client.py)

**Run it:**
```bash
python3 client.py
```

The script completes in ~30-90 seconds depending on PoW luck.

---

## Key Takeaways

### What We Learned

1. **Smart Contract Security:**
   - Always remove debug/test functions before deployment
   - Use access control modifiers (`onlyOwner`, etc.)
   - Conduct thorough audits of public functions

2. **Blockchain CTF Techniques:**
   - Bytecode analysis to extract function selectors
   - Using 4byte.directory for reverse engineering
   - Automated contract discovery via transaction receipts
   - Systematic function testing when ABI is unavailable

3. **Zero-Knowledge Proofs:**
   - Groth16 is a popular zk-SNARK construction
   - Proof systems have complex verification logic
   - The challenge name was a hint about the intended solution path
   - But the actual solution bypassed the crypto entirely!

---

## Tools Used

- **Python 3** with `web3.py` and `eth_account`
- **4byte.directory** - Function signature database
- **netcat** - Initial service exploration
- **Keccak hashing** - Function selector computation

---

## References

- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [4byte Directory](https://www.4byte.directory/)
- [Web3.py Documentation](https://web3py.readthedocs.io/)
- [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)

---


