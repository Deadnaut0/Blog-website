---
title: "Abyss Vault - CTF Writeup"
date: 2026-04-11
draft: false
description: "Cryptography challenge writeup"
tags: ["Cryptography", "Blockchain"]
categories: ["Writeups"]
---


**Challenge Name:** Abyss Vault  
**Category:** Blockchain / Cryptography  
**CTF:** CyberSummit V4.0 CTF  
**Description:** The vault does not care who you are. It cares who your child is. The right caller is not a wallet. It is a contract that is still being born.  
**Connection:** `nc 48.199.16.26 9992`  

---

## Recon

The service is menu-based and exposes a private chain instance:

```bash
nc 48.199.16.26 9992
```

Menu output:

```text
1 - show instance info
2 - get flag (if isSolved() is true)
3 - exit
action?
```

Actual option `1` output:

```text
1 - show instance info
2 - get flag (if isSolved() is true)
3 - exit
action?
a private chain has been deployed
the vault is behind a proxy
rpc endpoint: http://127.0.0.1:8645
deployer private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
deployer address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
factory address: 0x5FbDB2315678afecb367f032d93F642f64180aa3
proxy address: 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
implementation address: 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512

1 - show instance info
2 - get flag (if isSolved() is true)
3 - exit
action?
```

---

## Service Behavior

From the challenge host logic:

- `RelicFactory` is deployed first
- `AbyssVault` implementation is deployed second
- `EIP1967Proxy` is deployed third and points to `AbyssVault`
- `isSolved()` is checked through the proxy

This means direct source assumptions are dangerous: the real target is the proxy state, while critical constants are inside implementation bytecode.

---

## Contract Architecture

### 1) Proxy Layer

The challenge uses an EIP-1967 implementation slot:

- Slot key is `keccak256("eip1967.proxy.implementation") - 1`
- Calls to the proxy are delegated to `AbyssVault`

### 2) Vault Layer (`AbyssVault`)

The important checks in `solve(bytes32 proof)` are:

1. `msg.sender != tx.origin`
2. `msg.sender.code.length == 0`
3. `msg.sender == predictChild(secretSalt)`
4. `proof == keccak256(blockhash(block.number - 1), msg.sender, secretSalt)`

So caller must be a contract address with zero code at call-time, i.e. constructor context.

### 3) Factory + Constructor Relay

`RelicFactory.launch(target, salt, proof)` stores pending data and deploys `ConstructorRelay` with `CREATE2`.

Inside relay constructor:

- It fetches pending target/proof from factory
- Immediately calls `target.solve(proof)`

This is the exact primitive needed to satisfy both constructor and deterministic-address checks.

---

## Why Normal Calls Fail

- EOA call fails (`msg.sender == tx.origin`)
- Existing deployed contract fails (`msg.sender.code.length != 0`)
- Random constructor contract fails unless its address matches `predictChild(secretSalt)`

The challenge forces a very specific caller identity: the deterministic `CREATE2` child for the hidden `secretSalt`.

---

## Core Exploit Strategy

1. Resolve implementation address from proxy EIP-1967 storage slot.
2. Pull implementation bytecode.
3. Extract all `PUSH32` constants as candidate salts.
4. For each candidate `salt`:
   - Ask on-chain `predictChild(salt)` to get required constructor caller address.
   - Compute proof as:

$$
\text{proof} = \text{keccak256}(\text{blockhash}(n-1) \|\, \text{predictedChild} \|\, \text{salt})
$$

- Call `factory.launch(proxy, salt, proof)`.
- Check `isSolved()` on proxy.

Only the true `secretSalt` candidate succeeds. Decoys are intentionally present.

---

## Implementation Details

### Recover implementation from proxy

Use raw `eth_getStorageAt` on EIP-1967 implementation slot:

```js
const slot = ethers.keccak256(ethers.toUtf8Bytes('eip1967.proxy.implementation'));
const implSlot = `0x${((BigInt(slot) - 1n) & ((1n << 256n) - 1n)).toString(16).padStart(64, '0')}`;
const raw = await provider.send('eth_getStorageAt', [proxyAddress, implSlot, 'latest']);
const implementationAddress = ethers.getAddress(`0x${raw.slice(-40)}`);
```

### Candidate extraction

Scan implementation bytecode and collect immediate values of opcode `0x7f` (`PUSH32`).

### Deterministic child address

Instead of reproducing relay initcode hash off-chain, query vault oracle directly:

```js
const predictedChild = await challenge.predictChild(salt);
```

This avoids compiler-metadata drift problems.

---

## Automating the Solve

Full `solve.js` source:

```javascript
const solc = require('solc');
const { ethers } = require('ethers');

const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8645';
const TARGET = process.env.TARGET || process.env.PROXY || '';
const FACTORY = process.env.FACTORY || '';
const PRIVATE_KEY = process.env.PRIVATE_KEY || '';

if (!TARGET) {
   throw new Error('set TARGET to the proxy address');
}

if (!FACTORY) {
   throw new Error('set FACTORY to the factory address');
}

if (!PRIVATE_KEY) {
   throw new Error('set PRIVATE_KEY to the funded key');
}

const provider = new ethers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

const proxyAbi = [
   'function isSolved() view returns (bool)',
   'function predictChild(bytes32 salt) view returns (address)',
];

function extractPush32Constants(bytecode) {
   const stripped = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;
   const bytes = Buffer.from(stripped, 'hex');
   const constants = [];

   for (let index = 0; index < bytes.length;) {
      const opcode = bytes[index];
      index += 1;

      if (opcode === 0x7f && index + 32 <= bytes.length) {
         constants.push(`0x${bytes.slice(index, index + 32).toString('hex')}`);
         index += 32;
         continue;
      }

      if (opcode >= 0x60 && opcode <= 0x7f) {
         index += opcode - 0x5f;
      }
   }

   return [...new Set(constants)];
}

function eip1967ImplementationSlot() {
   const slot = ethers.keccak256(ethers.toUtf8Bytes('eip1967.proxy.implementation'));
   const value = (BigInt(slot) - 1n) & ((1n << 256n) - 1n);
   return `0x${value.toString(16).padStart(64, '0')}`;
}

async function getImplementationAddress(proxyAddress) {
   const slot = eip1967ImplementationSlot();
   const raw = await provider.send('eth_getStorageAt', [proxyAddress, slot, 'latest']);
   return ethers.getAddress(`0x${raw.slice(-40)}`);
}

async function main() {
   const proxyAddress = ethers.getAddress(TARGET);
   const factoryAddress = ethers.getAddress(FACTORY);
   const implementationAddress = await getImplementationAddress(proxyAddress);
   const code = await provider.getCode(implementationAddress);
   const constants = extractPush32Constants(code);

   if (constants.length === 0) {
      throw new Error('no PUSH32 constants found in implementation');
   }

   const challenge = new ethers.Contract(proxyAddress, proxyAbi, provider);
   const latestBlock = await provider.getBlock('latest');
   const blockHash = latestBlock.hash;

   console.log(`[+] proxy: ${proxyAddress}`);
   console.log(`[+] factory: ${factoryAddress}`);
   console.log(`[+] implementation: ${implementationAddress}`);
   console.log(`[+] candidate constants: ${constants.length}`);

   const factoryAbi = [
      'function launch(address target, bytes32 salt, bytes32 proof) returns (address)',
   ];
   const factory = new ethers.Contract(factoryAddress, factoryAbi, wallet);

   for (const salt of constants) {
      const onchainChild = await challenge.predictChild(salt);
      const predictedChild = onchainChild;

      console.log(`[+] on-chain child ${onchainChild}`);
      const proof = ethers.keccak256(
         ethers.concat([
            ethers.getBytes(blockHash),
            ethers.getBytes(predictedChild),
            ethers.getBytes(salt),
         ])
      );

      console.log(`[+] trying salt ${salt} with child ${predictedChild}`);

      try {
         const tx = await factory.launch(proxyAddress, salt, proof);
         await tx.wait();
         const solved = await challenge.isSolved();
         if (solved) {
            console.log('[+] solved');
            return;
         }
      } catch (error) {
         console.log(`[-] candidate failed: ${error.shortMessage || error.message}`);
      }
   }

   throw new Error('no candidate solved the vault');
}

main().catch((error) => {
   console.error(error);
   process.exit(1);
});
```

Run it with:

```bash
npm install
RPC_URL=http://<rpc-host>:<rpc-port> \
TARGET=0x<proxy> \
FACTORY=0x<factory> \
PRIVATE_KEY=0x<deployer_key> \
node solve.js
```

Actual solver output (captured from live host):

```text
[+] proxy: 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
[+] factory: 0x5FbDB2315678afecb367f032d93F642f64180aa3
[+] implementation: 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
[+] candidate constants: 6
[+] on-chain child 0xb51bBf2E122337166819d89Ef06C300D41a0AE1A
[+] trying salt 0x0132f2b73ca3216595c2d9b7bdd91b5f8b02ae7a1c8aa7760499072c7ab69ea4 with child 0xb51bBf2E122337166819d89Ef06C300D41a0AE1A
[-] candidate failed: missing revert data
[+] on-chain child 0x0ebbf4700993fa59a0d7d1cFaa3fbC2Fa378400C
[+] trying salt 0x10b4f10a3e44e01fbf04c4817b155b2161288360969cbb731572b5f54228fd9c with child 0x0ebbf4700993fa59a0d7d1cFaa3fbC2Fa378400C
[-] candidate failed: missing revert data
[+] on-chain child 0x3466C4AB46DAF546B61e05fEc74C2f321b790547
[+] trying salt 0x5130eba5d0945668f5f1a5ce4089ae36b6989b084843cfcda0a09db41e2276ff with child 0x3466C4AB46DAF546B61e05fEc74C2f321b790547
[+] solved
```

Then request flag from menu option `2`.

---

## End-to-End Run

1. Connect to menu service and choose `1`.
2. Copy `rpc endpoint`, `proxy address`, `factory address`, `deployer private key`.
3. Run solver script.
4. Return to menu and choose `2`.
5. Receive:

```text
1 - show instance info
2 - get flag (if isSolved() is true)
3 - exit
action?
flag: CyberTrace{W3ll_W33l_we3L_7h4T_W4sn7_4_Gr8T_1D3A}
1 - show instance info
2 - get flag (if isSolved() is true)
3 - exit
action?
```

---

## Final Flag

```text
CyberTrace{W3ll_W33l_we3L_7h4T_W4sn7_4_Gr8T_1D3A}
```

---

## Key Takeaways

- Constructor-time calls can bypass naive anti-bot conditions (`code.length == 0`).
- CREATE2 identity constraints are strong only if secret salt cannot be recovered.
- Immutable values may still leak via runtime bytecode constants.
- Proxy indirection adds reconnaissance complexity, not automatic security.
- On-chain helper oracles (`predictChild`) can simplify exploit determinism when used carefully.
