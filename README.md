::: {align="center"}
# Aurex AUX Miner

**High‑performance SHA‑256 Proof‑of‑Work miner for Aurex (AUX)**\
Built for the **Vexanium Blockchain (Antelope Protocol)**

Designed with architecture inspired by professional miners such as
**Bitcoin Core / cgminer**.

![Node](https://img.shields.io/badge/node-%3E%3D18-green)
![PoW](https://img.shields.io/badge/hash-SHA256-orange)
![Chain](https://img.shields.io/badge/blockchain-Vexanium-purple)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
:::

------------------------------------------------------------------------

# Table of Contents

1.  Introduction
2.  System Architecture
3.  Mining Flow Diagram
4.  Proof of Work Algorithm
5.  Miner Features
6.  System Requirements
7.  Installation
8.  Configuration
9.  Running the Miner
10. Example JavaScript PoW Implementation
11. Miner Output Example
12. Performance Optimization
13. RPC Node Strategy
14. Large‑Scale Mining Deployment
15. Troubleshooting
16. Security
17. License

------------------------------------------------------------------------

# Introduction

**Aurex AUX Miner** is a CPU‑based Proof‑of‑Work miner implemented in
**Node.js** designed to mine **Aurex (AUX)** tokens on the **Vexanium
blockchain**.

Key characteristics:

-   SHA‑256 Proof‑of‑Work
-   Multi‑core CPU mining
-   worker_threads parallel hashing
-   Professional terminal dashboard
-   Automatic RPC retry & backoff
-   Designed for **large‑scale miner fleets**

Mining contract:

    mine.aurex

Reward token:

    token.aurex

------------------------------------------------------------------------

# System Architecture

The miner follows a modular architecture separating networking, hashing
workers, and transaction submission.

``` mermaid
flowchart TD

A[Main Thread] --> B[RPC Communication]
A --> C[Transaction Builder]
A --> D[Terminal UI]

A --> E[Worker Thread 1]
A --> F[Worker Thread 2]
A --> G[Worker Thread N]

E --> H[SHA256 Hashing]
F --> H
G --> H

H --> I[Difficulty Check]
I --> J{Solution Found}

J -->|Yes| K[Submit Transaction]
J -->|No| E
```

------------------------------------------------------------------------

# Mining Flow Diagram

``` mermaid
sequenceDiagram

participant Miner
participant RPC
participant Contract

Miner->>RPC: get_table_rows(global)
RPC-->>Miner: challenge + diff_bits

Miner->>Miner: generate nonce
Miner->>Miner: sha256 hash

alt valid hash
    Miner->>Contract: push_transaction(mine)
    Contract-->>Miner: reward AUX
else invalid hash
    Miner->>Miner: next nonce
end
```

------------------------------------------------------------------------

# Proof of Work Algorithm

Hash calculation:

    pow_hash = sha256(challenge || miner || nonce)

Difficulty rule:

    leading_zero_bits(hash) >= diff_bits

Where:

-   **challenge** = value from blockchain
-   **miner** = account name
-   **nonce** = incrementing integer

------------------------------------------------------------------------

# Miner Features

## Professional Terminal UI

-   No screen flickering
-   No full terminal clearing
-   Line‑diff rendering
-   Smooth spinner animation
-   Live hashrate display

## Multi‑Thread CPU Mining

Uses:

    worker_threads

Example:

    8 core CPU → THREADS=7

## RPC Stability

Network features:

-   automatic retry
-   exponential backoff
-   request timeout protection
-   optional node switching

## Efficient RPC Usage

The miner minimizes RPC load.

AUX balance is fetched:

-   once at startup
-   once when a solution is found

------------------------------------------------------------------------

# System Requirements

Minimum:

    Node.js 18

Recommended:

    Node.js 20+

Check version:

``` bash
node -v
```

Supported OS:

-   Linux
-   macOS
-   Windows

------------------------------------------------------------------------

# Installation

Clone the repository:

``` bash
git clone https://github.com/aurexcore/aurex-miner.git
cd aurex-miner
```

Install dependencies:

``` bash
npm install
```

Build the miner bundle:

``` bash
npm run build
```

The compiled miner will be located in:

    dist/miner.cjs
    dist/aurex-miner

Run the miner:

``` bash
node dist/miner.cjs
```

or (Linux/macOS)

``` bash
./dist/aurex-miner
```

------------------------------------------------------------------------

# Configuration

Create configuration file:

    .env

Example configuration:

    ENDPOINT=https://api.windcrypto.com
    CONTRACT=mine.aurex

    MINER=youraccount
    PERM=active

    PRIVATE_KEY=YOUR_PRIVATE_KEY

    TOKEN_CONTRACT=token.aurex
    AUX_SYMBOL=AUX

    THREADS=auto
    BROADCAST=1

------------------------------------------------------------------------

# Running the Miner

Basic run:

``` bash
node dist/miner.cjs
```

Specify threads:

``` bash
node dist/miner.cjs --threads 8
```

The miner will:

1.  Fetch the PoW challenge from the blockchain
2.  Start CPU hashing
3.  Detect valid solutions
4.  Submit transactions automatically
5.  Display live mining stats

------------------------------------------------------------------------

# Example JavaScript PoW Implementation

Example SHA‑256 PoW hashing:

``` javascript
import crypto from "crypto";

function powHash(challenge, miner, nonce) {

    const header = Buffer.concat([
        Buffer.from(challenge, "hex"),
        Buffer.from(miner)
    ])

    const nonceBuffer = Buffer.alloc(8)
    nonceBuffer.writeBigUInt64LE(BigInt(nonce))

    const data = Buffer.concat([header, nonceBuffer])

    return crypto.createHash("sha256")
        .update(data)
        .digest("hex")
}
```

Difficulty check:

``` javascript
function leadingZeroBits(hex) {

    let bits = 0

    for (let i = 0; i < hex.length; i++) {

        const nibble = parseInt(hex[i], 16)

        if (nibble === 0) {
            bits += 4
        } else {
            bits += Math.clz32(nibble) - 28
            break
        }
    }

    return bits
}
```

------------------------------------------------------------------------

# Miner Output Example

    Aurex PoW Miner · mine.aurex · 245 kH/s · 7T · up 400s

    Endpoint  https://api.windcrypto.com
    Miner     txminer@active

    Height    227
    Diff      26

    Stats     found=3 pushed=3 failed=0

    AUX       1850.00000000 AUX

    ⠹ Mining… refresh=30s

------------------------------------------------------------------------

# Performance Optimization

Recommended settings:

    THREADS=auto
    READ_TIMEOUT_MS=12000
    READ_RETRY=5
    PUSH_RETRY=3

CPU recommendations:

  CPU       Threads
  --------- ---------
  4 Core    3
  8 Core    7
  16 Core   14

------------------------------------------------------------------------

# RPC Node Strategy

Use multiple RPC endpoints for redundancy.

Example:

    https://api.windcrypto.com
    https://explorer.vexanium.com
    https://api.databisnis.id

------------------------------------------------------------------------

# Large‑Scale Mining Deployment

For mining fleets:

    1000 – 10000 miners

Recommended:

-   RPC load balancing
-   jittered startup timing
-   monitoring tools
-   node health checks

PM2 deployment example:

``` bash
pm2 start dist/miner.cjs -i max
```

------------------------------------------------------------------------

# Troubleshooting

### RPC overload

Error:

    HTTP 429

Solution:

-   reduce threads
-   switch RPC endpoint

### Contract not initialized

Error:

    global row not found

Ensure the mining contract has been initialized.

------------------------------------------------------------------------

# Security

Never:

-   commit `.env`
-   expose private keys publicly

Always add `.env` to:

    .gitignore

------------------------------------------------------------------------

# License

MIT License

------------------------------------------------------------------------

# Credits

**Aurex AUX Miner**

Developed for the **Vexanium Blockchain** ecosystem.

Powered by:

-   Node.js
-   WharfKit Antelope
-   SHA‑256 Proof‑of‑Work