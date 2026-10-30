# Distributed SHRINCS Signing with Fantastic Four

[![CI](https://github.com/pGerhart/shrincs-mpc/actions/workflows/ci.yml/badge.svg)](https://github.com/pGerhart/shrincs-mpc/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue.svg)](rust-toolchain.toml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

This repository runs [SHRINCS](https://github.com/SHRINCS/shrincs-bip/blob/main/SHRINCS.md) key generation and signing distributed across four parties, one of which may be malicious.
As MPC protocol we use [Fantastic Four](https://eprint.iacr.org/2020/1330).
[`OVERVIEW.md`](OVERVIEW.md) describes how the parties compute key generation and signing.

> [!WARNING]
> **Prototype.** This is research code and it has **not** been security-audited.  
> It must not be used in production.

## Workspace

| crate | contents |
|---|---|
| [`shrincs`](shrincs) | SHRINCS in plaintext, byte-compatible with the BIP, for the public steps and as the test oracle |
| [`ff4`](ff4) | the Fantastic Four parties, distributed key generation, stateful and stateless signing |
| [`node`](node) | one party as a server, the TCP mesh, the coordinator-free ordering of requests |

## Build and test

```bash
cargo test --workspace --release
```

We test our `shrincs` implementation against the known-answer vectors from the BIP's Python reference [`impl/shrincs.py`](https://github.com/SHRINCS/shrincs-bip/blob/main/impl/shrincs.py) at commit `0329bb2`.

## WAN Results
We deployed our protocol on four `c6in.2xlarge` instances (8 vCPU, 16 GiB) in Frankfurt, Ireland, London and Paris, with round trips of 8 to 20 ms.
A client in Frankfurt sent each request to the next node in turn and verified every signature.

Each signature runs in one of four modes.
With exact `R`, the parties compute the BIP's `PRF_msg` inside the computation, so the signature equals that of `shrincs_sign`.
With random `R`, the parties open a joint random value instead, which a verifier cannot tell apart.
With the cache, the nodes open the chain nodes they stored at key generation, and without it they recompute the chains.

Times are medians over 10 stateful and 1 stateless signature per mode.
Traffic and RAM are the maxima over the four nodes, and the total traffic of all four nodes is about three times the maximum.

### Balanced tree, depth 11
The key allows 2,048 stateful signatures, and each node holds 64.1 MB of key shares with the cache and 96 B without.

| operation | `R` | cache | time | rounds | MB sent | MB received | RAM peak |
|---|---|---|---:|---:|---:|---:|---:|
| key generation | | | 160 s | 7,775 | 18,467 | 18,467 | 296 MB |
| stateful signature | random | on | 72 ms | 2 | 0.006 | 0.006 | 134 MB |
| stateful signature | exact | on | 9.9 s | 1,375 | 2.7 | 2.7 | 134 MB |
| stateful signature | random | off | 52.1 s | 7,316 | 14.3 | 14.3 | 134 MB |
| stateful signature | exact | off | 65.1 s | 8,689 to 9,146 | 17.8 | 17.8 | 134 MB |
| stateless signature | random | on | 152 s | 7,318 | 18,130 | 18,130 | 471 MB |
| stateless signature | exact | on | 158 s | 8,234 | 18,131 | 18,131 | 471 MB |
| stateless signature | random | off | 152 s | 7,318 | 18,144 | 18,144 | 479 MB |
| stateless signature | exact | off | 162 s | 8,691 | 18,146 | 18,146 | 479 MB |

### Unbalanced tree, depth 255
The key allows 256 stateful signatures, and each node holds 20.1 MB of key shares with the cache and 96 B without.

| operation | `R` | cache | time | rounds | MB sent | MB received | RAM peak |
|---|---|---|---:|---:|---:|---:|---:|
| key generation | | | 84 s | 7,775 | 5,779 | 5,779 | 111 MB |
| stateful signature | random | on | 72 ms | 2 | 0.006 | 0.006 | 51 MB |
| stateful signature | exact | on | 9.8 s | 1,375 | 2.7 | 2.7 | 51 MB |
| stateful signature | random | off | 52.0 s | 6,402 to 7,316 | 13.9 | 13.9 | 51 MB |
| stateful signature | exact | off | 65.1 s | 8,689 to 9,146 | 17.8 | 17.8 | 51 MB |

Stateless signing does not depend on the stateful tree, so we measured it with the balanced key only.
Without the cache, the rounds depend on the highest chain index of the signature.
On disk a node keeps only its journal of used leaves, 165 bytes per signature.
See [`runs/2026-10-30T171505Z`](runs/2026-10-30T171505Z) and [`runs/2026-10-30T175017Z`](runs/2026-10-30T175017Z) for detailed measurement results.

## Reproduce our results
To rerun our experiment, we use a cluster file which lists the four nodes, as in [`cluster_local.conf`](cluster_local.conf) and [`cluster_wan.conf`](cluster_wan.conf).
The ID of each server is its position in this file, starting with 0.
Each server starts the node with its own id.

```bash
cargo build --release --locked -p node
sudo sysctl -w net.core.wmem_max=67108864 net.core.rmem_max=67108864   # 64 MB socket buffers
./target/release/shrincs-node --cluster cluster_wan.conf --id 0
```

A typical run then has the following form:
```bash
curl -X POST 'http://h0:8080/keygen?depth=11&shape=balanced'
curl -X POST 'http://h2:8080/sign?msg=68656c6c6f&ctx='
curl -X POST 'http://h2:8080/sign?msg=68656c6c6f&ctx=&exact=1&cache=0'
curl -X POST 'http://h3:8080/sign_stateless?msg=68656c6c6f&ctx='
curl 'http://h1:8080/status'
./target/release/shrincs-verify <pk> 68656c6c6f <sig>
```

We use the option `shape=unbalanced` to select the BIP's unbalanced tree.
The options `exact=1` and `cache=0` select the modes above, and by default `R` is random and the cache is on.

### Benchmarks
Our benchmarks were computed using the following script.
The script signs `n` messages statefully in each mode of `exact` and `cache`, and `m` statelessly in each mode with the first key.
It verifies every signature and writes time, rounds, traffic, RAM and storage to `runs/<date>/summary.md`.

```bash
scripts/cluster.sh cluster_local.conf "balanced:11 unbalanced:255" 25 1   # starts four local nodes per key
scripts/cluster.sh cluster_wan.conf balanced:11 25 1                      # four running servers, one key per run
```
