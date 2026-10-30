# Distributed SHRINCS
The main idea behind this project is the fact that to sign in SHRINCS, many hash evaluations actually do not have a private input.
For example, digests, grinding, Merkle trees and the encoding depend only on public values.
We therefore open chain tips and nodes once they are public and compute the trees in the clear with [`shrincs`](shrincs).

To compute the public key for SHRINCS, one has to evaluate plenty of hash chains of 16 hashes each, but no chain depends on another.
Therefore, all these chains can be evaluated in parallel.
In addition, every secret value is derived from `sk_seed` or `sk_prf` through SHA-256.
The tweakable hash `SHA-256(pk_seed || 0^48 || ADRS || M)` has a public first block, so each secret hash costs one compression inside the computation.

We used the following parameters:

| parameter | value | imposed by |
|---|---|---|
| `n` | 16 bytes | the BIP, every hash truncated to 16 bytes |
| WOTS+C | 32 chains, `w = 16`, constant sum 240 | the BIP, stateful leaves |
| WOTS-TW | 35 chains, `w = 16` | the BIP, stateless hypertree |
| FORS | 10 trees of height 13 | the BIP, stateless path |
| hypertree | 5 layers, XMSS height 9 | the BIP, stateless path |
| stateful tree | balanced FXMSS of depth `d`, or unbalanced | the BIP's two shapes, `2^d` or `d + 1` stateful signatures |
| parties | 4, one malicious | Fantastic Four |

## Fantastic Four
Even if we have reduced the number of private hash-computations and parallelized their computation, we still have to compute them distributedly.
To do so efficiently without relying on NIZKs, we use the [Fantastic Four](https://eprint.iacr.org/2020/1330) protocol, which splits computation across four parties, one of which can be malicious.
In theory, we could also use other MPC protocols. With three parties, a multiplication costs one round without preprocessing, but only against semi-honest adversaries.
Using the fourth party, we also have security with abort against a malicious adversary.

The idea behind Fantastic Four is to split a bit into four XOR shares, and party `P_m` holds every share except `x_m`.
Then, each party can compute XOR and NOT locally.
Only an AND needs communication, for the six cross terms `x_i y_j + x_j y_i`, each known only to the two parties outside `{i, j}`.
To evaluate them, the parties communicate one round, as one of the parties sends the masked term, and the other folds it into a hash that the receiver checks before any value is opened.
A tampered term is detected, since two parties know it, and leads to an abort without zero-knowledge proofs.

An opening sends three copies of the missing share. A party aborts unless the three copies agree.
Joint randomness needs no communication, since each share comes from a stream keyed among its three holders.

The SHA-256 compression circuit uses carry-save and Sklansky adders and has 55,304 AND gates at depth 457.
We evaluate it bitsliced with 64 lanes per word and reuse registers, so memory follows its 4,638 live registers.

## Limitations

If a malicious party sees a joint random value such as `pk_seed` or a random `R` first, it can selectively abort.
An abort stops the nodes, and the key lives only in memory, so this yields no second `R` under the same key.
