| operation | key | R | cache | runs | client ms, median | client ms, max | rounds | MB sent, max node | MB received, max node | RAM peak MB, max node |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| keygen | balanced:11 | - | - | 1 | 159601.5 | 159601.5 | 7775 | 18466.821 | 18466.821 | 296 |
| sign | balanced:11 | fast | on | 10 | 71.9 | 98.0 | 2 | 0.006 | 0.006 | 134 |
| sign | balanced:11 | exact | on | 10 | 9857.6 | 9892.4 | 1375 | 2.683 | 2.683 | 134 |
| sign | balanced:11 | fast | off | 10 | 52147.7 | 52204.5 | 7316 | 14.281 | 14.281 | 134 |
| sign | balanced:11 | exact | off | 10 | 65067.1 | 65146.8 | 9100 | 17.761 | 17.761 | 134 |
| sign_stateless | balanced:11 | fast | on | 1 | 151677.9 | 151677.9 | 7318 | 18129.517 | 18129.517 | 471 |
| sign_stateless | balanced:11 | exact | on | 1 | 157552.9 | 157552.9 | 8234 | 18131.301 | 18131.302 | 471 |
| sign_stateless | balanced:11 | fast | off | 1 | 152375.3 | 152375.3 | 7318 | 18143.675 | 18143.675 | 479 |
| sign_stateless | balanced:11 | exact | off | 1 | 161651.3 | 161651.3 | 8691 | 18146.351 | 18146.352 | 479 |

| key | stateful signatures | secret per node, with cache | secret per node, minimum | public per node | RSS per node before keygen | RSS per node after keygen | signatures made | journal on disk per node |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| balanced:11 | 2048 | 64.1 MB | 96 B | 73.8 KB | 13 MB | 134 MB | 40 | 6.6 KB |
