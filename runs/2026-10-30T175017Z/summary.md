| operation | key | R | cache | runs | client ms, median | client ms, max | rounds | MB sent, max node | MB received, max node | RAM peak MB, max node |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| keygen | unbalanced:255 | - | - | 1 | 84279.6 | 84279.6 | 7775 | 5778.658 | 5778.658 | 111 |
| sign | unbalanced:255 | fast | on | 10 | 71.8 | 96.8 | 2 | 0.006 | 0.006 | 51 |
| sign | unbalanced:255 | exact | on | 10 | 9836.8 | 9863.2 | 1375 | 2.683 | 2.683 | 51 |
| sign | unbalanced:255 | fast | off | 10 | 51992.6 | 52042.1 | 7133 | 13.924 | 13.924 | 51 |
| sign | unbalanced:255 | exact | off | 10 | 65094.9 | 65159.3 | 9100 | 17.761 | 17.761 | 51 |

| key | stateful signatures | secret per node, with cache | secret per node, minimum | public per node | RSS per node before keygen | RSS per node after keygen | signatures made | journal on disk per node |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| unbalanced:255 | 256 | 20.1 MB | 96 B | 16.4 KB | 13 MB | 51 MB | 40 | 6.6 KB |
