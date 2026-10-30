#!/usr/bin/env bash
# Measures a cluster and records the run in runs/<stamp>/. Starts the
# nodes itself when all hosts are 127.x. Remote nodes must already run and
# take one key per run.
# usage: scripts/cluster.sh <cluster file> [keys] [n] [m]
#   keys: shape:depth items, e.g. "balanced:11 unbalanced:255"
#   n: stateful signatures per mode, m: stateless signatures per mode
set -euo pipefail
cd "$(dirname "$0")/.."
conf=$1; keys=${2:-"balanced:11 unbalanced:255"}; n=${3:-25}; m=${4:-1}

mapfile -t entries < <(sed 's/#.*//' "$conf" | awk 'NF == 2 { print $1, $2 }')
[ "${#entries[@]}" -eq 4 ] || { echo "$conf: need four lines 'host port'" >&2; exit 2; }
hosts=(); ports=(); local_run=1
for e in "${entries[@]}"; do
  hosts+=("${e% *}"); ports+=("${e#* }")
  [[ ${e% *} == 127.* ]] || local_run=0
done
if [ "$local_run" = 0 ] && [ "$(wc -w <<<"$keys")" -ne 1 ]; then
  echo "remote nodes generate one key per start, so give one key" >&2; exit 2
fi

cargo build --release --locked --quiet -p node
stamp=$(date -u +%Y-%m-%dT%H%M%SZ)
out=runs/$stamp; mkdir -p "$out"
cp "$conf" "$out/cluster.conf"
code=$(tar cf - --sort=name --mtime=@0 --owner=0 --group=0 --exclude=./target --exclude=./runs \
  --exclude=./experiments --exclude=.git . | sha256sum | cut -c1-16)

url() { echo "http://${hosts[$1]}:${ports[$1]}$2"; }
now() { date +%s.%N; }
field() { sed -n "s/.*\"$1\":\"\{0,1\}\([^\",}]*\).*/\1/p" <<<"$2"; }
status() { curl -sf "$(url "$1" /status)"; }
wait_up() { for i in 0 1 2 3; do
  for _ in $(seq 120); do status "$i" >/dev/null && break; sleep 1; done
  status "$i" >/dev/null || { echo "node $i at $(url "$i" "") is not up" >&2; exit 1; }
done; }
# Rounds of node 0, then bytes sent and received and peak RSS of each node.
snap() { local s
  s=$(status 0); echo -n "$(field rounds_total "$s")"
  for i in 0 1 2 3; do
    s=$(status "$i"); echo -n " $(field wire_sent_total "$s") $(field wire_recv_total "$s") $(field peak_rss_bytes "$s")"
  done
}
# Largest value of a status field over the four nodes.
max_field() { local m=0 v
  for i in 0 1 2 3; do v=$(field "$1" "$(status "$i")"); [ "$v" -gt "$m" ] && m=$v; done
  echo "$m"
}

pids=()
stop_nodes() { [ ${#pids[@]} -gt 0 ] && kill "${pids[@]}" 2>/dev/null; pids=(); }
start_nodes() {
  stop_nodes; sleep 0.5
  for i in 0 1 2 3; do
    rm -f "$out/node$i.journal"
    ./target/release/shrincs-node --cluster "$conf" --id "$i" --journal "$out/node$i.journal" >>"$out/node$i.log" 2>&1 &
    pids+=($!)
  done
}
trap stop_nodes EXIT

[ "$local_run" = 1 ] && start_nodes
wait_up
{
  echo "date $stamp"
  echo "code $code"
  echo "client $(rustc --version)"
  echo "binary shrincs-node $(wc -c <target/release/shrincs-node) bytes"
  echo "args keys=[$keys] n=$n m=$m"
  for i in 0 1 2 3; do
    s=$(status "$i")
    echo "node $i ${hosts[$i]}:${ports[$i]} version $(field version "$s"), $(field cpus "$s") cpus, $(field cpu "$s")"
  done
  echo "TCP connect ms, row to column"
  for i in 0 1 2 3; do
    row="node$i"
    for j in 0 1 2 3; do row="$row $(field connect_ms "$(curl -sf "$(url "$i" "/ping?peer=$j")")")"; done
    echo "$row"
  done
} | tee "$out/meta.txt"

printf 'op\tkey\texact\tcache\tk\tnode\tclient_ms\trounds\tsent_max\trecv_max\tram_max\n' >"$out/results.tsv"
printf 'key\tsignatures\tsecret_cache\tsecret_min\tpublic\trss_before\trss\tsigned\tjournal\n' >"$out/storage.tsv"
# run <op> <key> <exact> <cache> <k> <node> <path>: one request, measured on all four nodes.
run() {
  local before after s a
  before=$(snap); s=$(now)
  a=$(curl -sf -X POST "$(url "$6" "$7")") || { echo "$1 failed: no answer" >&2; exit 1; }
  ms=$(awk -v s="$s" -v e="$(now)" 'BEGIN { printf "%.1f", (e - s) * 1000 }')
  after=$(snap)
  [ "$(field ok "$a")" = true ] || { echo "$1 failed: $a" >&2; exit 1; }
  answer=$a
  awk -v b="$before" -v a="$after" -v pre="$1\t$2\t$3\t$4\t$5\t$6\t$ms" 'BEGIN {
    split(b, x, " "); split(a, y, " "); sm = 0; rm = 0; pm = 0
    for (i = 2; i <= 11; i += 3) {
      if (y[i] - x[i] > sm) sm = y[i] - x[i]; if (y[i+1] - x[i+1] > rm) rm = y[i+1] - x[i+1]; if (y[i+2] > pm) pm = y[i+2] }
    printf "%s\t%d\t%d\t%d\t%d\n", pre, y[1] - x[1], sm, rm, pm }' >>"$out/results.tsv"
}
modes="0:1 1:1 0:0 1:0"

first=1
for key in $keys; do
  shape=${key%:*}; depth=${key#*:}
  if [ "$local_run" = 1 ]; then start_nodes; wait_up; fi
  rss0=$(max_field rss_bytes)
  run keygen "$key" - - 0 0 "/keygen?depth=$depth&shape=$shape"
  pk=$(field pk "$answer"); sigs=$(field signatures "$answer")
  st=$(status 0); rss=$(max_field rss_bytes)
  echo "$key pk $pk" | tee -a "$out/meta.txt"
  per=$(( n * 4 <= sigs ? n : sigs / 4 ))
  for mode in $modes; do
    for ((k = 0; k < per; k++)); do
      node=$((k % 4)); msg=$(printf 'sf %s %s %s' "$key" "$mode" "$k" | od -An -tx1 | tr -d ' \n')
      run sign "$key" "${mode%:*}" "${mode#*:}" "$k" "$node" "/sign?msg=$msg&ctx=&exact=${mode%:*}&cache=${mode#*:}"
      ./target/release/shrincs-verify "$pk" "$msg" "$(field sig "$answer")" >/dev/null || { echo "invalid: $answer" >&2; exit 1; }
    done
  done
  if [ "$first" = 1 ]; then
    for mode in $modes; do
      for ((k = 0; k < m; k++)); do
        node=$((k % 4)); msg=$(printf 'sl %s %s' "$mode" "$k" | od -An -tx1 | tr -d ' \n')
        run sign_stateless "$key" "${mode%:*}" "${mode#*:}" "$k" "$node" "/sign_stateless?msg=$msg&ctx=&exact=${mode%:*}&cache=${mode#*:}"
        ./target/release/shrincs-verify "$pk" "$msg" "$(field sig "$answer")" >/dev/null || { echo "invalid: $answer" >&2; exit 1; }
      done
    done
  fi
  first=0
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$sigs" "$(field secret_bytes_cache "$st")" "$(field secret_bytes_min "$st")" \
    "$(field public_bytes "$st")" "$rss0" "$rss" "$(field used_leaves "$(status 0)")" "$(max_field journal_bytes)" >>"$out/storage.tsv"
done

{
  echo "| operation | key | R | cache | runs | client ms, median | client ms, max | rounds | MB sent, max node | MB received, max node | RAM peak MB, max node |"
  echo "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|"
  awk -F'\t' 'NR > 1 {
      g = $1 "\t" $2 "\t" $3 "\t" $4; if (!(g in cnt)) order[++ng] = g
      cnt[g]++; v[g, cnt[g]] = $7; r[g] += $8; s[g] += $9; q[g] += $10; if ($11 > p[g]) p[g] = $11 }
    END {
      for (o = 1; o <= ng; o++) {
        g = order[o]; k = cnt[g]
        for (i = 1; i <= k; i++) a[i] = v[g, i] + 0
        for (i = 1; i <= k; i++) for (j = i + 1; j <= k; j++) if (a[j] < a[i]) { t = a[i]; a[i] = a[j]; a[j] = t }
        split(g, f, "\t")
        rr = f[3] == "-" ? "-" : (f[3] == 1 ? "exact" : "fast"); cc = f[4] == "-" ? "-" : (f[4] == 1 ? "on" : "off")
        printf "| %s | %s | %s | %s | %d | %.1f | %.1f | %.0f | %.3f | %.3f | %.0f |\n", f[1], f[2], rr, cc, k, a[int((k + 1) / 2)], a[k], r[g] / k, s[g] / k / 1e6, q[g] / k / 1e6, p[g] / 1e6
      }
    }' "$out/results.tsv"
  echo
  echo "| key | stateful signatures | secret per node, with cache | secret per node, minimum | public per node | RSS per node before keygen | RSS per node after keygen | signatures made | journal on disk per node |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"
  awk -F'\t' 'NR > 1 { printf "| %s | %s | %.1f MB | %d B | %.1f KB | %.0f MB | %.0f MB | %s | %.1f KB |\n", $1, $2, $3 / 1e6, $4, $5 / 1e3, $6 / 1e6, $7 / 1e6, $8, $9 / 1e3 }' "$out/storage.tsv"
} >"$out/summary.md"
cat "$out/summary.md"
echo "run recorded in $out"
