# IoT Testbed Attack Simulation — Engagement Workspace

Master thesis, step 1: simulate the supervisor's attack catalogue against the approved, isolated IoT
testbed, kill-chain phase by phase, with reproducible evidence.

**Read `00_scope/scope.md` first.** All activity is confined to `10.100.101.0/24` over the WireGuard
tunnel, against the author's own devices in an institutionally approved testbed.

## Layout

```
00_scope/     scope + rules of engagement, methodology (ATT&CK/kill-chain), targets.csv (40 devices)
01_setup/     Linux attack-host setup + preflight.sh (WireGuard/toolchain verification)
02_scan/ ... 10_lateral/   one folder per session category — each holds its README (plan) + its script
lib.sh        shared helpers (HA-style markers + scope guard + episode brackets)
capture.sh    optional pcap capture on the tunnel, bracketed to an episode
dataset/      agent-training dataset: DATASET.md, actions.json, state_schema.json, assemble.py
wordlists/    seed credential lists for the brute_force phase
runs/         machine-generated, timestamped evidence + markers.log + pcaps
```

## Order of work (kill chain)

1. **scan** (`02_scan`) — Reconnaissance. Start here. `02_scan/recon.sh`
2. web → brute_force → cve_exploit (Exploitation)
3. web (Installation) → c2 (C2)
4. dos/ddos, exfil, mitm, lateral (Actions on Objectives) — run the disruptive ones last, one at a time.

## Getting started on the Linux attack host

```bash
# 1. set up & connect (one time)
#    follow 01_setup/attack-host-setup.md

# 2. verify before touching anything
./01_setup/preflight.sh

# 3. reconnaissance
./02_scan/recon.sh discovery              # who is alive on the subnet
./02_scan/recon.sh all 10.100.101.10      # full scan of one host (e.g. Tapo C200)
./02_scan/recon.sh all-inventory          # every device (long-running)
```

Every run writes a START/STOP marker to `runs/markers.log` and drops the exact command + raw output
(nmap `-oA` set) into `runs/scan/<timestamp>_<target>/`, so each result is citable and repeatable in
the thesis. After a run, add a one-line finding + ATT&CK ID to the relevant `0X_*/README.md`.

## Building the training dataset

The end goal is a dataset to train an **autonomous attack-selection agent** — see
[`dataset/DATASET.md`](dataset/DATASET.md) for the full design (learning formulation, state/action
space, reward). Collection fits around normal runs:

```bash
. ./lib.sh
episode_start tapo_c200_full          # bracket one campaign
./capture.sh start tapo_c200_full     # (optional) capture tunnel pcap in parallel
#   ... run recon → web → brute → cve actions against the target ...
./capture.sh stop  tapo_c200_full
episode_stop  tapo_c200_full

# label the ground-truth outcome of each run (success|fail|partial|wedged):
echo success > runs/scan/<ts>_<target>/result

# assemble the (state -> action -> outcome) trajectories:
./dataset/assemble.sh                 # -> dataset/out/{trajectories.jsonl, manifest.csv, episodes.json}
```
