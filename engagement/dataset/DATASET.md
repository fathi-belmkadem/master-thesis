# Dataset design — training an autonomous attack-selection agent

**Goal.** Collect data, by running the supervisor's catalogue against the approved testbed, that trains a
model to **autonomously choose and run the next attack** given what it currently knows about the
environment. Everything here is confined to the isolated, institutionally approved lab and the author's
own devices — the agent is a research artefact trained and evaluated *in that environment only*.

## Learning formulation

Each hand-run campaign is an **expert demonstration trajectory**: a sequence of
`(state, action, outcome)` steps where a knowledgeable operator (you) picks a sensible next action.

- **Stage 1 — Imitation learning (behaviour cloning).** Train a policy `π(action | state)` to reproduce
  the operator's choices from the collected trajectories. This is the primary use of the dataset and the
  realistic target for a master thesis — no live exploration needed, just the recorded campaigns.
- **Stage 2 — Reinforcement learning (optional, lab-only).** Treat the testbed as an environment with a
  reward for advancing the kill chain (see below); fine-tune the imitation policy by letting it act in the
  lab. Only do this if Stage 1 is solid and the supervisor approves live agent control.

This mirrors how autonomous-pentest / automated-red-team research is normally framed
(demonstrations → policy; lab as RL environment).

## State (what the agent observes)

Defined machine-readably in [`state_schema.json`](state_schema.json). In short, the state is the
**attacker's accumulating knowledge base**:

- **Global:** current kill-chain phase reached, episode step index, attacker on-link? (for MITM).
- **Per target** (keyed by WireGuard IP): `alive`, `device_class`, open `ports`, `services` (+versions),
  `firmware`, known `vulns`, recovered `creds`, `foothold` (y/n), `phase_reached`.

The state is **built up by the outcomes of prior actions** — e.g. a `scan.ports` success fills `ports`
and `services`; a `brute.rtsp` success fills `creds`; an exploit success flips `foothold`.

## Action space (what the agent can choose)

Defined machine-readably in [`actions.json`](actions.json): one entry per technique in the catalogue,
each carrying its session label, kill-chain phase, MITRE ATT&CK ID, the tool/script that runs it,
**preconditions** (state predicates that must hold for the action to be legal), and parameters (the
target). The preconditions are what make the problem learnable — a good policy learns to scan before it
exploits, to find creds before it pivots, etc.

Action = `(technique_id, target_ip[, params])`. Example: `("scan.ports", "10.100.101.10")`.

## Reward (for the optional RL stage)

Shaped around kill-chain progress per target, so the agent is rewarded for *making progress*, not for
noise:

| Event | Reward |
|-------|--------|
| New host discovered (`scan.discovery`) | small + |
| Services/vulns newly enumerated | small + |
| Credentials recovered | medium + |
| Foothold gained (exploit / web shell) | large + |
| New kill-chain phase reached on a target | large + |
| Objective action succeeds (exfil/dos/mitm/lateral) | large + |
| Action run whose preconditions were unmet / no new info | small − (discourage flailing) |
| Device wedged/bricked unintentionally | − (penalise collateral; also a fragility finding) |

Reward values are tuning parameters — start from this ordering.

## How a trajectory is captured (no changes to the attack scripts)

The attack scripts already emit everything needed; the dataset is **reconstructed** from `runs/`:

1. `lib.sh` writes `START/STOP <label> <target> <UTC>` to `runs/markers.log` around every action.
2. Each action's exact command is saved to `runs/<label>/<ts>_<target>/cmd.txt`, with raw tool output
   alongside (nmap `-oA`, nikto/hydra output, pcap, …).
3. **You** add the ground-truth outcome per run: create a one-line `result` file in that run folder with
   one of `success | fail | partial | wedged`, and (optionally) a `notes.md`. This is the only manual
   label, and it's the one a tool can't infer reliably.
4. [`assemble.py`](assemble.py) walks `runs/`, matches each run folder to its marker window, maps its
   `cmd.txt` to a technique+ATT&CK ID via `actions.json`, groups steps into **episodes**, reconstructs the
   evolving per-target **state before/after** each step, and writes the dataset.

Group campaigns into episodes with the helpers in `lib.sh`:
```bash
. engagement/lib.sh
episode_start tapo_c200_full     # writes START EPISODE <id> to markers.log
#   ... run your recon → web → brute → cve actions against the target ...
episode_stop  tapo_c200_full
```

## Outputs (`dataset/out/`)

- `trajectories.jsonl` — one JSON object per step: `{episode, step, ts_start, ts_stop, phase, category,
  technique, attck, target, params, cmd, result, evidence_dir, state_before, state_after}`. **This is the
  training file** (imitation learning reads `state_before → (technique,target)`).
- `manifest.csv` — flat index of every step for quick inspection / thesis tables.
- `episodes.json` — per-episode summary (length, phases reached, targets touched).

## Recommended data sources (your open question)

For an **agent**, the indispensable signal is the attacker-side `state→action→outcome` trace above — build
that first. **Additionally capture, synchronized by the same markers:**

- **Network pcap** (via [`../capture.sh`](../capture.sh), tcpdump on the tunnel): lets you optionally feed
  environment feedback into the agent's state later, and — importantly — makes the *same campaigns*
  double as a **labeled network-IDS dataset** (attacker agent + defender dataset from one collection
  effort: a strong thesis contribution).
- **Home Assistant telemetry** (device states + logbook) *if you can get an HA API token*: gives
  device-level ground truth of impact (plug toggled, camera DoS'd) — excellent reward signal and label
  quality. This is almost certainly why the catalogue names the "Home Assistant marker scheme".

Recommendation: **traces + pcap now; add HA telemetry once you have API access.** Start network capture
before an episode, stop it after, and keep the pcap in the episode's run folders.
