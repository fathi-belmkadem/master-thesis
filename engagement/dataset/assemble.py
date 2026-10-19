#!/usr/bin/env python3
"""Assemble the agent-training dataset from engagement/runs/.

Reconstructs (state -> action -> outcome) trajectories by:
  1. reading runs/markers.log for episode + action time windows,
  2. mapping each run folder's cmd.txt to a technique+ATT&CK id via actions.json,
  3. replaying outcomes to rebuild the attacker's per-target knowledge (state_before/after),
  4. writing dataset/out/{trajectories.jsonl, manifest.csv, episodes.json}.

Reads only files this toolkit produced. Stdlib only. Run: python3 assemble.py
"""
import csv, json, os, re, sys
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENG = HERE.parent
RUNS = ENG / "runs"
OUT = HERE / "out"
ACTIONS = json.loads((HERE / "actions.json").read_text(encoding="utf-8"))["actions"]
TARGETS_CSV = ENG / "00_scope" / "targets.csv"

PHASE_ORDER = ["Reconnaissance", "Delivery", "Exploitation", "Installation",
               "CommandAndControl", "ActionsOnObjectives", "Lateral Movement"]
PHASE_RANK = {p: i for i, p in enumerate(PHASE_ORDER)}


def compact(iso):  # "2026-10-20T14:05:09Z" -> "20261020-140509Z"  (matches tsfile())
    return iso.replace("-", "").replace(":", "").replace("T", "-")


def load_targets():
    meta = {}
    if TARGETS_CSV.exists():
        for row in csv.DictReader(TARGETS_CSV.open(encoding="utf-8")):
            meta[row["wireguard_ip"]] = {"device_class": row.get("device_class", ""),
                                         "model": row.get("device_model", "")}
    return meta


def parse_markers():
    """Return (episodes, action_markers).
    episodes: [{id, start, stop}]; action_markers: {(label,target,compact_start): (start,stop)}."""
    episodes, open_eps, actions = [], {}, {}
    open_acts = {}
    mf = RUNS / "markers.log"
    if not mf.exists():
        return episodes, actions
    for line in mf.read_text(encoding="utf-8").splitlines():
        p = line.split()
        if len(p) < 3:
            continue
        kind, rest, ts = p[0], p[1:-1], p[-1]
        if rest and rest[0] == "EPISODE":
            eid = rest[1]
            if kind == "START":
                open_eps[eid] = ts
            else:
                episodes.append({"id": eid, "start": open_eps.pop(eid, ts), "stop": ts})
            continue
        label = rest[0]
        target = rest[1] if len(rest) > 1 else "all"
        key = (label, target)
        if kind == "START":
            open_acts.setdefault(key, []).append(ts)
        else:
            starts = open_acts.get(key)
            if starts:
                st = starts.pop(0)
                actions[(label, target, compact(st))] = (st, ts)
    return episodes, actions


def episode_for(ts, episodes):
    for e in episodes:
        if e["start"] <= ts <= e["stop"]:
            return e["id"]
    return "default"


def map_action(cmd):
    """Pick the most specific action whose every 'match' token appears in cmd.
    Case-sensitive on purpose: nmap flags (-sS/-sU/-O vs -oA) differ only by case."""
    best, best_n = None, -1
    for a in ACTIONS:
        toks = a.get("match", [])
        if toks and all(t in cmd for t in toks) and len(toks) > best_n:
            best, best_n = a, len(toks)
    return best


def collect_runs(episodes, action_markers, tmeta):
    steps = []
    for label_dir in sorted(p for p in RUNS.iterdir() if p.is_dir() and p.name not in ("pcap",)):
        for run in sorted(label_dir.iterdir()):
            if not run.is_dir():
                continue
            cmd_f = run / "cmd.txt"
            if not cmd_f.exists():
                continue
            cmd = cmd_f.read_text(encoding="utf-8").strip()
            name = run.name                      # <compact_ts>_<target>
            comp = name.split("_", 1)[0]
            target = name.split("_", 1)[1] if "_" in name else "all"
            label = label_dir.name
            start, stop = action_markers.get((label, target, comp), (comp, comp))
            result = (run / "result").read_text(encoding="utf-8").strip() if (run / "result").exists() else "unset"
            action = map_action(cmd) or {"id": "unknown", "session_label": label, "phase": "", "attck": ""}
            steps.append({
                "episode": episode_for(start, episodes),
                "ts_start": start, "ts_stop": stop,
                "phase": action["phase"], "category": label,
                "technique": action["id"], "attck": action["attck"],
                "target": target, "cmd": cmd, "result": result,
                "evidence_dir": str(run.relative_to(ENG)).replace("\\", "/"),
                "device_class": tmeta.get(target, {}).get("device_class", ""),
                "model": tmeta.get(target, {}).get("model", ""),
            })
    steps.sort(key=lambda s: (s["episode"], s["ts_start"]))
    return steps


def blank_target(ip, tmeta):
    m = tmeta.get(ip, {})
    return {"ip": ip, "device_class": m.get("device_class", ""), "model": m.get("model", ""),
            "alive": False, "ports": [], "services": {}, "firmware": "",
            "vulns": [], "creds": [], "foothold": False, "phase_reached": None}


def apply_outcome(state, step, tmeta):
    """Mutate episode state given a (successful/partial) step. Best-effort from technique id."""
    if step["result"] not in ("success", "partial"):
        return
    tech, ip = step["technique"], step["target"]
    if tech.startswith("scan.discovery"):
        # discovery result is subnet-wide; mark the stated target set alive lazily per later steps
        return
    tgt = state["targets"].setdefault(ip, blank_target(ip, tmeta))
    tgt["alive"] = True
    if tech in ("scan.ports", "scan.udp"):
        pass  # exact ports parsed from evidence offline; flag that services are now known
    if tech in ("scan.ports", "scan.udp", "web.fingerprint"):
        tgt.setdefault("services", {})
    if tech == "scan.fingerprint":
        tgt["firmware"] = tgt["firmware"] or "fingerprinted"
    if tech in ("scan.vuln", "web.nikto"):
        tgt["vulns"].append(step["attck"])
    if tech.startswith("brute."):
        tgt["creds"].append({"service": step["category"], "ref": step["evidence_dir"]})
    if tech.startswith("cve.") or tech == "web.shell_upload":
        tgt["foothold"] = True
    if tech.startswith("mitm."):
        state["attacker_on_link"] = True
    # phase progress
    r = PHASE_RANK.get(step["phase"])
    if r is not None:
        if tgt["phase_reached"] is None or r > PHASE_RANK.get(tgt["phase_reached"], -1):
            tgt["phase_reached"] = step["phase"]
        if state["phase_reached"] is None or r > PHASE_RANK.get(state["phase_reached"], -1):
            state["phase_reached"] = step["phase"]


def build(steps, tmeta):
    traj, ep_state, ep_step = [], {}, {}
    for s in steps:
        eid = s["episode"]
        st = ep_state.setdefault(eid, {"targets": {}, "phase_reached": None, "attacker_on_link": False})
        s["step"] = ep_step.get(eid, 0)
        ep_step[eid] = s["step"] + 1
        s["state_before"] = deepcopy(st)
        apply_outcome(st, s, tmeta)
        s["state_after"] = deepcopy(st)
        traj.append(s)
    return traj


def main():
    if not RUNS.exists():
        print(f"no runs/ dir at {RUNS} — nothing to assemble yet", file=sys.stderr)
        return 1
    tmeta = load_targets()
    episodes, action_markers = parse_markers()
    steps = collect_runs(episodes, action_markers, tmeta)
    traj = build(steps, tmeta)
    OUT.mkdir(exist_ok=True)
    with (OUT / "trajectories.jsonl").open("w", encoding="utf-8") as f:
        for s in traj:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    cols = ["episode", "step", "ts_start", "ts_stop", "phase", "category", "technique",
            "attck", "target", "device_class", "result", "evidence_dir"]
    with (OUT / "manifest.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(traj)
    ep_summary = {}
    for s in traj:
        e = ep_summary.setdefault(s["episode"], {"steps": 0, "targets": set(), "phases": set()})
        e["steps"] += 1
        e["targets"].add(s["target"])
        if s["phase"]:
            e["phases"].add(s["phase"])
    for e in ep_summary.values():
        e["targets"] = sorted(e["targets"])
        e["phases"] = sorted(e["phases"], key=lambda p: PHASE_RANK.get(p, 99))
    (OUT / "episodes.json").write_text(json.dumps(ep_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"assembled {len(traj)} steps across {len(ep_summary)} episode(s) -> {OUT}")
    unknown = sum(1 for s in traj if s["technique"] == "unknown")
    unset = sum(1 for s in traj if s["result"] == "unset")
    if unknown:
        print(f"  note: {unknown} step(s) did not map to a known action (check actions.json 'match')")
    if unset:
        print(f"  note: {unset} step(s) have result=unset — add a 'result' file in those run folders")
    return 0


if __name__ == "__main__":
    sys.exit(main())
