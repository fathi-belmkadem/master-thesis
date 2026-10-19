#!/usr/bin/env bash
# Build the agent-training dataset from ../runs/ -> ./out/{trajectories.jsonl, manifest.csv, episodes.json}
# Run after one or more episodes have been recorded. Safe to re-run; it rebuilds from runs/.
cd "$(dirname "$0")"
exec python3 -I assemble.py "$@"
