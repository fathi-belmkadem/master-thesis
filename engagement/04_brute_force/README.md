# 04_brute_force — Credential brute force (session label: `brute_force`)

Kill-chain: **Exploitation**. Dictionary / credential-stuffing attacks against the auth services found
in `02_scan`. ATT&CK: T1110.001 (password guessing), T1110.004 (credential stuffing).

Driver: [`brute.sh`](brute.sh) (hydra). Seed lists in
[`../wordlists/`](../wordlists/). Evidence → `../runs/brute_force/`.

## Where to point it (from recon)

| Service | Likely devices | How |
|---------|----------------|-----|
| **RTSP 554** | cameras: Tapo C200 `.10`, Amcrest `.12`, TC70 `.19`, Reolink `.20/.56` | `./04_brute_force/brute.sh rtsp 10.100.101.10` |
| **ONVIF / HTTP-Digest** | same cameras (port 2020/80/8000) | `./04_brute_force/brute.sh http-get 10.100.101.12 /onvif/device_service` |
| **HTTP login form** | camera/Shelly/ESP web UIs | `./04_brute_force/brute.sh http-form <ip> "<form string>"` |
| **SSH / Telnet** | any device where recon shows 22/23 open | `./04_brute_force/brute.sh ssh 10.100.101.X` |

For the HTTP form string, capture the login POST in Burp/ZAP, then format for hydra, e.g.:
```
"/login:user=^USER^&pass=^PASS^:F=Login failed"
```

## Conservative by design — and why it matters here

IoT auth stacks lock out, rate-limit, or simply **wedge** under brute-force load. The script defaults to
`-t 4 -W 1` (low parallelism, a wait between tries). This protects the testbed *and* produces a cleaner
result: **if a device stops responding, that is itself a finding** (DoS-via-auth / fragility) — record it
in the run's `notes.md` with the attempt count, and power-cycle to recover.

- Start with the seed lists (`wordlists/users.txt`, `passwords.txt`) — small, IoT-default-heavy, fast.
- Only escalate to a large list (e.g. `rockyou`, vendor default-credential sets) on a device that
  tolerated the small run, and note the list + size for reproducibility.
- **Credential stuffing (T1110.004):** reuse any creds recovered on one device against the others
  (same vendor devices often share defaults) — document each reuse hit explicitly.

## Scope & safety

`brute.sh` refuses any target outside `10.100.101.0/24` and never touches the gateway. These are your
own lab devices; still, treat a recovered credential as sensitive — store it only in the run folder,
not in this README.

### Findings
_(target | service | result (creds / locked / wedged) | attempts | ATT&CK ID | evidence path)_
