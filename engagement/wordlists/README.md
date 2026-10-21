# wordlists — Seed Credential Lists

Small, IoT-default-focused credential lists used by `04_brute_force/brute.sh`.

---

## Files

### `users.txt` — Username list

```
admin, root, user, guest, Admin, support, tech, operator, ubnt
```

9 entries covering the most common default usernames across IP cameras, smart plugs,
routers, and embedded Linux devices (Ubiquiti, TP-Link, Amcrest, Reolink, Shelly).

### `passwords.txt` — Password list

```
admin, password, 12345, 123456, 1234, 0000, root, admin123, pass,
guest, user, support, default, changeme, tplink
```

15 entries covering vendor defaults:
- `admin` / `password` — universal defaults
- `12345` / `123456` / `1234` / `0000` — numeric PINs common on cameras and doorbells
- `tplink` — TP-Link / Tapo devices
- `changeme` / `default` — post-factory-reset defaults

---

## Extending the Lists

For a second brute-force pass after the seed lists produce no results:

```bash
# Use a larger wordlist (record the list name + entry count for reproducibility):
./04_brute_force/brute.sh ssh 10.100.101.10 /usr/share/wordlists/rockyou.txt passwords.txt

# Vendor-specific default lists (curated for IoT):
# - /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv
# - https://github.com/danielmiessler/SecLists (IoT defaults)
```

Only escalate to large lists on a device that tolerated the small run without wedging.
Record the list name, file path, and entry count in `04_brute_force/README.md` under Findings.

---

## Credential Stuffing (T1110.004)

Any credentials recovered from one device should be tried against other devices of the
same vendor (e.g. recovered Tapo C200 creds → try against other Tapo devices at `.34-.45`).
Use `brute.sh`'s hydra wrapper — do not manually iterate:

```bash
# Single-entry lists for stuffing a known credential:
echo "admin"    > /tmp/known_user.txt
echo "abc123"   > /tmp/known_pass.txt
./04_brute_force/brute.sh ssh 10.100.101.34 /tmp/known_user.txt /tmp/known_pass.txt
```

Document every reuse hit in `04_brute_force/README.md` under Findings.

---

## Security Note

These lists are **never committed with recovered credentials appended**.
If you add site-specific discovered passwords here, they go in `runs/` (gitignored),
not in `wordlists/`.
