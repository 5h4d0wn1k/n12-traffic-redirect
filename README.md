> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# N12 — Traffic Redirector

A **traffic redirection** toolkit that orchestrates **ARP-based MITM** labs
and iptables/nft transparent-proxy rules — defaulting to a fully offline
dry-run that prints every command it would run.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/n12-traffic-redirect)](https://github.com/5h4d0wn1k/n12-traffic-redirect)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/n12-traffic-redirect)](https://github.com/5h4d0wn1k/n12-traffic-redirect)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/n12-traffic-redirect)](https://github.com/5h4d0wn1k/n12-traffic-redirect)

## Why N12

Man-in-the-middle positioning is the foundation of network-level testing: how
traffic is diverted, inspected, and restored. N12 teaches that with a
programmatic ARP cache-pivot state machine (`IDLE → PIVOTED → RESTORED`) plus
the exact `iptables`/`nft` NAT rules for transparent proxying. The default
mode is **--dry-run**: fully offline, prints every command, exercises the
restore logic against an in-memory fake ARP table. Applying the rules
(`--apply`) happens only against 192.0.2.x/198.51.100.x documentation
addresses in your own isolated lab — never third-party networks.

## Features

- **ARP cache pivot** — redirect a target's ARP entry toward the lab host
- **iptables/nft orchestration** — prints or applies `nat PREROUTING`/`POSTROUTING` rules
- **Dry-run by default** — offline, no root, no network required
- **Auto-restore** — `--restore` puts ARP tables and firewall rules back
- **Packet capture support** — BPF filter and pcap export hooks for analysis
- **Protocol accounting** — TCP/UDP/DNS/ICMP packet counters
- **Thread-safe** — concurrent spoof and capture threads
- **Deterministic tests** — offline suite with fake ARP tables, no root needed

## Quickstart

```bash
# Offline harness (no root, no network)
cd firmware && python3 traffic_redirect.py
python3 traffic_redirect.py --dry-run --target 192.0.2.10 --gateway 192.0.2.1

# Authorized own-lab apply / restore (root required)
sudo python3 traffic_redirect.py --target 192.0.2.10 --gateway 192.0.2.1 --local-mac <lab-mac> --apply
sudo python3 traffic_redirect.py --target 192.0.2.10 --gateway 192.0.2.1 --local-mac <lab-mac> --restore

# Advanced: duration, BPF filter, pcap
sudo python3 traffic_redirect.py -t 192.0.2.10 -g 192.0.2.1 --duration 60 --filter "tcp port 80" --save capture.pcap

# Tests
python3 -m unittest discover -s tests -v
```

Run the offline state machine on any dev box; reserve `--apply`/`--restore`
for a **--dry-run-verified, isolated, self-owned lab**.

## Project structure

- `firmware/traffic_redirect.py` — ARP pivot, NAT rule orchestration, and offline harness
- `tests/` — deterministic dry-run and state-machine tests
- `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `ETHICS.md`, `SCOPE.md`, `SECURITY.md` — standards and legal scope

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)