# N12 — Traffic Redirector

ARP spoofing simulation, traffic capture, and MITM demonstration (local network only).

## Overview

This project implements a traffic redirection tool for authorized MITM demonstrations that:
- Performs ARP spoofing to redirect traffic between target and gateway
- Captures and analyzes redirected traffic
- Provides thread-safe concurrent spoofing and capturing
- Restores ARP tables on exit
- Supports BPF filters and pcap export

## Features

- **ARP spoofing**: Redirect traffic by poisoning ARP caches
- **Traffic capture**: Sniff and analyze redirected packets
- **Protocol analysis**: Count TCP, UDP, DNS, ICMP traffic
- **Thread-safe**: Concurrent spoof and capture threads
- **ARP restoration**: Auto-restore ARP tables on shutdown
- **pcap export**: Save captures for Wireshark analysis

## Installation

```bash
pip install scapy
```

## Usage

```bash
# Full MITM demo (requires root)
sudo python3 traffic_redirect.py --target 192.168.1.100 --gateway 192.168.1.1

# With duration limit
sudo python3 traffic_redirect.py --target 192.168.1.100 --gateway 192.168.1.1 --duration 60

# With capture filter (BPF syntax)
sudo python3 traffic_redirect.py --target 192.168.1.100 --gateway 192.168.1.1 --filter "tcp port 80"

# Save capture to pcap
sudo python3 traffic_redirect.py --target 192.168.1.100 --gateway 192.168.1.1 --save capture.pcap

# ARP spoof only (no capture)
sudo python3 traffic_redirect.py --target 192.168.1.100 --gateway 192.168.1.1 --spoof-only
```

## Example Output

```
╔═══════════════════════════════════════╗
║     N12 — Traffic Redirector          ║
║     MITM Demo (local only)            ║
╚═══════════════════════════════════════╝

[*] Resolving MAC addresses...
    Target:   192.168.1.100 -> AA:BB:CC:DD:EE:FF
    Gateway:  192.168.1.1   -> 11:22:33:44:55:66
    Local:    77:88:99:AA:BB:CC

[*] Starting MITM simulation...
[+] ARP spoofing started
[*] Starting packet capture...
    [CAPTURED] 192.168.1.100:44231 -> 142.250.80.46:443 (1420B)
    [CAPTURED] 192.168.1.100:44232 -> 142.250.80.46:443 (128B)
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
