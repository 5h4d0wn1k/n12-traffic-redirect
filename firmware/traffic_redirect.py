#!/usr/bin/env python3
"""
N12 - Traffic Redirector.

A programmatic iptables ARP/redirect suite. The default mode is --dry-run,
which prints the exact iptables and nft commands it would run and exercises
the ARP cache-pivot state machine against an in-memory fake ARP table - all
fully offline, no root, no network access. Explicit --apply / --restore
execute the commands for authorized own-lab use only (root required).

Authorized use only: documented placeholders 192.0.2.x / 198.51.100.x and
MAC 00:11:22:33:44:55. Never run against third-party networks.
"""

import argparse
import os
import subprocess
import sys


class FakeArpTable:
    """In-memory ARP cache used for fully offline testing of the pivot and
    restore logic. Maps ip -> mac, exactly like a real ARP cache."""

    def __init__(self, entries=None):
        self.entries = dict(entries or {})
        self._original = dict(self.entries)

    def get(self, ip):
        return self.entries.get(ip)

    def set(self, ip, mac):
        self.entries[ip] = mac

    def pivot_gateway(self, target_ip, local_mac):
        """Pivot the target's cache entry so its upstream address resolves to
        the local host (simulating an ARP cache pivot)."""
        self.entries[target_ip] = local_mac

    def restore(self):
        """Restore every entry to its pre-pivot value."""
        self.entries = dict(self._original)


class ArpCacheStateMachine:
    """Stateful controller for the ARP cache pivot / restore lifecycle.

    State transitions: IDLE -> PIVOTED -> RESTORED.
    """

    IDLE = 'IDLE'
    PIVOTED = 'PIVOTED'
    RESTORED = 'RESTORED'

    def __init__(self, arp_table=None, target=None, gateway=None,
                 local_mac=None):
        self.arp = arp_table or FakeArpTable()
        self.target = target
        self.gateway = gateway
        self.local_mac = local_mac
        self.state = self.IDLE
        self.transitions = []

    def pivot(self):
        if self.state != self.IDLE:
            raise RuntimeError(f'cannot pivot from state {self.state}')
        prev_mac = self.arp.get(self.target)
        self.arp.pivot_gateway(self.target, self.local_mac)
        self.transitions.append(('pivot', prev_mac, self.local_mac))
        self.state = self.PIVOTED
        return prev_mac

    def restore(self):
        if self.state != self.PIVOTED:
            raise RuntimeError(f'cannot restore from state {self.state}')
        self.arp.restore()
        self.transitions.append(('restore',))
        self.state = self.RESTORED


class RedirectPlanner:
    """Builds the exact iptables and nft command lists for apply and restore."""

    def __init__(self, target, gateway, local_mac, iface=None):
        self.target = target
        self.gateway = gateway
        self.local_mac = local_mac
        self.iface = iface
        self._validate()

    def _validate(self):
        for ip in (self.target, self.gateway):
            if not ip:
                raise ValueError('target and gateway are required')

    def apply_iptables(self):
        return [
            f'iptables -t nat -A PREROUTING -s {self.target} '
            f'-j DNAT --to-destination {self.gateway}',
            f'iptables -t nat -A POSTROUTING -s {self.target} '
            f'-j SNAT --to-source {self.gateway}',
        ]

    def restore_iptables(self):
        return [
            f'iptables -t nat -D PREROUTING -s {self.target} '
            f'-j DNAT --to-destination {self.gateway}',
            f'iptables -t nat -D POSTROUTING -s {self.target} '
            f'-j SNAT --to-source {self.gateway}',
        ]

    def apply_nft(self):
        return [
            f'nft add rule ip nat PREROUTING ip saddr {self.target} '
            f'dnat to {self.gateway}',
            f'nft add rule ip nat POSTROUTING ip saddr {self.target} '
            f'masquerade',
        ]

    def restore_nft(self):
        return [
            f'nft delete rule ip nat PREROUTING ip saddr {self.target} '
            f'dnat to {self.gateway}',
            f'nft delete rule ip nat POSTROUTING ip saddr {self.target} '
            f'masquerade',
        ]

    def arp_pivot_hint(self):
        return (f'ARP pivot: {self.target} cache entry now resolves to '
                f'{self.local_mac} (local host)')

    def arp_restore_hint(self):
        return f'ARP restore: {self.target} cache entry reverted to original MAC'


class TrafficRedirector:
    """Ties the planner and the ARP cache-pivot state machine together."""

    def __init__(self, target=None, gateway=None, local_mac=None, iface=None,
                 arp_table=None):
        self.planner = RedirectPlanner(target, gateway, local_mac, iface)
        self.machine = ArpCacheStateMachine(arp_table, target, gateway,
                                            local_mac)

    def plan_apply(self):
        return {
            'iptables': self.planner.apply_iptables(),
            'nft': self.planner.apply_nft(),
            'arp': [self.planner.arp_pivot_hint()],
        }

    def plan_restore(self):
        return {
            'iptables': self.planner.restore_iptables(),
            'nft': self.planner.restore_nft(),
            'arp': [self.planner.arp_restore_hint()],
        }

    def _run_commands(self, commands):
        proc = subprocess.run(commands, capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
        return proc.returncode

    def apply(self, dry_run=True):
        plan = self.plan_apply()
        mac = self.machine.pivot()
        self._print_plan(plan, 'APPLY')
        if not dry_run:
            for cmd in plan['iptables']:
                self._run_commands(cmd.split())
        return mac

    def restore(self, dry_run=True):
        plan = self.plan_restore()
        self.machine.restore()
        self._print_plan(plan, 'RESTORE')
        if not dry_run:
            for cmd in plan['iptables']:
                self._run_commands(cmd.split())

    @staticmethod
    def _print_plan(plan, phase):
        print(f'[{phase}] exact commands (dry-run):')
        for label, cmds in (('iptables', plan['iptables']),
                            ('nft', plan['nft']),
                            ('arp', plan['arp'])):
            print(f'  {label}:')
            for c in cmds:
                print(f'    $ {c}')


def run_offline_harness():
    """Fully offline harness: exercise the ARP cache-pivot state machine and
    the restore logic against a fake ARP table. No root, no iptables, no
    network access."""
    ok = True
    print('=== N12 Traffic Redirector: offline ARP pivot harness ===')

    placeholders = dict(
        target='192.0.2.10', gateway='192.0.2.1',
        local_mac='00:11:22:33:44:55')

    arp = FakeArpTable({
        '192.0.2.10': '00:11:22:33:44:66',   # target's real MAC
        '192.0.2.1':  '00:11:22:33:44:77',  # gateway's real MAC
    })
    gw_before = arp.get('192.0.2.10')
    machine = ArpCacheStateMachine(arp, **placeholders)

    def check(label, cond):
        nonlocal ok
        print(f'  [{"PASS" if cond else "FAIL"}] {label}')
        ok = ok and cond

    check('starts IDLE', machine.state == machine.IDLE)

    prev = machine.pivot()
    check('pivot transitions to PIVOTED', machine.state == machine.PIVOTED)
    check('pivot returns prior MAC', prev == gw_before)
    check('target cache pivoted to local MAC',
          arp.get('192.0.2.10') == '00:11:22:33:44:55')
    check('gateway cache untouched',
          arp.get('192.0.2.1') == '00:11:22:33:44:77')

    machine.restore()
    check('restore transitions to RESTORED', machine.state == machine.RESTORED)
    check('target cache restored to original',
          arp.get('192.0.2.10') == gw_before)

    redirector = TrafficRedirector(**placeholders)
    plan = redirector.plan_apply()
    check('apply plan emits iptables commands', len(plan['iptables']) == 2)
    check('apply plan emits nft commands', len(plan['nft']) == 2)
    check('apply plan emits ARP pivot hint', len(plan['arp']) == 1)

    redirector.machine = ArpCacheStateMachine(FakeArpTable(
        {'192.0.2.10': gw_before, '192.0.2.1': '00:11:22:33:44:77'}),
        **placeholders)
    restore_plan = redirector.plan_restore()
    check('restore plan emits iptables -D commands',
          all('-t nat -D' in c for c in restore_plan['iptables']))
    check('restore plan emits nft delete rules',
          all('delete rule' in c for c in restore_plan['nft']))

    print(f'\n[RESULT] ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description='N12 — Traffic Redirector (programmatic iptables '
                    'ARP/redirect suite; dry-run by default)')
    parser.add_argument('--target', '-t', default='192.0.2.10',
                        help='Target IP (documentation placeholder)')
    parser.add_argument('--gateway', '-g', default='192.0.2.1',
                        help='Gateway IP (documentation placeholder)')
    parser.add_argument('--local-mac', '-m', default='00:11:22:33:44:55',
                        help='Local MAC (documentation placeholder)')
    parser.add_argument('--interface', '-i', help='Network interface')
    parser.add_argument('--offline', action='store_true',
                        help='Run the offline ARP pivot harness (default '
                             'with no action flags)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print commands and exercise offline harness '
                             'without executing (default)')
    parser.add_argument('--apply', action='store_true',
                        help='Apply redirect rules (root, authorized lab '
                             'only)')
    parser.add_argument('--restore', action='store_true',
                        help='Restore redirect rules and ARP cache (root)')

    args = parser.parse_args()

    if not (args.apply or args.restore or args.offline):
        redirector = TrafficRedirector(
            target=args.target, gateway=args.gateway,
            local_mac=args.local_mac, iface=args.interface,
            arp_table=FakeArpTable({
                args.target or '192.0.2.10': '00:11:22:33:44:66',
                args.gateway or '192.0.2.1': '00:11:22:33:44:77',
            }))
        redirector.apply(dry_run=True)
        redirector.restore(dry_run=True)
        sys.exit(run_offline_harness())

    if args.offline:
        sys.exit(run_offline_harness())

    if os.geteuid() != 0:
        print('[-] --apply / --restore require root (authorized lab only)',
              file=sys.stderr)
        sys.exit(1)

    redirector = TrafficRedirector(
        target=args.target, gateway=args.gateway,
        local_mac=args.local_mac, iface=args.interface)
    if args.apply:
        redirector.apply(dry_run=False)
    elif args.restore:
        redirector.restore(dry_run=False)


if __name__ == '__main__':
    main()
