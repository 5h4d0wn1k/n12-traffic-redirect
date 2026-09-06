"""Tests for the N12 traffic redirector (offline, no iptables/root)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

from traffic_redirect import (ArpCacheStateMachine, FakeArpTable,
                              RedirectPlanner, TrafficRedirector,
                              run_offline_harness)

TARGET = '192.0.2.10'
GATEWAY = '192.0.2.1'
LOCAL_MAC = '00:11:22:33:44:55'
TARGET_REAL = '00:11:22:33:44:66'
GW_REAL = '00:11:22:33:44:77'

PLACEHOLDERS = dict(target=TARGET, gateway=GATEWAY, local_mac=LOCAL_MAC)


def make_table():
    return FakeArpTable({TARGET: TARGET_REAL, GATEWAY: GW_REAL})


class FakeArpTableTests(unittest.TestCase):

    def test_pivot_changes_target_mapping(self):
        arp = make_table()
        arp.pivot_gateway(TARGET, LOCAL_MAC)
        self.assertEqual(arp.get(TARGET), LOCAL_MAC)
        self.assertEqual(arp.get(GATEWAY), GW_REAL)

    def test_restore_reverts(self):
        arp = make_table()
        arp.pivot_gateway(TARGET, LOCAL_MAC)
        arp.restore()
        self.assertEqual(arp.get(TARGET), TARGET_REAL)

    def test_restore_restores_all_entries(self):
        arp = make_table()
        arp.set(GATEWAY, 'aa:bb:cc:dd:ee:ff')
        arp.pivot_gateway(TARGET, LOCAL_MAC)
        arp.restore()
        self.assertEqual(arp.get(TARGET), TARGET_REAL)
        self.assertEqual(arp.get(GATEWAY), GW_REAL)


class StateMachineTests(unittest.TestCase):

    def test_idle_to_pivoted_to_restored(self):
        arp = make_table()
        sm = ArpCacheStateMachine(arp, **PLACEHOLDERS)
        self.assertEqual(sm.state, sm.IDLE)
        prev = sm.pivot()
        self.assertEqual(sm.state, sm.PIVOTED)
        self.assertEqual(prev, TARGET_REAL)
        self.assertEqual(arp.get(TARGET), LOCAL_MAC)
        sm.restore()
        self.assertEqual(sm.state, sm.RESTORED)
        self.assertEqual(arp.get(TARGET), TARGET_REAL)

    def test_pivot_requires_idle(self):
        sm = ArpCacheStateMachine(make_table(), **PLACEHOLDERS)
        sm.pivot()
        with self.assertRaises(RuntimeError):
            sm.pivot()

    def test_restore_requires_pivoted(self):
        sm = ArpCacheStateMachine(make_table(), **PLACEHOLDERS)
        with self.assertRaises(RuntimeError):
            sm.restore()

    def test_transitions_logged(self):
        sm = ArpCacheStateMachine(make_table(), **PLACEHOLDERS)
        sm.pivot()
        sm.restore()
        self.assertEqual(len(sm.transitions), 2)
        self.assertEqual(sm.transitions[0][0], 'pivot')
        self.assertEqual(sm.transitions[1][0], 'restore')


class RedirectPlannerTests(unittest.TestCase):

    def setUp(self):
        self.planner = RedirectPlanner(TARGET, GATEWAY, LOCAL_MAC)

    def test_apply_iptables_exact(self):
        cmds = self.planner.apply_iptables()
        self.assertEqual(cmds[0],
                         'iptables -t nat -A PREROUTING -s 192.0.2.10 '
                         '-j DNAT --to-destination 192.0.2.1')
        self.assertTrue(all(c.startswith('iptables -t nat -A')
                            for c in cmds))
        self.assertEqual(len(cmds), 2)

    def test_restore_iptables_uses_dash_d(self):
        cmds = self.planner.restore_iptables()
        self.assertTrue(all('-t nat -D' in c for c in cmds))
        self.assertEqual(len(cmds), 2)

    def test_apply_nft_exact(self):
        cmds = self.planner.apply_nft()
        self.assertEqual(cmds[0],
                         'nft add rule ip nat PREROUTING ip saddr 192.0.2.10 '
                         'dnat to 192.0.2.1')
        self.assertTrue(all(c.startswith('nft add rule') for c in cmds))

    def test_restore_nft_uses_delete(self):
        cmds = self.planner.restore_nft()
        self.assertTrue(all('nft delete rule' in c for c in cmds))

    def test_arp_pivot_hint(self):
        self.assertIn('192.0.2.10', self.planner.arp_pivot_hint())


class RedirectorTests(unittest.TestCase):

    def test_plan_apply_shape(self):
        r = TrafficRedirector(**PLACEHOLDERS)
        plan = r.plan_apply()
        self.assertEqual(len(plan['iptables']), 2)
        self.assertEqual(len(plan['nft']), 2)
        self.assertEqual(len(plan['arp']), 1)

    def test_plan_restore_shape(self):
        r = TrafficRedirector(**PLACEHOLDERS)
        plan = r.plan_restore()
        self.assertEqual(len(plan['iptables']), 2)
        self.assertEqual(len(plan['nft']), 2)

    def test_apply_dry_run_pivots_fake_table(self):
        arp = make_table()
        r = TrafficRedirector(**PLACEHOLDERS, arp_table=arp)
        r.apply(dry_run=True)
        self.assertEqual(arp.get(TARGET), LOCAL_MAC)
        self.assertEqual(r.machine.state, r.machine.PIVOTED)

    def test_restore_dry_run_reverts_fake_table(self):
        arp = make_table()
        r = TrafficRedirector(**PLACEHOLDERS, arp_table=arp)
        r.apply(dry_run=True)
        r.restore(dry_run=True)
        self.assertEqual(arp.get(TARGET), TARGET_REAL)
        self.assertEqual(r.machine.state, r.machine.RESTORED)


class HarnessTests(unittest.TestCase):

    def test_offline_harness_passes(self):
        self.assertEqual(run_offline_harness(), 0)


if __name__ == '__main__':
    unittest.main()
