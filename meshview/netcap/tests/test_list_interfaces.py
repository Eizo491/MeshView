"""
`capture_live --list-interfaces` formatting.

The reported problem was Windows output like
`\\Device\\NPF_{3F2A...}` with no way to tell which adapter was which.
These tests build fakes shaped like scapy's Windows NetworkInterface
(friendly `name`, adapter `description`, raw `network_name`, and an
`ips` dict keyed by IP version) -- no scapy, Npcap or Windows needed.
"""

from collections import defaultdict
from types import SimpleNamespace

from django.test import SimpleTestCase

from netcap.capture.interfaces import collect_interfaces, format_interface_table


def fake_iface(name, description, guid, ipv4=(), ipv6=(), valid=True):
    ips = defaultdict(list)
    ips[4] = list(ipv4)
    ips[6] = list(ipv6)
    return SimpleNamespace(
        name=name,
        description=description,
        network_name=f"\\Device\\NPF_{{{guid}}}",
        ips=ips,
        ip=ipv4[0] if ipv4 else "",
        is_valid=lambda: valid,
    )


WINDOWS_LIKE = [
    fake_iface("Loopback Pseudo-Interface 1", "Software Loopback Interface 1",
               "AAAA0000-0000-0000-0000-000000000001", ["127.0.0.1"]),
    fake_iface("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter",
               "BBBB0000-0000-0000-0000-000000000002", ["172.24.16.1"]),
    fake_iface("Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz",
               "CCCC0000-0000-0000-0000-000000000003", ["192.168.1.23"], ["fe80::1"]),
    fake_iface("Ethernet", "Realtek PCIe GbE Family Controller",
               "DDDD0000-0000-0000-0000-000000000004", []),  # cable unplugged
    fake_iface("Bluetooth Network Connection", "Bluetooth Device (PAN)",
               "EEEE0000-0000-0000-0000-000000000005", valid=False),
]


class ListInterfacesTests(SimpleTestCase):
    def test_shows_friendly_names_and_ips_never_raw_npf_strings(self):
        rows, _ = collect_interfaces(WINDOWS_LIKE)
        text = format_interface_table(rows)

        self.assertIn("Wi-Fi", text)
        self.assertIn("192.168.1.23", text)
        self.assertIn("Intel(R) Wi-Fi 6 AX201 160MHz", text)
        self.assertNotIn("NPF_", text)
        self.assertNotIn("Device", text)

    def test_interfaces_with_an_ipv4_come_first(self):
        rows, _ = collect_interfaces(WINDOWS_LIKE)
        # IPv4-bearing adapters first (alphabetical), the unplugged
        # "Ethernet" (no IPv4) last.
        self.assertEqual(
            [r.name for r in rows],
            ["Loopback Pseudo-Interface 1", "vEthernet (WSL)", "Wi-Fi", "Ethernet"],
        )
        self.assertEqual(rows[-1].ipv4, "-")

    def test_invalid_interfaces_hidden_and_counted_unless_all_requested(self):
        rows, hidden = collect_interfaces(WINDOWS_LIKE)
        self.assertNotIn("Bluetooth Network Connection", [r.name for r in rows])
        self.assertEqual(hidden, 1)
        self.assertIn("1 interface without an IP/MAC", format_interface_table(rows, hidden))

        rows_all, hidden_all = collect_interfaces(WINDOWS_LIKE, include_invalid=True)
        self.assertIn("Bluetooth Network Connection", [r.name for r in rows_all])
        self.assertEqual(hidden_all, 0)

    def test_duplicate_friendly_names_fall_back_to_unique_network_name(self):
        # Two VPN adapters, same friendly name: sniff(iface="Ethernet 2")
        # would always pick the first, so the second must be addressable.
        twins = [
            fake_iface("Ethernet 2", "TAP-Windows Adapter V9", "1111", ["10.8.0.2"]),
            fake_iface("Ethernet 2", "TAP-Windows Adapter V9 #2", "2222", ["10.9.0.2"]),
        ]
        rows, _ = collect_interfaces(twins)
        self.assertEqual(len({r.name for r in rows}), 2)
        self.assertTrue(all("NPF_" in r.name for r in rows))

    def test_ipv4_falls_back_to_single_ip_attribute_on_older_scapy(self):
        old = SimpleNamespace(name="eth0", description="eth0", network_name="eth0",
                              ip="10.0.0.5", is_valid=lambda: True)  # no `ips` at all
        rows, _ = collect_interfaces([old])
        self.assertEqual(rows[0].ipv4, "10.0.0.5")
        self.assertEqual(rows[0].description, "")  # same as name -> not repeated

    def test_empty_list(self):
        rows, hidden = collect_interfaces([])
        self.assertEqual(format_interface_table(rows, hidden), "No capture-capable interfaces found.")

    def test_name_column_is_what_scapy_will_resolve(self):
        # scapy's resolve_iface() matches friendly name, description or
        # network_name. Whatever we print must be one of those.
        rows, _ = collect_interfaces(WINDOWS_LIKE)
        accepted = set()
        for i in WINDOWS_LIKE:
            accepted |= {i.name, i.description, i.network_name}
        self.assertTrue(all(r.name in accepted for r in rows))
