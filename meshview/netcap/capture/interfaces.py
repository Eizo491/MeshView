"""
Turns scapy's interface objects into the table `capture_live
--list-interfaces` prints.

Why this exists: `scapy.all.get_if_list()` returns each interface's
*network name*, which on Windows is the raw Npcap device path
(`\\Device\\NPF_{3F2A...}`) -- unreadable, and no way to tell which
line is the Wi-Fi card. scapy already knows the friendly name
("Wi-Fi"), the adapter description ("Intel(R) Wi-Fi 6 AX201") and the
IPs; this module just formats them.

Like `engine.py`, this file never imports scapy. It only reads
attributes off whatever objects it's handed (`name`, `description`,
`network_name`, `ips`, `is_valid()`), so it can be unit-tested with
plain fakes shaped like Windows adapters -- see
netcap/tests/test_list_interfaces.py.

What gets printed in the NAME column is always something
`sniff(iface=...)` accepts: scapy resolves a string by friendly
name, then by description, then by network name
(scapy.interfaces.resolve_iface). When two adapters share a friendly
name (common with VPN/virtual adapters), the first match would win
and the second could never be selected by name, so those rows show
their unique network name instead.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class InterfaceRow:
    name: str         # exactly what to pass to --iface
    ipv4: str         # comma-joined IPv4 addresses, or "-"
    description: str  # adapter model, "" if it adds nothing over `name`


def _ipv4_addresses(iface) -> list[str]:
    ips = getattr(iface, "ips", None)
    if ips:
        try:
            found = list(ips[4])
        except (KeyError, TypeError):
            found = []
        if found:
            return found
    single = getattr(iface, "ip", None)
    return [single] if single else []


def collect_interfaces(
    ifaces: Iterable, include_invalid: bool = False
) -> tuple[list[InterfaceRow], int]:
    """Returns (rows, hidden_count).

    Interfaces scapy considers invalid -- no IP/MAC, or on Windows no
    matching Npcap device, so it couldn't sniff them anyway -- are
    dropped, mirroring scapy's own `show_interfaces()`. `hidden_count`
    says how many were dropped so the caller can tell the user.
    """
    ifaces = list(ifaces)
    hidden = 0
    kept = []
    for iface in ifaces:
        valid = getattr(iface, "is_valid", lambda: True)()
        if not valid and not include_invalid:
            hidden += 1
            continue
        kept.append(iface)

    name_counts = Counter(getattr(i, "name", "") for i in kept)

    rows = []
    for iface in kept:
        friendly = getattr(iface, "name", "") or ""
        description = getattr(iface, "description", "") or ""
        network_name = getattr(iface, "network_name", "") or ""

        if friendly and name_counts[friendly] == 1:
            name = friendly
        else:
            # Empty or ambiguous friendly name: fall back to something
            # that identifies exactly one adapter.
            name = network_name or description or friendly

        rows.append(
            InterfaceRow(
                name=name,
                ipv4=", ".join(_ipv4_addresses(iface)) or "-",
                description="" if description in ("", name, friendly) else description,
            )
        )

    # Interfaces that actually have an IPv4 address are the ones people
    # want; put them first, then alphabetical.
    rows.sort(key=lambda r: (r.ipv4 == "-", r.name.lower()))
    return rows, hidden


def format_interface_table(rows: list[InterfaceRow], hidden: int = 0) -> str:
    if not rows:
        return "No capture-capable interfaces found."

    headers = ("NAME", "IPv4", "DESCRIPTION")
    widths = [
        max(len(headers[0]), *(len(r.name) for r in rows)),
        max(len(headers[1]), *(len(r.ipv4) for r in rows)),
    ]

    def line(name: str, ipv4: str, desc: str) -> str:
        return f"  {name:<{widths[0]}}  {ipv4:<{widths[1]}}  {desc}".rstrip()

    out = [line(*headers), line("-" * widths[0], "-" * widths[1], "-" * 11)]
    out += [line(r.name, r.ipv4, r.description) for r in rows]
    out.append("")
    example = next((r for r in rows if r.ipv4 != "-" and not r.ipv4.startswith("127.")), rows[0])
    out.append(f'Pass the NAME column to --iface, e.g.  --iface "{example.name}"')
    if hidden:
        out.append(
            f"({hidden} interface{'s' if hidden != 1 else ''} without an IP/MAC "
            "or Npcap device hidden; add --all to show them.)"
        )
    return "\n".join(out)
