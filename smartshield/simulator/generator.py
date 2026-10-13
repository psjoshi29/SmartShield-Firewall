"""Deterministic synthetic packet generator for SmartShield."""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import List, Optional

from smartshield.engine.models import Direction, Packet, Protocol


def generate_scenario_packets(
    scenario_key: str,
    count: int = 20,
    seed: Optional[int] = None,
) -> List[Packet]:
    """Generate synthetic network packets for a specified simulation scenario.

    Guarantees deterministic generation when seed is provided.
    All generated packets have is_simulated=True.
    """
    rng = random.Random(seed if seed is not None else random.randint(1, 1000000))
    now = datetime.now(timezone.utc).isoformat()
    packets: List[Packet] = []

    for i in range(count):
        if scenario_key == "web_browsing":
            # Outbound HTTPS / HTTP / DNS
            src_host = rng.choice([15, 22, 45, 101, 105, 150])
            src_ip = f"192.168.1.{src_host}"
            is_dns = (i % 4 == 0)

            if is_dns:
                dst_ip = rng.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9"])
                dst_port = 53
                src_port = rng.randint(49152, 65535)
                proto = Protocol.UDP
                flags = ""
                desc = "Outbound DNS resolution query"
            else:
                dst_ip = rng.choice([
                    "142.250.190.46",  # Google
                    "151.101.1.69",    # CDN
                    "104.16.132.229",  # Cloudflare
                    "20.112.52.29",    # Microsoft
                ])
                dst_port = rng.choice([443, 443, 443, 80])
                src_port = rng.randint(49152, 65535)
                proto = Protocol.TCP
                flags = rng.choice(["SYN", "ACK", "PSH-ACK"])
                desc = f"Outbound web request to {'HTTPS' if dst_port == 443 else 'HTTP'}"

            packets.append(Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                direction=Direction.OUTBOUND,
                flags=flags,
                payload_size=rng.randint(64, 1420),
                timestamp=now,
                is_simulated=True,
                description=desc,
            ))

        elif scenario_key == "untrusted_recon":
            # Inbound scanning from WAN against sensitive services
            src_ip = rng.choice([
                "203.0.113.19",
                "198.51.100.82",
                "192.0.2.144",
                "45.33.32.156",
            ])
            dst_ip = "192.168.1.10"
            dst_port = rng.choice([23, 445, 3389, 137, 139, 21])
            src_port = rng.randint(1024, 65535)
            proto = Protocol.TCP
            flags = "SYN"
            port_labels = {
                23: "Telnet probe",
                445: "SMB exploit probe",
                3389: "RDP port scan",
                137: "NetBIOS lookup probe",
                139: "NetBIOS session probe",
                21: "FTP anonymous probe",
            }

            packets.append(Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                direction=Direction.INBOUND,
                flags=flags,
                payload_size=rng.randint(40, 120),
                timestamp=now,
                is_simulated=True,
                description=f"Inbound reconnaissance sweep ({port_labels.get(dst_port, 'Port scan')})",
            ))

        elif scenario_key == "admin_management":
            # Inbound authorized SSH from 10.0.0.0/16
            admin_host = rng.randint(2, 250)
            src_ip = f"10.0.1.{admin_host}"
            dst_ip = "192.168.1.10"
            dst_port = 22
            src_port = rng.randint(49152, 65535)
            proto = Protocol.TCP
            flags = rng.choice(["SYN", "ACK", "PSH-ACK"])

            packets.append(Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                direction=Direction.INBOUND,
                flags=flags,
                payload_size=rng.randint(64, 512),
                timestamp=now,
                is_simulated=True,
                description="Authorized engineering SSH administration session",
            ))

        elif scenario_key == "untrusted_ssh":
            # Inbound SSH from external WAN
            src_ip = rng.choice(["203.0.113.88", "198.51.100.25", "185.220.101.5"])
            dst_ip = "192.168.1.10"
            dst_port = 22
            src_port = rng.randint(1024, 65535)

            packets.append(Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=Protocol.TCP,
                direction=Direction.INBOUND,
                flags="SYN",
                payload_size=64,
                timestamp=now,
                is_simulated=True,
                description="Unauthorized external SSH access attempt",
            ))

        elif scenario_key == "malformed_traffic":
            # Edge-cases and malformed simulated packets
            case = i % 4
            if case == 0:
                # Port 0 probe
                packets.append(Packet(
                    src_ip="203.0.113.99",
                    dst_ip="192.168.1.10",
                    src_port=0,
                    dst_port=0,
                    protocol=Protocol.TCP,
                    direction=Direction.INBOUND,
                    flags="NULL",
                    payload_size=0,
                    timestamp=now,
                    is_simulated=True,
                    description="Malformed TCP packet with invalid Port 0",
                ))
            elif case == 1:
                # Malformed IP simulation
                packets.append(Packet(
                    src_ip="999.999.999.999",  # Out of range octets
                    dst_ip="192.168.1.10",
                    src_port=1234,
                    dst_port=80,
                    protocol=Protocol.TCP,
                    direction=Direction.INBOUND,
                    flags="SYN",
                    payload_size=64,
                    timestamp=now,
                    is_simulated=True,
                    description="Corrupted IPv4 header with out-of-range octets",
                ))
            elif case == 2:
                # Unmatched ICMP Ping
                packets.append(Packet(
                    src_ip="203.0.113.5",
                    dst_ip="192.168.1.10",
                    src_port=0,
                    dst_port=0,
                    protocol=Protocol.ICMP,
                    direction=Direction.INBOUND,
                    flags="",
                    payload_size=32,
                    timestamp=now,
                    is_simulated=True,
                    description="External ICMP Echo Request (Ping)",
                ))
            else:
                # Non-standard high port
                packets.append(Packet(
                    src_ip="198.51.100.11",
                    dst_ip="192.168.1.10",
                    src_port=55555,
                    dst_port=31337,
                    protocol=Protocol.TCP,
                    direction=Direction.INBOUND,
                    flags="SYN",
                    payload_size=128,
                    timestamp=now,
                    is_simulated=True,
                    description="Suspicious backdoor port 31337 sweep",
                ))

        else:
            # mixed_traffic: balanced selection
            sub_scenario = rng.choice(["web_browsing", "untrusted_recon", "admin_management", "untrusted_ssh"])
            sub_pkts = generate_scenario_packets(sub_scenario, count=1, seed=rng.randint(1, 999999))
            packets.extend(sub_pkts)

    return packets
