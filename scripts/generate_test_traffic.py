#!/usr/bin/env python3
"""
generate_test_traffic.py

Generates a set of simulated-attack PCAP files for demonstrating the
custom Suricata rules in custom.rules, without needing real attacker
infrastructure. Run this in your lab VM, then either:

  (a) replay a pcap through Suricata offline:
        sudo suricata -c /etc/suricata/suricata.yaml -r pcaps/port_scan.pcap -l /var/log/suricata/

  (b) or, for a live demo, run send_live() against a target you own/control
      inside the same lab network (requires root / scapy send permissions).

Every pcap is written to ./pcaps/ relative to where this script is run.

Requires: pip install scapy
"""
import argparse
import os
import random
from scapy.all import (
    IP, TCP, UDP, ICMP, DNS, DNSQR, Raw,
    wrpcap, send, RandShort
)

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pcaps")
TARGET = "192.168.56.10"   # change to your lab VM's target IP
ATTACKER = "192.168.56.20"  # change to your lab VM's attacker IP


def ensure_out_dir():
    os.makedirs(OUT_DIR, exist_ok=True)


def gen_port_scan(target=TARGET, attacker=ATTACKER, n_ports=40):
    """SYN scan across many destination ports — triggers SID 9000001."""
    pkts = []
    for _ in range(n_ports):
        dport = random.randint(1, 65535)
        pkt = IP(src=attacker, dst=target) / TCP(sport=RandShort(), dport=dport, flags="S")
        pkts.append(pkt)
    wrpcap(os.path.join(OUT_DIR, "port_scan.pcap"), pkts)
    print(f"[+] Wrote port_scan.pcap ({len(pkts)} packets) -> triggers SID 9000001")


def gen_null_scan(target=TARGET, attacker=ATTACKER, n=5):
    """No TCP flags set — triggers SID 9000002."""
    pkts = [IP(src=attacker, dst=target) / TCP(sport=RandShort(), dport=80, flags=0) for _ in range(n)]
    wrpcap(os.path.join(OUT_DIR, "null_scan.pcap"), pkts)
    print(f"[+] Wrote null_scan.pcap ({len(pkts)} packets) -> triggers SID 9000002")


def gen_icmp_flood(target=TARGET, attacker=ATTACKER, n=80):
    """Rapid ICMP echo requests — triggers SID 9000010."""
    pkts = [IP(src=attacker, dst=target) / ICMP(type=8) for _ in range(n)]
    wrpcap(os.path.join(OUT_DIR, "icmp_flood.pcap"), pkts)
    print(f"[+] Wrote icmp_flood.pcap ({len(pkts)} packets) -> triggers SID 9000010")


def gen_syn_flood(target=TARGET, attacker=ATTACKER, n=150):
    """Rapid SYNs to one destination port — triggers SID 9000011."""
    pkts = [IP(src=attacker, dst=target) / TCP(sport=RandShort(), dport=80, flags="S") for _ in range(n)]
    wrpcap(os.path.join(OUT_DIR, "syn_flood.pcap"), pkts)
    print(f"[+] Wrote syn_flood.pcap ({len(pkts)} packets) -> triggers SID 9000011")


def gen_ssh_bruteforce(target=TARGET, attacker=ATTACKER, n=15):
    """Repeated SYNs to port 22 — triggers SID 9000020."""
    pkts = [IP(src=attacker, dst=target) / TCP(sport=RandShort(), dport=22, flags="S") for _ in range(n)]
    wrpcap(os.path.join(OUT_DIR, "ssh_bruteforce.pcap"), pkts)
    print(f"[+] Wrote ssh_bruteforce.pcap ({len(pkts)} packets) -> triggers SID 9000020")


def gen_sql_injection(target=TARGET, attacker=ATTACKER):
    """A single crafted HTTP GET with a UNION SELECT payload — triggers SID 9000031."""
    payload = (
        b"GET /product.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"User-Agent: Mozilla/5.0\r\n\r\n"
    )
    pkt = IP(src=attacker, dst=target) / TCP(sport=RandShort(), dport=80, flags="PA") / Raw(load=payload)
    wrpcap(os.path.join(OUT_DIR, "sql_injection.pcap"), [pkt])
    print("[+] Wrote sql_injection.pcap (1 packet) -> triggers SID 9000031")


def gen_dns_tunnel(target="8.8.8.8", attacker=ATTACKER):
    """An abnormally long DNS query label — triggers SID 9000040."""
    long_label = "".join(random.choice("abcdef0123456789") for _ in range(70)) + ".tunnel.example.com"
    pkt = IP(src=attacker, dst=target) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=long_label))
    wrpcap(os.path.join(OUT_DIR, "dns_tunnel.pcap"), [pkt])
    print("[+] Wrote dns_tunnel.pcap (1 packet) -> triggers SID 9000040")


def send_live(pcap_name):
    """Replay a previously generated pcap live onto the wire (requires root)."""
    from scapy.all import rdpcap
    pkts = rdpcap(os.path.join(OUT_DIR, pcap_name))
    print(f"[*] Sending {len(pkts)} packets live from {pcap_name} ...")
    send(pkts, verbose=False)
    print("[+] Done.")


ALL_GENERATORS = {
    "port_scan": gen_port_scan,
    "null_scan": gen_null_scan,
    "icmp_flood": gen_icmp_flood,
    "syn_flood": gen_syn_flood,
    "ssh_bruteforce": gen_ssh_bruteforce,
    "sql_injection": gen_sql_injection,
    "dns_tunnel": gen_dns_tunnel,
}


def main():
    parser = argparse.ArgumentParser(description="Generate simulated-attack PCAPs for NIDS demo/testing.")
    parser.add_argument("--which", choices=list(ALL_GENERATORS) + ["all"], default="all",
                         help="Which scenario to generate (default: all)")
    parser.add_argument("--target", default=TARGET, help="Simulated victim IP")
    parser.add_argument("--attacker", default=ATTACKER, help="Simulated attacker IP")
    args = parser.parse_args()

    ensure_out_dir()

    if args.which == "all":
        for name, fn in ALL_GENERATORS.items():
            try:
                fn(target=args.target, attacker=args.attacker)
            except TypeError:
                fn()  # generators with non-standard signatures (dns_tunnel)
    else:
        fn = ALL_GENERATORS[args.which]
        try:
            fn(target=args.target, attacker=args.attacker)
        except TypeError:
            fn()

    print(f"\n[+] All requested pcaps written to: {OUT_DIR}")
    print("    Replay offline with:")
    print("      sudo suricata -c /etc/suricata/suricata.yaml -r pcaps/<file>.pcap -l /var/log/suricata/ -k none")


if __name__ == "__main__":
    main()
