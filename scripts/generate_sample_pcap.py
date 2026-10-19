#!/usr/bin/env python3
"""
Synthetic 802.11 attack capture generator for WIDS-Sentinel demonstration.
Generates 'demo_attacks.pcap' containing legitimate traffic alongside simulated attacks.
"""

import os
import sys
import time

from scapy.utils import wrpcap
from scapy.layers.dot11 import (
    RadioTap,
    Dot11,
    Dot11Beacon,
    Dot11ProbeReq,
    Dot11ProbeResp,
    Dot11Deauth,
    Dot11Elt,
)


def create_demo_pcap(output_path: str = "demo_attacks.pcap"):
    packets = []
    base_time = time.time()

    # 1. Normal legitimate AP traffic (Corp_Secure_WiFi @ 00:11:22:33:44:55, Ch 6, WPA2)
    print("[*] Generating legitimate AP beacons...")
    for i in range(10):
        t = base_time + (i * 0.1024)
        rt = RadioTap()
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55", SC=(100 + i) << 4)
        beacon = Dot11Beacon(cap="ESS+privacy")
        essid = Dot11Elt(ID="SSID", info=b"Corp_Secure_WiFi")
        dsset = Dot11Elt(ID="DSset", info=bytes([6]))
        rsn = Dot11Elt(ID=48, info=b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00")
        pkt = rt / dot11 / beacon / essid / dsset / rsn
        pkt.time = t
        packets.append(pkt)

    # 2. Rogue AP / Evil Twin attack (same SSID, unauthorized BSSID 00:de:ad:be:ef:01, OPEN)
    print("[*] Generating Evil Twin rogue AP beacons (unauthorized BSSID + crypto downgrade)...")
    for i in range(5):
        t = base_time + 1.5 + (i * 0.1024)
        rt = RadioTap()
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:de:ad:be:ef:01", addr3="00:de:ad:be:ef:01", SC=(200 + i) << 4)
        beacon = Dot11Beacon(cap="ESS")  # Open, no privacy bit
        essid = Dot11Elt(ID="SSID", info=b"Corp_Secure_WiFi")
        dsset = Dot11Elt(ID="DSset", info=bytes([6]))
        pkt = rt / dot11 / beacon / essid / dsset
        pkt.time = t
        packets.append(pkt)

    # 3. Deauthentication flood attack (15 burst frames in 0.5 seconds targeting broadcast)
    print("[*] Generating Deauthentication flood attack...")
    for i in range(15):
        t = base_time + 2.0 + (i * 0.03)
        rt = RadioTap()
        dot11 = Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
        deauth = Dot11Deauth(reason=7)
        pkt = rt / dot11 / deauth
        pkt.time = t
        packets.append(pkt)

    # 4. Karma / MANA attack (single rogue BSSID responding to multiple client probe requests)
    print("[*] Generating Karma probe response attack...")
    rogue_karma_bssid = "aa:11:22:33:44:99"
    fake_ssids = [b"Airport_Free_WiFi", b"Starbucks_Guest", b"Hotel_Lobby_5G", b"Hilton_Honors"]
    for i, s in enumerate(fake_ssids):
        t = base_time + 3.0 + (i * 0.1)
        rt = RadioTap()
        dot11 = Dot11(type=0, subtype=5, addr1="12:34:56:78:90:ab", addr2=rogue_karma_bssid, addr3=rogue_karma_bssid)
        resp = Dot11ProbeResp(cap="ESS")
        essid = Dot11Elt(ID="SSID", info=s)
        dsset = Dot11Elt(ID="DSset", info=bytes([11]))
        pkt = rt / dot11 / resp / essid / dsset
        pkt.time = t
        packets.append(pkt)

    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} frames to '{output_path}'.")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "demo_attacks.pcap"
    create_demo_pcap(out)
