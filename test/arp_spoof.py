from scapy.all import *
import time

iface = "veth0"

# Inner MAC (real sender)
inner_mac = "92:b1:8b:3d:88:b2"
# Outer MAC (destination)
outer_mac = "f6:9d:96:ad:95:c0"

# Phase 1: legitimate ARP reply — teach the map this binding
print("Sending normal ARP...")
sendp(
    Ether(src=inner_mac, dst=outer_mac, type=0x0806) /
    ARP(op=2, hwsrc=inner_mac, psrc="10.0.0.2",
              hwdst=outer_mac, pdst="10.0.0.1"),
    iface=iface, verbose=1
)

time.sleep(1)

# Phase 2: spoofed ARP — same IP, different MAC
print("Sending SPOOFED ARP...")
sendp(
    Ether(src=inner_mac, dst=outer_mac, type=0x0806) /
    ARP(op=2, hwsrc="de:ad:be:ef:ca:fe", psrc="10.0.0.2",
              hwdst=outer_mac, pdst="10.0.0.1"),
    iface=iface, verbose=1
)
