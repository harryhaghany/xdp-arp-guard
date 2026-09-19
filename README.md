# xdp-arp-guard

An XDP kernel program that detects ARP spoofing attacks in real time by intercepting packets at the network driver level before the kernel processes them.

---

## Background

Reading about ARP in *Computer Networks: A Top-Down Approach* (Kurose & Ross), I kept thinking about what the protocol actually assumes: that every device on a network has a unique MAC address, and that the ARP table is a source of truth. The question that formed in my head was simple: what actually happens if that assumption breaks?

So I changed my laptop's MAC address to match another device on my home network and watched both connections fall apart in real time. The router couldn't decide where to send traffic. Both devices fought over the same identity

P.S this really pissed off my flatmate who was on his XBOX (sorry about that Max) 


---

## How ARP Spoofing Works

```
Normal ARP:
Device A asks:  "Who has 10.0.0.1?"
Router replies: "That's me — MAC AA:BB:CC:DD:EE:FF"
Device A caches: 10.0.0.1 → AA:BB:CC:DD:EE:FF ✓

ARP Spoofing:
Attacker sends unsolicited reply:
"I am 10.0.0.1 — my MAC is DE:AD:BE:EF:CA:FE"
Router updates cache: 10.0.0.1 → DE:AD:BE:EF:CA:FE ✗
Traffic now flows to attacker instead of legitimate device
```

---

## How This Program Detects It

```
Packet arrives at network interface
            ↓
XDP hook fires at driver level (before kernel sees the packet)
            ↓
Parse Ethernet header → is EtherType 0x0806 (ARP)?
            ↓
Parse 28-byte ARP block → extract sender IP + sender MAC
            ↓
Look up sender IP in BPF hash map
            ↓
First time?          MAC matches?        MAC changed?
store binding   →   pass quietly    →   ALERT: spoof detected
```

---

## Why XDP

XDP (eXpress Data Path) is a Linux kernel hook that fires at the network driver level before the kernel allocates socket buffers, before any socket processing, before any userspace program sees the packet. Programs written in restricted C are compiled to BPF bytecode, verified by the kernel verifier for safety and memory correctness, then loaded directly into the driver receive path.

---

## Project Structure

```
xdp-arp-guard/
├── README.md
├── src/
│   └── xdp_prog_kern.c     ← XDP kernel program (BPF bytecode)
├── test/
│   └── arp_spoof.py        ← Scapy script to simulate ARP spoofing
└── scripts/
    └── setup_and_run.sh    ← Compile, load, and verify
```

---

## Dependencies

```bash
sudo apt install clang llvm libbpf-dev linux-headers-arm64 \
                 python3-scapy bpftool tcpdump
```

You also need the libbpf source headers. Clone the xdp-tutorial repo which includes them as a submodule:

```bash
git clone --recurse-submodules https://github.com/xdp-project/xdp-tutorial.git
```

---

## Building

```bash
clang -O2 -g -Wall -target bpf \
  -I/usr/include/aarch64-linux-gnu \
  -I/path/to/xdp-tutorial/lib/libbpf/src \
  -c src/xdp_prog_kern.c -o src/xdp_prog_kern.o
```

Verify it compiled:

```bash
ls -la src/xdp_prog_kern.o  # must be non-zero
```

---

## Test Environment Setup

XDP programs attach to network interfaces. For safe testing, use a virtual ethernet pair with an isolated network namespace so you never touch your real network interface.

```bash
# Set up test environment using xdp-tutorial testenv
cd /path/to/xdp-tutorial
eval $(./testenv/testenv.sh alias)
t setup --name arptest --legacy-ip

# Verify IPv4 is assigned
t status --name arptest
```

You should see `10.0.0.1/24` on the outer `arptest` interface.

---

## Loading the XDP Program

```bash
# Load onto the outer interface
sudo ip link set dev arptest xdpgeneric obj src/xdp_prog_kern.o sec xdp

# Verify it loaded
sudo bpftool net show
sudo bpftool map list | grep ip_mac
```

You should see `arptest` in the XDP section and `ip_mac_map` in the map list.

---

## Running the Test

Open three terminals simultaneously.

**Terminal 1 — watch for alerts:**
```bash
sudo mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
sudo sh -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**Terminal 2 — send the attack:**
```bash
cd /path/to/xdp-tutorial
eval $(./testenv/testenv.sh alias)
t exec --name arptest -- python3 test/arp_spoof.py
```

**Terminal 3 — inspect the map after:**
```bash
sudo bpftool map dump name ip_mac_map
```

---

## Expected Output

**First packet — program learns the legitimate binding:**
```
[DEBUG] Packet entered XDP pipeline
[DEBUG] ARP packet detected!
[DEBUG] Packet size: 42 bytes (need 42)
[DEBUG] ARP Header parsed successfully. Opcode: 2 (Reply)
[DEBUG] Map Miss: First time seeing IP 10.0.0.2. Learning binding.
```

**Second packet — spoofed MAC detected:**
```
[DEBUG] Packet entered XDP pipeline
[DEBUG] ARP packet detected!
!!! ARP SPOOF ALERT !!!
[ALERT] IP 10.0.0.2 is target of conflicting claims!
[ALERT] Trusted Base MAC: 92:b1:8b:3d:88:b2
[ALERT] Malicious New MAC: de:ad:be:ef:ca:fe
```

**Map dump — stored binding:**
```
key: 0a 00 00 02  value: 92 b1 8b 3d 88 b2
```
`0a 00 00 02` = `10.0.0.2` in hex. `92:b1:8b:3d:88:b2` = legitimate MAC.

---

## How the Struct Packing Works

A critical detail: the `struct ethernet_arp` requires `__attribute__((packed))`.

Without it, the C compiler adds 4 bytes of padding after `ar_sip` to align `ar_tha` on a 4-byte boundary, making the struct 32 bytes instead of 28. The BPF verifier then rejects the bounds check because `arp + 1` points 4 bytes past the end of the actual packet. The packed attribute forces the struct to match the exact wire format.

```c
struct ethernet_arp {
    __be16 ar_hrd;
    __be16 ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    __be16 ar_op;
    unsigned char ar_sha[6];   // sender MAC ← detection key
    __be32        ar_sip;      // sender IP  ← map key
    unsigned char ar_tha[6];
    __be32        ar_tip;
} __attribute__((packed));     // ← critical: matches 28-byte wire format
```

---

## Cleanup

```bash
# Unload XDP program
sudo ip link set dev arptest xdpgeneric off

# Teardown test environment
cd /path/to/xdp-tutorial
eval $(./testenv/testenv.sh alias)
t teardown --name arptest
```

---

## References

- Kurose & Ross, *Computer Networks: A Top-Down Approach* — ARP chapter
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) — xdp-project
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf](https://github.com/libbpf/libbpf)

