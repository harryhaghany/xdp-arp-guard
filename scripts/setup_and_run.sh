#!/bin/bash
# Compile
clang -O2 -g -Wall -target bpf \
  -I/usr/include/aarch64-linux-gnu \
  -I../lib/libbpf/src \
  -c src/xdp_prog_kern.c -o src/xdp_prog_kern.o

# Load
sudo ip link set dev arptest xdpgeneric off 2>/dev/null
sudo ip link set dev arptest xdpgeneric obj src/xdp_prog_kern.o sec xdp

echo "XDP loaded. Watch trace pipe:"
echo "sudo cat /sys/kernel/debug/tracing/trace_pipe"
