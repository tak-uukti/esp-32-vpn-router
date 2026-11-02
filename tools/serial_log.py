#!/usr/bin/env python3
"""Stream an ESP32 serial console to a file, flushing per line so the log can be
inspected while a test is still running.

    sudo python3 tools/serial_log.py [seconds] [outfile] [port]

Needs pyserial. sudo is only required when the port is root-owned (e.g. /dev/ttyACM0
on most distros is root:dialout).
"""
import sys
import time

import serial

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 600
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/gadget_live.log"
PORT = sys.argv[3] if len(sys.argv) > 3 else "/dev/ttyACM0"

ser = serial.Serial(PORT, 115200, timeout=0.2)
start = time.time()
with open(OUT, "w", buffering=1) as fh:
    while time.time() - start < DURATION:
        chunk = ser.read(4096)
        if chunk:
            for line in chunk.decode("utf-8", "replace").replace("\r", "").splitlines():
                if line.strip():
                    fh.write(f"{time.time() - start:8.2f} {line}\n")
                    fh.flush()
ser.close()
print(f"done, {DURATION}s captured into {OUT}")
