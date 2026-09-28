#!/usr/bin/env python3
"""
btscan.py - Bluetooth security assessment toolkit
 - Classic BR/EDR discovery (via bluetoothctl)
 - BLE passive/active scan with RSSI + vendor lookup
 - GATT service/characteristic/descriptor enumeration
 - Optional characteristic read + notification subscription
Usage:
  sudo python3 btscan.py classic
  sudo python3 btscan.py ble --duration 15
  sudo python3 btscan.py gatt AA:BB:CC:DD:EE:FF
  sudo python3 btscan.py notify AA:BB:CC:DD:EE:FF
"""
import argparse, asyncio, subprocess, re, sys, time
from datetime import datetime

try:
    from bleak import BleakScanner, BleakClient
except ImportError:
    sys.exit("pip3 install bleak")

# --- minimal OUI vendor map; extend with the full IEEE file ---
OUI = {
    "00:1A:7D": "Apple", "AC:23:3F": "Apple", "F4:F5:D8": "Google",
    "44:65:0D": "Amazon", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "00:0E:8E": "Texas Instruments", "C4:BE:84": "Nordic Semiconductor",
    "F8:E6:1A": "Espressif", "24:0A:C4": "Espressif",
    "E0:E5:CF": "Samsung", "CC:2D:1B": "Xiaomi",
}

def vendor(mac):
    return OUI.get(mac[:8].upper(), "Unknown")

def ts():
    return datetime.now().strftime("%H:%M:%S")

# ---------------- Classic BR/EDR ----------------

def classic_scan(seconds=15):
    print(f"[*] Classic discovery for {seconds}s (bluetoothctl)")
    p = subprocess.Popen(["bluetoothctl"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for cmd in ("power on", "agent on", "default-agent", "scan on"):
        p.stdin.write(cmd + "\n"); p.stdin.flush()
    seen = {}
    start = time.time()
    while time.time() - start < seconds:
        line = p.stdout.readline()
        if not line:
            continue
        m = re.search(r"Device ([0-9A-F:]{17}) (.+)", line)
        if m:
            addr, name = m.group(1), m.group(2)
            if addr not in seen:
                seen[addr] = name
                print(f"[{ts()}] {addr}  {name:<30} vendor={vendor(addr)}")
    p.stdin.write("scan off\nquit\n"); p.stdin.flush()
    p.terminate()
    print(f"[+] {len(seen)} classic devices")

def sdp_dump(mac):
    print(f"[*] SDP service dump for {mac}")
    try:
        out = subprocess.run(["sdptool", "browse", mac],
                             capture_output=True, text=True, timeout=30).stdout
        print(out or "[!] no SDP records")
    except Exception as e:
        print(f"[!] sdptool: {e}")

# ---------------- BLE ----------------

async def ble_scan(duration=15, active=True):
    print(f"[*] BLE scan {duration}s (active={active})")
    found = {}
    def cb(dev, adv):
        rssi = adv.rssi
        found[dev.address] = (dev.name or adv.local_name or "?", rssi, adv)
        manuf = ""
        if adv.manufacturer_data:
            for cid, data in adv.manufacturer_data.items():
                manuf += f" mfr=0x{cid:04X}:{data.hex()}"
        svc = ",".join(adv.service_uuids) if adv.service_uuids else ""
        print(f"[{ts()}] {dev.address} rssi={rssi:>4} "
              f"{(dev.name or '?'):<28} vendor={vendor(dev.address)}{manuf} {svc}")

    scanner = BleakScanner(detection_callback=cb)
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()
    print(f"[+] {len(found)} BLE devices")

async def gatt_enum(mac, subscribe=False, read=False):
    print(f"[*] GATT enumeration for {mac}")
    async with BleakClient(mac, timeout=20) as client:
        print(f"[+] Connected: {client.is_connected}")
        for svc in client.services:
            print(f"\n  Service {svc.uuid}  ({svc.description})")
            for ch in svc.characteristics:
                print(f"    Char {ch.uuid}  props={','.join(ch.properties)}  ({ch.description})")
                if read and ("read" in ch.properties):
                    try:
                        val = await client.read_gatt_char(ch)
                        print(f"      value: {val.hex()}  ascii={val!r}")
                    except Exception as e:
                        print(f"      read err: {e}")
                if subscribe and ("notify" in ch.properties or "indicate" in ch.properties):
                    def handler(_, data, u=ch.uuid):
                        print(f"      [notify {u}] {data.hex()}")
                    await client.start_notify(ch, handler)
            for d in svc.descriptors if hasattr(svc, "descriptors") else []:
                print(f"    Desc {d.uuid}")
        if subscribe:
            print("[*] Listening for notifications (Ctrl-C to stop)...")
            while client.is_connected:
                await asyncio.sleep(1)

# ---------------- entry ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["classic", "ble", "gatt", "notify", "sdp"])
    ap.add_argument("target", nargs="?")
    ap.add_argument("--duration", type=int, default=15)
    ap.add_argument("--passive", action="store_true", help="BLE passive scan (no scan req)")
    a = ap.parse_args()

    if a.mode == "classic":
        classic_scan(a.duration)
    elif a.mode == "sdp":
        sdp_dump(a.target)
    elif a.mode == "ble":
        asyncio.run(ble_scan(a.duration, active=not a.passive))
    elif a.mode == "gatt":
        asyncio.run(gatt_enum(a.target, read=True))
    elif a.mode == "notify":
        asyncio.run(gatt_enum(a.target, subscribe=True, read=True))

if __name__ == "__main__":
    main()