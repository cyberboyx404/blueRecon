# BlueRecon

> Bluetooth security assessment toolkit for **BR/EDR** and **BLE** — recon, GATT enumeration, SDP mapping, and pairing-capture workflow.

![status](https://img.shields.io/badge/status-active-brightgreen)
![platform](https://img.shields.io/badge/platform-Kali%20%7C%20Debian-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![python](https://img.shields.io/badge/python-3.8%2B-blue)

## ⚠️ Disclaimer

BlueRecon is intended **only** for authorized security testing, penetration testing engagements, and
research on devices you own or have **explicit written permission** to assess. Unauthorized access to
Bluetooth devices, networks, or data is illegal in most jurisdictions. The authors assume no liability
and are not responsible for any misuse or damage caused by this tool.

## Features

- **Classic BR/EDR discovery** via `bluetoothctl` with live vendor identification.
- **BLE scanning** (active + passive) with RSSI tracking, manufacturer data, and service UUIDs.
- **GATT enumeration** — services, characteristics, descriptors, properties.
- **GATT read + notify** — dump unauthenticated readable values and subscribe to notifications/indications.
- **SDP service dump** — enumerate RFCOMM/OBEX and other exposed classic profiles.
- **Vendor fingerprinting** via OUI lookup.
- Integration guidance for **Crackle**, **Ubertooth**, and **Bettercap**.

## Requirements

- Linux (tested on Kali & Debian)
- Python 3.8+
- A Bluetooth adapter (`hci0`) supporting the modes you need
- **For sniffing/pairing capture**, dedicated hardware is required:
  - Ubertooth One — BR/EDR + BLE sniffing
  - Nordic nRF52840 / CC2540 dongle — BLE / LE sniffing

> The built-in adapter is sufficient for scanning and GATT enumeration but generally
> **not** for packet sniffing.

## Installation

### 1. System packages (Kali / Debian)

```bash
sudo apt update
sudo apt install -y \
    bluez bluez-tools bluez-hcidump bluetooth libbluetooth-dev \
    python3 python3-pip python3-dev python3-venv libglib2.0-dev