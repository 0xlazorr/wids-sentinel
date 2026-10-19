# wids-sentinel

802.11 wireless intrusion detection tool written in Python. Analyzes management frames in real time or from PCAP dumps to catch rogue access points, evil twin clones, deauth floods, and karma attacks.

## Detections

| Rule | Severity | What it catches |
|---|---|---|
| `DEAUTH_FLOOD` | Critical / High | High-rate deauth/disassociation frames targeting a client or broadcast |
| `EVIL_TWIN_ROGUE_AP` | Critical | Rogue AP advertising a known SSID with an unauthorized BSSID |
| `CRYPTO_DOWNGRADE` | Critical | Network expected to run WPA2/WPA3 broadcasting as OPEN or WEP |
| `CHANNEL_MISMATCH` | Medium | Authorized AP heard transmitting on an unexpected channel |
| `KARMA_MANA_ATTACK` | Critical | Rogue AP answering probe requests for multiple disparate SSIDs |
| `MALFORMED_BSSID` | High | Multicast bit set on a unicast AP beacon address |
| `BEACON_SEQ_ANOMALY` | Medium | Unusually large sequence number leaps (>200 within 0.5s) indicating injection |

## Requirements

- Linux
- Python 3.10+
- Wireless card with monitor mode support (for live capture) or PCAP file

## Setup

```bash
git clone https://github.com/0xlazorr/wids-sentinel.git
cd wids-sentinel
pip install -e .
```

## Usage

### 1. Replay a capture file

```bash
wids-sentinel -r data/demo_attacks.pcap -c data/sample_authorized_aps.json
```

Or pass authorized APs straight from the CLI:
```bash
wids-sentinel -r capture.pcap --auth-ssid "OfficeNet" --auth-bssid "00:11:22:33:44:55"
```

### 2. Live spectrum monitoring

Put your wireless card into monitor mode:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

Run the sniffer:
```bash
sudo wids-sentinel -i wlan0 -c data/sample_authorized_aps.json -o alerts.json
```

## Config

`config.json`:
```json
{
  "authorized_aps": [
    {
      "ssid": "Corp_Secure_WiFi",
      "bssid": "00:11:22:33:44:55",
      "channel": 6,
      "expected_crypto": "WPA2"
    }
  ],
  "deauth_threshold_burst": 8,
  "deauth_window_seconds": 2.0,
  "alert_log_file": "alerts.json"
}
```

## Tests

```bash
pytest -v
```

Generate a test PCAP containing sample attacks:
```bash
python scripts/generate_sample_pcap.py test.pcap
```

## License

MIT
