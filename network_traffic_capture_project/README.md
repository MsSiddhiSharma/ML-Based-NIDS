# Network Traffic Capture and Packet Extraction

A Python 3 tool for reading PCAP/PCAPNG files and capturing traffic from an explicitly authorized Linux test interface. It extracts timestamps, source/destination IP addresses and ports, protocol, packet lengths, TTL/hop limit, TCP flags, and MAC addresses. Malformed or truncated packets are reported with a parse status instead of terminating the run.

## Project structure

```text
network_traffic_capture_project/
├── packet_capture.py                 # Main CLI and packet parser
├── samples/                           # Synthetic/example PCAP and PCAPNG files
├── output/                            # Example extracted CSV files
├── tests/
│   └── test_packet_capture.py          # Unit tests
├── tools/
│   ├── make_samples.py                 # Rebuild sample capture files
│   └── generate_report.py               # Rebuild the extraction report
├── docs/
│   └── packet_extraction_report.md      # Report based on sample captures
└── README.md
```

## Requirements

- Python 3.8+
- Standard library only; no third-party packages required for offline PCAP parsing.
- Live capture is Linux-only and generally requires root or `CAP_NET_RAW`.

## Run the parser

From this project directory:

```bash
# Read a sample capture and print a summary
python3 packet_capture.py read samples/normal_traffic.pcap --summary --show 20

# Export per-packet data to CSV and JSON
python3 packet_capture.py read samples/normal_traffic.pcap \
  --csv output/normal.csv --json output/normal.json

# Read multiple captures (outputs get source-specific suffixes)
python3 packet_capture.py read samples/*.pcap --csv output/packets.csv --summary

# Run tests
python3 -m unittest discover -s tests -v

# Rebuild synthetic sample captures
python3 tools/make_samples.py

# Rebuild the report
python3 tools/generate_report.py
```

## Optional live capture (authorized test traffic only)

```bash
sudo python3 packet_capture.py capture --interface lo --count 100 \
  --timeout 30 --authorized --allow-interfaces lo \
  --pcap-out output/live.pcap --csv output/live.csv
```

Live capture requires Linux and permission to capture on the selected interface. The `--authorized` flag is mandatory; `--allow-interfaces` can further restrict which interface names are accepted. Capture only on systems and networks you own or are explicitly authorized to test.

## Output fields

The CSV includes packet number, epoch and ISO timestamps, source/destination IPs and ports, protocol, IP version, captured and original lengths, IP total length, TTL/hop limit, TCP flags, source/destination MAC addresses, parse status, and parsing errors. Fields unavailable from a packet are left empty in CSV output.
