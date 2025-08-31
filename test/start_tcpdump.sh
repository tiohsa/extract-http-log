#!/usr/bin/env bash
set -euo pipefail

# Capture HTTP traffic on a port (default 8080) and
# produce an Apache Combined style access log with extras using extract_http_requests.py
# Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i" src_ip:src_port dst_ip:dst_port <REQ_JSON> <RES_JSON>
# Note: tcpdump may require root (sudo) depending on your system and interface.

iface="lo"
port="8080"
duration=""   # seconds; if empty, runs until Ctrl-C
pcap="http_capture.pcap"
access_out="access.log"

usage() {
  cat <<USAGE
Usage: $0 [-i iface] [-p port] [-t seconds] [-o pcap] [-a access.log]
  -i  Interface (default: lo)
  -p  TCP port to capture (default: 8080)
  -t  Duration in seconds (optional; if omitted, stop with Ctrl-C)
  -o  Output pcap path (default: http_capture.pcap)
  -a  Apache-style combined log output (default: access.log)
USAGE
}

while getopts ":i:p:t:o:a:h" opt; do
  case "$opt" in
    i) iface="$OPTARG" ;;
    p) port="$OPTARG" ;;
    t) duration="$OPTARG" ;;
    o) pcap="$OPTARG" ;;
    a) access_out="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "ERROR: tcpdump not found. Please install it." >&2
  exit 1
fi

echo "Starting tcpdump on iface=$iface port=$port -> $pcap" >&2
set +e
tcpdump -i "$iface" -s 0 -U -w "$pcap" port "$port" &
tcp_pid=$!
set -e

trap 'echo "Stopping tcpdump (pid $tcp_pid)" >&2; kill "$tcp_pid" 2>/dev/null || true' INT TERM EXIT

if [[ -n "$duration" ]]; then
  sleep "$duration"
  echo "Time elapsed ($duration s). Stopping capture..." >&2
  kill "$tcp_pid" 2>/dev/null || true
  wait "$tcp_pid" 2>/dev/null || true
else
  echo "Capturing... press Ctrl-C to stop." >&2
  wait "$tcp_pid" 2>/dev/null || true
fi

trap - INT TERM EXIT

echo "Capture saved: $pcap" >&2

echo "Generating Apache-style access log -> $access_out" >&2
python3 extract_http_requests.py -i "$pcap" -o "$access_out" --decode-port "$port" --no-ct-filter || {
  echo "Failed to generate access log from $pcap." >&2
}

echo "Done. Outputs: $pcap , $access_out" >&2
