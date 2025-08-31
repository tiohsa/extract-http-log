#!/usr/bin/env bash
set -euo pipefail

# Send JSON to an HTTP endpoint (default: localhost:8080/api/orders).
# Useful for generating traffic for tcpdump/tshark extraction.

host="localhost"
port="8080"
path="/api/orders"
count=10
delay=0.2
data='{"user":"alice","password":"p@ss"}'

usage() {
  cat <<USAGE
Usage: $0 [-H host] [-p port] [-P path] [-c count] [-d json] [-w seconds]
  -H  Host (default: localhost)
  -p  Port (default: 8080)
  -P  Path (default: /api/orders)
  -c  Repeat count (default: 10)
  -d  JSON payload string
  -w  Wait seconds between requests (default: 0.2)
Examples:
  $0
  $0 -c 5 -d '{"user":"bob","token":"abc"}'
USAGE
}

while getopts ":H:p:P:c:d:w:h" opt; do
  case "$opt" in
    H) host="$OPTARG" ;;
    p) port="$OPTARG" ;;
    P) path="$OPTARG" ;;
    c) count="$OPTARG" ;;
    d) data="$OPTARG" ;;
    w) delay="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

url="http://$host:$port$path?abc=111111&def=22222222"
echo "POSTing to $url ($count request(s))" >&2

for ((i=1; i<=count; i++)); do
  echo "--- Request $i ---" >&2
  curl -sS -i -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "$data"
  if [[ "$i" -lt "$count" ]]; then
    sleep "$delay"
  fi
done
