#!/usr/bin/env bash
set -euo pipefail

# Build and print a tcpdump command for HTTP traffic capture on a port (default 8080).
# NOTE: This script no longer starts a capture nor generates access logs.

iface="lo"
port="8080"
pcap="http_capture.pcap"
# Rotation options (tcpdump):
#  -C <MB>  rotate the dump file after it reaches <MB> megabytes
#  -G <sec> rotate the dump file every <sec> seconds (filename must contain strftime(3) formats)
#  -W <N>   limit the number of files to N (used with -C or -G)
rotate_size_mb=""   # for -C
rotate_secs=""      # for -G
rotate_files=""     # for -W

usage() {
  cat <<USAGE
Usage: $0 [-i iface] [-p port] [-o pcap] [-C MB] [-G sec] [-W count]
  -i  Interface (default: lo)
  -p  TCP port to capture (default: 8080)
  -o  Output pcap path or pattern (default: http_capture.pcap)
  -C  Rotate pcap when file reaches MB megabytes (tcpdump -C)
  -G  Rotate pcap every sec seconds (tcpdump -G). When set and -o lacks time patterns, a pattern like name-%Y%m%d-%H%M%S.ext is used.
  -W  Keep at most 'count' files when using -C or -G (tcpdump -W)

This script only prints the tcpdump command; it does not execute it.
USAGE
}

while getopts ":i:p:o:C:G:W:h" opt; do
  case "$opt" in
    i) iface="$OPTARG" ;;
    p) port="$OPTARG" ;;
    o) pcap="$OPTARG" ;;
    C) rotate_size_mb="$OPTARG" ;;
    G) rotate_secs="$OPTARG" ;;
    W) rotate_files="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

# Build tcpdump command with optional rotation
tcpdump_cmd=(tcpdump -i "$iface" -s 0 -U)

# Decide output file/pattern
w_output="$pcap"
if [[ -n "$rotate_secs" ]]; then
  # If user didn't specify strftime patterns, inject one
  if [[ "$pcap" != *%* ]]; then
    base="${pcap%.*}"
    ext="${pcap##*.}"
    if [[ "$ext" == "$pcap" ]]; then
      # no extension
      w_output="${base}-%Y%m%d-%H%M%S.pcap"
    else
      w_output="${base}-%Y%m%d-%H%M%S.${ext}"
    fi
  fi
  tcpdump_cmd+=( -G "$rotate_secs" )
fi

if [[ -n "$rotate_size_mb" ]]; then
  tcpdump_cmd+=( -C "$rotate_size_mb" )
fi

if [[ -n "$rotate_files" ]]; then
  tcpdump_cmd+=( -W "$rotate_files" )
fi

tcpdump_cmd+=( -w "$w_output" port "$port" )

echo "Planned tcpdump command (not executed):" >&2
printf '%q ' "${tcpdump_cmd[@]}"
printf '\n'

echo "Note: Run the above command manually (use sudo if needed)." >&2
