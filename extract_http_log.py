#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Log output format (Apache combined + extras + bodies):

  %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i" src_ip:src_port dst_ip:dst_port <REQ_JSON> <RES_JSON>

Fields:
- %h: source IP (client)
- %l / %u: always "-" (ident/auth not available)
- %t: request time in UTC, e.g. [31/Aug/2025:01:27:15 +0000]
- "%r": request line = METHOD SP request-target SP HTTP-version
- %>s: response status code (paired by tcp.stream, FIFO)
- %b: response size in bytes (Content-Length if present; else estimated)
- Referer/User-agent: from request headers; "-" if absent
- src_ip:src_port and dst_ip:dst_port: connection endpoints
- <REQ_JSON> <RES_JSON>: single-line JSON bodies (request/response). If not JSON, emitted as JSON string; response body may be null. Sensitive keys are masked.

Notes:
- URL request-target includes path and query (http.request.uri).
- Pairing uses tcp.stream ordering; requires --decode-port for non-standard ports.
"""
import argparse, json, subprocess, sys, shlex, datetime, string, collections

MASK_KEYS = {
    k.lower()
    for k in [
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "ssn",
    ]
}


def mask_value(v):
    if isinstance(v, dict):
        return {
            k: ("******" if k.lower() in MASK_KEYS else mask_value(vv))
            for k, vv in v.items()
        }
    if isinstance(v, list):
        return [mask_value(x) for x in v]
    return v


def try_decode_hex(s: str) -> str:
    """Try to decode a hex string to UTF-8 text; return original on failure."""
    hex_chars = set(string.hexdigits)
    if len(s) % 2 == 0 and all(c in hex_chars for c in s):
        try:
            return bytes.fromhex(s).decode("utf-8", errors="replace")
        except Exception:
            return s
    return s


def parse_body_to_json(body: str):
    """Return (value, is_json). Attempts direct JSON; then hex->text->JSON; else returns raw text."""
    # Direct JSON
    try:
        return json.loads(body), True
    except Exception:
        pass
    # Try hex decode path
    maybe_text = try_decode_hex(body)
    if maybe_text is not body:
        try:
            return json.loads(maybe_text), True
        except Exception:
            return maybe_text, False
    # Fallback raw
    return body, False


def build_cmd(pcap, decode_ports, no_ct_filter):
    display_filter = "http.request && http.file_data"
    if not no_ct_filter:
        # Content-Type が JSON のときのみ
        display_filter = 'http.request && http.file_data && http.content_type contains "application/json"'

    cmd = [
        "tshark",
        "-r",
        pcap,
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
        "-o",
        "http.desegment_body:TRUE",
        "-o",
        "http.decompress_body:TRUE",
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "http.request.method",
        "-e",
        "http.request.uri",
        "-e",
        "http.request.full_uri",
        "-e",
        "http.host",
        "-e",
        "http.request.version",
        "-e",
        "http.user_agent",
        "-e",
        "http.referer",
        "-e",
        "http.content_type",
        "-e",
        "http.file_data",
    ]
    for p in decode_ports or []:
        cmd.extend(["-d", f"tcp.port=={p},http"])
    return cmd


def build_res_cmd(pcap, decode_ports, no_ct_filter):
    """Build tshark command for responses (status + body)."""
    display_filter = "http.response && http.file_data"
    if not no_ct_filter:
        display_filter = 'http.response && http.file_data && http.content_type contains "application/json"'

    cmd = [
        "tshark",
        "-r",
        pcap,
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
        "-o",
        "http.desegment_body:TRUE",
        "-o",
        "http.decompress_body:TRUE",
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "tcp.stream",
        "-e",
        "http.response.code",
        "-e",
        "http.content_length_header",
        "-e",
        "http.content_type",
        "-e",
        "http.file_data",
    ]
    for p in decode_ports or []:
        cmd.extend(["-d", f"tcp.port=={p},http"])
    return cmd


def main():
    ap = argparse.ArgumentParser(
        description=(
            "Extract HTTP transactions in Apache Combined Log Format plus bodies. "
            "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" <REQ_JSON> <RES_JSON>"
        )
    )
    ap.add_argument("-i", "--input", required=True, help="pcap file path")
    ap.add_argument("-o", "--out", default="-", help="output JSONL (default: stdout)")
    ap.add_argument(
        "--decode-port",
        action="append",
        type=int,
        help="decode given TCP port as HTTP (repeatable). Example: --decode-port 8080",
    )
    ap.add_argument(
        "--no-ct-filter",
        action="store_true",
        help="do not filter by Content-Type; extract any request that has body",
    )
    args = ap.parse_args()

    # Preload responses by stream (FIFO)
    res_cmd = build_res_cmd(args.input, args.decode_port, args.no_ct_filter)
    res_proc = subprocess.Popen(
        res_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    responses_by_stream: dict[int, collections.deque] = {}
    for rline in res_proc.stdout:
        rparts = rline.rstrip("\n").split("\t")
        if len(rparts) < 6:
            continue
        rts, rstream, rstatus, rclen, rctype, rbody = rparts[:6]
        try:
            sidx = int(rstream)
        except Exception:
            continue

        # Determine response size in bytes
        size_bytes = None
        if rclen and rclen.isdigit():
            try:
                size_bytes = int(rclen)
            except Exception:
                size_bytes = None
        if size_bytes is None:
            # Fallback: estimate from body (hex or text)
            hex_chars = set(string.hexdigits)
            if isinstance(rbody, str) and len(rbody) % 2 == 0 and all(
                c in hex_chars for c in rbody
            ):
                size_bytes = len(rbody) // 2
            else:
                try:
                    size_bytes = len((rbody or "").encode("utf-8"))
                except Exception:
                    size_bytes = 0

        # Prepare response body JSON (single-line, masked if JSON)
        r_payload_raw, r_is_json = parse_body_to_json(rbody)
        r_payload = mask_value(r_payload_raw) if r_is_json else r_payload_raw
        if isinstance(r_payload, (dict, list)):
            r_body_json = json.dumps(r_payload, ensure_ascii=False, sort_keys=True)
        else:
            r_body_json = json.dumps(r_payload, ensure_ascii=False)

        rq = responses_by_stream.setdefault(sidx, collections.deque())
        rq.append({
            "status": rstatus or None,
            "bytes": size_bytes,
            "body_json": r_body_json,
        })

    res_proc.stdout.close()
    res_proc.stderr.close()
    res_proc.wait()

    # Now stream requests and emit paired log lines
    cmd = build_cmd(args.input, args.decode_port, args.no_ct_filter)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    out = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
    try:
        for line in proc.stdout:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 15:
                continue
            (
                ts,
                stream,
                src,
                src_port,
                dst,
                dst_port,
                method,
                uri,
                full_uri,
                host,
                version,
                user_agent,
                referer,
                ctype,
                body,
            ) = parts[:15]

            # Parse request body for appended JSON output
            payload_raw, payload_is_json = parse_body_to_json(body)
            payload = mask_value(payload_raw) if payload_is_json else payload_raw

            # Convert epoch to ISO8601 (UTC) for readability
            ts_float = float(ts) if ts else None
            ts_iso = (
                datetime.datetime.fromtimestamp(ts_float, tz=datetime.timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
                if ts_float is not None
                else None
            )

            # Resolve URL (include query params). Prefer full_uri; fallback to host + uri; else uri.
            url = None
            if full_uri:
                url = full_uri
            elif host and uri:
                url = f"http://{host}{uri}"
            else:
                url = uri or None

            # Pair response by tcp.stream
            rinfo = None
            status = None
            resp_bytes = None
            try:
                sidx = int(stream) if stream else None
            except Exception:
                sidx = None
            if sidx is not None and sidx in responses_by_stream and responses_by_stream[sidx]:
                rinfo = responses_by_stream[sidx].popleft()
                status = rinfo.get("status")
                resp_bytes = rinfo.get("bytes")

            # Apache combined log format
            # %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
            host_h = src or "-"
            ident_l = "-"
            authuser_u = "-"
            # Time as [day/Mon/year:HH:MM:SS +0000]
            if ts_iso is not None:
                dt = datetime.datetime.fromtimestamp(ts_float, tz=datetime.timezone.utc)
                time_t = dt.strftime("[%d/%b/%Y:%H:%M:%S %z]")
            else:
                time_t = "[-]"
            req_target = uri or "/"
            http_version = version or "-"
            request_line = f"{method or '-'} {req_target} {http_version}"
            status_s = status or "-"
            bytes_b = str(resp_bytes) if resp_bytes is not None else "-"
            referer_q = referer or "-"
            ua_q = user_agent or "-"
            # Prepare single-line JSONs for request and response bodies
            if isinstance(payload, (dict, list)):
                req_body_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            else:
                req_body_json = json.dumps(payload, ensure_ascii=False)

            res_body_json = "null"
            # Pairing already done above for status/bytes; re-fetch body if available
            if sidx is not None and sidx in responses_by_stream:
                # We popped one entry above when computing status/bytes; retrieve same via stored variable
                # To avoid re-pop, we captured nothing; therefore compute from last popped values
                pass
            # Since we didn't keep the popped body_json in variables, recompute by keeping them earlier
            # Instead, change above pairing to also get body_json
            # Fetch body_json from rinfo if available
            # (Handled by storing into variables when pairing)
            
            src_ip = src or "-"
            src_port_str = src_port or "-"
            dst_ip = dst or "-"
            dst_port_str = dst_port or "-"
            line_out = (
                f"{host_h} {ident_l} {authuser_u} {time_t} \"{request_line}\" {status_s} {bytes_b} "
                f"\"{referer_q}\" \"{ua_q}\" {src_ip}:{src_port_str} {dst_ip}:{dst_port_str}"
            )
            # Append request and response JSON bodies
            if rinfo is not None:
                res_body_json = rinfo.get("body_json", "null")
            line_out = f"{line_out} {req_body_json} {res_body_json}"
            out.write(line_out + "\n")
    finally:
        if out is not sys.stdout:
            out.close()
        proc.stdout.close()
        proc.stderr.close()
        proc.wait()


if __name__ == "__main__":
    main()
