#!/usr/bin/env python3
"""
Educational TCP port scanner.

Usage:
    python port_scanner.py 127.0.0.1
    python port_scanner.py 127.0.0.1 --start-port 1 --end-port 1024 --timeout 0.5
"""

import argparse
import socket
from datetime import datetime


def scan_port(target: str, port: int, timeout: float = 0.5) -> bool:
    """Return True when a TCP connection to target:port succeeds."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((target, port)) == 0
    except (socket.gaierror, OSError):
        return False
    finally:
        sock.close()


def resolve_target(target: str) -> str:
    """Resolve a hostname/IP and return the resolved IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target: {target}") from exc


def scan_target(target: str, start_port: int, end_port: int, timeout: float):
    """Scan an inclusive TCP port range and return open ports."""
    if not 1 <= start_port <= 65535 or not 1 <= end_port <= 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    if start_port > end_port:
        raise ValueError("start-port cannot be greater than end-port.")
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0.")

    ip = resolve_target(target)
    open_ports = []

    print(f"\nTarget: {target}")
    print(f"Resolved IP: {ip}")
    print(f"TCP range: {start_port}-{end_port}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    for port in range(start_port, end_port + 1):
        if scan_port(ip, port, timeout):
            print(f"[OPEN] TCP/{port}")
            open_ports.append(port)

    print(f"\nScan complete. Open TCP ports found: {len(open_ports)}")
    return open_ports


def build_parser():
    parser = argparse.ArgumentParser(
        description="Educational TCP port scanner using Python sockets."
    )
    parser.add_argument("target", help="Hostname or IP address you are authorized to scan.")
    parser.add_argument("--start-port", type=int, default=1)
    parser.add_argument("--end-port", type=int, default=1024)
    parser.add_argument("--timeout", type=float, default=0.5)
    return parser


def main():
    args = build_parser().parse_args()
    try:
        scan_target(args.target, args.start_port, args.end_port, args.timeout)
    except ValueError as exc:
        raise SystemExit(f"Error: {exc}")


if __name__ == "__main__":
    main()
