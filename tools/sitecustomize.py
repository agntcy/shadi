# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

import os
import socket
from typing import Any


def _split_host_port(entry: str) -> tuple[str, int | None]:
    entry = entry.strip()
    if not entry:
        return "", None
    if entry.startswith("[") and "]" in entry:
        host = entry[1:entry.index("]")]
        rest = entry[entry.index("]") + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if entry.count(":") == 1:
        host, port = entry.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return entry, None


def _normalize_host(host: Any) -> str:
    if host is None:
        return ""
    if isinstance(host, bytes):
        host = host.decode("utf-8", errors="ignore")
    return str(host).strip().strip("[]").lower()


def _parse_allowlist(value: str) -> tuple[set[str], set[tuple[str, int]]]:
    hosts: set[str] = set()
    host_ports: set[tuple[str, int]] = set()
    for item in value.split(","):
        host, port = _split_host_port(item)
        host = _normalize_host(host)
        if not host:
            continue
        if port is None:
            hosts.add(host)
        else:
            host_ports.add((host, port))
    return hosts, host_ports


def _install_network_guard() -> None:
    raw_allowlist = os.getenv("SHADI_NET_ALLOWLIST", "").strip()
    if not raw_allowlist:
        return

    hosts, host_ports = _parse_allowlist(raw_allowlist)
    if not hosts and not host_ports:
        return

    original_create_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo

    def is_allowed(host: Any, port: Any) -> bool:
        if host is None:
            return True
        normalized = _normalize_host(host)
        if not normalized:
            return True
        if normalized in hosts:
            return True
        try:
            port_num = int(port)
        except (TypeError, ValueError):
            port_num = None
        if port_num is not None and (normalized, port_num) in host_ports:
            return True
        return False

    def guarded_create_connection(address, *args, **kwargs):
        if isinstance(address, tuple) and len(address) >= 2:
            host, port = address[0], address[1]
            if not is_allowed(host, port):
                raise OSError(f"SHADI sandbox blocked network to {host}:{port}")
        return original_create_connection(address, *args, **kwargs)

    def guarded_getaddrinfo(host, port, *args, **kwargs):
        if host is not None and not is_allowed(host, port):
            raise OSError(f"SHADI sandbox blocked network to {host}:{port}")
        return original_getaddrinfo(host, port, *args, **kwargs)

    socket.create_connection = guarded_create_connection
    socket.getaddrinfo = guarded_getaddrinfo


_install_network_guard()
