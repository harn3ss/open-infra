#!/usr/bin/env python3
"""A Fleet Manager Remote Desktop connection through the console, as the browser opens one, for
probe/fleet-manager-remote-desktop.sh: the websocket (the Guacamole protocol), the Windows credentials in
its first message, then the instructions until the session draws (a sync after image data) or ends with an
error. Prints one JSON object: the HTTP status of the upgrade, the connection id, the error guacd or the
console sent (its message and status code), and whether the session drew.

    remote_desktop_ws.py <console base URL> <cookie jar> <path>

The Windows user name and password are read from RDP_USERNAME and RDP_PASSWORD (never the command line),
and the password is never printed. Standard library only.
"""

import base64
import json
import os
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlparse


def session_cookie(jar):
    for line in open(jar):
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 7 and parts[5] == "oi_session":
            return parts[6]
    return ""


def send_frame(sock, text):
    data = text.encode()
    head = bytearray([0x81])
    n = len(data)
    if n < 126:
        head.append(0x80 | n)
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    mask = os.urandom(4)
    head += mask
    sock.sendall(bytes(head) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("closed")
        buf += chunk
    return buf


def recv_frame(sock):
    """The next data frame's text (a close frame raises EOFError)."""
    while True:
        b0, b1 = recv_exact(sock, 2)
        op, n = b0 & 0x0F, b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", recv_exact(sock, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", recv_exact(sock, 8))[0]
        payload = recv_exact(sock, n)
        if op == 0x8:
            raise EOFError("close")
        if op in (0x1, 0x2, 0x0):
            return payload.decode("utf-8", "replace")


def parse(buf):
    """Whole Guacamole instructions in buf, and what is left over."""
    out, i = [], 0
    while True:
        elems, j = [], i
        while True:
            dot = buf.find(".", j)
            if dot < 0:
                return out, buf[i:]
            n = int(buf[j:dot])
            end = dot + 1 + n
            if end >= len(buf):
                return out, buf[i:]
            elems.append(buf[dot + 1:end])
            j = end + 1
            if buf[end] == ";":
                out.append(elems)
                i = j
                break


def main():
    base, jar, path = sys.argv[1:4]
    u = urlparse(base)
    port = u.port or (443 if u.scheme == "https" else 80)
    result = {"status": 0, "connectionId": "", "error": None, "drew": False, "opcodes": {}}
    sock = socket.create_connection((u.hostname, port), timeout=30)
    if u.scheme == "https":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
    key = base64.b64encode(os.urandom(16)).decode()
    host = f"{u.hostname}:{port}"
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: guacamole\r\n"
           f"Origin: {u.scheme}://{host}\r\nCookie: oi_session={session_cookie(jar)}\r\n\r\n")
    sock.sendall(req.encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            break
        head += chunk
    status_line, _, rest = head.partition(b"\r\n")
    result["status"] = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0
    if result["status"] != 101:
        headers, _, body = rest.partition(b"\r\n\r\n")
        want = 0
        for h in headers.split(b"\r\n"):
            name, _, value = h.partition(b":")
            if name.strip().lower() == b"content-length" and value.strip().isdigit():
                want = int(value.strip())
        sock.settimeout(5)
        try:
            while len(body) < want:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body += chunk
        except socket.timeout:
            pass
        result["body"] = body[:400].decode("utf-8", "replace")
        print(json.dumps(result))
        return
    start = {"username": os.environ.get("RDP_USERNAME", ""), "password": os.environ.get("RDP_PASSWORD", ""),
             "width": 1024, "height": 768, "dpi": 96, "timezone": "UTC"}
    send_frame(sock, json.dumps(start))
    start["password"] = ""
    deadline = time.time() + float(os.environ.get("RDP_WAIT_SECONDS", "90"))
    buf, imaged = "", False
    sock.settimeout(5)
    try:
        while time.time() < deadline:
            try:
                buf += recv_frame(sock)
            except socket.timeout:
                continue
            ins, buf = parse(buf)
            for elems in ins:
                op, args = elems[0], elems[1:]
                result["opcodes"][op] = result["opcodes"].get(op, 0) + 1
                if op == "" and len(args) == 1 and not result["connectionId"]:
                    result["connectionId"] = args[0]
                elif op == "error":
                    result["error"] = {"message": args[0] if args else "", "code": int(args[1]) if len(args) > 1 and args[1].isdigit() else 0}
                elif op in ("img", "blob"):
                    imaged = True
                elif op == "sync" and imaged:
                    result["drew"] = True
                    send_frame(sock, "4.sync," + str(len(args[0])) + "." + args[0] + ";")
            if result["error"] or result["drew"]:
                break
    except EOFError:
        pass
    try:
        send_frame(sock, "10.disconnect;")
    except OSError:
        pass
    sock.close()
    print(json.dumps(result))


if __name__ == "__main__":
    main()
