#!/usr/bin/env python3
"""Minimal logging HTTP/HTTPS proxy for phone traffic capture via `adb reverse`.

Logs:
  * CONNECT host:port            (HTTPS tunnel targets)
  * HTTP request lines           (plain HTTP)
  * TLS ClientHello SNI          (hostname even when the client dials a raw IP)
"""
import socket, threading, sys, time, struct, os

LOG = sys.argv[2] if len(sys.argv) > 2 else 'proxy.log'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8888

lk = threading.Lock()
def log(line):
    with lk:
        with open(LOG, 'a') as f:
            f.write(f"{time.strftime('%H:%M:%S')} {line}\n")
        print(f"{time.strftime('%H:%M:%S')} {line}", flush=True)

def parse_sni(buf):
    """Extract SNI from a TLS ClientHello record if present."""
    try:
        if len(buf) < 6 or buf[0] != 0x16:
            return None
        # TLS record: type(1) ver(2) len(2) ; handshake: type(1) len(3)
        p = 5
        if buf[p] != 0x01:
            return None
        # skip handshake header
        p += 4
        p += 2 + 32                      # version + random
        sid_len = buf[p]; p += 1 + sid_len
        cs_len = struct.unpack('>H', buf[p:p+2])[0]; p += 2 + cs_len
        cm_len = buf[p]; p += 1 + cm_len
        ext_len = struct.unpack('>H', buf[p:p+2])[0]; p += 2
        end = p + ext_len
        while p + 4 <= end:
            etype, elen = struct.unpack('>HH', buf[p:p+4]); p += 4
            if etype == 0x00:            # server_name
                q = p + 2
                ntype = buf[q]; q += 1
                if ntype == 0:
                    nlen = struct.unpack('>H', buf[q:q+2])[0]; q += 2
                    return buf[q:q+nlen].decode('ascii', 'replace')
            p += elen
    except Exception:
        return None
    return None

def pipe(src, dst, tag, sni_probe=False):
    try:
        first = True
        while True:
            data = src.recv(65536)
            if not data:
                break
            if first and sni_probe:
                s = parse_sni(data)
                if s:
                    log(f"[SNI] {tag} -> {s}")
                first = False
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try: s.close()
            except Exception: pass

def handle(conn, addr):
    try:
        conn.settimeout(20)
        buf = b''
        while b'\r\n\r\n' not in buf and len(buf) < 65536:
            d = conn.recv(4096)
            if not d: break
            buf += d
        head = buf.split(b'\r\n\r\n', 1)[0].decode('latin1', 'replace')
        first = head.split('\r\n')[0]
        parts = first.split()
        if len(parts) >= 2 and parts[0].upper() == 'CONNECT':
            target = parts[1]
            log(f"[CONNECT] {addr[0]}:{addr[1]} -> {target}")
            host, _, port = target.rpartition(':')
            try:
                up = socket.create_connection((host, int(port or 443)), timeout=15)
            except Exception as e:
                conn.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n'); conn.close(); return
            conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            conn.settimeout(None)
            t1 = threading.Thread(target=pipe, args=(conn, up, target, True), daemon=True)
            t2 = threading.Thread(target=pipe, args=(up, conn, target, False), daemon=True)
            t1.start(); t2.start(); t1.join(); t2.join()
        else:
            log(f"[HTTP] {addr[0]}:{addr[1]} {first[:300]}")
            for h in head.split('\r\n')[1:]:
                if h.lower().startswith(('host:', 'user-agent:')):
                    log(f"        {h[:200]}")
            conn.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
            conn.close()
    except Exception as e:
        log(f"[ERR] {addr}: {e}")
        try: conn.close()
        except Exception: pass

def main():
    open(LOG, 'a').write(f"\n=== proxy start {time.strftime('%F %T')} on {PORT} ===\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', PORT))
    s.listen(128)
    log(f"listening on 127.0.0.1:{PORT}")
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()

if __name__ == '__main__':
    main()
