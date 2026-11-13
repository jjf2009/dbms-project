#!/usr/bin/env python3
"""Attack / traffic simulator (FR7, UC17).

Sends traffic to the demo website from a chosen source IP (via X-Forwarded-For),
so the SIEM sees distinct sources even though everything runs on one machine.

  brute   : N failed logins from one IP  -> triggers the threshold rule
  sqli    : SQL-injection search payloads -> triggers the pattern rule
  normal  : benign browsing / searches    -> background traffic

Examples:
  python simulator/simulate.py brute  --ip 10.0.0.5 --count 10
  python simulator/simulate.py sqli   --ip 10.0.0.9
  python simulator/simulate.py normal --ip 10.0.0.2 --count 50
"""
import argparse
import urllib.parse
import urllib.request

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "admin' --",
    "'; DROP TABLE items; --",
    "' UNION SELECT username, password_hash FROM demo_users --",
    "1' AND sleep(5) --",
    "' OR '1'='1",
]
NORMAL_QUERIES = ["keyboard", "monitor", "hub", "headset", "webcam", "usb", ""]


def _req(method, url, ip, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"X-Forwarded-For": ip, "User-Agent": "sim/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERR:{e}"


def brute(base, ip, count):
    for i in range(count):
        st = _req("POST", f"{base}/demo/login", ip,
                  {"username": "admin", "password": f"wrong{i}"})
        print(f"  login_failed #{i+1} from {ip} -> {st}")


def sqli(base, ip, count):
    for i in range(count):
        p = SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)]
        st = _req("GET", f"{base}/demo/?q={urllib.parse.quote(p)}", ip)
        print(f"  sqli search from {ip}: {p!r} -> {st}")


def normal(base, ip, count):
    for i in range(count):
        q = NORMAL_QUERIES[i % len(NORMAL_QUERIES)]
        st = _req("GET", f"{base}/demo/?q={urllib.parse.quote(q)}", ip)
        print(f"  browse from {ip}: q={q!r} -> {st}")


def main():
    ap = argparse.ArgumentParser(description="SIEM demo traffic simulator")
    ap.add_argument("mode", choices=["brute", "sqli", "normal"])
    ap.add_argument("--base", default="http://localhost:8000", help="demo site base URL")
    ap.add_argument("--ip", default="10.0.0.5", help="spoofed source IP (X-Forwarded-For)")
    ap.add_argument("--count", type=int, default=10)
    a = ap.parse_args()
    print(f"[{a.mode}] {a.count} requests from {a.ip} -> {a.base}")
    {"brute": brute, "sqli": sqli, "normal": normal}[a.mode](a.base, a.ip, a.count)
    print("done. Watch the SIEM dashboard / alerts.")


if __name__ == "__main__":
    main()
