import base64
import re
import time

import requests

API = "https://www.vpngate.net/api/iphone/"
DC = ["GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN", "AKAMAI",
      "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR", "HURRICANE",
      "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB", "SOFTETHER"]
RES = ["NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "SOFTBANK",
       "KOREA TELECOM", "SK BROADBAND", "LG U", "LG DACOM", "LG POWERCOMM",
       "COMCAST", "CHARTER", "VERIZON"]

text = requests.get(API, timeout=60, headers={"User-Agent": "jp-audit"}).text
lines = [l for l in text.splitlines() if l.strip()]
hi = next(i for i, l in enumerate(lines) if l.lstrip("#").startswith("HostName"))
rows = []
for l in lines[hi + 1:]:
    if l.startswith("*"):
        continue
    f = l.split(",")
    if len(f) < 7:
        continue
    rows.append({"host": f[0].strip(), "ip": f[1].strip(),
                 "long": f[5].strip(), "cc": f[6].strip(), "b64": f[-1].strip()})

jp = [r for r in rows if r["cc"] == "JP"]
print("TOTAL_ROWS=%d JP_TOTAL=%d" % (len(rows), len(jp)))

cache = {}


def asn(ip):
    if ip in cache:
        return cache[ip]
    try:
        r = requests.get("https://ipinfo.io/%s/json" % ip, timeout=20,
                         headers={"User-Agent": "jp-audit"}).json()
        cache[ip] = (r.get("asn", ""), r.get("org", ""), r.get("country", ""))
    except Exception as e:
        cache[ip] = ("ERR", str(e)[:40], "")
    time.sleep(0.4)
    return cache[ip]


def cls(host, org):
    o = (org or "").upper()
    if any(k in o for k in DC):
        return "datacenter"
    if any(k in o for k in RES):
        return "residential"
    if host.startswith("public-vpn"):
        return "datacenter"
    return "unknown"


sstp = 0
out = []
for r in jp:
    proto, port = "", ""
    try:
        cfg = base64.b64decode(r["b64"]).decode("utf-8", "ignore")
        m = re.search(r"^proto\s+(\S+)", cfg, re.M)
        proto = m.group(1) if m else ""
        pm = re.search(r"^remote\s+\S+\s+(\d+)", cfg, re.M)
        port = pm.group(1) if pm else ""
    except Exception:
        pass
    a, o, c = asn(r["ip"])
    k = cls(r["host"], o)
    if proto.lower().startswith("tcp"):
        sstp += 1
    out.append((r["host"], r["ip"], port, proto, a, o, c, k))

print("JP_SSTP_TCP=%d JP_NON_TCP=%d" % (sstp, len(jp) - sstp))
print("HOST|IP|PORT|PROTO|ASN|ORG|COUNTRY|CLASS")
for t in out:
    print("|".join(str(x) for x in t))
