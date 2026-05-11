# IP Cam Auditor v4.0 — Ultimate Edition

> **IP Camera Discovery · Fingerprinting · Exploit Check · Credential Audit**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Kali](https://img.shields.io/badge/Kali%20Linux-Ready-557C94?logo=kalilinux&logoColor=white)](https://www.kali.org)

IP Cam Auditor è un tool completo per penetration test su telecamere IP. Combina discovery multi-modale, fingerprinting intelligente, credential auditing, exploit checking e cattura di snapshot in un unico strumento professionale.

> **⚠️ Solo per test di sicurezza autorizzati. L'utente si assume ogni responsabilità.**

---

## ✨ Caratteristiche Principali

| Funzionalità | Dettaglio |
|---|---|
| **🔍 Discovery** | CIDR scan, singolo target, DNS/DDNS, UPnP, cloud ranges, file list |
| **🧬 Fingerprinting** | 25+ brand riconosciuti via HTTP headers/body, RTSP banner |
| **🔑 Credential Audit** | 220+ credenziali di default per 15 brand (HTTP, Digest, RTSP, ONVIF, Telnet) |
| **💥 Exploit Checks** | CVE-2017-7921, CVE-2021-36260, CVE-2017-12557, CVE-2014-4862, CVE-2020-7592, CVE-2018-11479 |
| **📸 Snapshot** | Cattura JPEG via HTTP / ONVIF / RTSP / MJPEG |
| **🌐 Ricerca Globale** | Shodan, Censys, FOFA, ZoomEye, Google Dorks |
| **🔌 Multi-Protocollo** | HTTP(S), RTSP, ONVIF, SNMP, Telnet, UPnP, NTLM |
| **📊 Report** | TXT, HTML (interattivo), CSV |
| **⚙️ Wizard** | Menu interattivo a 11 opzioni |

---

## 🚀 Installazione

```bash
git clone https://github.com/tuo_nome/ipcam-auditor.git
cd ipcam-auditor
pip install requests dnspython onvif-zeep opencv-python shodan aiohttp
