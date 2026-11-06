# 🦉 OImageScan

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Forensics%20/%20DFIR-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OImageScan** — Container image/layer inspector (reads image tar/manifest) ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OImageScan — Container image/layer inspector (reads image tar/manifest). Container Image / Layer Inspector Reads a "docker save" (or OCI) image tarball entirely with the standard library: archive/tar for the outer archive and each layer, compress/gzip for gzipped layers, encoding/json for manifest.json and the image config. Reports the manifest and config, per-layer sizes, a reconstructed build history, and a content scan for risky files (setuid/setgid, world-writable, secrets, SSH material, shell history).

---

## ✨ Features

- Inspect container images from tar/manifest inputs
- Enumerate layers, history and embedded filesystem clues
- Surface risky files, secrets and misconfig markers
- Offline analysis without needing a running daemon
- Structured findings for supply-chain review
- Export inventories suitable for CI gates

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OImageScan OImageScan.go
./OImageScan --help
./OImageScan --input image.tar
./OImageScan --input image.tar --format json --output layers.json
./OImageScan --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
