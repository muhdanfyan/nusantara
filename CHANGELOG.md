# Changelog

Semua perubahan penting pada proyek ini didokumentasikan di file ini.

Format berdasarkan [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.0.0] - 2026-07-10

### 🚀 Added
- **TUI Installer baru** berbasis Go (`bubbletea` + `huh`) menggantikan installer Bash lama
- **4 mode operasi**: Full Installation, Integrate Manual, PoC, Uninstall
- **Full Installation** — deploy Wazuh + n8n/Shuffle + IRIS + MISP dalam satu alur
- **Integrate Manual mode** — input URL & API key per service, disimpan ke JSON
- **PoC mode** — simulasi SSH Brute Force, EICAR Malware, Web Defacement
- **Uninstall mode** — hapus semua komponen dan state hingga bersih
- **Hardware Auto-Detection** — Identifikasi profil perangkat keras: High-End / Standard / Entry-Level
- **Idempotency** — state tracking di `/var/lib/tguard_state/`, aman dijalankan ulang
- **Certificate Auto-Generation** — SSL Wazuh Indexer dibuat otomatis sebelum deploy
- **VirusTotal integration** — API key langsung disuntik ke konfigurasi Wazuh
- **Post-install summary** — tampilkan semua URL + kredensial setelah install selesai
- **docker-compose.yml untuk n8n** dengan healthcheck, timezone Asia/Jakarta, dan volume persistent
- **`pkg/state`** — package baru untuk idempotency tracking
- **`pkg/network`** — fix memory leak (`defer` di dalam loop)

### 🔧 Fixed
- `defer resp.Body.Close()` di dalam loop di `network.go` (memory leak)
- `test_deploy.go` menyebabkan `main redeclared` compile error — diperbaiki dengan `//go:build ignore`
- Dummy directories `.pem` dibuat Docker menyebabkan error `not a directory` saat mounting Wazuh certs
- `hostIP` kosong saat step network di-skip karena idempotency — sekarang di-detect ulang dari env

### 🗑️ Removed
- Installer Bash lama (digantikan sepenuhnya oleh TUI Go)
- `test_deploy.go` dari build utama
- `tguard-installer-v2.zip` (sudah tidak diperlukan)

---

## [1.0.0] - 2025

### Added
- Installer berbasis Bash untuk Wazuh + n8n
- Script PoC dasar
- Integrasi VirusTotal manual
