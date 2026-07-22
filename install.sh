#!/usr/bin/env bash
# =============================================================================
#  T-Guard v2.2 — One-Step Installer Bootstrap
#
#  Cara penggunaan:
#    sudo bash install.sh
#
#  Script ini akan otomatis:
#    1. Memeriksa OS & hardware
#    2. Menginstal Go via apt jika belum ada
#    3. Build binary installer via make jika belum ada
#    4. Meluncurkan TUI installer T-Guard
# =============================================================================

set -euo pipefail

# ── Konstanta ─────────────────────────────────────────────────────────────────
readonly TGUARD_VERSION="2.2"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BINARY="$SCRIPT_DIR/tguard-installer-cli"

# ── Warna ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[•]${RESET} $*"; }
success() { echo -e "${GREEN}[✔]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
die()     { echo -e "${RED}[✖] ERROR: $*${RESET}" >&2; exit 1; }

prompt_confirm() {
    warn "$1 Lanjutkan? (y/N)"
    local reply=""
    if ! read -r -t 60 reply; then
        echo "Timeout — instalasi dibatalkan."
        exit 1
    fi
    [[ "$reply" =~ ^[Yy]$ ]] || { echo "Dibatalkan."; exit 0; }
}

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat <<'EOF'
  ████████╗       ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ╚══██╔══╝      ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
     ██║   █████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║
     ██║   ╚════╝██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
     ██║         ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
     ╚═╝          ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
EOF
    echo -e "  Next-Generation Security Operations Center — v${TGUARD_VERSION}${RESET}"
    echo
}

# ── Cek: harus root ───────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "Script ini harus dijalankan sebagai root.\n  Coba: ${BOLD}sudo bash install.sh${RESET}"
    fi
}

# ── Cek: OS Ubuntu / Debian ───────────────────────────────────────────────────
check_os() {
    info "Memeriksa sistem operasi..."
    [[ -f /etc/os-release ]] || die "File /etc/os-release tidak ditemukan. Hanya Ubuntu/Debian yang didukung."

    local os_id os_pretty
    os_id=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
    os_pretty=$(grep -oP '(?<=^PRETTY_NAME=).+' /etc/os-release | tr -d '"')

    [[ "$os_id" =~ ^(ubuntu|debian)$ ]] \
        || die "OS tidak didukung: ${os_pretty}\n  Hanya Ubuntu 22.04+ dan Debian 11+ yang didukung."

    success "OS: $os_pretty"
}

# ── Cek: Hardware minimum ─────────────────────────────────────────────────────
check_hardware() {
    info "Memeriksa spesifikasi hardware..."

    local cpu_cores ram_gb disk_gb
    cpu_cores=$(nproc)
    ram_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
    disk_gb=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {gsub("G","",$4); print $4}')

    echo -e "     CPU  : ${BOLD}${cpu_cores} cores${RESET}"
    echo -e "     RAM  : ${BOLD}${ram_gb} GB${RESET}"
    echo -e "     Disk : ${BOLD}${disk_gb} GB free${RESET}"

    local warn_shown=false
    [[ $cpu_cores -lt 4  ]] && { warn "CPU (${cpu_cores} cores) di bawah minimum (4 cores)"; warn_shown=true; }
    [[ $ram_gb    -lt 7  ]] && { warn "RAM (${ram_gb} GB) di bawah minimum (8 GB)";           warn_shown=true; }
    [[ $disk_gb   -lt 20 ]] && { warn "Disk free (${disk_gb} GB) di bawah minimum (20 GB)";   warn_shown=true; }

    if [[ "$warn_shown" == "true" ]]; then
        echo
        prompt_confirm "Hardware di bawah spesifikasi. Performa mungkin terganggu."
    else
        success "Hardware OK"
    fi
}

# ── Install: dependensi (golang + make) via apt ───────────────────────────────
ensure_deps() {
    local pkgs_to_install=()

    # Cek golang
    if ! command -v go &>/dev/null; then
        info "Go belum terinstal."
        pkgs_to_install+=(golang)
    else
        success "Go sudah terinstal: $(go version)"
    fi

    # Cek make
    if ! command -v make &>/dev/null; then
        info "make belum terinstal."
        pkgs_to_install+=(make)
    else
        success "make sudah terinstal"
    fi

    # Install semua yang kurang sekaligus
    if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then
        info "Menginstal: ${pkgs_to_install[*]} ..."
        apt-get update -qq
        apt-get install -y -qq "${pkgs_to_install[@]}"
        success "Dependensi berhasil diinstal: ${pkgs_to_install[*]}"
    fi
}

# ── Build binary installer via make ──────────────────────────────────────────
build_installer() {
    if [[ -f "$BINARY" ]]; then
        info "Binary sudah ada, melewati proses build."
        success "Binary: $BINARY"
        return
    fi

    [[ -f "$SCRIPT_DIR/Makefile" ]] \
        || die "Makefile tidak ditemukan di: $SCRIPT_DIR\n  Pastikan Anda menjalankan script dari dalam direktori t-guard."

    info "Membangun T-Guard Installer CLI..."
    if ! make -C "$SCRIPT_DIR" build; then
        die "Build gagal. Periksa output di atas untuk detail error."
    fi
    success "Binary berhasil dibangun: $BINARY"
}

# ── Jalankan installer ────────────────────────────────────────────────────────
run_installer() {
    [[ -f "$BINARY" ]] || die "Binary tidak ditemukan: $BINARY"
    chmod +x "$BINARY"

    echo
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}${BOLD}  Semua persiapan selesai! Meluncurkan T-Guard...${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
    sleep 1
    exec "$BINARY"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    print_banner
    check_root
    check_os
    check_hardware
    ensure_deps
    build_installer
    run_installer
}

main "$@"
