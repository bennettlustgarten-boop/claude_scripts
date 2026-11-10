#!/usr/bin/env bash
#
# hunt_lkm_persistence.sh
# -----------------------
# Threat-hunting / detection script for kernel-module persistence.
#
# MITRE ATT&CK: T1547.006 - Boot or Logon Autostart Execution:
#               Kernel Modules and Extensions
#
# Purpose: enumerate loaded modules, every module autoload location, and
# module files on disk, then flag anything suspicious (out-of-tree,
# unsigned, odd path, or a known IOC). Read-only -- it changes nothing.
#
# Usage:   sudo ./hunt_lkm_persistence.sh
#          sudo ./hunt_lkm_persistence.sh > report.txt
#
# Exit code: 0 = nothing flagged, 1 = findings, 2 = run error.

set -uo pipefail

# ----- known indicators of compromise to hunt for -------------------------
# Add one IOC per line. These are the breadcrumbs for THIS hunt.
IOCS=(
    "/usr/lib/modules/hwmon_extras.ko"
    "hwmon_extras"
)

# Directories a legitimately-installed module should live under.
EXPECTED_PREFIXES=(
    "/lib/modules/"
    "/usr/lib/modules/kernel/"   # vendor tree under the running kernel
)

findings=0
RED=$'\e[31m'; YLW=$'\e[33m'; GRN=$'\e[32m'; CLR=$'\e[0m'
[[ -t 1 ]] || { RED=""; YLW=""; GRN=""; CLR=""; }

hit()  { printf '%s[FLAG]%s %s\n' "$RED" "$CLR" "$*"; findings=$((findings+1)); }
note() { printf '%s[note]%s %s\n' "$YLW" "$CLR" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$GRN" "$CLR" "$*"; }
hdr()  { printf '\n==== %s ====\n' "$*"; }

[[ $EUID -eq 0 ]] || note "Not running as root -- some paths (initramfs, signatures) may be unreadable."

echo "Kernel-module persistence hunt (T1547.006)"
echo "host: $(hostname)   kernel: $(uname -r)   date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ----- 1. kernel taint ----------------------------------------------------
hdr "1. Kernel taint state"
if [[ -r /proc/sys/kernel/tainted ]]; then
    t=$(cat /proc/sys/kernel/tainted)
    if (( t == 0 )); then
        ok "Kernel not tainted (value 0)."
    else
        note "Kernel tainted, value=$t. Bit 12 (0x1000)=out-of-tree, bit 13 (0x2000)=unsigned module loaded."
        (( (t & 0x1000) != 0 )) && hit "Out-of-tree module loaded (taint bit 12)."
        (( (t & 0x2000) != 0 )) && hit "Unsigned module loaded (taint bit 13)."
    fi
fi

# ----- 2. direct IOC check ------------------------------------------------
hdr "2. Known IOCs"
for ioc in "${IOCS[@]}"; do
    if [[ "$ioc" == /* ]]; then
        [[ -e "$ioc" ]] && hit "IOC file present on disk: $ioc" || ok "Absent: $ioc"
    else
        if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "${ioc//-/_}"; then
            hit "IOC module currently loaded: $ioc"
        else
            ok "Not loaded: $ioc"
        fi
    fi
done

# ----- 3. loaded modules: unsigned / out-of-tree / odd path ---------------
hdr "3. Loaded modules — signature, path, and taint"
while read -r mod _; do
    [[ "$mod" == "Module" ]] && continue
    info=$(modinfo "$mod" 2>/dev/null) || continue
    fname=$(awk -F': *' '/^filename:/{print $2; exit}' <<<"$info")
    sig=$(awk -F': *'   '/^sig_id:/{print $2; exit}'   <<<"$info")
    intree=$(awk -F': *' '/^intree:/{print $2; exit}' <<<"$info")

    if [[ -z "$sig" ]]; then
        hit "Unsigned loaded module: $mod  ($fname)"
    fi
    if [[ "$intree" != "Y" && -n "$intree" ]]; then
        note "Out-of-tree module loaded: $mod  ($fname)"
    fi
    # path outside the expected trees
    if [[ -n "$fname" ]]; then
        expected=0
        for p in "${EXPECTED_PREFIXES[@]}"; do [[ "$fname" == "$p"* ]] && expected=1; done
        [[ "$fname" == /lib/modules/$(uname -r)/* ]] && expected=1
        (( expected == 0 )) && hit "Loaded module in unexpected path: $mod  ->  $fname"
    fi
done < <(lsmod 2>/dev/null)

# ----- 4. autoload persistence locations ----------------------------------
hdr "4. Module autoload configuration"
autoload_paths=(
    /etc/modules
    /etc/modules-load.d/
    /run/modules-load.d/
    /usr/lib/modules-load.d/
    /etc/modprobe.d/
    /run/modprobe.d/
    /usr/lib/modprobe.d/
)
for ap in "${autoload_paths[@]}"; do
    [[ -e "$ap" ]] || continue
    if [[ -d "$ap" ]]; then
        files=$(find "$ap" -type f 2>/dev/null)
    else
        files="$ap"
    fi
    for f in $files; do
        # lines that force-load a module or override its path/options
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            if grep -qiE 'install|modprobe|insmod|/.*\.ko' <<<"$line"; then
                note "$f: $line"
            fi
        done < "$f"
    done
done
ok "Reviewed autoload configs above — eyeball any 'install ... /bin/...' lines (that runs a command, not a module)."

# ----- 5. .ko files on disk not owned by a package ------------------------
hdr "5. Module files on disk with no owning package"
pkgcheck() {
    if command -v dpkg >/dev/null 2>&1;  then dpkg -S "$1" >/dev/null 2>&1; return
    elif command -v rpm >/dev/null 2>&1; then rpm -qf  "$1" >/dev/null 2>&1; return
    fi
    return 2
}
while IFS= read -r ko; do
    pkgcheck "$ko"; rc=$?
    case $rc in
      1) hit "Module not owned by any package: $ko" ;;
      2) note "No package manager to verify ownership of: $ko" ;;
    esac
done < <(find /lib/modules /usr/lib/modules -name '*.ko' -o -name '*.ko.*' 2>/dev/null)

# ----- 6. initramfs (persists across a module file being cleaned) ---------
hdr "6. initramfs references"
img="/boot/initrd.img-$(uname -r)"
[[ -e "$img" ]] || img="/boot/initramfs-$(uname -r).img"
if [[ -r "$img" ]] && command -v lsinitramfs >/dev/null 2>&1; then
    for ioc in "${IOCS[@]}"; do
        base=$(basename "$ioc")
        lsinitramfs "$img" 2>/dev/null | grep -qi "$base" && hit "IOC '$base' baked into initramfs: $img"
    done
    ok "initramfs scanned: $img"
else
    note "initramfs not readable or lsinitramfs missing — check manually: $img"
fi

# ----- summary ------------------------------------------------------------
hdr "Summary"
if (( findings > 0 )); then
    printf '%s%d item(s) flagged — investigate above.%s\n' "$RED" "$findings" "$CLR"
    exit 1
else
    ok "No flagged items. (Review [note] lines — they are context, not clean bills of health.)"
    exit 0
fi
