#!/usr/bin/env bash
#
# Install the patched python-validity (06cb:00bb support) on this machine.
#
#   sudo ./install-00bb.sh            install the driver, udev rule and service
#   sudo ./install-00bb.sh --check    only verify prerequisites
#   sudo ./install-00bb.sh --uninstall remove the installed driver files
#
# This script never touches PAM configuration, never removes packages and never
# reflashes the sensor. Package-level changes (open-fprintd / fprintd-clients)
# are printed as commands for you to run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX=/usr
SITE_PACKAGES=/usr/lib/python3/dist-packages
UNIT=/etc/systemd/system/python3-validity.service
UDEV_RULE=/etc/udev/rules.d/60-python3-validity.rules
DBUS_CONF=/usr/share/dbus-1/system.d/io.github.uunicorn.Fprint.conf
CONFIG_DIR=/etc/python-validity
STATE_DIR=/var/lib/python-validity
MODE=install

for arg in "$@"; do
  case "$arg" in
    --check) MODE=check ;;
    --uninstall) MODE=uninstall ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
ok()  { printf '  [ok] %s\n' "$*"; }
bad() { printf '  [!!] %s\n' "$*"; }
note() { printf '  [--] %s\n' "$*"; }

# dpkg -s succeeds even for packages in the "rc" (removed, configs left) state,
# which made a previously removed fprintd look installed.
pkg_installed() {
  [ "$(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null)" = "ii " ]
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This step needs root: sudo $0 $*" >&2
    exit 1
  fi
}

check_python_modules() {
  local missing=()
  for module in usb cryptography yaml dbus gi; do
    if ! python3 - "$module" 2>/dev/null <<'PY'
import importlib, sys
importlib.import_module(sys.argv[1])
PY
    then
      missing+=("$module")
    fi
  done
  if [ ${#missing[@]} -gt 0 ]; then
    bad "missing Python modules: ${missing[*]}"
    say "       sudo apt install python3-usb python3-cryptography python3-yaml python3-dbus python3-gi"
    return 1
  fi
  ok "python modules: usb, cryptography, yaml, dbus, gi"
}

check_extractor() {
  if command -v cabextract >/dev/null || command -v innoextract >/dev/null; then
    ok "SoftPaq extractor: $(command -v cabextract || command -v innoextract)"
  else
    bad "neither cabextract nor innoextract is installed"
    say "       sudo apt install cabextract"
    return 1
  fi
}

check_backend() {
  local rc=0
  if pkg_installed open-fprintd; then
    ok "open-fprintd installed ($(dpkg-query -W -f='${Version}' open-fprintd))"
  else
    bad "open-fprintd is not installed"
    say "       sudo add-apt-repository ppa:uunicorn/open-fprintd"
    say "       sudo apt update"
    say "       sudo apt install open-fprintd fprintd-clients"
    rc=1
  fi
  if pkg_installed fprintd; then
    bad "the old 'fprintd' package is still installed and conflicts with open-fprintd"
    say "       sudo apt install open-fprintd fprintd-clients   # replaces it"
    rc=1
  else
    ok "old fprintd package absent"
  fi
  if [ -e /usr/lib/x86_64-linux-gnu/security/pam_fprintd.so ] \
     || [ -e /lib/x86_64-linux-gnu/security/pam_fprintd.so ]; then
    ok "pam_fprintd.so present"
  else
    bad "pam_fprintd.so missing; install fprintd-clients"
    rc=1
  fi
  # The module being installed does not mean PAM uses it: the profile ships
  # disabled, so common-auth has no pam_fprintd line until it is enabled.
  if grep -q pam_fprintd /etc/pam.d/common-auth 2>/dev/null; then
    ok "PAM uses pam_fprintd (screen unlock / sudo offer a finger)"
  else
    note "PAM does not use pam_fprintd yet; enable it with:"
    say "       sudo pam-auth-update --enable fprintd"
    say "       (not done by this script, which never edits PAM)"
  fi
  return $rc
}

do_check() {
  local rc=0
  say "Prerequisite check"
  check_python_modules || rc=1
  check_extractor || rc=1
  check_backend || rc=1
  if [ $rc -ne 0 ]; then
    say ""
    say "Fix the [!!] items above, then re-run: sudo $0"
    return 1
  fi
  say ""
  say "All prerequisites satisfied."
}

do_install() {
  need_root "$@"
  do_check || exit 1

  say ""
  say "Installing the patched python-validity package"
  cd "$HERE"
  # --single-version-externally-managed is what makes this use the Debian
  # layout instead of falling back to easy_install.  The fallback installs an
  # .egg and silently SKIPS data_files, so /usr/lib/python-validity/dbus-service
  # (the service's ExecStart) was never created and the daemon died with
  # status=203/EXEC.
  python3 setup.py install --prefix="$PREFIX" --install-layout=deb \
      --single-version-externally-managed --record=/tmp/00bb-installed.txt \
      >/tmp/00bb-setup.log 2>&1 || {
    bad "setup.py install failed; see /tmp/00bb-setup.log"
    tail -20 /tmp/00bb-setup.log
    exit 1
  }
  ok "validitysensor installed in $SITE_PACKAGES"

  # Remove the artefacts of an older easy_install-style run so the plain
  # package tree wins and the .pth does not point at a deleted egg.
  for egg in "$SITE_PACKAGES"/python_validity-*.egg; do
    [ -e "$egg" ] || continue
    rm -rf "$egg"
    ok "removed stale egg $(basename "$egg")"
  done
  if [ -f "$SITE_PACKAGES/easy-install.pth" ]; then
    sed -i '/python_validity-.*\.egg/d' "$SITE_PACKAGES/easy-install.pth"
  fi

  for path in "$SITE_PACKAGES/validitysensor/__init__.py" \
              $PREFIX/lib/python-validity/dbus-service \
              $PREFIX/share/dbus-1/system.d/io.github.uunicorn.Fprint.conf; do
    if [ ! -e "$path" ]; then
      bad "installation incomplete: $path is missing"
      exit 1
    fi
  done
  # The service imports the installed copy, so prove it resolves outside this
  # checkout (a leftover egg or a stale PYTHONPATH could otherwise mask it).
  if ! (cd / && python3 -c 'import validitysensor' 2>/dev/null); then
    bad "the installed validitysensor package is not importable from /"
    exit 1
  fi
  ok "driver files complete (dbus-service, D-Bus policy, module)"

  rm -rf "$HERE/build" "$HERE/python_validity.egg-info"

  say ""
  say "Installing udev rule and systemd unit"
  install -d -m 0755 /etc/udev/rules.d /etc/systemd/system "$CONFIG_DIR"
  install -m 0644 "$HERE/debian/python3-validity.udev" "$UDEV_RULE"
  install -m 0644 "$HERE/debian/python3-validity.service" "$UNIT"
  ok "$UDEV_RULE"
  ok "$UNIT"

  if [ ! -e "$CONFIG_DIR/dbus-service.yaml" ]; then
    install -m 0600 "$HERE/etc/python-validity/dbus-service.yaml" "$CONFIG_DIR/dbus-service.yaml"
    ok "$CONFIG_DIR/dbus-service.yaml (new)"
  else
    ok "$CONFIG_DIR/dbus-service.yaml (kept existing)"
  fi

  install -d -m 0700 "$STATE_DIR"

  systemctl daemon-reload
  udevadm control --reload-rules
  # Match what the .deb does (enable, do not start) and clear the failed state
  # left by any earlier run, then let the udev add event start the daemon.
  systemctl enable python3-validity.service >/dev/null 2>&1 || true
  systemctl reset-failed python3-validity.service 2>/dev/null || true
  udevadm trigger --attr-match=idVendor=06cb --attr-match=idProduct=00bb || true
  ok "udev cache and systemd reloaded (service enabled)"

  say ""
  say "Done. Next steps:"
  say "  1. sudo python3 $HERE/tools/probe00bb.py"
  say "     (read-only; confirms identity, backs up the old cert-store)"
  say "  2. sudo python3 $HERE/tools/flash00bb.py --phase preflight"
  say "     (read-only; caches the pinned HP firmware before anything is wiped)"
  say "  3. sudo python3 $HERE/tools/flash00bb.py --phase all"
  say "     (DESTRUCTIVE: destroys the Windows Hello pairing on the sensor)"
  say "  4. sudo pam-auth-update --enable fprintd"
  say "     (lets the login screen and sudo actually offer a finger)"
  say "  5. fprintd-enroll -f right-index-finger \"\$USER\""
  say "  6. lock the screen and log in with your finger; then test 'sudo -k; sudo true'"
}

do_uninstall() {
  need_root "$@"
  say "Removing the patched python-validity driver files"
  systemctl disable --now python3-validity.service 2>/dev/null || true
  systemctl stop python3-validity.service 2>/dev/null || true

  rm -f "$UNIT" "$UDEV_RULE" "$DBUS_CONF"
  rm -rf /usr/lib/python-validity /usr/share/python-validity
  rm -rf "$SITE_PACKAGES/validitysensor" "$SITE_PACKAGES"/python_validity-*.egg-info
  rm -rf "$SITE_PACKAGES"/python_validity-*.egg
  if [ -f "$SITE_PACKAGES/easy-install.pth" ]; then
    sed -i '/python_validity-.*\.egg/d' "$SITE_PACKAGES/easy-install.pth"
  fi
  rm -f /usr/bin/validity-led-dance /usr/bin/validity-sensors-firmware

  systemctl daemon-reload
  udevadm control --reload-rules

  ok "driver files removed"
  say ""
  say "Kept on purpose:"
  say "  $CONFIG_DIR   (D-Bus service config)"
  say "  $STATE_DIR    (calibration data, cached xpfwext)"
  say ""
  say "To restore stock fprintd afterwards:"
  say "  sudo apt install fprintd libpam-fprintd"
  say ""
  say "The sensor itself stays paired to this machine; re-pairing it with"
  say "Windows Hello would break the Linux pairing again."
}

case "$MODE" in
  check) do_check ;;
  install) do_install "$@" ;;
  uninstall) do_uninstall "$@" ;;
esac
