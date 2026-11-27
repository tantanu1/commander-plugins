#!/usr/bin/env bash
# Release packaging of the plugins repo (.github/workflows/release.yml). Source of truth:
# packaging/plugins-repo/package.sh in the Commander repo (tools/export_plugins.sh copies it).
# From the repo root, after `cargo build --release --locked --target <target>`:
#   bash scripts/package.sh <target> <version> <out dir>
# Writes to <out dir>:
#   <id>-<plugin version>-<target>.zip      ONE plugin: <id>/{plugin.toml, library, README.md};
#                                           a plugin using another's library also gets that
#                                           plugin's folder (ftps -> ftp/), so it installs alone
#   commander-plugins-<version>-<target>.zip  every plugin
# each with INSTALL-PLUGINS.md, LICENSE.txt (MIT) + THIRD-PARTY-NOTICES.txt at the root. This
# is the layout Commander's zip install (drop on a panel, Options > Plugins, registry) and a
# plain unzip into the user plugin folder expect: one `<id>/plugin.toml` folder per plugin.
set -euo pipefail
t=${1:?usage: package.sh <target> <version> <out dir>} v=${2:?version} out=${3:?out dir}
PLUGINS="s3 ftp ftps sftp smb sevenzip vmware" # folders under plugins/ (abi: shared crate)
libs=${CARGO_TARGET_DIR:-target}/$t/release
case $t in *windows*) os=windows ;; *apple*) os=macos ;; *) os=linux ;; esac
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# `key = "value"` (first match) of a toml file.
key() { sed -n "s/^$1 = \"\(.*\)\"/\1/p" "$2" | head -1; }

# Source folder of plugin id $1 (vmware-vms-disk -> vmware).
src_of() {
  local s
  for s in $PLUGINS; do
    if [ "$(key id "plugins/$s/plugin.toml")" = "$1" ]; then echo "$s"; return; fi
  done
  echo "no plugin with id $1" >&2
  return 1
}

# stage <src folder> <dir>: <dir>/<id>/{plugin.toml, README.md, library}.
stage() {
  local m=plugins/$1/plugin.toml id lib owner src
  id=$(key id "$m")
  lib=$(key "$os" "$m")
  [ -n "$lib" ] || { echo "$m: no $os library" >&2; return 1; }
  mkdir -p "$2/$id"
  cp "$m" "$2/$id/"
  cp "docs/plugins/$id.md" "$2/$id/README.md"
  case $lib in
    ../*/*) # library of another plugin (ftps: ../ftp/<lib>): ship that plugin too
      owner=${lib#../}
      owner=${owner%%/*}
      src=$(src_of "$owner") || return 1
      stage "$src" "$2" ;;
    */*) echo "$m: unsupported library path $lib" >&2; return 1 ;;
    *) cp "$libs/$lib" "$2/$id/" ;;
  esac
}

# pack <dir> <zip>: guide + license files, then zip the contents of <dir> ('/'-separated relative names).
pack() {
  cp LICENSE "$1/LICENSE.txt"
  cp THIRD-PARTY-NOTICES.txt "$1/"
  cp docs/INSTALL-PLUGINS.md "$1/"
  rm -f "$2"
  if command -v zip >/dev/null; then
    (cd "$1" && zip -qrX "$2" .)
  elif command -v 7z >/dev/null; then
    (cd "$1" && 7z a -tzip "$2" . >/dev/null)
  else
    local py
    for py in python3 python; do "$py" -c '' 2>/dev/null && break; done
    (cd "$1" && "$py" -m zipfile -c "$2" ./*)
  fi
  echo "$(basename "$2")"
}

for s in $PLUGINS; do
  m=plugins/$s/plugin.toml
  id=$(key id "$m")
  stage "$s" "$work/$id"
  pack "$work/$id" "$out/$id-$(key version "$m")-$t.zip"
done
all=$work/.bundle # never a plugin id (ids never start with '.')
for s in $PLUGINS; do stage "$s" "$all"; done
pack "$all" "$out/commander-plugins-$v-$t.zip"
