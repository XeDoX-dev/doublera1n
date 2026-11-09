#!/usr/bin/env bash
# Rebuild the device binaries of payload/ from these sources (needs Xcode + ldid).
#   src/build.sh            -> payload/boot, payload/setup, payload/device
#   src/build.sh <outdir>   -> the same files into <outdir>/{boot,setup,device} (to compare before replacing)
# Not built here: src/pl27 (own build.sh, needs Swift), the small diagnostics (kcq, kcacl, dnsq, lsq, mkbstate,
# sysapps, stackdump), and launchctl (src/launchctl/build.sh).
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
J="$SRC/jbinit"
if [ $# -gt 0 ]; then BOOT="$1/boot"; SETUP="$1/setup"; DEV="$1/device"
else BOOT="$SRC/../payload/boot"; SETUP="$SRC/../payload/setup"; DEV="$SRC/../payload/device"; fi
mkdir -p "$BOOT" "$SETUP" "$DEV"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
CF=(-target arm64-apple-ios17.0 -isysroot "$SDK" -O2 -Wall)
cc() { xcrun clang "$@"; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
# fat <out> <cmd...>: run cmd once per arch with ARCH set, then lipo the per-arch outputs ($TMP/<name>_<arch>)
fat() {
  local out=$1; shift; local name; name=$(basename "$out")
  for ARCH in arm64 arm64e; do "$@" "$ARCH" "$TMP/${name}_$ARCH"; done
  lipo -create "$TMP/${name}_arm64" "$TMP/${name}_arm64e" -output "$out"
}
OB=/private/preboot/Cryptexes/ob   # Preboot dir readable by sandboxed daemons (coreauthd, launchd children)

# ---------------------------------------------------------------- boot ramdisk (payload/boot)
# jbinit: static PID 1 posing as /usr/lib/dyld of the ramdisk's launchd stub
cc "${CF[@]}" -nostdlib -ffreestanding -fno-stack-protector -fno-builtin -static \
   -Wl,-dylinker -Wl,-dylinker_install_name,/usr/lib/dyld -e __dyld_start \
   "$J/start.S" "$J/main.c" -o "$BOOT/dyld"
ldid -S "$BOOT/dyld"
# 2nd iOS (developing feature): same jbinit, but it mounts OS2System (named by the ramdisk's /jbin/os2-system)
# instead of the stock System volume. Built as "dyld" so its code-signing identifier matches the 2nd Data one.
mkdir -p "$TMP/os2"
cc "${CF[@]}" -DOS2 -nostdlib -ffreestanding -fno-stack-protector -fno-builtin -static \
   -Wl,-dylinker -Wl,-dylinker_install_name,/usr/lib/dyld -e __dyld_start \
   "$J/start.S" "$J/main.c" -o "$TMP/os2/dyld"
ldid -S "$TMP/os2/dyld"; cp "$TMP/os2/dyld" "$BOOT/dyld-os2"
# PID 1's entitlements come from the main image (the stub), so it carries launchd's set
cc "${CF[@]}" "$J/stub.c" -o "$BOOT/launchd"
ldid -S"$J/launchd.ents.plist" "$BOOT/launchd"
cc "${CF[@]}" "$J/jbloader.c" -larchive -o "$BOOT/jbloader"
ldid -S"$J/jbloader.ents.plist" "$BOOT/jbloader"
cc -target arm64e-apple-ios17.0 -isysroot "$SDK" -O2 -Wall -dynamiclib -fobjc-arc \
   "$J/hacthook.m" -framework Foundation -o "$BOOT/hacthook.dylib"
ldid -S "$BOOT/hacthook.dylib"
for t in bpexec lsimg hactpoke; do
  cc "${CF[@]}" "$J/$t.c" -o "$BOOT/$t"; ldid -S"$J/jbloader.ents.plist" "$BOOT/$t"
done
cc "${CF[@]}" -fobjc-arc -framework Foundation "$J/maactivate.m" -o "$BOOT/maactivate"
ldid -S"$J/maactivate.ents.plist" "$BOOT/maactivate"
# obhook: launchd hook (launchd loads /cores/obhook.dylib; children get the Preboot copy)
H="$SRC/obhook"
obhook() { cc -arch "$1" -miphoneos-version-min=15.0 -isysroot "$SDK" -dynamiclib -O2 -Wall \
  "-DOBHOOK_SELF_PATH=\"$OB/obhook.dylib\"" "-DOBHOOK_PAYLOAD_A=\"$OB/systemhook.dylib\"" \
  -Wl,-not_for_dyld_shared_cache -install_name "$OB/obhook.dylib" -o "$2" "$H/obhook.c"; }
fat "$BOOT/obhook.dylib" obhook; ldid -S "$BOOT/obhook.dylib"

# ---------------------------------------------------------------- setup ramdisk (payload/setup)
# it runs as restored_external: the platform policy only lets it open /dev/disk* (APFSVolumeDelete in remove mode
# loads the container from /dev/disk1) with disk-device-access, like the stock restored_external and newfs_apfs
cc "${CF[@]}" "$SRC/rdsetup.c" "$SRC/rdsetup_usb.c" -framework CoreFoundation -framework IOKit -o "$SETUP/rdsetup"
ldid -S"$SRC/rdsetup.ents.plist" "$SETUP/rdsetup"
# 2nd iOS volumes (developing feature): run on 2nd Data over SSH; newfs_apfs + APFSVolumeDelete need the same
# disk-device-access entitlement as rdsetup
cc "${CF[@]}" "$SRC/os2vol.c" -framework CoreFoundation -framework IOKit -o "$DEV/os2vol"
ldid -S"$SRC/os2vol.ents.plist" "$DEV/os2vol"

# ---------------------------------------------------------------- DataB / Preboot (payload/device)
systemhook() { cc -arch "$1" -miphoneos-version-min=15.0 -isysroot "$SDK" -dynamiclib -O2 -Wall \
  -Wl,-not_for_dyld_shared_cache -install_name "$OB/systemhook.dylib" -o "$2" "$H/systemhook_icon.c"; }
fat "$DEV/systemhook.dylib" systemhook; ldid -S "$DEV/systemhook.dylib"
for t in sbextissue obhookctl; do
  tool() { cc -arch "$1" -miphoneos-version-min=15.0 -isysroot "$SDK" -O2 -Wall -o "$2" "$H/$t.c"; }
  fat "$DEV/$t" tool; ldid -S "$DEV/$t"
done
# securityd: software keychain class keys + ACL guard
K="$SRC/obkeychain"
obkeychain() { cc -isysroot "$SDK" -arch "$1" -miphoneos-version-min=15.0 -O2 -Wall -Wextra -dynamiclib \
  -Wl,-not_for_dyld_shared_cache -install_name /private/var/Keychains/obkeychain.dylib \
  '-DOBKEYCHAIN_MARKER_SYSTEM="/private/var/Keychains/.obkeychain"' "$K/AppleKeyStore.tbd" \
  -framework Foundation -framework Security -fobjc-arc -o "$2" "$K/obkeychain.m" "$K/obacl.m"; }
fat "$DEV/obkeychain.dylib" obkeychain; ldid -S -Icom.dualboot.obkeychain "$DEV/obkeychain.dylib"
# lockdownd: pairing-key fallback; coreauthd: ratchet-state guard (arm64e daemons only)
cc -arch arm64e -miphoneos-version-min=15.0 -isysroot "$SDK" -O2 -Wall -dynamiclib -Wl,-not_for_dyld_shared_cache \
   -install_name /private/var/root/Library/Lockdown/obpair.dylib -framework CoreFoundation -framework Foundation \
   -framework Security -o "$DEV/obpair.dylib" "$SRC/obpair/obpair.c" "$SRC/obpair/obpair_auth.m"
ldid -S "$DEV/obpair.dylib"
cc -arch arm64e -miphoneos-version-min=15.0 -isysroot "$SDK" -O2 -Wall -dynamiclib -Wl,-not_for_dyld_shared_cache \
   -install_name "$OB/ca.dylib" -framework Foundation -o "$DEV/obcoreauth.dylib" "$SRC/obcoreauth/obcoreauth.m"
ldid -S "$DEV/obcoreauth.dylib"
# CommCenter: FDR demotion-state answers (own build.sh, writes next to its sources)
"$SRC/obfdr/build.sh" >/dev/null
mv -f "$SRC/obfdr/obfdr.dylib" "$DEV/obfdr.dylib"; rm -f "$SRC/obfdr/obradio"
# RemoteUI WebKit assert -> no-op (ElleKit tweak, UIKit processes)
cc -isysroot "$SDK" -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -O2 -Wall -dynamiclib -lobjc \
   -install_name /var/jb/Library/MobileSubstrate/DynamicLibraries/obremoteui.dylib \
   -o "$DEV/obremoteui.dylib" "$SRC/obremoteui/obremoteui.m"
ldid -S "$DEV/obremoteui.dylib"; cp "$SRC/obremoteui/obremoteui.plist" "$DEV/obremoteui.plist"
# PosterBoard repair watcher, persona 99 for Sileo's root helper
(cd "$SRC/pfwatch" && cc -isysroot "$SDK" -arch arm64 -arch arm64e -miphoneos-version-min=26.0 -O2 -Wall \
   -framework Foundation pfwatch.m -o "$DEV/pfwatch")
ldid -S"$SRC/pfwatch/pfwatch.ent" -Cadhoc "$DEV/pfwatch"
cc -isysroot "$SDK" -arch arm64 -miphoneos-version-min=15.0 -O2 -Wall "$SRC/personaalloc/personaalloc.c" -o "$DEV/personaalloc"
ldid -Icom.apple.personaalloc -S"$SRC/personaalloc/personaalloc.ents.plist" -Cadhoc "$DEV/personaalloc"

echo "built into $BOOT, $SETUP, $DEV"
