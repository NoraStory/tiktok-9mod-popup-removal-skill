#!/bin/bash
# popup watcher: log window focus, snapshot UI when a dialog-ish window appears
# Usage: popup_watch.sh <device_serial> [output_dir]
#   device_serial: adb device serial (e.g. 192.168.1.104:34899)
#   output_dir: where to save logs/snapshots (default: ./snaps)
D="${1:?usage: $0 <device_serial> [output_dir]}"
OUT="${2:-./snaps}"
mkdir -p "$OUT"
i=0
while [ $i -lt 240 ]; do
  i=$((i+1))
  F=$(adb -s "$D" shell dumpsys window 2>/dev/null | grep -m1 mCurrentFocus | sed 's/.*u0 //;s/ type=.*//')
  TS=$(date +%H%M%S)
  echo "$TS  $F" >> "$OUT/focus.log"
  case "$F" in
    *Dialog*|*Popup*|*Sheet*|*Alert*|*crash*|*Crash*|*acra*)
      adb -s "$D" shell uiautomator dump /sdcard/snap.xml >/dev/null 2>&1
      adb -s "$D" pull /sdcard/snap.xml "$OUT/$TS.xml" >/dev/null 2>&1
      echo "  >>> SNAPPED $TS  focus=$F" ;;
  esac
  sleep 1.5
done
echo "watcher done"
