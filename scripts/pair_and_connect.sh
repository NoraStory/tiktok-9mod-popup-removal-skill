#!/bin/bash
# adb wireless pairing + connect helper (retries to beat the 30s pairing window)
# usage: pair_and_connect.sh <ip:pair_port> <code> [ip:connect_port]
export PATH=/usr/bin:/bin:$PATH
PAIR_EP="$1"; CODE="$2"; CONN_EP="$3"
MAXT="${4:-12}"   # attempts
if [ -z "$PAIR_EP" ] || [ -z "$CODE" ]; then
  echo "usage: $0 <ip:pair_port> <code> [ip:connect_port]"; exit 1
fi
adb start-server >/dev/null 2>&1
i=0
while [ "$i" -lt "$MAXT" ]; do
  i=$((i+1))
  out=$(timeout 12 adb pair "$PAIR_EP" "$CODE" 2>&1)
  echo "[try $i] $out"
  case "$out" in
    *uccess*|*uccessfully*) echo "PAIR_OK"; break ;;
  esac
  sleep 2
done
adb devices -l
if [ -n "$CONN_EP" ]; then
  echo "--- connect $CONN_EP ---"
  timeout 15 adb connect "$CONN_EP" 2>&1
  sleep 1
  adb devices -l
fi
