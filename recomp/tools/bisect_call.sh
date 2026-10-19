#!/bin/sh
# Find the last call of FUNC that happens before build/war stops abnormally,
# dump its entry state and checkpoint-diff it (Unicorn vs lifted).
#   tools/bisect_call.sh 318a0
# Needs a RECOMP_TRACE build (make war GAME_DEFS=-DRECOMP_TRACE) and build/libgame.dylib.
set -u
FUNC=$1
run() { SDL_VIDEODRIVER=dummy WAR_DUMP_AT=$FUNC WAR_DUMP_SKIP=$1 ./build/war 2>&1 | grep -c "dumped entry state"; }
lo=0; hi=1
while [ "$(run $hi)" = "1" ]; do lo=$hi; hi=$((hi * 2)); done
if [ "$lo" = "0" ] && [ "$(run 0)" = "0" ]; then echo "$FUNC is never reached before the stop"; exit 1; fi
while [ $((hi - lo)) -gt 1 ]; do
  mid=$(((lo + hi) / 2))
  if [ "$(run $mid)" = "1" ]; then lo=$mid; else hi=$mid; fi
done
echo "last call of $FUNC before the stop: #$lo"
run $lo > /dev/null
python3 tools/ckdiff.py build/dump_$FUNC.bin
