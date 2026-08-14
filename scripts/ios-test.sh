#!/usr/bin/env bash
# Run the iOS test suite on the simulator, recovering from CoreSimulator
# flakes (Mach -308 "server died", invalid device state) that otherwise make
# the run fail before a single test executes. Regenerates the Xcode project
# first so a stale Generated/Info.plist can never be tested against.
set -uo pipefail
cd "$(dirname "$0")/../ios/App"

DEST="${IOS_TEST_DEST:-platform=iOS Simulator,name=iPhone 17 Pro Max}"
LOG="$(mktemp -t evanproxy-ios-test)"
trap 'rm -f "$LOG"' EXIT

xcodegen generate -q || exit 1

for attempt in 1 2 3; do
  xcodebuild -project EvanProxyApp.xcodeproj -scheme EvanProxyApp \
    -destination "$DEST" test >"$LOG" 2>&1
  status=$?
  if [ "$status" -eq 0 ]; then
    grep -E "Executed [0-9]+ tests" "$LOG" | tail -2
    echo "iOS tests passed (attempt $attempt)"
    exit 0
  fi
  if grep -qE "Mach error -308|server died|Invalid device state|Unable to boot|Failed to launch" "$LOG"; then
    echo "CoreSimulator flake on attempt $attempt — resetting simulators and retrying" >&2
    xcrun simctl shutdown all >/dev/null 2>&1
    sleep 3
    continue
  fi
  tail -80 "$LOG"
  exit "$status"
done

tail -40 "$LOG"
echo "iOS tests still failing after simulator resets" >&2
exit 1
