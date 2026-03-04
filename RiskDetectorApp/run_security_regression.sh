#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "[security-regression] Running SDK 3.4 hardening tests..."

run_swift_test_with_fallback() {
    local cmd="$1"
    local output
    local status

    set +e
    output=$(eval "$cmd" 2>&1)
    status=$?
    set -e
    echo "$output"

    if [ $status -ne 0 ] && [[ "$output" == *"sandbox-exec: sandbox_apply: Operation not permitted"* ]]; then
        local fallback_cmd="$cmd --disable-sandbox"
        echo ""
        echo "[security-regression] sandbox 限制，自动重试: $fallback_cmd"
        echo ""

        set +e
        output=$(eval "$fallback_cmd" 2>&1)
        status=$?
        set -e
        echo "$output"
    fi

    return $status
}

run_swift_test_with_fallback "swift test --filter ReportEnvelopeSecurityTests"
run_swift_test_with_fallback "swift test --filter CapabilityProbeEngineRoadmapTests"
run_swift_test_with_fallback "swift test --filter ChallengeTriggerRoadmapTests"
run_swift_test_with_fallback "swift test --filter SecureUploadWiringTests"

echo "[security-regression] All security regression tests passed."
