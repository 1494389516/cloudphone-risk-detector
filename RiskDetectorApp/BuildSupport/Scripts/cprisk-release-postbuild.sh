#!/bin/sh
set -eu

is_truthy() {
  case "${1:-}" in
    1|YES|yes|TRUE|true|ON|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

note() {
  printf 'note: %s\n' "$*"
}

warn() {
  printf 'warning: %s\n' "$*"
}

if [ "${CONFIGURATION:-}" != "Release" ]; then
  exit 0
fi

app_binary_path="${BUILT_PRODUCTS_DIR:-}/${EXECUTABLE_PATH:-}"
if [ -z "${BUILT_PRODUCTS_DIR:-}" ] || [ -z "${EXECUTABLE_PATH:-}" ] || [ ! -f "${app_binary_path}" ]; then
  warn "App binary not found at ${app_binary_path:-<unset>}, skipping protected Release post-build steps"
  exit 0
fi

if is_truthy "${CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE:-}"; then
  note "CPRISK: Swift metadata convergence was requested for this Release build"
fi

if [ -z "${CPRISK_ARMOR_KEY:-}" ]; then
  warn "CPRISK_ARMOR_KEY not set, skipping cprisk-armor (Release build keeps strip + optional compiler-level convergence only)"
else
  armor_cli="${PROJECT_DIR}/../cprisk-armor/.build/release/cprisk-armor"
  if [ ! -f "${armor_cli}" ]; then
    warn "cprisk-armor not built at ${armor_cli}, run: cd cprisk-armor && swift build -c release"
  else
    note "Running cprisk-armor on app binary: ${app_binary_path}"
    "${armor_cli}" --input "${app_binary_path}" --output "${app_binary_path}" --all --key "${CPRISK_ARMOR_KEY}"
  fi
fi

note "Stripping symbols from app binary..."
xcrun strip -x "${app_binary_path}" 2>/dev/null || true
xcrun strip "${app_binary_path}" 2>/dev/null || true
note "Release post-build protection complete."
