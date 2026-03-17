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

marker_root() {
  if [ -n "${TARGET_TEMP_DIR:-}" ]; then
    printf '%s\n' "${TARGET_TEMP_DIR}"
    return 0
  fi
  if [ -n "${DERIVED_FILE_DIR:-}" ]; then
    printf '%s\n' "${DERIVED_FILE_DIR}"
    return 0
  fi
  printf '%s\n' "/tmp"
}

emit_once() {
  level="$1"
  key="$2"
  shift 2
  message="$*"
  root="$(marker_root)"
  marker="${root}/.${key}"
  mkdir -p "${root}" 2>/dev/null || true
  if [ -f "${marker}" ]; then
    return 0
  fi
  : > "${marker}" 2>/dev/null || true
  printf '%s: %s\n' "${level}" "${message}"
}

resolve_tool_candidate() {
  candidate="$1"
  if [ -z "${candidate}" ]; then
    return 1
  fi
  if [ -x "${candidate}" ]; then
    printf '%s\n' "${candidate}"
    return 0
  fi
  if command -v "${candidate}" >/dev/null 2>&1; then
    command -v "${candidate}"
    return 0
  fi
  return 1
}

resolve_system_swiftc() {
  if [ -n "${TOOLCHAIN_DIR:-}" ] && [ -x "${TOOLCHAIN_DIR}/usr/bin/swiftc" ]; then
    printf '%s\n' "${TOOLCHAIN_DIR}/usr/bin/swiftc"
    return 0
  fi
  xcrun --find swiftc
}

compiler="$(resolve_system_swiftc)"

if [ "${CONFIGURATION:-}" = "Release" ] && is_truthy "${CPRISK_ENABLE_HIKARI:-}"; then
  if [ -n "${HIKARI_SWIFTC:-}" ]; then
    if resolved_hikari_swiftc="$(resolve_tool_candidate "${HIKARI_SWIFTC}")"; then
      compiler="${resolved_hikari_swiftc}"
      emit_once "note" "cprisk_hikari_swiftc_enabled" \
        "CPRISK: using Hikari Swift compiler wrapper at ${compiler}"
    else
      emit_once "warning" "cprisk_hikari_swiftc_missing" \
        "CPRISK_ENABLE_HIKARI=1 but HIKARI_SWIFTC is not executable (${HIKARI_SWIFTC}); falling back to host swiftc"
    fi
  else
    emit_once "warning" "cprisk_hikari_swiftc_unset" \
      "CPRISK_ENABLE_HIKARI=1 but HIKARI_SWIFTC is not set; Swift targets fall back to host swiftc"
  fi
fi

if [ "${CONFIGURATION:-}" = "Release" ] && is_truthy "${CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE:-}"; then
  set -- "$@" \
    -Xfrontend -disable-reflection-metadata \
    -Xfrontend -disable-reflection-names
  emit_once "note" "cprisk_swift_metadata_convergence" \
    "CPRISK: enabled Swift Release metadata convergence flags (-disable-reflection-metadata -disable-reflection-names)"
fi

exec "${compiler}" "$@"
