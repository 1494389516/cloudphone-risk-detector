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

resolve_system_clang() {
  xcrun --find clang
}

compiler="$(resolve_system_clang)"

if [ "${CONFIGURATION:-}" = "Release" ] && is_truthy "${CPRISK_ENABLE_HIKARI:-}"; then
  if [ -n "${HIKARI_CLANG:-}" ]; then
    if resolved_hikari_clang="$(resolve_tool_candidate "${HIKARI_CLANG}")"; then
      compiler="${resolved_hikari_clang}"
      emit_once "note" "cprisk_hikari_clang_enabled" \
        "CPRISK: using Hikari Clang wrapper at ${compiler}"
    else
      emit_once "warning" "cprisk_hikari_clang_missing" \
        "CPRISK_ENABLE_HIKARI=1 but HIKARI_CLANG is not executable (${HIKARI_CLANG}); CRiskCore falls back to host clang"
    fi
  else
    emit_once "warning" "cprisk_hikari_clang_unset" \
      "CPRISK_ENABLE_HIKARI=1 but HIKARI_CLANG is not set; CRiskCore falls back to host clang"
  fi
fi

exec "${compiler}" "$@"
