#!/bin/bash
set -euo pipefail

# Apply cprisk-armor to the Release executable.
#
# DEFAULT BEHAVIOR — READ BEFORE SHIPPING: when armor is NOT requested
# (no CPRISK_ARMOR_KEY / CPRISK_ARMOR_ARGS / CPRISK_ARMOR_PROFILE /
# CPRISK_ARMOR_REQUIRED), this script exits 0 with a warning and the Release
# binary ships UNHARDENED. Armor is opt-in, not default. To require armor,
# set CPRISK_ARMOR_REQUIRED=1 (plus CPRISK_ARMOR_KEY); any requested-but-
# skipped case below is a HARD FAILURE, never a silent skip.
#
# Pass 13 (VMProtector) is disabled in the CLI: any run that enables it
# (including --all) hard-fails. This script therefore NEVER passes --all;
# the standard profile passes an explicit pass list that excludes Pass 13,
# and CPRISK_ARMOR_ARGS containing --all / --pass13 is rejected outright.
#
# Tool build: the armor tool is NOT rebuilt on every Release build. Set
# CPRISK_ARMOR_PREBUILT_TOOL to an existing executable to use it directly;
# otherwise a cached `swift build` output is reused when no source file is
# newer than the cached tool, and rebuilt only when sources changed.

tool_root="${SRCROOT}/../cprisk-armor"
executable="${TARGET_BUILD_DIR}/${EXECUTABLE_PATH}"
stamp_path="${SCRIPT_OUTPUT_FILE_1}"
seed_file="${DERIVED_FILE_DIR}/cprisk_armor_build_seed"

write_stamp() {
  mkdir -p "$(dirname "$stamp_path")"
  /bin/date -u +"%Y-%m-%dT%H:%M:%SZ" > "$stamp_path"
  # Xcode declares the seed handoff as an output/input edge between phases.
  # Optional skips still materialize an empty marker so dependency analysis
  # does not fail before the self-expect script can make its own skip decision.
  : > "$seed_file"
}

armor_requested=0
if [[ -n "${CPRISK_ARMOR_KEY:-}" ||
      -n "${CPRISK_ARMOR_ARGS:-}" ||
      -n "${CPRISK_ARMOR_PROFILE:-}" ||
      "${CPRISK_ARMOR_REQUIRED:-0}" == "1" ]]; then
  armor_requested=1
fi

if [[ "${CONFIGURATION:-}" != "Release" ]]; then
  # Explicitly requested armor must never be silently skipped, even in
  # non-Release builds: fail so the misconfiguration is visible.
  if [[ "$armor_requested" == "1" ]]; then
    echo "error: cprisk-armor was explicitly requested but CONFIGURATION=${CONFIGURATION:-unknown} is not Release; refusing to silently skip requested armor" >&2
    exit 1
  fi
  echo "note: cprisk-armor skipped for ${CONFIGURATION:-unknown} build"
  write_stamp
  exit 0
fi

if [[ ! -d "$tool_root" || ! -f "$executable" ]]; then
  if [[ "$armor_requested" == "1" ]]; then
    echo "error: cprisk-armor requested but toolroot or executable is missing" >&2
    exit 1
  fi
  echo "warning: cprisk-armor skipped: toolroot or executable is missing; shipping UNHARDENED Release binary (armor is opt-in — set CPRISK_ARMOR_REQUIRED=1 to require it)" >&2
  write_stamp
  exit 0
fi

if [[ -z "${CPRISK_ARMOR_KEY:-}" ]]; then
  if [[ "$armor_requested" == "1" ]]; then
    echo "error: cprisk-armor requested but CPRISK_ARMOR_KEY is not set" >&2
    exit 1
  fi
  echo "warning: cprisk-armor skipped: CPRISK_ARMOR_KEY is not set; shipping UNHARDENED Release binary (armor is opt-in — set CPRISK_ARMOR_REQUIRED=1 to require it)" >&2
  write_stamp
  exit 0
fi

if [[ ! "$CPRISK_ARMOR_KEY" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  echo "error: CPRISK_ARMOR_KEY must contain exactly 64 hexadecimal characters" >&2
  exit 1
fi

case "${CPRISK_ARMOR_PROFILE:-standard}" in
  standard|appstore-safe) ;;
  *)
    echo "error: unsupported CPRISK_ARMOR_PROFILE '${CPRISK_ARMOR_PROFILE}'" >&2
    exit 1
    ;;
esac

build_seed="${CPRISK_ARMOR_BUILD_SEED:-${CPRISK_BUILD_SEED:-}}"
if [[ -z "$build_seed" ]]; then
  build_seed="$(/usr/bin/od -An -N8 -tu8 /dev/urandom | /usr/bin/tr -d '[:space:]')"
  [[ "$build_seed" != "0" ]] || build_seed="1"
fi
if [[ ! "$build_seed" =~ ^([0-9]+|0[xX][0-9A-Fa-f]+)$ ]]; then
  echo "error: armor build seed must be decimal or 0x-prefixed hexadecimal" >&2
  exit 1
fi

mkdir -p "$(dirname "$seed_file")"
printf '%s\n' "$build_seed" > "$seed_file"
export CPRISK_ARMOR_BUILD_SEED="$build_seed"

unset SDKROOT
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
if [[ -n "${CPRISK_ARMOR_PREBUILT_TOOL:-}" ]]; then
  # Explicit prebuilt tool: use it verbatim, never rebuild.
  tool="${CPRISK_ARMOR_PREBUILT_TOOL}"
  if [[ ! -x "$tool" ]]; then
    echo "error: CPRISK_ARMOR_PREBUILT_TOOL is set but not executable: $tool" >&2
    exit 1
  fi
  echo "note: using prebuilt cprisk-armor tool at $tool (no rebuild)"
else
  bin_dir="$(cd "$tool_root" && swift build --disable-sandbox -c release --show-bin-path)"
  tool="${bin_dir}/cprisk-armor"
  # Reuse the cached tool when no armor source is newer than it; rebuild
  # only when sources changed. `swift build --show-bin-path` above only
  # resolves the path and does not compile.
  needs_rebuild=1
  if [[ -x "$tool" ]]; then
    needs_rebuild=0
    if [[ -n "$(find "$tool_root/Sources" "$tool_root/Package.swift" -type f -newer "$tool" -print -quit 2>/dev/null)" ]]; then
      needs_rebuild=1
    fi
  fi
  if [[ "$needs_rebuild" == "1" ]]; then
    echo "note: building cprisk-armor tool (sources changed or no cached tool)"
    (cd "$tool_root" && swift build --disable-sandbox -c release --product cprisk-armor >/dev/null)
  else
    echo "note: reusing cached cprisk-armor tool at $tool (sources unchanged)"
  fi
fi
if [[ ! -x "$tool" ]]; then
  echo "error: cprisk-armor tool not found at $tool" >&2
  exit 1
fi

# NEVER pass --all: --all includes Pass 13, which the CLI hard-fails.
# Standard = every pass except Pass 13, listed explicitly.
armor_args=(--pass1 --pass2 --pass3 --pass4 --pass5 --pass6 --pass7 --pass8 --pass9 --pass10 --pass11 --pass12)
if [[ "${CPRISK_ARMOR_PROFILE:-standard}" == "appstore-safe" ]]; then
  armor_args=(
    --pass3 --pass4 --pass5 --pass6 --pass7 --pass10 --pass11
    --safety-profile appstore-safe
  )
fi
if [[ -n "${CPRISK_ARMOR_ARGS:-}" ]]; then
  # Custom arguments are intentionally tokenized without eval. Paths containing
  # spaces should be passed via the default policy locations instead.
  read -r -a armor_args <<< "$CPRISK_ARMOR_ARGS"
  for armor_arg in "${armor_args[@]}"; do
    case "$armor_arg" in
      --input|--output|--key|--key-file|--build-seed|--input=*|--output=*|--key=*|--key-file=*|--build-seed=*)
        echo "error: CPRISK_ARMOR_ARGS cannot override pipeline-owned paths, keys or build seed" >&2
        exit 1
        ;;
      --all|--pass13)
        echo "error: CPRISK_ARMOR_ARGS must not contain '$armor_arg': Pass 13 is disabled and the CLI hard-fails any run that enables it (including --all). Select passes explicitly without --pass13." >&2
        exit 1
        ;;
    esac
  done
fi
if [[ "${CPRISK_ARMOR_VERBOSE:-0}" == "1" ]]; then
  armor_args+=(--verbose)
fi

echo "note: running cprisk-armor (${armor_args[*]}) on $executable"
"$tool" \
  --input "$executable" \
  --output "$executable" \
  --build-seed "$build_seed" \
  "${armor_args[@]}"

/usr/bin/stat -f "%m %z" "$executable" > "$stamp_path"
