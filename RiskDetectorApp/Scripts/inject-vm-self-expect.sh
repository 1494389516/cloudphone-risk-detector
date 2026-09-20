#!/bin/bash
set -euo pipefail

tool_root="${SRCROOT}/../cprisk-armor"
executable="${TARGET_BUILD_DIR}/${EXECUTABLE_PATH}"
stamp_path="${SCRIPT_OUTPUT_FILE_1}"
seed_file="${DERIVED_FILE_DIR}/cprisk_armor_build_seed"

write_stamp() {
  mkdir -p "$(dirname "$stamp_path")"
  /bin/date -u +"%Y-%m-%dT%H:%M:%SZ" > "$stamp_path"
}

if [[ "${CONFIGURATION:-}" != "Release" ]]; then
  echo "note: VM self-expect skipped for ${CONFIGURATION:-unknown} build"
  write_stamp
  exit 0
fi

armor_requested=0
if [[ -n "${CPRISK_ARMOR_KEY:-}" ||
      -n "${CPRISK_ARMOR_ARGS:-}" ||
      -n "${CPRISK_ARMOR_PROFILE:-}" ||
      "${CPRISK_ARMOR_REQUIRED:-0}" == "1" ]]; then
  armor_requested=1
fi
if [[ "$armor_requested" == "0" ]]; then
  echo "note: VM self-expect skipped because armor was not requested"
  write_stamp
  exit 0
fi

vmp_enabled=1
if [[ "${CPRISK_ARMOR_PROFILE:-standard}" == "appstore-safe" ]]; then
  vmp_enabled=0
fi
if [[ -n "${CPRISK_ARMOR_ARGS:-}" ]]; then
  vmp_enabled=0
  read -r -a custom_args <<< "$CPRISK_ARMOR_ARGS"
  for argument in "${custom_args[@]}"; do
    if [[ "$argument" == "--all" || "$argument" == "--pass13" ]]; then
      vmp_enabled=1
      break
    fi
  done
fi
if [[ "$vmp_enabled" == "0" ]]; then
  echo "note: VM self-expect skipped because Pass 13 is disabled"
  write_stamp
  exit 0
fi

if [[ ! -d "$tool_root" || ! -f "$executable" ]]; then
  echo "error: VM self-expect required but toolroot or executable is missing" >&2
  exit 1
fi
if [[ ! "${CPRISK_ARMOR_KEY:-}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  echo "error: VM self-expect requires a 64-hex-character CPRISK_ARMOR_KEY" >&2
  exit 1
fi
if [[ ! -f "$seed_file" ]]; then
  echo "error: armor build seed handoff is missing at $seed_file" >&2
  exit 1
fi

build_seed="$(/usr/bin/tr -d '[:space:]' < "$seed_file")"
if [[ ! "$build_seed" =~ ^([0-9]+|0[xX][0-9A-Fa-f]+)$ ]]; then
  echo "error: invalid armor build seed handoff" >&2
  exit 1
fi
export CPRISK_ARMOR_BUILD_SEED="$build_seed"

unset SDKROOT
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
(cd "$tool_root" && swift build --disable-sandbox -c release --product cprisk-vm-self-expect >/dev/null)
bin_dir="$(cd "$tool_root" && swift build --disable-sandbox -c release --show-bin-path)"
tool="${bin_dir}/cprisk-vm-self-expect"
if [[ ! -x "$tool" ]]; then
  echo "error: cprisk-vm-self-expect tool not found at $tool" >&2
  exit 1
fi

"$tool" \
  --in "$executable" \
  --hmac

/usr/bin/stat -f "%m %z" "$executable" > "$stamp_path"
