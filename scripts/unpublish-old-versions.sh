#!/usr/bin/env bash
set -u

DEFAULT_PACKAGE_NAMES="@rodit/rodit-auth-be @rodit/rodit-auth-fe"
PACKAGE_NAMES="${PACKAGE_NAMES:-${PACKAGE_NAME:-$DEFAULT_PACKAGE_NAMES}}"
REGISTRY="${REGISTRY:-https://registry.npmjs.org/}"
MODE="dry-run"
otp=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/unpublish-old-versions.sh [--execute]

Environment:
  PACKAGE_NAMES  Space-separated packages to unpublish old versions from
                 (default: @rodit/rodit-auth-be @rodit/rodit-auth-fe)
  PACKAGE_NAME   Single package override for backwards compatibility
  REGISTRY       npm registry URL (default: https://registry.npmjs.org/)

By default this script only prints what it would unpublish.
Pass --execute to run npm unpublish for every version except the current latest dist-tag.

The script is safe to re-run: each run fetches current registry metadata and only
targets versions that still exist and are not the latest dist-tag. On --execute,
if npm rejects the OTP (EOTP), you are prompted for a fresh code and the same
version is retried before moving on.
USAGE
}

prompt_for_otp() {
  echo
  if [ ! -r /dev/tty ]; then
    echo "Cannot prompt for OTP: /dev/tty is not available." >&2
    exit 1
  fi
  # Read from the controlling terminal, not stdin (the version list uses a heredoc).
  read -rp "npm OTP: " otp </dev/tty
}

needs_new_otp() {
  printf '%s' "$1" | grep -qE 'EOTP|one-time password|child "otp"'
}

unpublish_version() {
  package_name="$1"
  version="$2"
  npm_output=""

  while true; do
    if [ -z "$otp" ]; then
      prompt_for_otp
    fi

    echo
    echo "Unpublishing $package_name@$version ..."

    if npm_output="$(npm unpublish "$package_name@$version" --force --otp "$otp" --registry "$REGISTRY" 2>&1)"; then
      printf '%s\n' "$npm_output"
      return 0
    fi

    printf '%s\n' "$npm_output" >&2

    if needs_new_otp "$npm_output"; then
      echo "OTP missing, expired, or invalid; enter a new code to continue." >&2
      otp=""
      continue
    fi

    return 1
  done
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute)
      MODE="execute"
      shift
      ;;
    --dry-run)
      MODE="dry-run"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$PACKAGE_NAMES" ]; then
  echo "No packages configured. Set PACKAGE_NAMES or PACKAGE_NAME." >&2
  exit 2
fi

process_package() {
  package_name="$1"

  metadata_json="$(npm view "$package_name" version versions dist-tags --json --registry "$REGISTRY")" || {
    echo "Failed to fetch npm metadata for $package_name" >&2
    return 1
  }

  latest_version="$(printf '%s' "$metadata_json" | node -e '
const metadata = JSON.parse(require("fs").readFileSync(0, "utf8"));
console.log(metadata["dist-tags"]?.latest || metadata.version || "");
')"

  versions_to_unpublish="$(printf '%s' "$metadata_json" | node -e '
const metadata = JSON.parse(require("fs").readFileSync(0, "utf8"));
const versions = Array.isArray(metadata.versions) ? metadata.versions : [];
const latest = metadata["dist-tags"]?.latest || metadata.version;
if (!latest) throw new Error("Could not determine latest version");
console.log(versions.filter((version) => version !== latest).join("\n"));
')"

  if [ -z "$latest_version" ]; then
    echo "Could not determine latest version for $package_name" >&2
    return 1
  fi

  echo "Package: $package_name"
  echo "Registry: $REGISTRY"
  echo "Keeping latest: $latest_version"

  if [ -z "$versions_to_unpublish" ]; then
    echo "No older versions found."
    return 0
  fi

  echo
  echo "Versions targeted for unpublish:"
  printf '%s\n' "$versions_to_unpublish"

  if [ "$MODE" = "dry-run" ]; then
    echo
    echo "Dry run only. Re-run with --execute to unpublish these versions."
    return 0
  fi

  while IFS= read -r version <&3 || [ -n "${version:-}" ]; do
    [ -n "$version" ] || continue

    if unpublish_version "$package_name" "$version"; then
      success_count=$((success_count + 1))
    else
      failure_count=$((failure_count + 1))
      failed_versions="${failed_versions}${package_name}@${version}"$'\n'
    fi
  done 3<<EOF
$versions_to_unpublish
EOF
}

success_count=0
failure_count=0
failed_versions=""
package_failure_count=0

for package_name in $PACKAGE_NAMES; do
  echo
  if ! process_package "$package_name"; then
    package_failure_count=$((package_failure_count + 1))
  fi
done

echo
echo "Done."
echo "Succeeded: $success_count"
echo "Failed: $failure_count"

if [ "$package_failure_count" -gt 0 ]; then
  echo "Package metadata failures: $package_failure_count"
fi

if [ "$failure_count" -gt 0 ]; then
  echo
  echo "Failed package versions:"
  printf '%s' "$failed_versions"
  echo
  echo "If npm still reports dependent-package policy failures, wait for registry propagation and rerun this script."
  echo "OTP prompts appear automatically when npm reports an expired or invalid code."
fi

if [ "$failure_count" -gt 0 ] || [ "$package_failure_count" -gt 0 ]; then
  exit 1
fi
