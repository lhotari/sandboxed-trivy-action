#!/bin/bash
# shellcheck disable=SC2129 # individual redirects to trivy_envs.txt are more readable
set -euo pipefail

# Resolve the directory where this script lives (for finding docker_entrypoint.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Directory setup ---
ACTION_TMPDIR=$(mktemp -d)
# shellcheck disable=SC2317,SC2329 # invoked via trap
cleanup() { rm -rf "$ACTION_TMPDIR"; }
trap cleanup EXIT

INPUT_DIR="$ACTION_TMPDIR/input"
OUTPUT_DIR="$ACTION_TMPDIR/output"
mkdir -p "$INPUT_DIR" "$OUTPUT_DIR"

CACHE_DIR="${INPUT_CACHE_DIR:-${GITHUB_WORKSPACE:-.}/.cache/trivy}"
mkdir -p "$CACHE_DIR"
CACHE_DIR="$(realpath "$CACHE_DIR")"

# --- Copy docker_entrypoint.sh into the input dir ---
cp "$SCRIPT_DIR/docker_entrypoint.sh" "$INPUT_DIR/docker_entrypoint.sh"
chmod +x "$INPUT_DIR/docker_entrypoint.sh"

# --- Docker security flags ---
docker_args=(
  --rm
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --user "$(id -u):$(id -g)"
)

# --- Mount strategy (always present) ---
docker_args+=(-v "$INPUT_DIR:/input:ro")
docker_args+=(-v "$OUTPUT_DIR:/output:rw")
docker_args+=(-v "$CACHE_DIR:/cache:rw")

# --- Scan type handling ---
scanType="${INPUT_SCAN_TYPE:-image}"
scanRef="${INPUT_SCAN_REF:-}"
containerScanRef=""

if [ -z "$scanRef" ] && [ -z "${INPUT_TRIVY_CONFIG:-}" ]; then
  echo "ERROR: scan-ref is required (unless trivy-config is provided)." >&2
  exit 1
fi

case "$scanType" in
  image)
    if [ -n "$scanRef" ]; then
      if [ -f "$scanRef" ]; then
        # scan-ref is an existing file (tar file)
        inputFile="$(realpath "$scanRef")"
        inputBasename="$(basename "$inputFile")"
        docker_args+=(-v "$inputFile:/docker-tar/$inputBasename:ro")
        containerInput="/docker-tar/$inputBasename"
      else
        # scan-ref is a docker image name — docker save it
        DOCKER_TAR_DIR="${INPUT_DOCKER_TAR_DIR:-$ACTION_TMPDIR/docker-tar}"
        mkdir -p "$DOCKER_TAR_DIR"
        sanitizedName="$(echo "$scanRef" | tr '/:@' '___')"
        tarFile="$DOCKER_TAR_DIR/${sanitizedName}.tar"
        if ! docker image inspect "$scanRef" >/dev/null 2>&1; then
          echo "Pulling docker image '$scanRef'..."
          docker pull "$scanRef"
        fi
        echo "Saving docker image '$scanRef' to '$tarFile'..."
        docker save "$scanRef" -o "$tarFile"
        docker_args+=(-v "$DOCKER_TAR_DIR:/docker-tar:ro")
        containerInput="/docker-tar/${sanitizedName}.tar"
      fi
    fi
    docker_args+=(--tmpfs "/tmp:rw,noexec")
    ;;
  fs | rootfs | config)
    if [ -n "$scanRef" ]; then
      localPath="$(realpath "$scanRef")"
      if [ -f "$localPath" ]; then
        parentDir="$(dirname "$localPath")"
        baseName="$(basename "$localPath")"
        docker_args+=(-v "$parentDir:/scan-target:ro")
        containerScanRef="/scan-target/$baseName"
      else
        docker_args+=(-v "$localPath:/scan-target:ro")
        containerScanRef="/scan-target"
      fi
    fi
    docker_args+=(--tmpfs "/tmp:rw,noexec")
    ;;
  repo)
    containerScanRef="$scanRef"
    # repo scan needs exec in /tmp for git clone
    docker_args+=(--tmpfs "/tmp:rw,exec")
    ;;
  *)
    echo "ERROR: Unknown scan type '$scanType'" >&2
    exit 1
    ;;
esac

# --- Copy input files to INPUT_DIR ---

# Trivyignores
if [ -n "${INPUT_TRIVYIGNORES:-}" ]; then
  mkdir -p "$INPUT_DIR/trivyignores"
  containerTrivyignores=""
  for f in ${INPUT_TRIVYIGNORES//,/ }; do
    if [ ! -f "$f" ]; then
      echo "ERROR: cannot find ignorefile '$f'." >&2
      exit 1
    fi
    baseName="$(basename "$f")"
    cp "$f" "$INPUT_DIR/trivyignores/$baseName"
    if [ -n "$containerTrivyignores" ]; then
      containerTrivyignores="$containerTrivyignores,/input/trivyignores/$baseName"
    else
      containerTrivyignores="/input/trivyignores/$baseName"
    fi
  done
fi

# Trivy config
if [ -n "${INPUT_TRIVY_CONFIG:-}" ]; then
  cp "$(realpath "$INPUT_TRIVY_CONFIG")" "$INPUT_DIR/trivy-config.yaml"
fi

# Template (non-builtin)
if [ -n "${INPUT_TEMPLATE:-}" ]; then
  case "$INPUT_TEMPLATE" in
    @/*)
      # Built-in template inside the trivy image, pass as-is via env
      ;;
    *)
      # User-provided template file — strip leading @ if present
      templatePath="${INPUT_TEMPLATE#@}"
      cp "$(realpath "$templatePath")" "$INPUT_DIR/template"
      ;;
  esac
fi

# Ignore policy
if [ -n "${INPUT_IGNORE_POLICY:-}" ]; then
  cp "$(realpath "$INPUT_IGNORE_POLICY")" "$INPUT_DIR/ignore-policy.rego"
fi

# --- Write trivy_envs.txt ---
TRIVY_ENVS="$INPUT_DIR/trivy_envs.txt"
: >"$TRIVY_ENVS"

set_env_var_if_provided() {
  local var_name="$1"
  local input_value="$2"
  local default_value="${3:-}"

  if [ -n "$input_value" ] && [ "$input_value" != "$default_value" ]; then
    printf 'export %s=%q\n' "$var_name" "$input_value" >>"$TRIVY_ENVS"
  fi
}

# From INPUT_* vars
set_env_var_if_provided "TRIVY_EXIT_CODE" "${INPUT_EXIT_CODE:-}" ""
set_env_var_if_provided "TRIVY_IGNORE_UNFIXED" "${INPUT_IGNORE_UNFIXED:-false}" "false"
set_env_var_if_provided "TRIVY_PKG_TYPES" "${INPUT_VULN_TYPE:-os,library}" "os,library"
set_env_var_if_provided "TRIVY_SEVERITY" "${INPUT_SEVERITY:-UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL}" "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
set_env_var_if_provided "TRIVY_FORMAT" "${INPUT_FORMAT:-table}" "table"
set_env_var_if_provided "TRIVY_SKIP_DIRS" "${INPUT_SKIP_DIRS:-}" ""
set_env_var_if_provided "TRIVY_SKIP_FILES" "${INPUT_SKIP_FILES:-}" ""
set_env_var_if_provided "TRIVY_TIMEOUT" "${INPUT_TIMEOUT:-}" ""
set_env_var_if_provided "TRIVY_QUIET" "${INPUT_HIDE_PROGRESS:-}" ""
set_env_var_if_provided "TRIVY_LIST_ALL_PKGS" "${INPUT_LIST_ALL_PKGS:-false}" "false"
set_env_var_if_provided "TRIVY_SCANNERS" "${INPUT_SCANNERS:-}" ""

# Template: built-in templates passed as-is, user templates detected by docker_entrypoint.sh
if [ -n "${INPUT_TEMPLATE:-}" ]; then
  case "$INPUT_TEMPLATE" in
    @/*)
      printf 'export TRIVY_TEMPLATE=%q\n' "$INPUT_TEMPLATE" >>"$TRIVY_ENVS"
      ;;
  esac
fi

# Input (for image scans via tar)
if [ -n "${containerInput:-}" ]; then
  printf 'export TRIVY_INPUT=%q\n' "$containerInput" >>"$TRIVY_ENVS"
fi

# Output mapped to container path
if [ -n "${INPUT_OUTPUT:-}" ]; then
  outputBasename="$(basename "$INPUT_OUTPUT")"
  printf 'export TRIVY_OUTPUT=%q\n' "/output/$outputBasename" >>"$TRIVY_ENVS"
fi

# Defaults (can be overridden via trivy-env since those are appended later)
printf 'export TRIVY_CACHE_DIR=/cache\n' >>"$TRIVY_ENVS"
printf 'export TRIVY_SKIP_VERSION_CHECK=true\n' >>"$TRIVY_ENVS"
printf 'export TRIVY_DISABLE_TELEMETRY=true\n' >>"$TRIVY_ENVS"

# Control vars for docker_entrypoint.sh
printf 'export INPUT_SCAN_TYPE=%q\n' "$scanType" >>"$TRIVY_ENVS"
printf 'export INPUT_SCAN_REF=%q\n' "$containerScanRef" >>"$TRIVY_ENVS"
if [ -n "${containerTrivyignores:-}" ]; then
  printf 'export INPUT_TRIVYIGNORES=%q\n' "$containerTrivyignores" >>"$TRIVY_ENVS"
fi
set_env_var_if_provided "INPUT_LIMIT_SEVERITIES_FOR_SARIF" "${INPUT_LIMIT_SEVERITIES_FOR_SARIF:-}" ""

# Validate and append trivy-env entries (newline-separated NAME=VALUE pairs)
if [ -n "${INPUT_TRIVY_ENV:-}" ]; then
  while IFS= read -r line; do
    # Skip empty lines and comments
    [ -z "$line" ] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    # Trim whitespace
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$line" ] && continue
    # Validate NAME=VALUE format
    if ! [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*=.* ]]; then
      echo "ERROR: Invalid trivy-env entry: '$line'. Expected NAME=VALUE format." >&2
      exit 1
    fi
    varName="${line%%=*}"
    varValue="${line#*=}"
    printf 'export %s=%q\n' "$varName" "$varValue" >>"$TRIVY_ENVS"
  done <<<"$INPUT_TRIVY_ENV"
fi

# --- Run docker ---
TRIVY_IMAGE="${INPUT_TRIVY_IMAGE:-aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c}"

echo "Running Trivy in sandboxed container ($TRIVY_IMAGE)..."
returnCode=0
docker run "${docker_args[@]}" \
  --entrypoint /bin/sh "$TRIVY_IMAGE" /input/docker_entrypoint.sh || returnCode=$?

# --- Copy output back to host ---
if [ -n "${INPUT_OUTPUT:-}" ]; then
  outputBasename="$(basename "$INPUT_OUTPUT")"
  if [ -f "$OUTPUT_DIR/$outputBasename" ]; then
    cp "$OUTPUT_DIR/$outputBasename" "$INPUT_OUTPUT"
  fi
fi

exit "$returnCode"
