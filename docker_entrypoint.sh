#!/bin/sh
set -eu

# Source configuration from trivy_envs.txt (written by entrypoint.sh)
if [ -f /input/trivy_envs.txt ]; then
  # shellcheck disable=SC1091 # file is generated at runtime
  . /input/trivy_envs.txt
fi

# --- Trivyignore handling ---
if [ -n "${INPUT_TRIVYIGNORES:-}" ]; then
  yaml_count=0
  plain_count=0

  # Validate files and detect types
  for f in $(echo "$INPUT_TRIVYIGNORES" | tr ',' ' '); do
    if [ ! -f "$f" ]; then
      echo "ERROR: cannot find ignorefile '$f'." >&2
      exit 1
    fi

    case "$f" in
      *.yml | *.yaml) yaml_count=$((yaml_count + 1)) ;;
      *) plain_count=$((plain_count + 1)) ;;
    esac
  done

  # Mixed types are not allowed
  if [ "$yaml_count" -gt 0 ] && [ "$plain_count" -gt 0 ]; then
    echo "ERROR: Cannot mix YAML and plain trivy ignore files." >&2
    exit 1
  fi

  # YAML mode
  if [ "$yaml_count" -gt 0 ]; then
    if [ "$yaml_count" -gt 1 ]; then
      echo "ERROR: Multiple YAML ignore files provided. Only one YAML file is supported." >&2
      exit 1
    fi

    yaml_file="$(echo "$INPUT_TRIVYIGNORES" | tr ',' ' ' | awk '{print $1}')"
    echo "Using YAML ignorefile '$yaml_file':"
    cat "$yaml_file"
    export TRIVY_IGNOREFILE="$yaml_file"
  else
    # Plain mode — merge all files into /tmp/trivyignores
    ignorefile="/tmp/trivyignores"
    : >"$ignorefile"

    for f in $(echo "$INPUT_TRIVYIGNORES" | tr ',' ' '); do
      echo "Found ignorefile '$f':"
      cat "$f"
      cat "$f" >>"$ignorefile"
    done

    export TRIVY_IGNOREFILE="$ignorefile"
  fi
fi

# --- SARIF handling ---
if [ "${TRIVY_FORMAT:-}" = "sarif" ]; then
  if [ "${INPUT_LIMIT_SEVERITIES_FOR_SARIF:-false}" != "true" ]; then
    echo "Building SARIF report with all severities"
    unset TRIVY_SEVERITY
  else
    echo "Building SARIF report"
  fi
fi

# --- Config file paths (detect files in /input/) ---
if [ -f /input/trivy-config.yaml ]; then
  export TRIVY_CONFIG=/input/trivy-config.yaml
fi

if [ -f /input/template ]; then
  export TRIVY_TEMPLATE=@/input/template
fi

if [ -f /input/ignore-policy.rego ]; then
  export TRIVY_IGNORE_POLICY=/input/ignore-policy.rego
fi

# --- Run trivy ---
scanType="${INPUT_SCAN_TYPE:-image}"
scanRef="${INPUT_SCAN_REF:-}"

if [ -n "$scanRef" ]; then
  echo "Running Trivy: trivy $scanType $scanRef"
  exec trivy "$scanType" "$scanRef"
else
  echo "Running Trivy: trivy $scanType"
  exec trivy "$scanType"
fi
