#!/usr/bin/env bats
# shellcheck disable=SC2030,SC2031 # exports in @test blocks are intentionally local
# Unit tests for entrypoint.sh and docker_entrypoint.sh using mocks

bats_load_library bats-support
bats_load_library bats-assert

setup() {
  export BATS_TEST_TMPDIR="${BATS_TEST_TMPDIR:-$(mktemp -d)}"

  # Create mock bin directory and add to PATH first
  MOCK_BIN="$BATS_TEST_TMPDIR/mock-bin"
  mkdir -p "$MOCK_BIN"
  export PATH="$MOCK_BIN:$PATH"

  # Directory where mock docker captures the input dir contents
  CAPTURE_DIR="$BATS_TEST_TMPDIR/captured"
  export CAPTURE_DIR
  mkdir -p "$CAPTURE_DIR"

  # Log file for docker args
  DOCKER_LOG="$BATS_TEST_TMPDIR/docker-args.log"
  export DOCKER_LOG

  # Create a mock docker command that logs args and captures the input dir
  cat > "$MOCK_BIN/docker" <<'MOCK'
#!/bin/bash
echo "$@" >> "$DOCKER_LOG"
# For "docker save", create the tar file
if [ "$1" = "save" ]; then
  prev=""
  for arg in "$@"; do
    if [ "$prev" = "-o" ]; then
      touch "$arg"
      break
    fi
    prev="$arg"
  done
  exit 0
fi
# For "docker run", capture the input dir and handle output
if [ "$1" = "run" ]; then
  input_dir=""
  output_dir=""
  for arg in "$@"; do
    if echo "$arg" | grep -q ':/input:ro$'; then
      input_dir="${arg%%:*}"
    fi
    if echo "$arg" | grep -q ':/output:rw$'; then
      output_dir="${arg%%:*}"
    fi
  done
  # Snapshot input dir contents for test inspection
  if [ -n "$input_dir" ] && [ -d "$input_dir" ]; then
    cp -a "$input_dir/." "$CAPTURE_DIR/"
  fi
  # If output is expected, create a dummy output file
  if [ -n "$output_dir" ] && [ -n "$input_dir" ] && [ -f "$input_dir/trivy_envs.txt" ]; then
    (
      . "$input_dir/trivy_envs.txt"
      if [ -n "${TRIVY_OUTPUT:-}" ]; then
        basename="$(basename "$TRIVY_OUTPUT")"
        echo '{"results":[]}' > "$output_dir/$basename"
      fi
    )
  fi
fi
exit 0
MOCK
  chmod +x "$MOCK_BIN/docker"

  # Defaults
  export INPUT_SCAN_TYPE=fs
  export INPUT_SCAN_REF="$BATS_TEST_TMPDIR"
  export INPUT_CACHE_DIR="$BATS_TEST_TMPDIR/cache"
  export INPUT_TRIVY_IMAGE="aquasec/trivy:test"
  mkdir -p "$INPUT_CACHE_DIR"
}

teardown() {
  local var
  for var in $(env | grep '^INPUT_\|^TRIVY_' | cut -d= -f1); do
    unset "$var"
  done
}

# --- entrypoint.sh tests ---

@test "entrypoint.sh writes trivy_envs.txt with correct TRIVY_CACHE_DIR" {
  run ./entrypoint.sh
  assert_success
  assert [ -f "$CAPTURE_DIR/trivy_envs.txt" ]
  assert grep -q 'export TRIVY_CACHE_DIR=/cache' "$CAPTURE_DIR/trivy_envs.txt"
}

@test "entrypoint.sh writes INPUT_SCAN_TYPE to trivy_envs.txt" {
  export INPUT_SCAN_TYPE=fs
  run ./entrypoint.sh
  assert_success
  assert grep -q "export INPUT_SCAN_TYPE=fs" "$CAPTURE_DIR/trivy_envs.txt"
}

@test "entrypoint.sh writes INPUT_SCAN_REF for fs scan" {
  export INPUT_SCAN_TYPE=fs
  export INPUT_SCAN_REF="$BATS_TEST_TMPDIR"

  run ./entrypoint.sh
  assert_success
  assert grep -q 'export INPUT_SCAN_REF=/scan-target' "$CAPTURE_DIR/trivy_envs.txt"
}

@test "entrypoint.sh mounts scan target read-only for fs scan" {
  export INPUT_SCAN_TYPE=fs
  export INPUT_SCAN_REF="$BATS_TEST_TMPDIR"

  run ./entrypoint.sh
  assert_success
  assert grep -q "/scan-target:ro" "$DOCKER_LOG"
}

@test "entrypoint.sh uses docker save for image scan with image name" {
  export INPUT_SCAN_TYPE=image
  export INPUT_SCAN_REF="myimage:latest"

  run ./entrypoint.sh
  assert_success
  assert grep -q "save myimage:latest -o" "$DOCKER_LOG"
  assert grep -q "/docker-tar:ro" "$DOCKER_LOG"
}

@test "entrypoint.sh mounts existing tar file for image scan" {
  local tar_file="$BATS_TEST_TMPDIR/test-image.tar"
  touch "$tar_file"

  export INPUT_SCAN_TYPE=image
  export INPUT_SCAN_REF="$tar_file"

  run ./entrypoint.sh
  assert_success
  refute grep -q "save" "$DOCKER_LOG"
  assert grep -q "test-image.tar:/docker-tar/test-image.tar:ro" "$DOCKER_LOG"
}

@test "entrypoint.sh passes security flags to docker run" {
  run ./entrypoint.sh
  assert_success
  assert grep -q -- "--read-only" "$DOCKER_LOG"
  assert grep -q -- "--cap-drop ALL" "$DOCKER_LOG"
  assert grep -q -- "--security-opt no-new-privileges:true" "$DOCKER_LOG"
}

@test "entrypoint.sh copies docker_entrypoint.sh to input dir" {
  run ./entrypoint.sh
  assert_success
  assert [ -f "$CAPTURE_DIR/docker_entrypoint.sh" ]
}

@test "entrypoint.sh copies trivy config file to input dir" {
  local config_file="$BATS_TEST_TMPDIR/trivy.yaml"
  echo "format: json" > "$config_file"
  export INPUT_TRIVY_CONFIG="$config_file"

  run ./entrypoint.sh
  assert_success
  assert [ -f "$CAPTURE_DIR/trivy-config.yaml" ]
}

@test "entrypoint.sh copies trivyignore files to input dir" {
  local ignore1="$BATS_TEST_TMPDIR/ignore1"
  local ignore2="$BATS_TEST_TMPDIR/ignore2"
  echo "CVE-1" > "$ignore1"
  echo "CVE-2" > "$ignore2"
  export INPUT_TRIVYIGNORES="$ignore1,$ignore2"

  run ./entrypoint.sh
  assert_success
  assert [ -f "$CAPTURE_DIR/trivyignores/ignore1" ]
  assert [ -f "$CAPTURE_DIR/trivyignores/ignore2" ]
}

@test "entrypoint.sh fails if trivyignore file does not exist" {
  export INPUT_TRIVYIGNORES="$BATS_TEST_TMPDIR/nonexistent"

  run ./entrypoint.sh
  assert_failure
  assert_output --partial "cannot find ignorefile"
}

@test "entrypoint.sh fails without scan-ref and without trivy-config" {
  unset INPUT_SCAN_REF

  run ./entrypoint.sh
  assert_failure
  assert_output --partial "scan-ref is required"
}

@test "entrypoint.sh succeeds without scan-ref when trivy-config is provided" {
  unset INPUT_SCAN_REF
  local config_file="$BATS_TEST_TMPDIR/trivy.yaml"
  echo "format: json" > "$config_file"
  export INPUT_TRIVY_CONFIG="$config_file"
  export INPUT_SCAN_TYPE=fs

  run ./entrypoint.sh
  assert_success
  assert [ -f "$CAPTURE_DIR/trivy-config.yaml" ]
  # scan-ref should be empty in trivy_envs.txt
  assert grep -q "export INPUT_SCAN_REF=''" "$CAPTURE_DIR/trivy_envs.txt"
}

@test "entrypoint.sh writes non-default severity to trivy_envs.txt" {
  export INPUT_SEVERITY="CRITICAL,HIGH"

  run ./entrypoint.sh
  assert_success
  assert grep -q 'TRIVY_SEVERITY=CRITICAL' "$CAPTURE_DIR/trivy_envs.txt"
}

@test "entrypoint.sh skips default severity in trivy_envs.txt" {
  export INPUT_SEVERITY="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"

  run ./entrypoint.sh
  assert_success
  refute grep -q 'TRIVY_SEVERITY=' "$CAPTURE_DIR/trivy_envs.txt"
}

@test "entrypoint.sh writes trivy-env entries to trivy_envs.txt" {
  export INPUT_TRIVY_ENV="TRIVY_DB_REPOSITORY=ghcr.io/test/trivy-db:latest
TRIVY_DEBUG=true"

  run ./entrypoint.sh
  assert_success
  assert grep -q 'TRIVY_DB_REPOSITORY=ghcr.io/test/trivy-db:latest' "$CAPTURE_DIR/trivy_envs.txt"
  assert grep -q 'TRIVY_DEBUG=true' "$CAPTURE_DIR/trivy_envs.txt"
}

@test "entrypoint.sh rejects invalid trivy-env entry" {
  export INPUT_TRIVY_ENV="not-valid-format"

  run ./entrypoint.sh
  assert_failure
  assert_output --partial "Invalid trivy-env entry"
}

@test "entrypoint.sh ignores comments and blank lines in trivy-env" {
  export INPUT_TRIVY_ENV="# this is a comment

TRIVY_DEBUG=true
  # indented comment
"

  run ./entrypoint.sh
  assert_success
  assert grep -q 'TRIVY_DEBUG=true' "$CAPTURE_DIR/trivy_envs.txt"
  refute grep -q 'comment' "$CAPTURE_DIR/trivy_envs.txt"
}

@test "entrypoint.sh copies output back to host" {
  local output_file="$BATS_TEST_TMPDIR/results.json"
  export INPUT_OUTPUT="$output_file"

  run ./entrypoint.sh
  assert_success
  assert [ -f "$output_file" ]
}

@test "entrypoint.sh adds tmpfs with exec for repo scan" {
  export INPUT_SCAN_TYPE=repo
  export INPUT_SCAN_REF="https://github.com/example/repo"

  run ./entrypoint.sh
  assert_success
  assert grep -q -- "--tmpfs /tmp:rw,exec" "$DOCKER_LOG"
}

@test "entrypoint.sh uses correct trivy image" {
  export INPUT_TRIVY_IMAGE="custom/trivy:1.0"

  run ./entrypoint.sh
  assert_success
  assert grep -q "custom/trivy:1.0" "$DOCKER_LOG"
}

# --- docker_entrypoint.sh unit tests ---

# Helper: create a test-friendly copy of docker_entrypoint.sh with /input/ replaced
make_test_docker_entrypoint() {
  local fake_input="$1"
  local test_script="$BATS_TEST_TMPDIR/test_docker_entrypoint.sh"
  sed "s|/input/|$fake_input/|g" docker_entrypoint.sh > "$test_script"
  chmod +x "$test_script"
  echo "$test_script"
}

@test "docker_entrypoint.sh sources trivy_envs.txt and runs trivy" {
  cat > "$MOCK_BIN/trivy" <<'MOCK'
#!/bin/sh
echo "trivy $*"
exit 0
MOCK
  chmod +x "$MOCK_BIN/trivy"

  local fake_input="$BATS_TEST_TMPDIR/fake-input"
  mkdir -p "$fake_input"
  cat > "$fake_input/trivy_envs.txt" <<EOF
export INPUT_SCAN_TYPE=fs
export INPUT_SCAN_REF=/scan-target
export TRIVY_CACHE_DIR=/cache
EOF

  local test_script
  test_script="$(make_test_docker_entrypoint "$fake_input")"

  run "$test_script"
  assert_success
  assert_output --partial "Running Trivy: trivy fs /scan-target"
}

@test "docker_entrypoint.sh detects trivy-config.yaml in input" {
  cat > "$MOCK_BIN/trivy" <<'MOCK'
#!/bin/sh
echo "TRIVY_CONFIG=$TRIVY_CONFIG"
exit 0
MOCK
  chmod +x "$MOCK_BIN/trivy"

  local fake_input="$BATS_TEST_TMPDIR/fake-input"
  mkdir -p "$fake_input"
  echo "format: json" > "$fake_input/trivy-config.yaml"
  cat > "$fake_input/trivy_envs.txt" <<EOF
export INPUT_SCAN_TYPE=fs
export INPUT_SCAN_REF=/scan-target
EOF

  local test_script
  test_script="$(make_test_docker_entrypoint "$fake_input")"

  run "$test_script"
  assert_success
  assert_output --partial "TRIVY_CONFIG=$fake_input/trivy-config.yaml"
}

@test "docker_entrypoint.sh unsets TRIVY_SEVERITY for SARIF" {
  cat > "$MOCK_BIN/trivy" <<'MOCK'
#!/bin/sh
echo "TRIVY_SEVERITY=${TRIVY_SEVERITY:-unset}"
exit 0
MOCK
  chmod +x "$MOCK_BIN/trivy"

  local fake_input="$BATS_TEST_TMPDIR/fake-input"
  mkdir -p "$fake_input"
  cat > "$fake_input/trivy_envs.txt" <<EOF
export INPUT_SCAN_TYPE=config
export INPUT_SCAN_REF=/scan-target
export TRIVY_FORMAT=sarif
export TRIVY_SEVERITY=CRITICAL
EOF

  local test_script
  test_script="$(make_test_docker_entrypoint "$fake_input")"

  run "$test_script"
  assert_success
  assert_output --partial "Building SARIF report with all severities"
  assert_output --partial "TRIVY_SEVERITY=unset"
}

@test "docker_entrypoint.sh validates mixed trivyignore types" {
  local fake_input="$BATS_TEST_TMPDIR/fake-input"
  mkdir -p "$fake_input/trivyignores"
  touch "$fake_input/trivyignores/plain.txt"
  touch "$fake_input/trivyignores/config.yaml"

  cat > "$fake_input/trivy_envs.txt" <<EOF
export INPUT_SCAN_TYPE=fs
export INPUT_SCAN_REF=/scan-target
export INPUT_TRIVYIGNORES=$fake_input/trivyignores/plain.txt,$fake_input/trivyignores/config.yaml
EOF

  local test_script
  test_script="$(make_test_docker_entrypoint "$fake_input")"

  run "$test_script"
  assert_failure
  assert_output --partial "Cannot mix YAML and plain trivy ignore files"
}
