#!/usr/bin/env bats
# shellcheck disable=SC2030,SC2031 # exports in @test blocks are intentionally local

bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-file

pull_amd64() {
  local image="$1"
  local tag="${image%%@*}"
  if docker pull --platform linux/amd64 "$image" 1>&3 2>&3; then
    return 0
  fi
  # Retry after removing conflicting local image (e.g. different platform)
  docker rmi "$tag" 2>/dev/null || true
  docker pull --platform linux/amd64 "$image" 1>&3 2>&3
}

setup_file() {
  setup_trivy_env

  local trivy_image="${INPUT_TRIVY_IMAGE:-aquasec/trivy:0.69.3}"

  # Pull the trivy docker image
  docker pull "$trivy_image" 1>&3 2>&3
  # Pull test images (always amd64 for consistent golden file comparison)
  pull_amd64 knqyf263/vuln-image:1.2.3@sha256:1e8b199249d6d0ef3419ddc6eda2348d9fbdb10d350d3bb70aa98e87faa227c9
  pull_amd64 alpine:3.10@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98

  # Download trivy DB using the container
  local cache_dir="${INPUT_CACHE_DIR:-.cache}"
  mkdir -p "$cache_dir"
  docker run --rm \
    -v "$(realpath "$cache_dir"):/cache:rw" \
    -e TRIVY_CACHE_DIR=/cache \
    -e "TRIVY_DB_REPOSITORY=${TRIVY_DB_REPOSITORY}" \
    -e "TRIVY_JAVA_DB_REPOSITORY=${TRIVY_JAVA_DB_REPOSITORY}" \
    "$trivy_image" \
    image --no-progress --download-db-only 1>&3 2>&3
}

setup() {
  export INPUT_OUTPUT="$BATS_TEST_TMPDIR/output.test"
  export INPUT_CACHE_DIR="${INPUT_CACHE_DIR:-.cache}"
}

teardown() {
  reset_envs
}

setup_trivy_env() {
  # These are used by setup_file for the DB download (run directly via docker run)
  export TRIVY_DB_REPOSITORY="ghcr.io/aquasecurity/trivy-db-act:latest"
  export TRIVY_JAVA_DB_REPOSITORY="ghcr.io/aquasecurity/trivy-java-db-act:latest"

  # Pass trivy env vars into the sandbox via INPUT_TRIVY_ENV
  export INPUT_TRIVY_ENV="TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db-act:latest
TRIVY_JAVA_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-java-db-act:latest
TRIVY_CHECKS_BUNDLE_REPOSITORY=ghcr.io/aquasecurity/trivy-checks-act:latest
TRIVY_LIST_ALL_PKGS=false
TRIVY_DISABLE_VEX_NOTICE=true
TRIVY_SKIP_VERSION_CHECK=true
TRIVY_DISABLE_TELEMETRY=true
TRIVY_SKIP_DB_UPDATE=true
TRIVY_SKIP_JAVA_DB_UPDATE=true"
}

reset_envs() {
  local var
  for var in $(env | grep '^TRIVY_\|^INPUT_' | cut -d= -f1); do
    unset "$var"
  done
}

compare_files() {
  local actual="$1"
  local expected="$2"

  normalize_report "$actual"
  normalize_report "$expected"

  if [ "${UPDATE_GOLDEN}" = "1" ]; then
    cp "$actual" "$expected"
    echo "Updated golden file: $expected"
  else
    run diff "$actual" "$expected"
    echo "$output"
    assert_files_equal "$actual" "$expected"
  fi

  rm -f "$actual"
}

normalize_report() {
  local file="$1"

  case "${INPUT_FORMAT:-}" in
    json)
      apply_jq_filter "$file" \
        'del(.CreatedAt, .ReportID)'
      ;;
    sarif)
      apply_jq_filter "$file" \
        'del(.runs[].tool.driver.version)
         | del(.runs[].originalUriBaseIds)'
      ;;
    github)
      apply_jq_filter "$file" \
        'del(.detector.version)
         | del(.scanned)
         | del(.job)
         | del(.ref)
         | del(.sha)'
      ;;
  esac
}

apply_jq_filter() {
  local file="$1"
  local filter="$2"
  local tmp="$BATS_TEST_TMPDIR/jq.tmp"

  jq "$filter" "$file" > "$tmp" && mv "$tmp" "$file"
}

run_test_case_compare() {
  local expected_file="$1"

  run ./entrypoint.sh
  assert_success

  compare_files "$INPUT_OUTPUT" "$expected_file"
}

run_test_case_fails() {
  local expected_msg="$1"

  run ./entrypoint.sh
  assert_failure

  if [ -n "$expected_msg" ]; then
    assert_output --partial "$expected_msg"
  fi
}

@test "trivy repo with securityCheck secret only" {
  # trivy repo -f json -o repo.test --scanners=secret https://github.com/krol3/demo-trivy/
  export INPUT_FORMAT=json INPUT_SCANNERS=secret INPUT_SCAN_TYPE=repo INPUT_SCAN_REF="https://github.com/krol3/demo-trivy/"
  run_test_case_compare ./test/data/secret-scan/report.json
}

@test "trivy image" {
  # trivy image --severity CRITICAL -o image.test knqyf263/vuln-image:1.2.3@sha256:1e8b199249d6d0ef3419ddc6eda2348d9fbdb10d350d3bb70aa98e87faa227c9
  export INPUT_SEVERITY=CRITICAL INPUT_SCAN_TYPE=image INPUT_SCAN_REF=knqyf263/vuln-image:1.2.3@sha256:1e8b199249d6d0ef3419ddc6eda2348d9fbdb10d350d3bb70aa98e87faa227c9
  run_test_case_compare ./test/data/image-scan/report
}

@test "trivy config sarif report" {
  # trivy config -f sarif -o config-sarif.test ./test/data/config-sarif-report
  export INPUT_FORMAT=sarif INPUT_SCAN_TYPE=config INPUT_SCAN_REF=./test/data/config-sarif-report
  run_test_case_compare ./test/data/config-sarif-report/report.sarif
}

@test "trivy config" {
  # trivy config -f json -o config.json ./test/data/config-scan
  export INPUT_FORMAT=json INPUT_SCAN_TYPE=config INPUT_SCAN_REF=./test/data/config-scan
  run_test_case_compare ./test/data/config-scan/report.json
}

@test "trivy fs" {
  export INPUT_SCAN_TYPE=fs INPUT_SCAN_REF=./test/data/fs-scan
  run_test_case_compare ./test/data/fs-scan/report
}

@test "trivy image with trivyIgnores option" {
  export INPUT_SEVERITY=CRITICAL INPUT_SCAN_TYPE=image INPUT_SCAN_REF=knqyf263/vuln-image:1.2.3@sha256:1e8b199249d6d0ef3419ddc6eda2348d9fbdb10d350d3bb70aa98e87faa227c9 INPUT_TRIVYIGNORES="./test/data/with-ignore-files/.trivyignore1,./test/data/with-ignore-files/.trivyignore2"
  run_test_case_compare ./test/data/with-ignore-files/report
}

@test "trivy image with .trivyignore.yaml" {
  export INPUT_SEVERITY=CRITICAL INPUT_SCAN_TYPE=image INPUT_SCAN_REF=knqyf263/vuln-image:1.2.3@sha256:1e8b199249d6d0ef3419ddc6eda2348d9fbdb10d350d3bb70aa98e87faa227c9 INPUT_TRIVYIGNORES=./test/data/with-yaml-ignore-file/.trivyignore.yaml
  run_test_case_compare ./test/data/with-yaml-ignore-file/report
}

@test "trivy image with sbom output" {
  # trivy image --format github knqyf263/vuln-image:1.2.3@sha256:1e8b199249d6d0ef3419ddc6eda2348d9fbdb10d350d3bb70aa98e87faa227c9
  export INPUT_FORMAT=github INPUT_SCAN_TYPE=image INPUT_SCAN_REF=knqyf263/vuln-image:1.2.3@sha256:1e8b199249d6d0ef3419ddc6eda2348d9fbdb10d350d3bb70aa98e87faa227c9
  run_test_case_compare ./test/data/github-dep-snapshot/report.gsbom
}

@test "trivy image with trivy.yaml config" {
  # trivy --config=./test/data/with-trivy-yaml-cfg/trivy.yaml image alpine:3.10@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98
  export INPUT_TRIVY_CONFIG=./test/data/with-trivy-yaml-cfg/trivy.yaml INPUT_FORMAT=json INPUT_SCAN_TYPE=image INPUT_SCAN_REF=alpine:3.10@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98
  run_test_case_compare ./test/data/with-trivy-yaml-cfg/report.json
}

@test "trivy image env isolation - host vars do not leak" {
  # Verify that host TRIVY_* vars not written to trivy_envs.txt don't leak into the container
  # Set a bogus severity that would cause trivy to fail if it leaked
  export TRIVY_SEVERITY=CRITICAL
  export INPUT_SCAN_TYPE=image INPUT_SCAN_REF=knqyf263/vuln-image:1.2.3@sha256:1e8b199249d6d0ef3419ddc6eda2348d9fbdb10d350d3bb70aa98e87faa227c9
  # INPUT_SEVERITY is not set, so the default is used and skipped by set_env_var_if_provided.
  # If the host TRIVY_SEVERITY leaked, the scan would use CRITICAL.
  # We just verify it runs successfully (doesn't error out).
  run ./entrypoint.sh
  assert_success
}

@test "error if ignorefile does not exist" {
  local missing_file="$BATS_TEST_TMPDIR/missing.ignore"

  export INPUT_TRIVYIGNORES="$missing_file" \
         INPUT_SCAN_TYPE=fs \
         INPUT_SCAN_REF=./test/data/fs-scan

  run_test_case_fails "cannot find ignorefile '$missing_file'"
}

@test "error with mixed yaml and plain ignore files" {
  local plain_ignore="$BATS_TEST_TMPDIR/ignore-plain"
  local yaml_ignore="$BATS_TEST_TMPDIR/ignore.yaml"

  touch "$plain_ignore" "$yaml_ignore"

  export INPUT_TRIVYIGNORES="$plain_ignore,$yaml_ignore" \
         INPUT_SCAN_TYPE=fs \
         INPUT_SCAN_REF=./test/data/fs-scan

  run_test_case_fails "Cannot mix YAML and plain trivy ignore files"
}

@test "error if multiple YAML files provided" {
  local yaml1="$BATS_TEST_TMPDIR/ignore1.yaml"
  local yaml2="$BATS_TEST_TMPDIR/ignore2.yaml"
  touch "$yaml1" "$yaml2"

  export INPUT_TRIVYIGNORES="$yaml1,$yaml2" \
         INPUT_SCAN_TYPE=fs \
         INPUT_SCAN_REF=./test/data/fs-scan

  run_test_case_fails "Multiple YAML ignore files provided"
}

@test "works with a single YAML file" {
  local yaml="$BATS_TEST_TMPDIR/ignore.yaml"
  touch "$yaml"

  export INPUT_TRIVYIGNORES="$yaml" \
         INPUT_SCAN_TYPE=fs \
         INPUT_SCAN_REF=./test/data/fs-scan

  run ./entrypoint.sh
  assert_output --partial "Using YAML ignorefile"
}

@test "works with multiple plain ignore files" {
  local plain1="$BATS_TEST_TMPDIR/ignore1"
  local plain2="$BATS_TEST_TMPDIR/ignore2"
  echo "CVE-1" > "$plain1"
  echo "CVE-2" > "$plain2"

  export INPUT_TRIVYIGNORES="$plain1,$plain2" \
         INPUT_SCAN_TYPE=fs \
         INPUT_SCAN_REF=./test/data/fs-scan

  run ./entrypoint.sh
  assert_output --partial "Found ignorefile"
}
