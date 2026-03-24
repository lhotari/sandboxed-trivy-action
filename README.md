# Sandboxed Trivy Action

> [GitHub Action](https://github.com/features/actions) for [Trivy](https://github.com/aquasecurity/trivy), running inside a sandboxed Docker container

[![License][license-img]][license]

This action is forked from [aquasecurity/trivy-action](https://github.com/aquasecurity/trivy-action) with security hardened by running Trivy inside a sandboxed Docker container. Credits to [Aqua Security](https://www.aquasec.com/) for the original action.

## Security

This action runs Trivy inside a Docker container with strict security settings to prevent container escape:

- `--read-only` filesystem — the container's root filesystem is read-only
- `--cap-drop ALL` — all Linux capabilities are dropped
- `--security-opt no-new-privileges:true` — prevents privilege escalation inside the container
- All scan targets are mounted **read-only**
- Only the output and cache directories are mounted writable
- A `tmpfs` is mounted at `/tmp` for Trivy's temporary files
- No direct Docker socket access — image scans use `docker save` to export a tar file which is mounted read-only into the container

## Table of Contents

* [Usage](#usage)
  * [Scan CI Pipeline](#scan-ci-pipeline)
  * [Scan CI Pipeline (w/ Trivy Config)](#scan-ci-pipeline-w-trivy-config)
  * [Cache](#cache)
  * [Scanning a Tarball](#scanning-a-tarball)
  * [Using Trivy with GitHub Code Scanning](#using-trivy-with-github-code-scanning)
  * [Using Trivy to scan your Git repo](#using-trivy-to-scan-your-git-repo)
  * [Using Trivy to scan Infrastructure as Code](#using-trivy-to-scan-infrastructure-as-code)
  * [Using Trivy if you don't have code scanning enabled](#using-trivy-if-you-dont-have-code-scanning-enabled)
* [Customizing](#customizing)
  * [inputs](#inputs)
  * [Environment variables](#environment-variables)
  * [Trivy config file](#trivy-config-file)
  * [Pinning the action version](#pinning-the-action-version)

## Usage

### Scan CI Pipeline

```yaml
name: build
on:
  push:
    branches:
      - main
  pull_request:
jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v6
      - name: Build an image from Dockerfile
        run: docker build -t my-app:${{ github.sha }} .
      - name: Run Trivy vulnerability scanner
        # For security, pin to a full length commit hash. See "Pinning the action version" below.
        uses: lhotari/sandboxed-trivy-action@v1
        with:
          scan-type: 'image'
          scan-ref: 'my-app:${{ github.sha }}'
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          vuln-type: 'os,library'
          severity: 'CRITICAL,HIGH'
```

### Scan CI Pipeline (w/ Trivy Config)

```yaml
name: build
on:
  push:
    branches:
    - main
  pull_request:
jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v6

    - name: Run Trivy vulnerability scanner in fs mode
      # For security, pin to a full length commit hash. See "Pinning the action version" below.
      uses: lhotari/sandboxed-trivy-action@v1
      with:
        scan-type: 'fs'
        scan-ref: '.'
        trivy-config: trivy.yaml
```

In this case `trivy.yaml` is a YAML configuration that is checked in as part of the repo. Detailed information is available on the Trivy website but an example is as follows:
```yaml
format: json
exit-code: 1
severity: CRITICAL
secret:
  config: config/trivy/secret.yaml
```

It is possible to define all options in the `trivy.yaml` file, including the scan target. When using `trivy-config`, `scan-ref` is optional — Trivy will use the target defined in the config file. `scan-type` is still recommended to ensure correct sandboxing behavior.

### Cache
The action has a built-in functionality for caching and restoring [the vulnerability DB](https://github.com/aquasecurity/trivy-db) and [the Java DB](https://github.com/aquasecurity/trivy-java-db) if they are downloaded during the scan.
The cache is stored in the `$GITHUB_WORKSPACE/.cache/trivy` directory by default.
The cache is restored before the scan starts and saved after the scan finishes.

It uses [actions/cache](https://github.com/actions/cache) under the hood but requires less configuration settings.
The cache input is optional, and caching is turned on by default.

#### Disabling caching
If you want to disable caching, set the `cache` input to `false`, but we recommend keeping it enabled to avoid rate limiting issues.

```yaml
    - name: Run Trivy scanner without cache
      # For security, pin to a full length commit hash. See "Pinning the action version" below.
      uses: lhotari/sandboxed-trivy-action@v1
      with:
        scan-type: 'fs'
        scan-ref: '.'
        cache: 'false'
```

### Scanning a Tarball
```yaml
name: build
on:
  push:
    branches:
    - main
  pull_request:
jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v6

    - name: Generate tarball from image
      run: |
        docker pull <your-docker-image>
        docker save -o vuln-image.tar <your-docker-image>

    - name: Run Trivy vulnerability scanner in tarball mode
      # For security, pin to a full length commit hash. See "Pinning the action version" below.
      uses: lhotari/sandboxed-trivy-action@v1
      with:
        scan-type: 'image'
        scan-ref: vuln-image.tar
        severity: 'CRITICAL,HIGH'
```

### Using Trivy with GitHub Code Scanning
If you have [GitHub code scanning](https://docs.github.com/en/github/finding-security-vulnerabilities-and-errors-in-your-code/about-code-scanning) available you can use Trivy as a scanning tool as follows:
```yaml
name: build
on:
  push:
    branches:
      - main
  pull_request:
jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v6

      - name: Build an image from Dockerfile
        run: docker build -t my-app:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        # For security, pin to a full length commit hash. See "Pinning the action version" below.
        uses: lhotari/sandboxed-trivy-action@v1
        with:
          scan-type: 'image'
          scan-ref: 'my-app:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'
```

### Using Trivy to scan your Git repo
It's also possible to scan your git repos with Trivy's built-in repo scan. This can be handy if you want to run Trivy as a build time check on each PR that gets opened in your repo.

```yaml
name: build
on:
  push:
    branches:
      - main
  pull_request:
jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v6

      - name: Run Trivy vulnerability scanner in repo mode
        # For security, pin to a full length commit hash. See "Pinning the action version" below.
        uses: lhotari/sandboxed-trivy-action@v1
        with:
          scan-type: 'fs'
          scan-ref: '.'
          ignore-unfixed: true
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL'

      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: 'trivy-results.sarif'
```

### Using Trivy to scan Infrastructure as Code
It's also possible to scan your IaC repos with Trivy's built-in config scan.

```yaml
name: build
on:
  push:
    branches:
      - main
  pull_request:
jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v6

      - name: Run Trivy vulnerability scanner in IaC mode
        # For security, pin to a full length commit hash. See "Pinning the action version" below.
        uses: lhotari/sandboxed-trivy-action@v1
        with:
          scan-type: 'config'
          scan-ref: '.'
          hide-progress: true
          format: 'sarif'
          output: 'trivy-results.sarif'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy scan results to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: 'trivy-results.sarif'
```

### Using Trivy if you don't have code scanning enabled

It's also possible to browse a scan result in a workflow summary.

This step is especially useful for private repositories without [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) license.

```yaml
- name: Run Trivy scanner
  # For security, pin to a full length commit hash. See "Pinning the action version" below.
  uses: lhotari/sandboxed-trivy-action@v1
  with:
    scan-type: config
    scan-ref: '.'
    hide-progress: true
    output: trivy.txt

- name: Publish Trivy Output to Summary
  run: |
    if [[ -s trivy.txt ]]; then
      {
        echo "### Security Output"
        echo "<details><summary>Click to expand</summary>"
        echo ""
        echo '```'
        cat trivy.txt
        echo '```'
        echo "</details>"
      } >> $GITHUB_STEP_SUMMARY
    fi
```

## Customizing

Configuration priority:
- [Inputs](#inputs)
- [Environment variables](#environment-variables)
- [Trivy config file](#trivy-config-file)
- Default values


### inputs

Following inputs can be used as `step.with` keys:

| Name                         | Type    | Default                            | Description                                                                                                                                                      |
|------------------------------|---------|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `scan-type`                  | String  | `image`                            | Scan type, e.g. `image`, `fs`, `repo`, `config`                                                                                                                 |
| `scan-ref`                   | String  |                                    | Scan reference: image name or tar file for image scans, path for fs/config scans, URL for repo scans. Required unless `trivy-config` is provided.                |
| `format`                     | String  | `table`                            | Output format (`table`, `json`, `template`, `sarif`, `cyclonedx`, `spdx`, `spdx-json`, `github`, `cosign-vuln`)                                                  |
| `template`                   | String  |                                    | Output template (`@/contrib/gitlab.tpl`, `@/contrib/junit.tpl`, `@/contrib/html.tpl`)                                                                            |
| `output`                     | String  |                                    | Save results to a file                                                                                                                                           |
| `exit-code`                  | String  | `0`                                | Exit code when specified vulnerabilities are found                                                                                                               |
| `ignore-unfixed`             | Boolean | false                              | Ignore unpatched/unfixed vulnerabilities                                                                                                                         |
| `vuln-type`                  | String  | `os,library`                       | Vulnerability types (os,library)                                                                                                                                 |
| `severity`                   | String  | `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL` | Severities of vulnerabilities to scanned for and displayed                                                                                                       |
| `skip-dirs`                  | String  |                                    | Comma separated list of directories where traversal is skipped                                                                                                   |
| `skip-files`                 | String  |                                    | Comma separated list of files where traversal is skipped                                                                                                         |
| `cache-dir`                  | String  | `$GITHUB_WORKSPACE/.cache/trivy`   | Cache directory                                                                                                                                                  |
| `timeout`                    | String  | `5m0s`                             | Scan timeout duration                                                                                                                                            |
| `ignore-policy`              | String  |                                    | Filter vulnerabilities with OPA rego language                                                                                                                    |
| `hide-progress`              | String  | `false`                            | Suppress progress bar and log output                                                                                                                             |
| `list-all-pkgs`              | String  |                                    | Output all packages regardless of vulnerability                                                                                                                  |
| `scanners`                   | String  | `vuln,secret`                      | comma-separated list of what security issues to detect (`vuln`,`secret`,`misconfig`,`license`)                                                                   |
| `trivyignores`               | String  |                                    | comma-separated list of relative paths to `.trivyignore` files, or a single `.trivyignore.yaml` file                                                             |
| `trivy-config`               | String  |                                    | Path to trivy.yaml config                                                                                                                                        |
| `limit-severities-for-sarif` | Boolean | false                              | By default *SARIF* format enforces output of all vulnerabilities regardless of configured severities. To override this behavior set this parameter to **true**   |
| `trivy-image`                | String  | `aquasec/trivy:0.69.3@sha256:bcc3...` | Docker image to use for running Trivy                                                                                                                            |
| `docker-tar-dir`             | String  |                                    | Directory for storing docker save tar files (for image scans). Uses a temp directory if empty                                                                     |
| `trivy-env`                  | String  |                                    | Newline-separated list of `NAME=VALUE` pairs for additional [Trivy environment variables][trivy-env] to pass into the container                                  |
| `cache`                      | Boolean | true                               | Enable caching of the vulnerability DB                                                                                                                           |

### Environment variables
Since Trivy runs inside a sandboxed Docker container, host environment variables are **not** automatically passed through. To set additional [Trivy environment variables][trivy-env] (including flags not supported by [Inputs](#inputs), such as `--secret-config`), use the `trivy-env` input:

```yaml
    - name: Run Trivy vulnerability scanner
      # For security, pin to a full length commit hash. See "Pinning the action version" below.
      uses: lhotari/sandboxed-trivy-action@v1
      with:
        scan-type: 'fs'
        scan-ref: '.'
        trivy-env: |
          TRIVY_SKIP_DB_UPDATE=true
          TRIVY_SKIP_JAVA_DB_UPDATE=true
```

Each line must be in `NAME=VALUE` format. Empty lines and lines starting with `#` are ignored.

### Trivy config file
When using the `trivy-config` [Input](#inputs), you can set options using the [Trivy config file][trivy-config] (including flags that are not supported by [Inputs](#inputs), such as `--secret-config`).

### Pinning the action version

For improved security, it is recommended to pin the action to a full length commit hash instead of a tag. This prevents a compromised or force-pushed tag from altering the action's behavior.

To find the full commit hash for a tag:
```bash
git ls-remote https://github.com/lhotari/sandboxed-trivy-action.git v1 | awk '{print $1}'
```

Then use it in your workflow:
```yaml
      - name: Run Trivy vulnerability scanner
        uses: lhotari/sandboxed-trivy-action@<full-commit-hash>
```

[license]: https://github.com/lhotari/sandboxed-trivy-action/blob/main/LICENSE
[license-img]: https://img.shields.io/github/license/lhotari/sandboxed-trivy-action
[trivy-env]: https://aquasecurity.github.io/trivy/latest/docs/configuration/#environment-variables
[trivy-config]: https://aquasecurity.github.io/trivy/latest/docs/references/configuration/config-file/
