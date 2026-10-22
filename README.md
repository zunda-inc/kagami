# kagami

[![crates.io](https://img.shields.io/crates/v/kagami-cli.svg)](https://crates.io/crates/kagami-cli)
[![CI](https://github.com/zunda-inc/kagami/actions/workflows/ci.yml/badge.svg)](https://github.com/zunda-inc/kagami/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)

kagami checks whether there are any publicly disclosed vulnerabilities in a list of defined software.

Package audits such as `npm audit` or Dependabot only see what is written in a lockfile. kagami is
for the software they cannot see: a PHP runtime installed on a server, Docker Engine on a host, or
a controller pinned by its image tag in a Kubernetes manifest. Write down what you run in a YAML
file, and kagami looks each version up in the [GitHub Advisory Database](https://github.com/advisories)
or in the security advisories that a project publishes in its own GitHub repository.

## Installation

Install kagami from [crates.io](https://crates.io/crates/kagami-cli) with
[Cargo](https://www.rust-lang.org/tools/install) (Rust 1.91 or later):

```sh
cargo install --locked kagami-cli
```

> [!TIP]
> The crate is named `kagami-cli` because the name `kagami` is taken on crates.io by an unrelated
> project. The installed command is `kagami`.

## Usage

Write the software you run into `kagami.yaml`:

```yaml
targets:
  # Looked up in the GitHub Advisory Database by package name.
  - name: k8s.io/ingress-nginx
    version: 1.11.4
    ecosystem: go
    advisory_type: github

  # Looked up in the advisories published in the php/php-src repository.
  - version: 8.5.9
    advisory_type: github_repository
    repository_path: php/php-src
```

Then run kagami in the same directory:

```console
$ kagami
25 Advisories found for 2 targets - Critical 3, High 7, Medium 12, Low 3, Unknown 0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 k8s.io/ingress-nginx@1.11.4 Github go
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
9 Advisories found - Critical 1, High 5, Medium 2, Low 1, Unknown 0
Critical - ingress-nginx admission controller RCE escalation
ID         GHSA-mgvx-rpfc-9mpv / CVE-2025-1974
URL        https://github.com/advisories/GHSA-mgvx-rpfc-9mpv
CVSS v3    9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
CVSS v4    N/A
EPSS       99.384% (99.9th percentile)
Published  2025-03-25 (updated 2026-02-04)
Affected   go/k8s.io/ingress-nginx < 1.11.5 (patched: 1.11.5)
           go/k8s.io/ingress-nginx >= 1.12.0-beta.0, < 1.12.1 (patched: 1.12.1)

...
```

The [`kagami.yaml`](kagami.yaml) of this repository is a larger example.

```text
kagami [OPTIONS] [CONFIG_FILE_PATH]
```

- `CONFIG_FILE_PATH`: the config file to read (default: `kagami.yaml`)
- `-o`, `--output-format`: `text` (default), `json`, `yaml` or `simple-markdown-text`
- `-l`, `--log-level`: `error`, `warn` (default), `info`, `debug` or `trace`

The options override the settings in the config file. Logs are written to stderr, so they do not
mix with the output.

## Configuration

### Targets

| Field             | Required                | Description                                                                                                                       |
|-------------------|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `advisory_type`   | Yes                     | Where to look for advisories: `github` or `github_repository` (see below).                                                        |
| `version`         | Yes                     | The version you run, as a full semantic version like `1.29.0`. `1.29` and `v1.29.0` are rejected.                                 |
| `name`            | For `github`            | The package name in the GitHub Advisory Database, like `k8s.io/kubernetes`. With `github_repository` it is only the display name. |
| `ecosystem`       | No                      | Limits the `github` search to one ecosystem, like `go`, `npm` or `pip`.                                                           |
| `repository_path` | For `github_repository` | The repository that publishes the advisories, as `owner/repo`.                                                                    |

### `github` or `github_repository`

- `github` searches the [GitHub Advisory Database](https://github.com/advisories) by package name.
  GitHub reviews these advisories and normalizes their version ranges, so prefer this type
  whenever the software is listed there. It does not have to be a library you depend on:
  Kubernetes (`k8s.io/kubernetes`), ingress-nginx (`k8s.io/ingress-nginx`), Docker Engine (`github.com/moby/moby`) and
  Argo CD (`github.com/argoproj/argo-cd/v2`) are listed as Go modules.
- `github_repository` lists the advisories that a project publishes in the "Security" tab of its
  own GitHub repository. Use it for software that is not in the database, such as the PHP
  interpreter (`php/php-src`) or Envoy Gateway (`envoyproxy/gateway`). New advisories also show up
  here before GitHub has reviewed them into the database.

### Other settings

| Field           | Default | Values                                         |
|-----------------|---------|------------------------------------------------|
| `output_format` | `text`  | `text`, `json`, `yaml`, `simple_markdown_text` |
| `log_level`     | `warn`  | `error`, `warn`, `info`, `debug`, `trace`      |

## Output

| Format                 | Description                                                                                |
|------------------------|--------------------------------------------------------------------------------------------|
| `text`                 | A colored report for the terminal.                                                         |
| `json`, `yaml`         | The full results as structured data, for scripts and other tools.                          |
| `simple-markdown-text` | One line per advisory with its severity and link, for posting to Slack or GitHub or Teams. |

kagami exits with `0` once the check has finished, whether or not it found advisories, and with
`1` when the config file is invalid or a request to GitHub fails. To fail a CI job when advisories
are found, check the JSON output, for example with [jq](https://jqlang.org/):

```sh
kagami -o json | jq -e 'all(.[]; .advisories == [])'
```

## GitHub API token

kagami reads the advisories through the GitHub REST API. It takes a token from the first of these
that is available:

1. The `GH_TOKEN` or `GITHUB_TOKEN` environment variable
2. `gh auth token`, if you are logged in with the [GitHub CLI](https://cli.github.com/)

Without a token kagami calls the API anonymously, which GitHub limits to 60 requests per hour.

> [!IMPORTANT]
> kagami only reads public data, so the token needs no extra scopes or permissions.

## How version ranges are read

kagami matches the target version against the vulnerable version ranges of each advisory.

- Ranges in the GitHub Advisory Database are normalized by GitHub.
- Ranges in repository advisories are written by hand, in shapes like `>= v1.19.0`, `All`,
  `1.2.0 through 1.8.7` or `1.20.1 and earlier`. kagami rewrites the shapes whose meaning is clear
  into semver ranges. A range that it still cannot read is logged as a warning and treated as not
  affecting the target, so check those advisories yourself.
- A list of upper bounds such as `< 1.8.4, < 1.9.1` is read as one fix per release branch
  (`>= 1.8.0, < 1.8.4 || >= 1.9.0, < 1.9.1`).
- A pre-release target such as `1.32.0-rc.2` is also checked as the release it leads to (`1.32.0`).

Hand-written ranges do not always describe every release branch precisely, so read the ranges in
the output before acting on them.

## Development

The Rust toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml), and
`rustup toolchain install` installs it. CI runs these checks on every pull request:

```sh
cargo nextest run
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`cargo test` works as well if you do not have [cargo-nextest](https://nexte.st/).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability in kagami.

## License

kagami is released under the [MIT License](LICENSE.md).

Copyright (c) 2026 ZUNDA Inc.
