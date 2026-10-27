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
- `-f`, `--fail-on-severity`: `unknown`, `low`, `medium`, `high` or `critical`, the lowest severity
  that makes kagami exit with `1` (not set by default, see [Output](#output))

The options override the settings in the config file. Logs are written to stderr, so they do not
mix with the output.

## Configuration

### Targets

| Field                        | Required                | Description                                                                                                                       |
|------------------------------|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `advisory_type`              | Yes                     | Where to look for advisories: `github` or `github_repository` (see below).                                                        |
| `version`                    | Yes                     | The version you run, as a full semantic version like `1.29.0`. `1.29` and `v1.29.0` are rejected.                                 |
| `name`                       | For `github`            | The package name in the GitHub Advisory Database, like `k8s.io/kubernetes`. With `github_repository` it is only the display name. |
| `ecosystem`                  | No                      | Limits the `github` search to one ecosystem, like `go`, `npm` or `pip`.                                                           |
| `repository_path`            | For `github_repository` | The repository that publishes the advisories, as `owner/repo`.                                                                    |
| `packages`                   | No                      | Only the advisory entries of these packages count, like `Microsoft.NETCore.App.Runtime.linux-x64` (see below).                    |
| `ignore`                     | No                      | GHSA or CVE IDs of the advisories to leave out for this target, like `GHSA-4789-qfc9-5f9q`.                                       |
| `ignore_before_published_at` | No                      | Leaves out the advisories published before this time, like `2026-08-27T01:18:49Z` (see below).                                    |

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

> [!NOTE]
> When the tags of a project are not versions of its Go module, the database writes the ranges of
> the module with pseudo-versions such as `0.0.0-20260303131938-204dbb2e3ff7`. Dex
> (`github.com/dexidp/dex`, tagged `v2.x.y` without `/v2`) is one of them. No release is inside
> such a range, so check that kind of software with `github_repository`.

### Narrowing down the results

Some projects list many packages in one advisory, each with its own platform or version scheme:
an advisory of .NET can name `Microsoft.NETCore.App.Runtime.win-x64` and
`aspnetcorev2_inprocess.dll` next to the runtime you use. With `packages`, only the entries of the
listed packages decide whether an advisory affects the target. Names are compared ignoring case,
and an entry named `Microsoft.AspNetCore.App.Runtime.*` covers every name after the dot. An entry
without a package name always counts.

```yaml
targets:
  - name: .NET Runtime
    version: 10.0.14
    advisory_type: github_repository
    repository_path: dotnet/runtime
    packages: [Microsoft.NETCore.App.Runtime.linux-x64]
```

`ignore` lists the advisories that you have checked by hand. They are left out of the output and
of `fail_on_severity` for that target. Write the IDs as the advisory does, like
`GHSA-4789-qfc9-5f9q` or `CVE-2025-49844`.

Some projects, such as Envoy and Redis, give one range for every release branch and write the fix
of each branch only in the patched versions, which kagami does not use to decide. Set
`ignore_before_published_at` to the release time of the version you run, and kagami leaves out the
advisories published before it, as that release already has their fixes. An advisory that names
no fixed version for the packages of the target, like `TBD`, is still reported.

```yaml
targets:
  - name: envoy
    version: 1.39.1
    advisory_type: github_repository
    repository_path: envoyproxy/envoy
    ignore_before_published_at: 2026-08-27T01:18:49Z
```

> [!IMPORTANT]
> `ignore_before_published_at` takes a time with its time zone. A date alone is rejected. Update
> it when you upgrade, and never set it later than the release you run, or advisories that affect
> you are left out as well.

### Other settings

| Field              | Default | Values                                         |
|--------------------|---------|------------------------------------------------|
| `output_format`    | `text`  | `text`, `json`, `yaml`, `simple_markdown_text` |
| `log_level`        | `warn`  | `error`, `warn`, `info`, `debug`, `trace`      |
| `fail_on_severity` | Not set | `unknown`, `low`, `medium`, `high`, `critical` |

## Output

| Format                 | Description                                                                                |
|------------------------|--------------------------------------------------------------------------------------------|
| `text`                 | A colored report for the terminal.                                                         |
| `json`, `yaml`         | The full results as structured data, for scripts and other tools.                          |
| `simple-markdown-text` | One line per advisory with its severity and link, for posting to Slack or GitHub or Teams. |

By default, kagami exits with `0` once the check has finished, whether or not it found advisories,
and with `1` when the config file is invalid or a request to GitHub fails.

To fail a CI job when advisories are found, set `-f` or `fail_on_severity` in the config file.
kagami writes the output as usual, then exits with `1` if it found an advisory of that severity or
higher:

```sh
kagami -f high
```

`unknown` counts as the lowest severity, so `-f unknown` fails on any advisory.

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
  (`< 1.8.4 || >= 1.9.0, < 1.9.1`). Only the versions of a listed branch from its fix on are taken
  out: the branches before the lowest bound, and the minor versions that the list skips before a
  listed branch of the same major version, stay affected, as they never got the fix.
- A version without an operator, such as `10.0.0`, means that version only (semver alone would
  read it as `^10.0.0`). Next to a bound whose release branch misses its other end, it is that
  end: `>= 5.0.0, 6.0.0` is read as `>= 5.0.0, <= 6.0.0`.
- A list of versions such as `1.37.0, 1.36.4` means exactly these versions. Some advisories use the
  same list for these and the earlier versions of their branches, which only the description tells
  apart, so read the description when your branch is in the list.
- A hyphen between two versions is a range. Without spaces (`1.9.0-1.9.6`), it is one only when a
  version with a dot follows it; otherwise it belongs to the version, as in `10.0.0-rc.1` or
  `7.1.1-4`.
- A pre-release target such as `1.32.0-rc.2` is also checked as the release it leads to (`1.32.0`).
  With `github`, GitHub picks the advisories for the exact version first, so a pre-release can get
  fewer advisories than its release.

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
