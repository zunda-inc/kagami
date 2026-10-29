// kagami reads `--version` itself instead of clap, so that `--fancy` can come with it. The version
// is printed before the config file is read, so these runs pass a config file that does not exist.
use std::process::Command;

#[test]
fn version_is_printed_as_by_clap() {
    let output = Command::new(env!("CARGO_BIN_EXE_kagami"))
        .args(["--version", "missing.yaml"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("kagami {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn fancy_version_shows_the_version_in_its_title() {
    let output = Command::new(env!("CARGO_BIN_EXE_kagami"))
        .args(["-V", "--fancy", "missing.yaml"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(
        stdout.contains(format!("kagami {}", env!("CARGO_PKG_VERSION")).as_str()),
        "{stdout}"
    );
}

// `--fancy` alone is a usage error, which clap exits with `2`.
#[test]
fn fancy_requires_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_kagami"))
        .arg("--fancy")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "");
}
