//! Developer-only offline validation and macOS/arm64 distribution packaging.
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Serialize;
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const TARGET: &str = "aarch64-apple-darwin";
const PAYLOAD: [&str; 5] = [
    "install.sh",
    "lzh-hole",
    "config.toml.example",
    "com.lzhhole.daemon.plist",
    "manifest.json",
];
const TEMPLATES: &str = ".agents/skills/lzh-hole-ops/templates";

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("missing workspace")?;
    let args: Vec<_> = env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["check"] => check(root),
        ["dist"] => dist(root),
        [] | ["--help"] | ["-h"] => {
            println!(
                "cargo xtask check  Full offline checks (no network/privileges)\ncargo xtask dist   Check, build and package into dist/ (macOS arm64)"
            );
            Ok(())
        }
        _ => Err("expected check or dist; see cargo xtask --help".into()),
    }
}

fn run(command: &mut Command) -> Result<()> {
    eprintln!("+ {command:?}");
    let status = command.status()?;
    if !status.success() {
        return Err(format!("command exited {status}: {command:?}").into());
    }
    Ok(())
}

fn output(root: &Path, program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .current_dir(root)
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "{program} {args:?} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn cargo(root: &Path, args: &[&str]) -> Result<()> {
    run(Command::new("cargo").current_dir(root).args(args))
}

fn check(root: &Path) -> Result<()> {
    cargo(root, &["build", "--release", "--locked", "--offline"])?;
    cargo(root, &["fmt", "--all", "--", "--check"])?;
    cargo(
        root,
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--offline",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    cargo(root, &["test", "--workspace", "--locked", "--offline"])?;
    for args in [
        vec!["--help"],
        vec!["daemon", "--help"],
        vec!["doctor", "--help"],
        vec!["pair", "--help"],
    ] {
        let mut full = vec!["run", "--locked", "--offline", "--bin", "lzh-hole", "--"];
        full.extend(args);
        cargo(root, &full)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Manifest {
    package: &'static str,
    version: &'static str,
    git_revision: String,
    dirty: bool,
    target: &'static str,
    rustc: String,
    minimum_macos: String,
    // This is build metadata, not a claim of cross-version runtime acceptance.
    compatibility_tested: &'static str,
}

fn system_libraries(text: &str) -> Result<()> {
    let mut count = 0;
    for line in text.lines().skip(1).filter(|line| !line.trim().is_empty()) {
        let library = line
            .trim()
            .split(" (compatibility version")
            .next()
            .unwrap_or("");
        if !library.starts_with("/usr/lib/") && !library.starts_with("/System/Library/") {
            return Err(format!("non-system dynamic dependency: {library}").into());
        }
        count += 1;
    }
    if count == 0 {
        return Err("otool returned no dynamic libraries".into());
    }
    Ok(())
}

fn minimum_macos(text: &str) -> Result<String> {
    let mut build_version = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("cmd ") {
            build_version = line == "cmd LC_BUILD_VERSION" || line == "cmd LC_VERSION_MIN_MACOSX";
        } else if build_version {
            for key in ["minos ", "version "] {
                if let Some(value) = line.strip_prefix(key)
                    && !value.is_empty()
                    && value.chars().all(|c| c.is_ascii_digit() || c == '.')
                {
                    return Ok(value.to_owned());
                }
            }
        }
    }
    Err("cannot determine Mach-O minimum macOS version".into())
}

fn sha256(path: &Path) -> Result<String> {
    let mut input = fs::File::open(path)?;
    let mut hash = Sha256::new();
    io::copy(&mut input, &mut hash)?;
    Ok(format!("{:x}", hash.finalize()))
}

fn assemble(root: &Path, binary: &Path, bundle: &Path, manifest: &Manifest) -> Result<PathBuf> {
    fs::create_dir(bundle)?;
    for (source, name, mode) in [
        (root.join("xtask/install.sh"), "install.sh", 0o755),
        (binary.to_path_buf(), "lzh-hole", 0o755),
        (
            root.join(TEMPLATES).join("config.toml.example"),
            "config.toml.example",
            0o644,
        ),
        (
            root.join(TEMPLATES).join("com.lzhhole.daemon.plist"),
            "com.lzhhole.daemon.plist",
            0o644,
        ),
    ] {
        fs::copy(source, bundle.join(name))?;
        fs::set_permissions(bundle.join(name), fs::Permissions::from_mode(mode))?;
    }
    fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec_pretty(manifest)?,
    )?;
    let mut sums = String::new();
    for name in PAYLOAD {
        sums.push_str(&format!("{}  {name}\n", sha256(&bundle.join(name))?));
    }
    fs::write(bundle.join("SHA256SUMS"), sums)?;
    let revision = &manifest.git_revision[..12.min(manifest.git_revision.len())];
    if !revision.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid git revision".into());
    }
    let suffix = if manifest.dirty { "-dirty" } else { "" };
    let name = format!(
        "lzh-hole-{}-{revision}{suffix}-{TARGET}.tar.gz",
        manifest.version
    );
    let archive = bundle.join(&name);
    let mut command = Command::new("/usr/bin/tar");
    command
        .current_dir(bundle)
        .env("COPYFILE_DISABLE", "1")
        .args(["-czf"])
        .arg(&archive)
        .args(PAYLOAD)
        .arg("SHA256SUMS");
    run(&mut command)?;
    fs::write(
        bundle.join(format!("{name}.sha256")),
        format!("{}  {name}\n", sha256(&archive)?),
    )?;
    Ok(archive)
}

fn publish(bundle: &Path, destination: &Path, staging: &Path) -> Result<()> {
    let backup = staging.join("previous-dist");
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("dist is not a real directory".into());
            }
            fs::rename(destination, &backup)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Err(error) = fs::rename(bundle, destination) {
        if backup.exists() {
            fs::rename(&backup, destination)?;
        }
        return Err(error.into());
    }
    Ok(())
}

fn dist(root: &Path) -> Result<()> {
    if env::consts::OS != "macos" || env::consts::ARCH != "aarch64" {
        return Err("dist must be built locally on Apple Silicon macOS".into());
    }
    // Do not touch dist until every check, build, copy and archive operation succeeds.
    check(root)?;
    cargo(
        root,
        &[
            "build",
            "--release",
            "--locked",
            "--offline",
            "--bin",
            "lzh-hole",
            "--target",
            TARGET,
            "--target-dir",
            "target",
        ],
    )?;
    let binary = root.join("target").join(TARGET).join("release/lzh-hole");
    let binary_str = binary.to_str().ok_or("non-UTF8 workspace path")?;
    if output(root, "/usr/bin/lipo", &["-archs", binary_str])? != "arm64" {
        return Err("binary must contain only arm64".into());
    }
    system_libraries(&output(root, "/usr/bin/otool", &["-L", binary_str])?)?;
    let manifest = Manifest {
        package: "lzh-hole",
        version: env!("CARGO_PKG_VERSION"),
        git_revision: output(root, "git", &["rev-parse", "HEAD"])?,
        dirty: !output(
            root,
            "git",
            &["status", "--porcelain", "--untracked-files=normal"],
        )?
        .is_empty(),
        target: TARGET,
        rustc: output(root, "rustc", &["--version"])?,
        minimum_macos: minimum_macos(&output(root, "/usr/bin/otool", &["-l", binary_str])?)?,
        compatibility_tested: "not a cross-version or network acceptance claim",
    };
    run(Command::new("/bin/bash")
        .args(["-n"])
        .arg(root.join("xtask/install.sh")))?;
    let staging_root = root.join("target/xtask");
    fs::create_dir_all(&staging_root)?;
    let staging = tempfile::Builder::new()
        .prefix("dist-")
        .tempdir_in(staging_root)?;
    let bundle = staging.path().join("bundle");
    let archive = assemble(root, &binary, &bundle, &manifest)?;
    let filename = archive
        .file_name()
        .ok_or("missing archive name")?
        .to_owned();
    publish(&bundle, &root.join("dist"), staging.path())?;
    println!(
        "Distribution ready: {}\nInstaller: {}\nArchive: {}",
        root.join("dist").display(),
        root.join("dist/install.sh").display(),
        root.join("dist").join(filename).display()
    );
    Ok(())
}

#[cfg(test)]
mod tests;
