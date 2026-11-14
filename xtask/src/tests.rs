use super::*;
use std::os::unix::fs::symlink;
use std::process::Output;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

struct Mock {
    temp: tempfile::TempDir,
    base: PathBuf,
    bundle: PathBuf,
    bin: PathBuf,
}

impl Mock {
    fn new(loaded: bool) -> Self {
        let temp = tempfile::Builder::new()
            .prefix("lzh-hole mock ")
            .tempdir()
            .unwrap();
        let base = temp.path().canonicalize().unwrap();
        let bundle = base.join("package with spaces");
        let bin = base.join("sys/libexec/lzh-hole");
        for path in [
            &bundle,
            bin.parent().unwrap(),
            &base.join("sys/etc"),
            &base.join("sys/launchd"),
            &base.join("state"),
            &base.join("tools"),
        ] {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(
            base.join("sys/etc/config.toml"),
            b"synthetic existing config\n",
        )
        .unwrap();
        fs::write(
            base.join("state/ntfy-pacing.json"),
            b"synthetic persistent pacing\n",
        )
        .unwrap();
        let template = fs::read_to_string(root().join(TEMPLATES).join("com.lzhhole.daemon.plist"))
            .unwrap()
            .replace("/usr/local/libexec/lzh-hole", bin.to_str().unwrap())
            .replace(
                "/etc/lzh-hole/config.toml",
                base.join("sys/etc/config.toml").to_str().unwrap(),
            )
            .replace("/var/db/lzh-hole", base.join("state").to_str().unwrap());
        fs::write(bundle.join("com.lzhhole.daemon.plist"), &template).unwrap();
        fs::write(bundle.join("config.toml.example"), b"synthetic example\n").unwrap();
        fs::copy(root().join("xtask/install.sh"), bundle.join("install.sh")).unwrap();
        fs::write(bundle.join("manifest.json"), r#"{"package":"lzh-hole","version":"0.1.0","target":"aarch64-apple-darwin","minimum_macos":"11.0"}"#).unwrap();
        let binary = r#"#!/bin/bash
set -eu
ROOT=__ROOT__
NEW=__NEW__
if [[ $1 = --version ]]; then echo 'lzh-hole 0.1.0'; exit 0; fi
if [[ $1 = doctor && $2 = --preflight ]]; then
    [[ ! -e "$ROOT/preflight_fail" ]] || exit 1
    printf '{"state_dir":"%s/state","control_socket":"%s/control.sock","peer_vip":"10.203.0.2"}\n' "$ROOT" "$ROOT"
    exit 0
fi
[[ -e "$ROOT/loaded" ]] || exit 1
[[ $NEW = 0 || ! -e "$ROOT/fail_ready" ]] || exit 1
printf '%s\n' '{"report":{"daemon":{"state":"running","pid":424242},"tun":{"state":"healthy","detail":"actual utun999 if_index=99 mtu=1200"},"routes":{"state":"healthy"},"overlay":{"direct_reachable":false,"currently_healthy":false}}}'
"#.replace("__ROOT__", &quote(base.to_str().unwrap()));
        fs::write(bundle.join("lzh-hole"), binary.replace("__NEW__", "1")).unwrap();
        fs::set_permissions(bundle.join("lzh-hole"), fs::Permissions::from_mode(0o755)).unwrap();
        if loaded {
            fs::write(&bin, binary.replace("__NEW__", "0")).unwrap();
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(base.join("loaded"), "").unwrap();
            fs::write(base.join("control.sock"), "").unwrap();
            fs::write(
                base.join("sys/launchd/daemon.plist"),
                format!("{template}\n<!-- retain custom content -->\n"),
            )
            .unwrap();
        }
        let tools = [
            (
                "launchctl",
                r#"case "$1" in
print) [[ -e "$ROOT/loaded" ]] || exit 1; echo 'pid = 424242' ;;
bootout) echo bootout >> "$ROOT/events"; /bin/rm -f "$ROOT/loaded" "$ROOT/control.sock" ;;
bootstrap) echo bootstrap >> "$ROOT/events"
 if [[ -e "$ROOT/fail_bootstrap" ]]; then /bin/rm "$ROOT/fail_bootstrap"; exit 1; fi
 : > "$ROOT/loaded"; : > "$ROOT/control.sock" ;;
*) exit 9 ;;
esac
"#,
            ),
            ("ifconfig", r#"[[ -e "$ROOT/loaded" ]]"#),
            (
                "netstat",
                r#"echo 'Destination Gateway Flags Netif'
if [[ -e "$ROOT/loaded" || -e "$ROOT/cleanup_stuck" ]]; then echo '10.203.0.2 10.203.0.1 UH utun999'; fi
"#,
            ),
        ];
        for (name, body) in tools {
            let path = base.join("tools").join(name);
            fs::write(
                &path,
                format!(
                    "#!/bin/bash\nset -eu\nROOT={}\n{body}\n",
                    quote(base.to_str().unwrap())
                ),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let this = Self {
            temp,
            base,
            bundle,
            bin,
        };
        this.rehash();
        this
    }
    fn rehash(&self) {
        let sums = PAYLOAD
            .into_iter()
            .map(|name| format!("{}  {name}\n", sha256(&self.bundle.join(name)).unwrap()))
            .collect::<String>();
        fs::write(self.bundle.join("SHA256SUMS"), sums).unwrap();
    }
    fn run(&self, args: &[&str]) -> Output {
        let mut script = format!(
            "source {}\n",
            quote(root().join("xtask/install.sh").to_str().unwrap())
        );
        for (name, path) in [
            ("BUNDLE", self.bundle.clone()),
            ("BIN", self.bin.clone()),
            ("CONFIG", self.base.join("sys/etc/config.toml")),
            ("EXAMPLE", self.base.join("sys/etc/config.toml.example")),
            ("STATE", self.base.join("state")),
            ("SOCKET", self.base.join("control.sock")),
            ("PLIST", self.base.join("sys/launchd/daemon.plist")),
            ("LAUNCHCTL", self.base.join("tools/launchctl")),
            ("IFCONFIG", self.base.join("tools/ifconfig")),
            ("NETSTAT", self.base.join("tools/netstat")),
        ] {
            script.push_str(&format!("{name}={}\n", quote(path.to_str().unwrap())));
        }
        script.push_str(r#"
# Mock only through sourcing/functions. Production exposes no privileged test overrides.
is_root() { return 0; }
platform_check() { :; }
process_alive() { return 1; }
install_file() { /usr/bin/install -m "$1" "$2" "$3"; }
destination_check() {
 for path in "$BIN" "$CONFIG" "$EXAMPLE" "$PLIST" "$STATE" "$SOCKET"; do safe_path "$path" || return 1; done
}
STOP_TIMEOUT=0
START_TIMEOUT=0
main "$@"
"#);
        Command::new("/bin/bash")
            .args(["-c", &script, "mock-installer"])
            .args(args)
            .current_dir(self.temp.path())
            .output()
            .unwrap()
    }
    fn events(&self) -> String {
        fs::read_to_string(self.base.join("events")).unwrap_or_default()
    }
    fn old_bytes(&self) -> Vec<u8> {
        fs::read(&self.bin).unwrap()
    }
    fn preserved(&self) {
        assert_eq!(
            fs::read(self.base.join("sys/etc/config.toml")).unwrap(),
            b"synthetic existing config\n"
        );
        assert_eq!(
            fs::read(self.base.join("state/ntfy-pacing.json")).unwrap(),
            b"synthetic persistent pacing\n"
        );
    }
    fn lock(&self) -> PathBuf {
        self.bin.parent().unwrap().join(".lzh-hole-install.lock")
    }
}

fn success(out: &Output) {
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
fn failure(out: &Output) {
    assert!(
        !out.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn fresh_install_does_not_create_state_or_register_service() {
    let m = Mock::new(false);
    fs::remove_dir_all(m.base.join("state")).unwrap();
    success(&m.run(&["--yes"]));
    assert_eq!(
        fs::read(&m.bin).unwrap(),
        fs::read(m.bundle.join("lzh-hole")).unwrap()
    );
    assert!(!m.base.join("state").exists());
    assert!(!m.base.join("sys/launchd/daemon.plist").exists());
    assert!(m.events().is_empty());
    assert!(!m.lock().exists());
    assert_eq!(
        fs::metadata(&m.bin).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn upgrade_preserves_config_custom_plist_pacing_and_is_idempotent() {
    let m = Mock::new(true);
    let plist = fs::read(m.base.join("sys/launchd/daemon.plist")).unwrap();
    success(&m.run(&["--yes"]));
    assert_eq!(m.events(), "bootout\nbootstrap\n");
    assert_eq!(
        fs::read(m.base.join("sys/launchd/daemon.plist")).unwrap(),
        plist
    );
    assert!(m.base.join("loaded").exists());
    m.preserved();
    success(&m.run(&["--yes"]));
    assert_eq!(m.events(), "bootout\nbootstrap\n");
    assert!(!m.lock().exists());
}

#[test]
fn plist_program_override_is_checked_before_stopping_service() {
    for matches_binary in [false, true] {
        let m = Mock::new(true);
        let path = m.base.join("sys/launchd/daemon.plist");
        let old = m.old_bytes();
        let program = if matches_binary {
            m.bin.clone()
        } else {
            m.base.join("other-old-binary")
        };
        let plist = fs::read_to_string(&path).unwrap().replace(
            "<key>ProgramArguments</key>",
            &format!(
                "<key>Program</key><string>{}</string><key>ProgramArguments</key>",
                program.display()
            ),
        );
        fs::write(&path, &plist).unwrap();
        let out = m.run(&["--yes"]);
        if matches_binary {
            success(&out);
            assert_eq!(m.events(), "bootout\nbootstrap\n");
        } else {
            failure(&out);
            assert_eq!(m.old_bytes(), old);
            assert!(m.events().is_empty());
            assert!(m.base.join("loaded").exists());
            assert!(!m.lock().exists());
        }
        assert_eq!(fs::read_to_string(path).unwrap(), plist);
        m.preserved();
    }
}

#[test]
fn dry_run_and_noninteractive_without_consent_do_not_write() {
    let m = Mock::new(true);
    let old = m.old_bytes();
    success(&m.run(&["--dry-run"]));
    failure(&m.run(&[]));
    assert_eq!(m.old_bytes(), old);
    assert!(m.events().is_empty());
    assert!(!m.lock().exists());
    m.preserved();
}

#[test]
fn corrupt_or_omitted_checksum_payload_is_rejected_before_stop() {
    let m = Mock::new(true);
    let old = m.old_bytes();
    fs::write(m.bundle.join("config.toml.example"), b"tampered").unwrap();
    failure(&m.run(&["--yes"]));
    m.rehash();
    let sums = fs::read_to_string(m.bundle.join("SHA256SUMS")).unwrap();
    fs::write(
        m.bundle.join("SHA256SUMS"),
        sums.lines().skip(1).collect::<Vec<_>>().join("\n"),
    )
    .unwrap();
    failure(&m.run(&["--yes"]));
    assert_eq!(m.old_bytes(), old);
    assert!(m.events().is_empty());
}

#[test]
fn preflight_failure_does_not_stop_existing_service() {
    let m = Mock::new(true);
    fs::write(m.base.join("preflight_fail"), "").unwrap();
    let old = m.old_bytes();
    failure(&m.run(&["--yes"]));
    assert_eq!(m.old_bytes(), old);
    assert!(m.events().is_empty());
    assert!(m.base.join("loaded").exists());
    assert!(!m.lock().exists());
    m.preserved();
}

#[test]
fn cleanup_timeout_keeps_backup_and_never_deletes_resources() {
    let m = Mock::new(true);
    fs::write(m.base.join("cleanup_stuck"), "").unwrap();
    let old = m.old_bytes();
    let out = m.run(&["--yes"]);
    failure(&out);
    assert_eq!(m.old_bytes(), old);
    assert_eq!(m.events(), "bootout\n");
    assert!(m.lock().join("old-bin").exists());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ROLLBACK FAILED"));
    m.preserved();
}

#[test]
fn bootstrap_or_readiness_failure_restores_previous_running_binary() {
    for marker in ["fail_bootstrap", "fail_ready"] {
        let m = Mock::new(true);
        fs::write(m.base.join(marker), "").unwrap();
        let old = m.old_bytes();
        failure(&m.run(&["--yes"]));
        assert_eq!(m.old_bytes(), old, "{marker}");
        assert!(m.base.join("loaded").exists(), "{marker}");
        assert!(!m.lock().exists(), "{marker}");
        assert!(!m.base.join("sys/etc/config.toml.example").exists());
        m.preserved();
    }
}

#[test]
fn enabling_requires_explicit_tun_permission_and_valid_preflight() {
    let m = Mock::new(false);
    failure(&m.run(&["--yes", "--enable-service"]));
    failure(&m.run(&["--yes", "--allow-tun"]));
    fs::write(m.base.join("preflight_fail"), "").unwrap();
    failure(&m.run(&["--yes", "--enable-service", "--allow-tun"]));
    assert!(!m.base.join("loaded").exists());
    assert!(!m.base.join("sys/launchd/daemon.plist").exists());
    fs::remove_file(m.base.join("preflight_fail")).unwrap();
    success(&m.run(&["--yes", "--enable-service", "--allow-tun"]));
    assert!(m.base.join("loaded").exists());
    assert!(m.base.join("sys/launchd/daemon.plist").exists());
    m.preserved();
}

#[test]
fn unloaded_existing_install_is_not_started_on_upgrade() {
    let m = Mock::new(true);
    fs::remove_file(m.base.join("loaded")).unwrap();
    fs::remove_file(m.base.join("control.sock")).unwrap();
    success(&m.run(&["--yes"]));
    assert!(!m.base.join("loaded").exists());
    assert!(m.events().is_empty());
    m.preserved();
}

#[test]
fn destination_symlink_and_concurrent_installer_are_refused() {
    let m = Mock::new(false);
    symlink(m.bundle.join("lzh-hole"), &m.bin).unwrap();
    failure(&m.run(&["--yes"]));
    fs::remove_file(&m.bin).unwrap();
    fs::create_dir(m.lock()).unwrap();
    fs::write(m.lock().join("sentinel"), "keep").unwrap();
    failure(&m.run(&["--yes"]));
    assert_eq!(
        fs::read_to_string(m.lock().join("sentinel")).unwrap(),
        "keep"
    );
    assert!(!m.bin.exists());
}

#[test]
fn only_system_dynamic_libraries_are_accepted_and_minimum_is_recorded() {
    assert!(
        system_libraries("binary:\n /usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n")
            .is_ok()
    );
    assert!(
        system_libraries(
            "binary:\n /opt/homebrew/lib/libfoo.dylib (compatibility version 1.0.0)\n"
        )
        .is_err()
    );
    assert!(
        system_libraries("binary:\n @rpath/libfoo.dylib (compatibility version 1.0.0)\n").is_err()
    );
    assert!(system_libraries("binary:\n").is_err());
    assert_eq!(
        minimum_macos(" cmd LC_BUILD_VERSION\n platform 1\n minos 11.0\n sdk 27.0").unwrap(),
        "11.0"
    );
    assert!(minimum_macos(" cmd LC_UUID\n version 1.0").is_err());
}

#[test]
fn bundle_archive_is_allowlisted_checksummed_and_executable() {
    let m = Mock::new(false);
    let staging = tempfile::tempdir().unwrap();
    let bundle = staging.path().join("bundle");
    let manifest = Manifest {
        package: "lzh-hole",
        version: "0.1.0",
        git_revision: "1234567890abcdef".into(),
        dirty: true,
        target: TARGET,
        rustc: "synthetic".into(),
        minimum_macos: "11.0".into(),
        compatibility_tested: "not tested",
    };
    let archive = assemble(&root(), &m.bundle.join("lzh-hole"), &bundle, &manifest).unwrap();
    let list = Command::new("/usr/bin/tar")
        .arg("-tzf")
        .arg(&archive)
        .output()
        .unwrap();
    success(&list);
    let names = String::from_utf8(list.stdout).unwrap();
    assert_eq!(
        names.lines().collect::<Vec<_>>(),
        PAYLOAD
            .into_iter()
            .chain(["SHA256SUMS"])
            .collect::<Vec<_>>()
    );
    success(
        &Command::new("/usr/bin/shasum")
            .args(["-a", "256", "-c", "SHA256SUMS"])
            .current_dir(&bundle)
            .output()
            .unwrap(),
    );
    assert_eq!(
        fs::metadata(bundle.join("install.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(
        archive
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("-dirty-")
    );
}

#[test]
fn failed_publication_restores_previous_dist() {
    let temp = tempfile::tempdir().unwrap();
    let dest = temp.path().join("dist");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("sentinel"), "previous complete bundle").unwrap();
    assert!(publish(&temp.path().join("missing-bundle"), &dest, temp.path()).is_err());
    assert_eq!(
        fs::read_to_string(dest.join("sentinel")).unwrap(),
        "previous complete bundle"
    );
}
