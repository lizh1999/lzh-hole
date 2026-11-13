use std::time::Duration;

use tokio::sync::{mpsc, watch};

use super::*;
use crate::dto::{ComponentState, DaemonState, DropCounters, MAX_DROP_REASONS, ServiceSnapshot};

fn runtime_config(directory: &Path) -> ControlConfig {
    ControlConfig::new(
        directory.join("control").join("control.sock"),
        effective_uid(),
    )
    .unwrap()
}

#[test]
fn protocol_is_doctor_only_closed_and_bounded() {
    assert_eq!(
        serde_json::to_string(&ControlRequest::Doctor).unwrap(),
        r#"{"command":"doctor"}"#
    );
    for rejected in [
        r#"{"command":"status"}"#,
        r#"{"command":"reconnect"}"#,
        r#"{"command":"shell","line":"id"}"#,
        r#"{"command":"doctor","path":"/"}"#,
    ] {
        assert!(serde_json::from_str::<ControlRequest>(rejected).is_err());
    }
    let codec = LinesCodec::new_with_max_length(MAX_CONTROL_LINE_BYTES);
    assert_eq!(codec.max_length(), MAX_CONTROL_LINE_BYTES);
}

#[test]
fn default_snapshot_does_not_claim_networking_or_external_acceptance() {
    let snapshot = ServiceSnapshot::default();
    assert_eq!(snapshot.daemon.state, DaemonState::Unknown);
    assert_eq!(snapshot.ntfy.state, ComponentState::Unknown);
    assert_eq!(snapshot.lan.state, ComponentState::Unknown);
    assert_eq!(snapshot.stun.state, ComponentState::Unknown);
    assert_eq!(snapshot.session.state, ComponentState::Unknown);
    assert_eq!(snapshot.tun.state, ComponentState::Unknown);
    assert_eq!(snapshot.routes.state, ComponentState::Unknown);
    assert_eq!(snapshot.overlay.direct_reachable, None);
    assert_eq!(snapshot.overlay.currently_healthy, None);
    assert!(snapshot.current_path.is_none());
    assert!(snapshot.candidates.is_empty());
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("functional_pass"));
    assert!(!json.contains("p0_qualified"));
}

#[test]
fn additive_doctor_fields_remain_strict_and_round_trip() {
    let snapshot = ServiceSnapshot::default();
    let mut value = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(
        serde_json::from_value::<ServiceSnapshot>(value.clone()).unwrap(),
        snapshot,
    );
    value["discovery"]["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ServiceSnapshot>(value).is_err());
}

#[test]
fn drop_reasons_are_bounded() {
    let mut drops = DropCounters::default();
    assert!(drops.record("bad_mac", 2));
    assert!(drops.record("bad_mac", 3));
    assert_eq!(drops.total, 5);
    assert_eq!(drops.reasons["bad_mac"], 5);
    assert!(!drops.record(" attacker-controlled ", 1));
    for index in 1..MAX_DROP_REASONS {
        assert!(drops.record(&format!("reason_{index}"), 1));
    }
    assert!(!drops.record("one_too_many", 1));
    assert_eq!(drops.reasons.len(), MAX_DROP_REASONS);
}

#[test]
fn peer_uid_policy_allows_only_root_and_manager() {
    assert!(uid_allowed(0, 501));
    assert!(uid_allowed(501, 501));
    assert!(!uid_allowed(502, 501));
}

#[tokio::test(flavor = "current_thread")]
async fn existing_file_is_never_removed() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(temp.path());
    std::fs::create_dir(config.socket_path.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        config.socket_path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(&config.socket_path, b"not a socket").unwrap();
    let (command_tx, _command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let result = ControlServer::bind(&config, command_tx);
    assert!(matches!(result, Err(ControlError::AlreadyExists(_))));
    assert_eq!(std::fs::read(&config.socket_path).unwrap(), b"not a socket");
}

#[tokio::test(flavor = "current_thread")]
async fn doctor_round_trip_and_clean_shutdown_release_resources() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(temp.path());
    let socket_path = config.socket_path.clone();
    let (command_tx, mut command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let server = ControlServer::bind(&config, command_tx).unwrap();
    let metadata = std::fs::symlink_metadata(&socket_path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.serve(shutdown_rx));
    let worker = tokio::spawn(async move {
        let ServiceCommand::Doctor { reply } = command_rx.recv().await.unwrap();
        let mut report = ServiceSnapshot::starting(1234, 10);
        report.mark_daemon_running(11);
        report.ntfy.state = ComponentState::Healthy;
        reply.send(Ok(report)).unwrap();
    });

    let response = crate::doctor(&socket_path).await.unwrap();
    let ControlResponse::Doctor { report } = response else {
        panic!("expected doctor response");
    };
    assert_eq!(report.daemon.state, DaemonState::Running);
    assert_eq!(report.ntfy.state, ComponentState::Healthy);

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    worker.await.unwrap();
    assert!(!socket_path.exists());
}
