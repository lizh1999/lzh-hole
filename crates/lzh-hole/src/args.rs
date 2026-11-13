use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "lzh-hole",
    version,
    about = "Direct-only IPv4-over-UDP networking for two paired macOS hosts",
    long_about = "No business traffic is relayed through a third party.\n\
                  Payload is authenticated with HMAC-SHA256 but NOT encrypted."
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Create or inspect a local identity in a private state directory.
    Init(InitArgs),
    /// Exchange pairing material over a channel you already trust.
    Pair {
        #[command(subcommand)]
        action: PairAction,
    },
    /// Run the resident direct-only engine. Network access is explicit by this command.
    Daemon(DaemonArgs),
    /// Request fresh actual daemon/subsystem observations.
    Doctor(ControlArgs),
}

#[derive(Args)]
pub(crate) struct InitArgs {
    /// State directory. Created with mode 0700.
    #[arg(long)]
    pub(crate) state: PathBuf,
    /// Replace an existing identity. The old one is not recoverable.
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Subcommand)]
pub(crate) enum PairAction {
    /// Create an offer containing a fresh relationship PSK.
    Offer(PairOfferArgs),
    /// Accept an offer, binding your own public key to it.
    Accept(PairAcceptArgs),
    /// Verify the acceptance and finalise the relationship locally.
    Finalize(PairFinalizeArgs),
}

#[derive(Args)]
pub(crate) struct PairOfferArgs {
    /// Your state directory.
    #[arg(long)]
    pub(crate) state: PathBuf,
    /// Expected responder public key, z-base-32 or hex.
    #[arg(long)]
    pub(crate) peer_key: String,
    /// Your overlay address.
    #[arg(long)]
    pub(crate) self_vip: String,
    /// The peer's overlay address.
    #[arg(long)]
    pub(crate) peer_vip: String,
    /// Where to write the offer file. Created with mode 0600.
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct PairAcceptArgs {
    /// Your state directory.
    #[arg(long)]
    pub(crate) state: PathBuf,
    /// The offer file you received.
    #[arg(long)]
    pub(crate) offer: PathBuf,
    /// Where to write the acceptance file. Created with mode 0600.
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum PairRoleArg {
    /// We created the offer and are verifying an acceptance.
    Initiator,
    /// We accepted an offer and are verifying the offer itself.
    Responder,
}

#[derive(Args)]
pub(crate) struct PairFinalizeArgs {
    /// Your state directory.
    #[arg(long)]
    pub(crate) state: PathBuf,
    /// Which side of the pairing you are.
    #[arg(long, value_enum)]
    pub(crate) role: PairRoleArg,
    /// The peer public key you expect. Anything else is refused.
    #[arg(long)]
    pub(crate) expect_peer_key: String,
    /// The acceptance file. Required for the initiator.
    #[arg(long)]
    pub(crate) accept: Option<PathBuf>,
    /// The offer file. Required for the responder.
    #[arg(long)]
    pub(crate) offer: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct DaemonArgs {
    /// Explicit non-secret service TOML. VIPs and peer identity come from pairing.
    #[arg(long)]
    pub(crate) config: PathBuf,
    /// Explicitly permit creating utun and its one owned peer /32 route.
    #[arg(long)]
    pub(crate) allow_tun: bool,
}

#[derive(Args)]
pub(crate) struct ControlArgs {
    /// Daemon control socket inside its private directory.
    #[arg(long)]
    pub(crate) socket: PathBuf,
}
