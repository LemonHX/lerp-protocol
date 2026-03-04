//! lerp-daemon — the lerp protocol daemon / client CLI.
//!
//! # Sub-commands
//!
//! ```
//! lerp-daemon new-endpoint
//!     Generate a fresh Ed25519 endpoint identity and store it in ~/.lerp/keys/.
//!
//! lerp-daemon list-endpoints
//!     List all locally stored endpoint identities.
//!
//! lerp-daemon ticket --eid <EID> [--relay <HOST>] [--relay-sec <HEX>]
//!     Generate a shareable ticket for an endpoint.
//!
//! lerp-daemon serve
//!     Start the daemon in "serve" mode: read [[serve]] entries from
//!     ~/.lerp/config.toml and connect to the relay as a responder.
//!
//! lerp-daemon connect
//!     Start the daemon in "connect" mode: read [[connect]] entries from
//!     ~/.lerp/config.toml and expose remote endpoints as local TCP listeners.
//!
//! lerp-daemon daemon
//!     Run both serve and connect mode concurrently (all config entries).
//!
//! lerp-daemon status
//!     Query the running daemon for connection status via the IPC socket.
//! ```

mod config;
mod connect;
mod crypto;
mod error;
mod forward;
mod handshake;
mod holepunch;
mod ipc;
mod keepalive;
mod keystore;
mod serve;

use std::{path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::{
    config::Config,
    connect::{ConnectCfg, run_connect_entry},
    error::DaemonError,
    ipc::{IpcRequest, send_request},
    serve::{ServeCfg, run_serve_entry},
};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "lerp-daemon", about = "lerp protocol daemon / client")]
struct Cli {
    /// Path to the config file (default: ~/.lerp/config.toml).
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new endpoint identity (Ed25519 keypair).
    NewEndpoint,

    /// List all stored endpoint identities.
    ListEndpoints,

    /// Generate a shareable ticket for an endpoint.
    Ticket {
        /// Endpoint ID (base32).
        #[arg(long)]
        eid: String,

        /// Relay hostname (e.g. `relay.example.com`).
        #[arg(long)]
        relay: Option<String>,

        /// Relay secret, hex-encoded 32 bytes.
        #[arg(long, name = "relay-sec")]
        relay_sec: Option<String>,

        /// Arbitrary app-defined metadata fields, e.g. `--field name=alice`.
        /// May be repeated. Values are always strings; use JSON for complex types.
        #[arg(long = "field", value_name = "KEY=VALUE", value_parser = parse_field)]
        fields: Vec<(String, String)>,
    },

    /// Start the daemon as a WebTransport responder (serve mode).
    ///
    /// Reads `[[serve]]` entries from `~/.lerp/config.toml`.
    Serve,

    /// Start the daemon as an initiator (connect mode).
    ///
    /// Reads `[[connect]]` entries from `~/.lerp/config.toml`.
    Connect,

    /// Run both serve and connect mode for all config entries.
    Daemon,

    /// Query the running daemon for status (via IPC socket).
    Status,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    if let Err(e) = run(cli.command, cli.config).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cmd: Command, config_path: Option<PathBuf>) -> Result<(), DaemonError> {
    match cmd {
        Command::NewEndpoint => cmd_new_endpoint().await,
        Command::ListEndpoints => cmd_list_endpoints().await,
        Command::Ticket { eid, relay, relay_sec, fields } => {
            cmd_ticket(eid, relay, relay_sec, fields).await
        }
        Command::Serve => cmd_serve(config_path).await,
        Command::Connect => cmd_connect(config_path).await,
        Command::Daemon => cmd_daemon(config_path).await,
        Command::Status => cmd_status().await,
    }
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

async fn cmd_new_endpoint() -> Result<(), DaemonError> {
    let (_sk, eid) = keystore::generate()?;
    println!("{}", eid.to_base32());
    Ok(())
}

async fn cmd_list_endpoints() -> Result<(), DaemonError> {
    let eids = keystore::list_endpoints()?;
    if eids.is_empty() {
        println!("(no endpoints stored)");
    } else {
        for eid in &eids {
            println!("{}", eid.to_base32());
        }
    }
    Ok(())
}

async fn cmd_ticket(
    eid_b32: String,
    relay: Option<String>,
    relay_sec_hex: Option<String>,
    fields: Vec<(String, String)>,
) -> Result<(), DaemonError> {
    use lerp_proto::ticket::Ticket;

    let (_sk, eid) = keystore::load_by_b32(&eid_b32)?;

    let relay_secret: Option<[u8; 32]> = match relay_sec_hex.as_deref() {
        Some(hex) => {
            let bytes = data_encoding::HEXLOWER_PERMISSIVE
                .decode(hex.trim().as_bytes())
                .map_err(|e| DaemonError::Config(format!("invalid --relay-sec: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| DaemonError::Config("--relay-sec must be 32 bytes (64 hex chars)".into()))?;
            Some(arr)
        }
        None => None,
    };

    let mut ticket = Ticket::new(&eid);
    if let Some(host) = relay {
        if let Some(secret) = relay_secret {
            ticket = ticket.with_relay(host, secret);
        } else {
            return Err(DaemonError::Config("--relay-sec is required when --relay is set".into()));
        }
    }
    for (k, v) in fields {
        ticket.app_fields.insert(k, rmpv::Value::String(rmpv::Utf8String::from(v.as_str())));
    }

    let encoded = ticket.encode().map_err(|e| DaemonError::Ticket(e.to_string()))?;
    println!("{encoded}");
    Ok(())
}

async fn cmd_serve(config_path: Option<PathBuf>) -> Result<(), DaemonError> {
    let cfg = Config::load_from(config_path)?;
    let tasks = build_serve_tasks(&cfg)?;
    if tasks.is_empty() {
        eprintln!("warning: no [[serve]] entries in ~/.lerp/config.toml");
        return Ok(());
    }
    run_tasks(tasks, vec![]).await;
    Ok(())
}

async fn cmd_connect(config_path: Option<PathBuf>) -> Result<(), DaemonError> {
    let cfg = Config::load_from(config_path)?;
    let tasks = build_connect_tasks(&cfg)?;
    if tasks.is_empty() {
        eprintln!("warning: no [[connect]] entries in ~/.lerp/config.toml");
        return Ok(());
    }
    run_tasks(vec![], tasks).await;
    Ok(())
}

async fn cmd_daemon(config_path: Option<PathBuf>) -> Result<(), DaemonError> {
    let cfg = Config::load_from(config_path)?;
    let serve_tasks = build_serve_tasks(&cfg)?;
    let connect_tasks = build_connect_tasks(&cfg)?;
    if serve_tasks.is_empty() && connect_tasks.is_empty() {
        eprintln!("warning: no [[serve]] or [[connect]] entries in ~/.lerp/config.toml");
        return Ok(());
    }
    // Spawn IPC server alongside.
    tokio::spawn(async {
        if let Err(e) = ipc::run_ipc_server().await {
            tracing::error!("IPC server error: {e}");
        }
    });
    run_tasks(serve_tasks, connect_tasks).await;
    Ok(())
}

async fn cmd_status() -> Result<(), DaemonError> {
    let resp = send_request(&IpcRequest::Status).await?;
    println!("{}", serde_json::to_string_pretty(&resp).unwrap_or_else(|_| resp.to_string()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Argument parsers
// ---------------------------------------------------------------------------

fn parse_field(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected KEY=VALUE, got `{s}`"))
}

// ---------------------------------------------------------------------------
// Task builders
// ---------------------------------------------------------------------------

fn build_serve_tasks(cfg: &Config) -> Result<Vec<ServeCfg>, DaemonError> {
    let mut tasks = Vec::new();
    for entry in &cfg.serve {
        let (sk, eid) = keystore::load_by_b32(&entry.eid)?;

        let relay_host = entry
            .relay
            .clone()
            .ok_or_else(|| DaemonError::Config("serve entry missing `relay`".into()))?;

        let relay_secret = entry
            .relay_secret()?
            .ok_or_else(|| DaemonError::Config("serve entry missing `relay_sec_hex`".into()))?;

        tasks.push(ServeCfg {
            sk: Arc::new(sk),
            eid_b32: eid.to_base32(),
            relay_host,
            relay_secret,
            quic_port: cfg.daemon.quic_port,
            forward_addr: entry.forward.clone(),
            on_connect_hook: entry.on_connect_hook.clone(),
        });
    }
    Ok(tasks)
}

fn build_connect_tasks(cfg: &Config) -> Result<Vec<ConnectCfg>, DaemonError> {
    Ok(cfg
        .connect
        .iter()
        .map(|e| ConnectCfg {
            ticket_b64: e.ticket.clone(),
            local_port: e.local_port,
            meta: None,
            quic_port: cfg.daemon.quic_port,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Task runner
// ---------------------------------------------------------------------------

async fn run_tasks(serve: Vec<ServeCfg>, connect: Vec<ConnectCfg>) {
    let mut handles = Vec::new();

    for cfg in serve {
        handles.push(tokio::spawn(run_serve_entry(cfg)));
    }
    for cfg in connect {
        handles.push(tokio::spawn(run_connect_entry(cfg)));
    }

    // Wait for all tasks (they loop forever unless the process is killed).
    for h in handles {
        let _ = h.await;
    }
}
