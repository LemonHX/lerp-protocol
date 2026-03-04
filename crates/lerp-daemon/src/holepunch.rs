//! P2P direct-connection (hole-punching) module.
//!
//! Current implementation focus:
//! - Keep relay as fallback path (make-before-break).
//! - Exchange candidates via LPP `AddrOffer` on uni streams (msgpack).
//! - Include relay-observed public IP (QAD) in candidate set when available.
//! - Prefer direct path for newly opened streams once direct is up.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, timeout};
use wtransport::endpoint::endpoint_side;
use wtransport::stream::{RecvStream, SendStream};
use wtransport::{ClientConfig, Connection, Endpoint, Identity, ServerConfig};

use lerp_proto::identity::{EndpointId, SecretKey};
use lerp_proto::lpp::{self, AddrOffer, Close, LppMessage, ProbeSuccess};

use crate::{
    error::DaemonError,
    handshake,
};

const HOLEPUNCH_TIMEOUT: Duration = Duration::from_secs(20);
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const CONTROL_STEP_TIMEOUT: Duration = Duration::from_secs(6);
const DIRECT_PATH: &str = "/lerp-direct";

type ServerEndpoint = Endpoint<endpoint_side::Server>;
type ClientEndpoint = Endpoint<endpoint_side::Client>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectConnRole {
    InboundAccept,
    OutboundDial,
}

#[derive(Clone)]
pub struct DirectPath {
    pub conn: Arc<Connection>,
    pub chosen_peer_addr: String,
    role: DirectConnRole,
    _endpoint_guard: Arc<dyn std::any::Any + Send + Sync>,
}

pub fn spawn_initiator(
    relay: Arc<Connection>,
    our_sk: Arc<SecretKey>,
    peer_eid: String,
    quic_port: Option<u16>,
    observed_public_ip: Option<IpAddr>,
) -> watch::Receiver<Option<DirectPath>> {
    let (tx, rx) = watch::channel(None::<DirectPath>);
    let our_eid = our_sk.endpoint_id().to_base32();

    tokio::spawn(async move {
        log_holepunch_start(&our_eid, &peer_eid, "initiator");

        match timeout(
            HOLEPUNCH_TIMEOUT,
            run_initiator(
                &relay,
                Arc::clone(&our_sk),
                &our_eid,
                &peer_eid,
                quic_port,
                observed_public_ip,
            ),
        )
        .await
        {
            Ok(Ok(path)) => {
                log_p2p_victory(&our_eid, &peer_eid, "initiator", &path.chosen_peer_addr);
                let _ = tx.send(Some(path.clone()));
                monitor_direct_initiator(path, tx, peer_eid).await;
            }
            Ok(Err(e)) => {
                tracing::warn!("holepunch[init]: failed ({e}), staying on relay");
            }
            Err(_) => {
                tracing::warn!(
                    timeout_s = HOLEPUNCH_TIMEOUT.as_secs(),
                    "holepunch[init]: timed out, staying on relay"
                );
            }
        }
    });

    rx
}

pub async fn open_bi(
    relay: &Connection,
    direct_rx: &watch::Receiver<Option<DirectPath>>,
) -> Result<(SendStream, RecvStream), DaemonError> {
    let direct = direct_rx.borrow().clone();
    if let Some(d) = direct {
        match try_open_bi(&d.conn).await {
            Ok(pair) => return Ok(pair),
            Err(e) => {
                tracing::warn!("holepunch[init]: direct open_bi failed ({e}), using relay");
            }
        }
    }
    try_open_bi(relay).await
}

pub fn spawn_responder(
    relay: Arc<Connection>,
    our_sk: Arc<SecretKey>,
    peer_eid: String,
    quic_port: Option<u16>,
    observed_public_ip: Option<IpAddr>,
) -> mpsc::UnboundedReceiver<(SendStream, RecvStream)> {
    let (stream_tx, stream_rx) = mpsc::unbounded_channel::<(SendStream, RecvStream)>();
    let our_eid = our_sk.endpoint_id().to_base32();

    tokio::spawn(async move {
        log_holepunch_start(&our_eid, &peer_eid, "responder");

        let direct = match timeout(
            HOLEPUNCH_TIMEOUT,
            run_responder(
                &relay,
                Arc::clone(&our_sk),
                &our_eid,
                &peer_eid,
                quic_port,
                observed_public_ip,
            ),
        )
        .await
        {
            Ok(Ok(p)) => {
                log_p2p_victory(&our_eid, &peer_eid, "responder", &p.chosen_peer_addr);
                Some(p)
            }
            Ok(Err(e)) => {
                tracing::warn!("holepunch[resp]: failed ({e}), staying on relay");
                None
            }
            Err(_) => {
                tracing::warn!(
                    timeout_s = HOLEPUNCH_TIMEOUT.as_secs(),
                    "holepunch[resp]: timed out, staying on relay"
                );
                None
            }
        };

        let relay_for_loop = Arc::clone(&relay);
        let stream_tx_relay = stream_tx.clone();
        let peer_eid_relay = peer_eid.clone();
        tokio::spawn(async move {
            loop {
                match relay_for_loop.accept_bi().await {
                    Ok((s, r)) => {
                        tracing::debug!(peer = %peer_eid_relay, "holepunch[resp]: stream on relay path");
                        if stream_tx_relay.send((s, r)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(peer = %peer_eid_relay, "holepunch[resp]: relay accept_bi ended: {e}");
                        break;
                    }
                }
            }
        });

        if let Some(path) = direct {
            let stream_tx_direct = stream_tx.clone();
            let peer_eid_direct = peer_eid.clone();
            tokio::spawn(async move {
                loop {
                    match path.conn.accept_bi().await {
                        Ok((s, r)) => {
                            tracing::debug!(peer = %peer_eid_direct, "holepunch[resp]: stream on DIRECT path ✓");
                            if stream_tx_direct.send((s, r)).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(peer = %peer_eid_direct, "holepunch[resp]: direct path closed ({e}), relay still active");
                            break;
                        }
                    }
                }
            });
        }

        drop(stream_tx);
    });

    stream_rx
}

async fn run_initiator(
    relay: &Connection,
    our_sk: Arc<SecretKey>,
    our_eid: &str,
    peer_eid: &str,
    quic_port: Option<u16>,
    observed_public_ip: Option<IpAddr>,
) -> Result<DirectPath, DaemonError> {
    let expected_peer = EndpointId::from_base32(peer_eid)
        .map_err(|e| DaemonError::Handshake(format!("invalid peer eid for direct path: {e}")))?;
    let we_send_du = our_eid < peer_eid;

    let (server_ep, local_port) = start_direct_server(quic_port).await?;
    let our_addrs = collect_local_candidates(local_port, observed_public_ip);
    tracing::info!(candidates = ?our_addrs, "holepunch[init]: local candidates prepared");

    send_addr_offer(relay, our_addrs.clone()).await?;
    tracing::debug!("holepunch[init]: AddrOffer sent");

    let peer_addrs = recv_addr_offer(relay).await?;
    tracing::info!(candidates = ?peer_addrs, "holepunch[init]: peer AddrOffer received");

    let path = race_direct_connection(peer_eid, server_ep, peer_addrs, we_send_du).await?;
    validate_direct_identity(&path, &our_sk, &expected_peer).await?;
    complete_upgrade_signaling(relay, our_eid, peer_eid, we_send_du, &path.chosen_peer_addr).await?;
    Ok(path)
}

async fn run_responder(
    relay: &Connection,
    our_sk: Arc<SecretKey>,
    our_eid: &str,
    peer_eid: &str,
    quic_port: Option<u16>,
    observed_public_ip: Option<IpAddr>,
) -> Result<DirectPath, DaemonError> {
    let expected_peer = EndpointId::from_base32(peer_eid)
        .map_err(|e| DaemonError::Handshake(format!("invalid peer eid for direct path: {e}")))?;
    let we_send_du = our_eid < peer_eid;

    let (server_ep, local_port) = start_direct_server(quic_port).await?;
    let our_addrs = collect_local_candidates(local_port, observed_public_ip);
    tracing::info!(candidates = ?our_addrs, "holepunch[resp]: local candidates prepared");

    send_addr_offer(relay, our_addrs.clone()).await?;
    tracing::debug!("holepunch[resp]: AddrOffer sent");

    let peer_addrs = recv_addr_offer(relay).await?;
    tracing::info!(candidates = ?peer_addrs, "holepunch[resp]: peer AddrOffer received");

    let path = race_direct_connection(peer_eid, server_ep, peer_addrs, we_send_du).await?;
    validate_direct_identity(&path, &our_sk, &expected_peer).await?;
    complete_upgrade_signaling(relay, our_eid, peer_eid, we_send_du, &path.chosen_peer_addr).await?;
    Ok(path)
}

async fn race_direct_connection(
    peer_eid: &str,
    server_ep: Arc<ServerEndpoint>,
    peer_addrs: Vec<String>,
    prefer_outbound: bool,
) -> Result<DirectPath, DaemonError> {
    let (winner_tx, mut winner_rx) = mpsc::unbounded_channel::<DirectPath>();

    {
        let winner_tx = winner_tx.clone();
        let server_ep_accept = Arc::clone(&server_ep);
        let peer_eid = peer_eid.to_string();
        tokio::spawn(async move {
            let incoming = server_ep_accept.accept().await;
            match incoming.await {
                Ok(req) => {
                    let from = req.remote_address().to_string();
                    match req.accept().await {
                        Ok(conn) => {
                            tracing::info!(peer = %peer_eid, from = %from, "holepunch: inbound direct QUIC connected");
                            let endpoint_guard: Arc<dyn std::any::Any + Send + Sync> = server_ep_accept;
                            let _ = winner_tx.send(DirectPath {
                                conn: Arc::new(conn),
                                chosen_peer_addr: from,
                                role: DirectConnRole::InboundAccept,
                                _endpoint_guard: endpoint_guard,
                            });
                        }
                        Err(e) => {
                            tracing::debug!(peer = %peer_eid, from = %from, "holepunch: inbound direct accept failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(peer = %peer_eid, "holepunch: inbound direct wait ended: {e}");
                }
            }
        });
    }

    if !peer_addrs.is_empty() {
        let client_cfg = ClientConfig::builder()
            .with_bind_default()
            .with_no_cert_validation()
            .build();
        let client_ep: Arc<ClientEndpoint> = Arc::new(
            Endpoint::client(client_cfg)
                .map_err(|e| DaemonError::WebTransport(format!("direct client endpoint: {e}")))?,
        );

        for addr in peer_addrs {
            let winner_tx = winner_tx.clone();
            let client_ep = Arc::clone(&client_ep);
            let peer_eid = peer_eid.to_string();
            tokio::spawn(async move {
                let url = format!("https://{addr}{DIRECT_PATH}");
                tracing::debug!(peer = %peer_eid, %url, "holepunch: probing direct candidate");
                match client_ep.connect(&url).await {
                    Ok(conn) => {
                        tracing::info!(peer = %peer_eid, %url, "holepunch: outbound direct QUIC connected");
                        let endpoint_guard: Arc<dyn std::any::Any + Send + Sync> = client_ep;
                        let _ = winner_tx.send(DirectPath {
                            conn: Arc::new(conn),
                            chosen_peer_addr: addr,
                            role: DirectConnRole::OutboundDial,
                            _endpoint_guard: endpoint_guard,
                        });
                    }
                    Err(e) => {
                        tracing::debug!(peer = %peer_eid, %url, "holepunch: direct candidate failed: {e}");
                    }
                }
            });
        }
    }

    drop(winner_tx);

    let preferred_role = if prefer_outbound {
        DirectConnRole::OutboundDial
    } else {
        DirectConnRole::InboundAccept
    };

    let deadline = Instant::now() + DIRECT_CONNECT_TIMEOUT;
    let mut fallback: Option<DirectPath> = None;

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }

        let remaining = deadline - now;
        match timeout(remaining, winner_rx.recv()).await {
            Ok(Some(path)) => {
                if path.role == preferred_role {
                    tracing::debug!(
                        peer = %peer_eid,
                        role = ?path.role,
                        preferred = ?preferred_role,
                        "holepunch: selected preferred direct connection role"
                    );
                    return Ok(path);
                }

                tracing::debug!(
                    peer = %peer_eid,
                    role = ?path.role,
                    preferred = ?preferred_role,
                    "holepunch: received non-preferred direct role, keeping as fallback"
                );
                if fallback.is_none() {
                    fallback = Some(path);
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    if let Some(path) = fallback {
        tracing::warn!(
            peer = %peer_eid,
            role = ?path.role,
            preferred = ?preferred_role,
            "holepunch: preferred direct role not observed in time, using fallback role"
        );
        Ok(path)
    } else {
        Err(DaemonError::WebTransport(format!(
            "direct connection timed out ({}s)",
            DIRECT_CONNECT_TIMEOUT.as_secs()
        )))
    }
}

async fn monitor_direct_initiator(
    direct: DirectPath,
    tx: watch::Sender<Option<DirectPath>>,
    peer_eid: String,
) {
    direct.conn.closed().await;
    tracing::warn!(peer = %peer_eid, "holepunch[init]: direct path closed — falling back to relay");
    let _ = tx.send(None);
}

async fn start_direct_server(
    quic_port: Option<u16>,
) -> Result<(Arc<ServerEndpoint>, u16), DaemonError> {
    let identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"])
        .map_err(|e| DaemonError::WebTransport(format!("self-signed cert: {e}")))?;

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], quic_port.unwrap_or(0)));
    let server_cfg = ServerConfig::builder()
        .with_bind_address(bind_addr)
        .with_identity(identity)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();

    let endpoint = Arc::new(
        Endpoint::server(server_cfg)
            .map_err(|e| DaemonError::WebTransport(format!("direct endpoint: {e}")))?,
    );

    let local_port = endpoint.local_addr().map_err(DaemonError::Io)?.port();
    tracing::info!(bind = %bind_addr, actual_port = local_port, "holepunch: direct WT server listening");

    Ok((endpoint, local_port))
}

fn collect_local_candidates(port: u16, observed_public_ip: Option<IpAddr>) -> Vec<String> {
    if port == 0 {
        return Vec::new();
    }

    let mut ips = Vec::<IpAddr>::new();

    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            let ip = iface.ip();
            if !ip.is_loopback() {
                ips.push(ip);
            }
        }
    }

    if let Some(ip) = observed_public_ip {
        if !ip.is_loopback() {
            ips.push(ip);
        }
    }

    ips.sort();
    ips.dedup();

    ips.into_iter().map(|ip| format_host_port(ip, port)).collect()
}

fn format_host_port(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

async fn complete_upgrade_signaling(
    relay: &Connection,
    our_eid: &str,
    peer_eid: &str,
    we_send_du: bool,
    chosen_peer_addr: &str,
) -> Result<(), DaemonError> {
    send_probe_success(relay, chosen_peer_addr).await?;
    tracing::info!(peer = %peer_eid, addr = %chosen_peer_addr, "holepunch: ProbeSuccess sent");

    let peer_probe = recv_probe_success(relay).await?;
    tracing::info!(peer = %peer_eid, addr = %peer_probe, "holepunch: ProbeSuccess received");

    if we_send_du {
        send_direct_upgrade(relay).await?;
        tracing::info!(our = %our_eid, peer = %peer_eid, "holepunch: DirectUpgrade sent (we are initiator)");

        recv_direct_ack(relay).await?;
        tracing::info!(our = %our_eid, peer = %peer_eid, "holepunch: DirectAck received");
    } else {
        recv_direct_upgrade(relay).await?;
        tracing::info!(our = %our_eid, peer = %peer_eid, "holepunch: DirectUpgrade received (peer initiates)");

        send_direct_ack(relay).await?;
        tracing::info!(our = %our_eid, peer = %peer_eid, "holepunch: DirectAck sent");
    }

    Ok(())
}

async fn validate_direct_identity(
    path: &DirectPath,
    our_sk: &SecretKey,
    expected_peer: &EndpointId,
) -> Result<(), DaemonError> {
    match path.role {
        DirectConnRole::OutboundDial => {
            let _ = handshake::initiator_handshake(&path.conn, our_sk, expected_peer, None).await?;
            tracing::info!(peer = %expected_peer.to_base32(), "holepunch: direct outbound identity verified");
        }
        DirectConnRole::InboundAccept => {
            let hs = handshake::responder_handshake(&path.conn, our_sk).await?;
            if hs.peer_eid != *expected_peer {
                return Err(DaemonError::Handshake(format!(
                    "direct eid mismatch: expected {}, got {}",
                    expected_peer.to_base32(),
                    hs.peer_eid.to_base32()
                )));
            }
            tracing::info!(peer = %expected_peer.to_base32(), "holepunch: direct inbound identity verified");
        }
    }

    Ok(())
}

async fn send_probe_success(conn: &Connection, addr: &str) -> Result<(), DaemonError> {
    send_control_message(
        conn,
        LppMessage::ProbeSuccess(ProbeSuccess {
            addr: addr.to_string(),
        }),
    )
    .await
}

async fn recv_probe_success(conn: &Connection) -> Result<String, DaemonError> {
    loop {
        match recv_control_message(conn).await? {
            LppMessage::ProbeSuccess(ProbeSuccess { addr }) => return Ok(addr),
            LppMessage::Close(Close { reason }) => {
                return Err(DaemonError::Handshake(format!(
                    "peer sent Close while waiting ProbeSuccess: {reason}"
                )));
            }
            other => {
                tracing::debug!(?other, "holepunch: ignoring control while waiting ProbeSuccess");
            }
        }
    }
}

async fn send_direct_upgrade(conn: &Connection) -> Result<(), DaemonError> {
    send_control_message(conn, LppMessage::DirectUpgrade).await
}

async fn recv_direct_upgrade(conn: &Connection) -> Result<(), DaemonError> {
    loop {
        match recv_control_message(conn).await? {
            LppMessage::DirectUpgrade => return Ok(()),
            LppMessage::Close(Close { reason }) => {
                return Err(DaemonError::Handshake(format!(
                    "peer sent Close while waiting DirectUpgrade: {reason}"
                )));
            }
            other => {
                tracing::debug!(?other, "holepunch: ignoring control while waiting DirectUpgrade");
            }
        }
    }
}

async fn send_direct_ack(conn: &Connection) -> Result<(), DaemonError> {
    send_control_message(conn, LppMessage::DirectAck).await
}

async fn recv_direct_ack(conn: &Connection) -> Result<(), DaemonError> {
    loop {
        match recv_control_message(conn).await? {
            LppMessage::DirectAck => return Ok(()),
            LppMessage::Close(Close { reason }) => {
                return Err(DaemonError::Handshake(format!(
                    "peer sent Close while waiting DirectAck: {reason}"
                )));
            }
            other => {
                tracing::debug!(?other, "holepunch: ignoring control while waiting DirectAck");
            }
        }
    }
}

async fn send_control_message(conn: &Connection, msg: LppMessage) -> Result<(), DaemonError> {
    let bytes = lpp::encode(&msg).map_err(|e| DaemonError::Handshake(e.to_string()))?;
    handshake::send_uni(conn, &bytes).await
}

async fn recv_control_message(conn: &Connection) -> Result<LppMessage, DaemonError> {
    let bytes = timeout(CONTROL_STEP_TIMEOUT, handshake::recv_uni(conn))
        .await
        .map_err(|_| DaemonError::Handshake("timed out waiting for control message".into()))??;

    lpp::decode(&bytes).map_err(|e| DaemonError::Handshake(e.to_string()))
}

async fn send_addr_offer(conn: &Connection, addrs: Vec<String>) -> Result<(), DaemonError> {
    let bytes = lpp::encode(&LppMessage::AddrOffer(AddrOffer { addrs }))
        .map_err(|e| DaemonError::Handshake(e.to_string()))?;
    handshake::send_uni(conn, &bytes).await
}

async fn recv_addr_offer(conn: &Connection) -> Result<Vec<String>, DaemonError> {
    loop {
        let bytes = handshake::recv_uni(conn).await?;
        let msg = lpp::decode(&bytes).map_err(|e| DaemonError::Handshake(e.to_string()))?;

        match msg {
            LppMessage::AddrOffer(offer) => return Ok(offer.addrs),
            LppMessage::Close(Close { reason }) => {
                return Err(DaemonError::Handshake(format!(
                    "peer sent Close while waiting AddrOffer: {reason}"
                )));
            }
            other => {
                tracing::debug!(?other, "holepunch: ignoring non-AddrOffer control message");
            }
        }
    }
}

fn log_holepunch_start(our_eid: &str, peer_eid: &str, role: &str) {
    tracing::info!(our = %our_eid, peer = %peer_eid, role = %role, "holepunch: start direct-upgrade workflow");
}

fn log_p2p_victory(our_eid: &str, peer_eid: &str, our_role: &str, chosen_peer_addr: &str) {
    tracing::info!(
        our = %our_eid,
        peer = %peer_eid,
        role = %our_role,
        selected = %chosen_peer_addr,
        "holepunch: direct path established; new streams prefer direct, relay kept as fallback"
    );
}

async fn try_open_bi(conn: &Connection) -> Result<(SendStream, RecvStream), DaemonError> {
    let (s, r) = conn
        .open_bi()
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?;
    Ok((s, r))
}
