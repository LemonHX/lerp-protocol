use std::sync::Arc;
use std::time::Duration;

use tokio::time::{self, Instant, MissedTickBehavior};
use wtransport::{Connection, VarInt};

use lerp_proto::lpp::{self, LppMessage, Ping, Pong};

const PING_INTERVAL: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(10);
const SILENT_RECONNECT_WINDOW: Duration = Duration::from_secs(90);
const MISSED_LIMIT: u8 = 3;
const KEEPALIVE_CLOSE_CODE: u32 = 0x1001;

pub fn spawn_relay_keepalive(conn: Arc<Connection>, peer_eid: String) {
    tokio::spawn(async move {
        run_relay_keepalive(conn, peer_eid).await;
    });
}

async fn run_relay_keepalive(conn: Arc<Connection>, peer_eid: String) {
    let mut ticker = time::interval(PING_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;

    let mut seq = 0u64;
    let mut pending_ping: Option<(u64, Instant)> = None;
    let mut consecutive_misses: u8 = 0;
    let mut last_activity = Instant::now();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let now = Instant::now();

                if let Some((pending_seq, sent_at)) = pending_ping {
                    if now.duration_since(sent_at) >= PING_TIMEOUT {
                        consecutive_misses = consecutive_misses.saturating_add(1);
                        tracing::warn!(
                            peer = %peer_eid,
                            seq = pending_seq,
                            misses = consecutive_misses,
                            "keepalive: ping timeout"
                        );
                    }
                }

                let silent_for = now.duration_since(last_activity);
                if consecutive_misses >= MISSED_LIMIT && silent_for >= SILENT_RECONNECT_WINDOW {
                    tracing::warn!(
                        peer = %peer_eid,
                        misses = consecutive_misses,
                        silent_for_s = silent_for.as_secs(),
                        "keepalive: relay considered dead; closing connection"
                    );
                    conn.close(VarInt::from_u32(KEEPALIVE_CLOSE_CODE), b"keepalive timeout");
                    break;
                }

                seq = seq.wrapping_add(1);
                if let Err(e) = send_ping(&conn, seq) {
                    tracing::warn!(peer = %peer_eid, "keepalive: failed to send ping: {e}");
                    break;
                }
                pending_ping = Some((seq, now));
            }

            dgram = conn.receive_datagram() => {
                match dgram {
                    Ok(d) => {
                        last_activity = Instant::now();
                        let payload = d.payload();
                        if let Err(e) = handle_datagram(&conn, &peer_eid, &payload, &mut pending_ping, &mut consecutive_misses) {
                            tracing::debug!(peer = %peer_eid, "keepalive: datagram handling error: {e}");
                        }
                    }
                    Err(e) => {
                        tracing::debug!(peer = %peer_eid, "keepalive: receive_datagram ended: {e}");
                        break;
                    }
                }
            }

            _ = conn.closed() => {
                tracing::debug!(peer = %peer_eid, "keepalive: relay connection closed");
                break;
            }
        }
    }
}

fn handle_datagram(
    conn: &Connection,
    peer_eid: &str,
    payload: &[u8],
    pending_ping: &mut Option<(u64, Instant)>,
    consecutive_misses: &mut u8,
) -> Result<(), String> {
    let msg = lpp::decode(payload).map_err(|e| e.to_string())?;

    match msg {
        LppMessage::Ping(Ping { seq }) => {
            send_pong(conn, seq).map_err(|e| e.to_string())?;
            tracing::debug!(peer = %peer_eid, seq, "keepalive: ping received; pong sent");
        }
        LppMessage::Pong(Pong { seq }) => {
            if let Some((pending_seq, _)) = *pending_ping {
                if pending_seq == seq {
                    *pending_ping = None;
                    *consecutive_misses = 0;
                    tracing::debug!(peer = %peer_eid, seq, "keepalive: pong matched pending ping");
                } else {
                    tracing::debug!(peer = %peer_eid, seq, pending_seq, "keepalive: pong seq mismatch");
                }
            } else {
                tracing::debug!(peer = %peer_eid, seq, "keepalive: pong without pending ping");
            }
        }
        other => {
            tracing::debug!(peer = %peer_eid, ?other, "keepalive: ignoring non-ping datagram");
        }
    }

    Ok(())
}

fn send_ping(conn: &Connection, seq: u64) -> Result<(), String> {
    let bytes = lpp::encode(&LppMessage::Ping(Ping { seq })).map_err(|e| e.to_string())?;
    conn.send_datagram(&bytes).map_err(|e| e.to_string())
}

fn send_pong(conn: &Connection, seq: u64) -> Result<(), String> {
    let bytes = lpp::encode(&LppMessage::Pong(Pong { seq })).map_err(|e| e.to_string())?;
    conn.send_datagram(&bytes).map_err(|e| e.to_string())
}
