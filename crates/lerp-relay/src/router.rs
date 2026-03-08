//! Pending-connection table: pairs two WebTransport connections that share the same EndpointId.
//!
//! The spec (§ 04-relay) requires:
//!   1. When connection A arrives, if no peer is waiting → suspend A for up to `pair_timeout`.
//!   2. When connection B arrives with the same EndpointId → immediately pair with A.
//!   3. Whichever side arrived first clones its `Connection` handle into the table so the second
//!      side can run the bidirectional pipe; the first side's task just exits normally.
//!
//! # DashMap usage rules
//!
//! DashMap shards are protected by **synchronous** RwLocks. Violating either rule below
//! will cause a deadlock that is impossible to debug at runtime:
//!
//! * **Rule 1**: Never hold a `Ref`, `RefMut`, or `Entry` guard across an `.await` point.
//!   Always extract the value and let the guard drop *before* any async operation.
//! * **Rule 2**: Never call `dashmap` from inside a synchronous context that already holds
//!   a shard lock (i.e., don't nest DashMap operations on the same key chain).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use tokio::sync::oneshot;
use tokio::time::timeout;
use wtransport::Connection;

use lerp_proto::identity::EndpointId;

use crate::error::RelayError;

/// Outcome returned by [`PendingTable::pair`].
pub enum PairOutcome {
    /// We are the second connection to arrive — we hold both connections and must run the pipe.
    Initiator {
        /// Our own connection.
        our_conn: Connection,
        /// The previously-waiting peer connection.
        peer_conn: Connection,
    },
    /// We were the first to arrive; our clone is already in the table for the peer to pick up.
    /// The pipe will be managed by the peer's task.
    Waiter,
    /// No peer arrived within the pair timeout; the connection should be closed.
    Timeout,
}

/// Thread-safe table of connections waiting for their peer.
///
/// Backed by a [`DashMap`] for lock-free concurrent reads and fine-grained shard locking on
/// writes, avoiding the full-table contention of a `Mutex<HashMap>`.
pub struct PendingTable {
    /// `EndpointId → (cloned Connection, notify-waiter channel)`
    ///
    /// The `Connection` stored here is a cheap clone (internal Arc); the `oneshot::Sender`
    /// is used to wake up the waiting task once a peer has been paired.
    pending: DashMap<EndpointId, PendingPeer>,
    pair_timeout: Duration,
    next_waiter_id: AtomicU64,
}

struct PendingPeer {
    conn: Connection,
    waiter_id: u64,
    notify_tx: oneshot::Sender<()>,
}

impl PendingTable {
    /// Create a new, empty table wrapped in `Arc`.
    pub fn new(pair_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            pending: DashMap::new(),
            pair_timeout,
            next_waiter_id: AtomicU64::new(1),
        })
    }

    /// Returns `true` if there is currently a connection waiting for this `eid`.
    ///
    /// This is a synchronous, lock-free check — no `.await` needed.
    pub fn has_pending(&self, eid: &EndpointId) -> bool {
        self.pending.contains_key(eid)
    }

    /// Attempt to pair `conn` with a waiting peer for `eid`.
    ///
    /// * If a peer is already waiting, removes it from the table atomically, notifies the
    ///   waiter that it is done, and returns [`PairOutcome::Initiator`] with both connections.
    /// * If no peer is waiting, stores a clone of `conn` together with a notification channel,
    ///   then awaits the peer. Returns [`PairOutcome::Waiter`] on success or
    ///   [`PairOutcome::Timeout`] if the timer fires first.
    pub async fn pair(
        &self,
        eid: EndpointId,
        conn: Connection,
    ) -> Result<PairOutcome, RelayError> {
        let (notify_rx, waiter_id) = loop {
            match self.pending.entry(eid.clone()) {
                Entry::Occupied(occupied) => {
                    // Atomic remove+pair on the same key shard.
                    let peer = occupied.remove();
                    let _ = peer.notify_tx.send(());
                    return Ok(PairOutcome::Initiator {
                        our_conn: conn,
                        peer_conn: peer.conn,
                    });
                }
                Entry::Vacant(vacant) => {
                    let (notify_tx, notify_rx) = oneshot::channel::<()>();
                    let waiter_id = self.next_waiter_id.fetch_add(1, Ordering::Relaxed);
                    vacant.insert(PendingPeer {
                        conn: conn.clone(),
                        waiter_id,
                        notify_tx,
                    });
                    break (notify_rx, waiter_id);
                }
            }
        };

        match timeout(self.pair_timeout, notify_rx).await {
            Ok(Ok(())) => {
                // Peer arrived and already removed our entry; it will run the pipe.
                Ok(PairOutcome::Waiter)
            }
            Ok(Err(_)) => {
                // Channel closed while we waited. If our exact waiter entry still exists,
                // we timed out; otherwise we were already paired.
                if self.try_remove_if_still_waiting(&eid, waiter_id) {
                    Ok(PairOutcome::Timeout)
                } else {
                    Ok(PairOutcome::Waiter)
                }
            }
            Err(_elapsed) => {
                // Timeout — remove only if our exact waiter entry is still pending.
                if self.try_remove_if_still_waiting(&eid, waiter_id) {
                    Ok(PairOutcome::Timeout)
                } else {
                    Ok(PairOutcome::Waiter)
                }
            }
        }
    }

    fn try_remove_if_still_waiting(&self, eid: &EndpointId, waiter_id: u64) -> bool {
        match self.pending.entry(eid.clone()) {
            Entry::Occupied(occupied) => {
                if occupied.get().waiter_id == waiter_id {
                    occupied.remove();
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(_) => false,
        }
    }
}

