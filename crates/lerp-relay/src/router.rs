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

use std::sync::Arc;
use std::time::Duration;

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
    pending: DashMap<EndpointId, (Connection, oneshot::Sender<()>)>,
    pair_timeout: Duration,
}

impl PendingTable {
    /// Create a new, empty table wrapped in `Arc`.
    pub fn new(pair_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            pending: DashMap::new(),
            pair_timeout,
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
        // --- Check if a peer is already waiting ---
        //
        // IMPORTANT: `remove` returns `Option<(K, V)>`. We extract the value immediately and
        // let the DashMap guard drop so we never hold it across the `notify_tx.send()` call or
        // any future await point. (Rule 1)
        let maybe_waiting = self.pending.remove(&eid).map(|(_, v)| v);

        if let Some((peer_conn, notify_tx)) = maybe_waiting {
            // Notify the waiter that it has been paired — fire-and-forget; if it already timed
            // out the send just fails silently.
            let _ = notify_tx.send(());
            return Ok(PairOutcome::Initiator {
                our_conn: conn,
                peer_conn,
            });
        }

        // --- No peer yet — register ourselves as the waiter ---
        let (notify_tx, notify_rx) = oneshot::channel::<()>();

        // Insert and immediately drop the DashMap entry guard (Rule 1: no guard across await).
        self.pending.insert(eid.clone(), (conn.clone(), notify_tx));

        // Now it is safe to await — no DashMap guard is held.
        match timeout(self.pair_timeout, notify_rx).await {
            Ok(Ok(())) => {
                // Peer arrived and already removed our entry; it will run the pipe.
                Ok(PairOutcome::Waiter)
            }
            Ok(Err(_)) => {
                // Sender dropped without sending — shouldn't happen; treat as timeout.
                self.pending.remove(&eid);
                Ok(PairOutcome::Timeout)
            }
            Err(_elapsed) => {
                // Timeout — remove our stale entry.
                self.pending.remove(&eid);
                Ok(PairOutcome::Timeout)
            }
        }
    }
}

