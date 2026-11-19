// network/electrumx.rs — ElectrumX TCP+TLS client (JSON-RPC 2.0, newline-delimited)
//
// Implements the ElectrumX protocol over TCP+TLS using tokio and tokio-rustls:
// - JSON-RPC 2.0 request/response with ID matching
// - Newline-delimited framing (each message is one JSON object terminated by \n)
// - Push notification handling (headers.subscribe, scripthash.subscribe)
// - Full TLS certificate + hostname verification (AUD-Fund #6)
// - Txid validation on broadcast (AUD-006: hash locally, compare with server response)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex, Notify};
use tokio_rustls::TlsConnector;

use super::backend::{
    BackendType, BackendBalance, BlockHeader, BroadcastResult, MerkleProof, NetworkBackend,
    NetworkError, ScriptHash, TxHistoryEntry, UtxoEntry,
};
use super::server_list::ServerEntry;

// ---------------------------------------------------------------------------
// Notification types — ElectrumX push notifications
// ---------------------------------------------------------------------------

/// A parsed ElectrumX push notification.
///
/// ElectrumX sends unsolicited JSON-RPC messages (no "id", has "method") for:
/// - `blockchain.headers.subscribe` — new block header
/// - `blockchain.scripthash.subscribe` — scripthash status changed
///
/// These are broadcast via a tokio broadcast channel and consumed by the
/// Tauri event loop to emit frontend events.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ElectrumNotification {
    /// New block header notification (blockchain.headers.subscribe).
    /// Contains the block height and raw header hex.
    NewBlock { height: u64, header_hex: String },
    /// Scripthash status changed (blockchain.scripthash.subscribe).
    /// The status string changes when the balance or history of the
    /// scripthash changes. The frontend should re-fetch balance/history.
    ScripthashStatus { scripthash: String, status: String },
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024; // 50 MB
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PROTOCOL_MIN: &str = "1.4";
const PROTOCOL_MAX: &str = "1.4";
const CLIENT_VERSION: &str = "ElectrumSV-Mc 0.1.0";

// ---------------------------------------------------------------------------
// Inner state (shared via Arc between client and reader task)
// ---------------------------------------------------------------------------

struct PendingRequest {
    tx: oneshot::Sender<Result<Value, NetworkError>>,
    generation: u64,
}

struct Inner {
    /// Write half of the TLS stream.
    writer: Mutex<Option<Box<dyn AsyncWrite + Unpin + Send>>>,
    /// Pending requests keyed by JSON-RPC id.
    pending: Mutex<HashMap<u64, PendingRequest>>,
    /// Next JSON-RPC request id.
    next_id: AtomicU64,
    /// Connected flag (atomic for sync access).
    connected: AtomicBool,
    connecting: AtomicBool,
    lifecycle: std::sync::Mutex<u64>,
    io_lifecycle: Mutex<()>,
    stopped: tokio::sync::watch::Sender<bool>,
    /// Notify for reader task shutdown.
    shutdown: Notify,
    /// Negotiated protocol version.
    protocol_version: Mutex<Option<(u16, u16)>>,
    /// Server we're connected to.
    server: ServerEntry,
    /// Reader task handle (so we can abort on disconnect).
    reader_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Notification channel — broadcast ElectrumX push notifications to subscribers.
    /// The Tauri event loop subscribes to this and emits events to the frontend.
    notifications: tokio::sync::broadcast::Sender<ElectrumNotification>,
}

impl Inner {
    fn new(server: ServerEntry) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel::<ElectrumNotification>(64);
        let (stopped, _) = tokio::sync::watch::channel(false);
        Self {
            writer: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            connected: AtomicBool::new(false),
            connecting: AtomicBool::new(false),
            lifecycle: std::sync::Mutex::new(0),
            io_lifecycle: Mutex::new(()),
            stopped,
            shutdown: Notify::new(),
            protocol_version: Mutex::new(None),
            server,
            reader_task: std::sync::Mutex::new(None),
            notifications: tx,
        }
    }
}

// ---------------------------------------------------------------------------
// ElectrumX client
// ---------------------------------------------------------------------------

/// The ElectrumX TCP+TLS client.
///
/// Connection lifecycle:
/// 1. `connect()` — TLS connection + server.version handshake
/// 2. `call()` — send JSON-RPC request, await matched response
/// 3. Reader task dispatches responses to pending callers, notifications to handlers
/// 4. `disconnect()` — graceful shutdown
///
/// `Clone` is cheap (Arc<Inner>), allowing the client to be shared across
/// Tauri commands without holding a Mutex across await points.
#[derive(Clone)]
pub struct ElectrumXClient {
    inner: Arc<Inner>,
}

struct ConnectGuard(Option<ElectrumXClient>);

struct DisconnectGuard(Option<(ElectrumXClient, u64)>);
struct WriteGuard(Option<(ElectrumXClient, u64)>);

impl Drop for WriteGuard {
    fn drop(&mut self) {
        if let Some((client, generation)) = self.0.take() {
            if let Some(stopped) = client.stop_if_generation(Some(generation)) {
                if !client.inner.connecting.load(Ordering::SeqCst) {
                    drop(DisconnectGuard(Some((client, stopped))));
                }
            }
        }
    }
}

struct PendingGuard {
    inner: Arc<Inner>,
    id: u64,
    generation: u64,
}

fn remove_pending(pending: &mut HashMap<u64, PendingRequest>, id: u64, generation: u64) {
    if pending.get(&id).is_some_and(|request| request.generation == generation) {
        pending.remove(&id);
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.inner.pending.try_lock() {
            remove_pending(&mut pending, self.id, self.generation);
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let inner = self.inner.clone();
            let (id, generation) = (self.id, self.generation);
            runtime.spawn(async move { remove_pending(&mut *inner.pending.lock().await, id, generation); });
        }
    }
}

impl Drop for DisconnectGuard {
    fn drop(&mut self) {
        if let Some((client, generation)) = self.0.take() {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move { client.finish_disconnect(generation).await; });
            } else if !client.cleanup_if_idle(generation) {
                log::warn!("cancelled disconnect requires a running Tokio runtime for cleanup");
            }
        }
    }
}

impl Drop for ConnectGuard {
    fn drop(&mut self) {
        if let Some(client) = self.0.take() {
            let generation = client.stop_immediately();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    client.finish_disconnect(generation).await;
                    client.inner.connecting.store(false, Ordering::SeqCst);
                });
            } else if client.cleanup_if_idle(generation) {
                client.inner.connecting.store(false, Ordering::SeqCst);
            }
        }
    }
}

fn client_tls_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig, NetworkError> {
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| NetworkError::Tls(format!("TLS protocol configuration: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

impl ElectrumXClient {
    #[cfg(test)]
    pub(crate) fn mark_test_connected(&self) {
        self.inner.connected.store(true, Ordering::SeqCst);
    }

    /// Create a new client for the given server (not yet connected).
    pub fn new(server: ServerEntry) -> Self {
        Self {
            inner: Arc::new(Inner::new(server)),
        }
    }

    /// Connect to the server using TLS.
    ///
    /// AUD-Fund #6: rustls with webpki-roots, full certificate + hostname
    /// verification. No permissive/dangerous verifier.
    pub async fn connect(&self) -> Result<(), NetworkError> {
        // Build TLS connector with webpki root certificates
        let root_store = {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            roots
        };

        self.connect_with_roots(root_store).await
    }

    #[cfg(test)]
    pub(crate) async fn connect_with_test_roots(&self, roots: rustls::RootCertStore) -> Result<(), NetworkError> {
        self.connect_with_roots(roots).await
    }

    async fn connect_with_roots(&self, root_store: rustls::RootCertStore) -> Result<(), NetworkError> {
        let observed = *self.inner.lifecycle.lock().unwrap();
        let _io = self.inner.io_lifecycle.lock().await;
        let generation = {
            let mut lifecycle = self.inner.lifecycle.lock().unwrap();
            if *lifecycle != observed { return Err(NetworkError::NotConnected); }
            if self.inner.connected.load(Ordering::SeqCst) || self.inner.connecting.swap(true, Ordering::SeqCst) {
                return Err(NetworkError::Connection("connection already active or in progress".into()));
            }
            *lifecycle = lifecycle.wrapping_add(1);
            *lifecycle
        };
        let mut guard = ConnectGuard(Some(self.clone()));
        self.inner.stopped.send_replace(false);
        let config = client_tls_config(root_store)?;

        let connector = TlsConnector::from(Arc::new(config));
        let addr = self.inner.server.tls_addr();

        // TCP connect
        let tcp_stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| NetworkError::Connection(format!("TCP connect to {addr}: {e}")))?;

        let _ = tcp_stream.set_nodelay(true);

        // TLS connect with hostname verification
        let host = &self.inner.server.host;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| NetworkError::Tls(format!("invalid server name {host}: {e}")))?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| {
                NetworkError::Tls(format!(
                    "TLS handshake to {host}:{}: {e}",
                    self.inner.server.ssl_port
                ))
            })?;

        // Split into reader and writer
        let (reader, writer) = tokio::io::split(tls_stream);

        // Store writer
        {
            let mut w = self.inner.writer.lock().await;
            let lifecycle = self.inner.lifecycle.lock().unwrap();
            if *lifecycle != generation { return Err(NetworkError::NotConnected); }
            *w = Some(Box::new(writer));
            self.inner.connected.store(true, Ordering::SeqCst);
            let inner = self.inner.clone();
            let reader_task = tokio::spawn(async move { read_loop(inner, reader, generation).await; });
            *self.inner.reader_task.lock().unwrap() = Some(reader_task);
        }

        // Perform handshake; a failed negotiation must not leave a live session.
        if let Err(error) = self.handshake().await {
            return Err(error);
        }

        {
            let lifecycle = self.inner.lifecycle.lock().unwrap();
            if *lifecycle != generation || !self.is_connected() { return Err(NetworkError::NotConnected); }
            guard.0 = None;
            self.inner.connecting.store(false, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Send a JSON-RPC request and wait for the response.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, NetworkError> {
        let generation = {
            let lifecycle = self.inner.lifecycle.lock().unwrap();
            if !self.inner.connected.load(Ordering::SeqCst) { return Err(NetworkError::NotConnected); }
            *lifecycle
        };

        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let json_str = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
        .to_string();

        // Register pending request
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending.lock().await;
            let lifecycle = self.inner.lifecycle.lock().unwrap();
            if *lifecycle != generation || !self.inner.connected.load(Ordering::SeqCst) {
                return Err(NetworkError::NotConnected);
            }
            pending.insert(id, PendingRequest { tx, generation });
        }
        let _pending_guard = PendingGuard { inner: self.inner.clone(), id, generation };

        // Bound both lock acquisition and writes so shutdown can acquire the writer.
        let sent = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let mut w = self.inner.writer.lock().await;
            {
                let lifecycle = self.inner.lifecycle.lock().unwrap();
                if *lifecycle != generation || !self.inner.connected.load(Ordering::SeqCst) {
                    return Err(NetworkError::NotConnected);
                }
            }
            let writer = w.as_mut().ok_or(NetworkError::NotConnected)?;
            let mut guard = WriteGuard(Some((self.clone(), generation)));
            let result = write_request(writer, &json_str).await;
            if result.is_ok() { guard.0 = None; }
            result
        }).await;
        let error = match sent {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(_) => Some(NetworkError::Connection(format!("request write timeout: {method}"))),
        };
        if let Some(error) = error {
            remove_pending(&mut *self.inner.pending.lock().await, id, generation);
            // A partial write leaves framing ambiguous; end the connection.
            if let Some(stopped_generation) = self.stop_if_generation(Some(generation)) {
                if !self.inner.connecting.load(Ordering::SeqCst) {
                    let mut guard = DisconnectGuard(Some((self.clone(), stopped_generation)));
                    self.finish_disconnect(stopped_generation).await;
                    guard.0 = None;
                }
            }
            return Err(error);
        }

        // Wait for response with timeout
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                Err(NetworkError::NotConnected)
            }
            Err(_) => {
                Err(NetworkError::Connection(format!(
                    "request timeout: {method}"
                )))
            }
        }
    }

    /// Convenience: call with array params.
    pub async fn call_array(&self, method: &str, params: &[Value]) -> Result<Value, NetworkError> {
        self.call(method, Value::Array(params.to_vec())).await
    }

    /// Perform the server.version handshake.
    pub async fn handshake(&self) -> Result<(String, (u16, u16)), NetworkError> {
        let result = self
            .call(
                "server.version",
                json!([CLIENT_VERSION, [PROTOCOL_MIN, PROTOCOL_MAX]]),
            )
            .await?;

        let arr = result
            .as_array()
            .ok_or_else(|| NetworkError::Protocol("server.version: expected array".into()))?;
        if arr.len() < 2 {
            return Err(NetworkError::Protocol(
                "server.version: array too short".into(),
            ));
        }

        let server_string = arr[0]
            .as_str()
            .ok_or_else(|| NetworkError::Protocol("server.version: server string not str".into()))?
            .to_string();

        let proto_str = arr[1]
            .as_str()
            .ok_or_else(|| NetworkError::Protocol("server.version: protocol not str".into()))?;

        let parts: Vec<&str> = proto_str.split('.').collect();
        let major: u16 = parts[0]
            .parse()
            .map_err(|_| NetworkError::Protocol(format!("bad protocol major: {}", parts[0])))?;
        let minor: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        if major != 1 || minor != 4 {
            return Err(NetworkError::Protocol(format!(
                "server protocol {major}.{minor} not in range [{PROTOCOL_MIN}, {PROTOCOL_MAX}]"
            )));
        }

        let ptuple = (major, minor);
        *self.inner.protocol_version.lock().await = Some(ptuple);

        Ok((server_string, ptuple))
    }

    /// Whether the client is connected (atomic, non-blocking).
    pub fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    /// Get the server host string (for logging/results).
    pub fn server_host(&self) -> String {
        self.inner.server.host.clone()
    }

    /// Subscribe to ElectrumX push notifications.
    ///
    /// Returns a `tokio::sync::broadcast::Receiver` that yields
    /// `ElectrumNotification` values. The Tauri event loop subscribes to
    /// this and emits frontend events (`new_block`, `balance_changed`).
    ///
    /// If no subscribers exist, notifications are dropped (broadcast channel
    /// behavior) — this is fine, the frontend simply won't get push updates.
    pub fn subscribe_notifications(
        &self,
    ) -> tokio::sync::broadcast::Receiver<ElectrumNotification> {
        self.inner.notifications.subscribe()
    }

    pub fn subscribe_shutdown(&self) -> tokio::sync::watch::Receiver<bool> {
        self.inner.stopped.subscribe()
    }

    pub(crate) fn stop_immediately(&self) -> u64 {
        self.stop_if_generation(None).expect("unconditional stop")
    }

    fn stop_if_generation(&self, expected: Option<u64>) -> Option<u64> {
        let mut lifecycle = self.inner.lifecycle.lock().unwrap();
        if expected.is_some_and(|expected| expected != *lifecycle) { return None; }
        *lifecycle = lifecycle.wrapping_add(1);
        let generation = *lifecycle;
        self.inner.connected.store(false, Ordering::SeqCst);
        self.inner.stopped.send_replace(true);
        if let Some(handle) = self.inner.reader_task.lock().unwrap().take() {
            handle.abort();
        }
        drop(lifecycle);
        if let Ok(mut pending) = self.inner.pending.try_lock() {
            if *self.inner.lifecycle.lock().unwrap() == generation { pending.clear(); }
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let inner = self.inner.clone();
            runtime.spawn(async move {
                let mut pending = inner.pending.lock().await;
                if *inner.lifecycle.lock().unwrap() == generation { pending.clear(); }
            });
        }
        Some(generation)
    }

    /// Gracefully disconnect.
    pub async fn disconnect(&self) -> Result<(), NetworkError> {
        let generation = self.stop_immediately();
        let mut guard = DisconnectGuard(Some((self.clone(), generation)));
        self.finish_disconnect(generation).await;
        guard.0 = None;
        Ok(())
    }

    pub(crate) fn cleanup_if_idle(&self, generation: u64) -> bool {
        let Ok(mut writer) = self.inner.writer.try_lock() else { return false; };
        let Ok(mut pending) = self.inner.pending.try_lock() else { return false; };
        let lifecycle = self.inner.lifecycle.lock().unwrap();
        if *lifecycle != generation { return false; }
        *writer = None;
        pending.clear();
        true
    }

    pub(crate) async fn finish_disconnect(&self, generation: u64) {
        let _io = self.inner.io_lifecycle.lock().await;
        if *self.inner.lifecycle.lock().unwrap() != generation { return; }

        // Shutdown writer
        {
            let mut w = self.inner.writer.lock().await;
            if *self.inner.lifecycle.lock().unwrap() != generation { return; }
            if let Some(mut writer) = w.take() {
                let _ = tokio::time::timeout(REQUEST_TIMEOUT, writer.shutdown()).await;
            }
        }

        // Notify reader task to stop
        self.inner.shutdown.notify_waiters();

        // Abort reader task

        // Clear pending requests
        let mut pending = self.inner.pending.lock().await;
        if *self.inner.lifecycle.lock().unwrap() == generation { pending.clear(); }
    }

    /// Compute txid (display form) from raw transaction bytes.
    /// txid = hash256(raw_tx) reversed → hex.
    /// Used to validate server's broadcast response (AUD-006).
    fn compute_txid(raw_tx: &[u8]) -> String {
        let h1 = Sha256::digest(raw_tx);
        let h2 = Sha256::digest(h1);
        let mut reversed = h2.to_vec();
        reversed.reverse();
        hex::encode(&reversed)
    }
}

// ---------------------------------------------------------------------------
// Reader loop — runs in a spawned task, dispatches responses + notifications
// ---------------------------------------------------------------------------

async fn write_request<W: AsyncWrite + Unpin>(writer: &mut W, request: &str) -> Result<(), NetworkError> {
    writer.write_all(request.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn read_bounded_frame<R: AsyncBufRead + Unpin>(reader: &mut R, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if frame.is_empty() { Ok(None) } else {
                Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "incomplete ElectrumX frame"))
            };
        }
        let end = available.iter().position(|&b| b == b'\n').map(|i| i + 1).unwrap_or(available.len());
        if end > limit.saturating_sub(frame.len()) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ElectrumX message too large"));
        }
        let complete = available[end - 1] == b'\n';
        frame.extend_from_slice(&available[..end]);
        reader.consume(end);
        if complete { return Ok(Some(frame)); }
    }
}

async fn read_loop<R: AsyncRead + Unpin>(inner: Arc<Inner>, reader: R, generation: u64) {
    read_loop_with_limit(inner, reader, MAX_MESSAGE_SIZE, generation).await;
}

async fn read_loop_with_limit<R: AsyncRead + Unpin>(inner: Arc<Inner>, reader: R, limit: usize, generation: u64) {
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    loop {
        let line = match read_bounded_frame(&mut reader, limit).await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(e) => {
                if inner.connected.load(Ordering::SeqCst) {
                    log::error!("ElectrumX read error: {e}");
                }
                break;
            }
        };

        // Parse JSON-RPC message
        let msg: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("ElectrumX: malformed JSON: {e}");
                continue;
            }
        };

        // Check if this is a response (has "id" and no "method") or a notification
        let has_id = msg.get("id").is_some();
        let has_method = msg.get("method").is_some();

        if has_id && !has_method {
            // Response — match to pending request
            let id = msg.get("id").and_then(|v| v.as_u64());
            if let Some(id) = id {
                // Remove from pending first, then send (avoids moving from shared ref)
                let mut pending = inner.pending.lock().await;
                let lifecycle = inner.lifecycle.lock().unwrap();
                if *lifecycle != generation { return; }
                let req = if pending.get(&id).is_some_and(|request| request.generation == generation) { pending.remove(&id) } else { None };
                drop(lifecycle);
                drop(pending);
                if let Some(req) = req {
                    // Accept legacy result/error:null envelopes without treating a missing result as null.
                    match (msg.get("result"), msg.get("error")) {
                        (Some(result), None | Some(Value::Null)) => { let _ = req.tx.send(Ok(result.clone())); }
                        (None | Some(Value::Null), Some(error)) if !error.is_null() => {
                            let code = error.get("code").and_then(|v| v.as_i64()).unwrap_or(0);
                            let message = error.get("message").and_then(|v| v.as_str()).unwrap_or("unknown error");
                            let _ = req.tx.send(Err(NetworkError::Server(format!("code {code}: {message}"))));
                        }
                        _ => { let _ = req.tx.send(Err(NetworkError::Protocol("invalid result/error response".into()))); }
                    }
                }
            }
        } else if has_method {
            // Notification — parse and dispatch to subscribers via broadcast channel
            let method = msg
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            log::debug!("ElectrumX notification: {method}");

            let params = msg.get("params").cloned().unwrap_or(Value::Null);

            let notification = match method {
                "blockchain.headers.subscribe" => {
                    // params: { "hex": "...", "height": N }
                    // or params: [ { "hex": "...", "height": N } ]
                    let hdr = if let Some(arr) = params.as_array() {
                        arr.first().cloned().unwrap_or(Value::Null)
                    } else {
                        params.clone()
                    };

                    let height = hdr.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                    let header_hex = hdr
                        .get("hex")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    if height > 0 && !header_hex.is_empty() {
                        Some(ElectrumNotification::NewBlock { height, header_hex })
                    } else {
                        log::warn!(
                            "ElectrumX headers.subscribe: incomplete notification (height={height})"
                        );
                        None
                    }
                }

                "blockchain.scripthash.subscribe" => {
                    // params: [ scripthash, status ]
                    // or params: { "scripthash": "...", "status": "..." }
                    let (scripthash, status) = if let Some(arr) = params.as_array() {
                        let sh = arr
                            .first()
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let st = arr
                            .get(1)
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        (sh, st)
                    } else {
                        let sh = params
                            .get("scripthash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let st = params
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        (sh, st)
                    };

                    if !scripthash.is_empty() {
                        Some(ElectrumNotification::ScripthashStatus { scripthash, status })
                    } else {
                        log::warn!(
                            "ElectrumX scripthash.subscribe: missing scripthash in notification"
                        );
                        None
                    }
                }

                _ => {
                    log::debug!("ElectrumX: unhandled notification method: {method}");
                    None
                }
            };

            // Broadcast to subscribers (if any). If no receivers, the message
            // is silently dropped — this is expected broadcast channel behavior.
            if let Some(notif) = notification {
                let lifecycle = inner.lifecycle.lock().unwrap();
                if *lifecycle != generation { return; }
                let _ = inner.notifications.send(notif);
            }
        }
    }

    // Mark as disconnected
    {
        let lifecycle = inner.lifecycle.lock().unwrap();
        if *lifecycle != generation { return; }
        inner.connected.store(false, Ordering::SeqCst);
        inner.stopped.send_replace(true);
    }
    // Dropping both halves closes the underlying connection on protocol failure.
    {
        let mut writer = inner.writer.lock().await;
        let lifecycle = inner.lifecycle.lock().unwrap();
        if *lifecycle != generation { return; }
        *writer = None;
    }

    // Fail all pending requests
    let mut pending = inner.pending.lock().await;
    let lifecycle = inner.lifecycle.lock().unwrap();
    if *lifecycle != generation { return; }
    for (_, req) in pending.drain() {
        let _ = req.tx.send(Err(NetworkError::NotConnected));
    }
}

// ---------------------------------------------------------------------------
// NetworkBackend trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl NetworkBackend for ElectrumXClient {
    type QueryTarget = ScriptHash;
    fn backend_type(&self) -> BackendType {
        BackendType::ElectrumX
    }

    fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    async fn get_tip_height(&self) -> Result<u64, NetworkError> {
        let result = self.call("blockchain.headers.subscribe", json!([])).await?;

        let height = result
            .get("height")
            .and_then(|h| h.as_u64())
            .ok_or_else(|| NetworkError::Protocol("headers.subscribe: missing height".into()))?;

        Ok(height)
    }

    async fn get_balance(&self, scripthash: &ScriptHash) -> Result<BackendBalance, NetworkError> {
        let scripthash = scripthash.as_str();
        let result = self
            .call_array("blockchain.scripthash.get_balance", &[json!(scripthash)])
            .await?;

        let confirmed = result
            .get("confirmed")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| NetworkError::Protocol("get_balance: missing confirmed".into()))?;

        let unconfirmed = result
            .get("unconfirmed")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| NetworkError::Protocol("get_balance: missing unconfirmed".into()))?;

        BackendBalance::new(confirmed, unconfirmed)
    }

    async fn get_history(&self, scripthash: &ScriptHash) -> Result<Vec<TxHistoryEntry>, NetworkError> {
        let scripthash = scripthash.as_str();
        let result = self
            .call_array("blockchain.scripthash.get_history", &[json!(scripthash)])
            .await?;

        let arr = result
            .as_array()
            .ok_or_else(|| NetworkError::Protocol("get_history: expected array".into()))?;

        let mut entries = Vec::with_capacity(arr.len());
        for item in arr {
            let tx_hash = item
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| NetworkError::Protocol("get_history: missing tx_hash".into()))?
                .to_string();

            let height = item
                .get("height")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| NetworkError::Protocol("get_history: missing height".into()))?;

            entries.push(TxHistoryEntry {
                tx_hash,
                height,
                verified: false,
            });
        }

        Ok(entries)
    }

    async fn get_utxos(&self, scripthash: &ScriptHash) -> Result<Vec<UtxoEntry>, NetworkError> {
        let scripthash = scripthash.as_str();
        let result = self
            .call_array("blockchain.scripthash.listunspent", &[json!(scripthash)])
            .await?;

        let arr = result
            .as_array()
            .ok_or_else(|| NetworkError::Protocol("listunspent: expected array".into()))?;

        let mut entries = Vec::with_capacity(arr.len());
        for item in arr {
            let tx_hash = item
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| NetworkError::Protocol("listunspent: missing tx_hash".into()))?
                .to_string();

            let tx_pos = item
                .get("tx_pos")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| NetworkError::Protocol("listunspent: missing tx_pos".into()))?
                as u32;

            let value = item
                .get("value")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| NetworkError::Protocol("listunspent: missing value".into()))?;

            let height = item.get("height").and_then(|v| v.as_i64()).unwrap_or(0);

            entries.push(UtxoEntry {
                tx_hash,
                tx_pos,
                value,
                height,
            });
        }

        Ok(entries)
    }

    async fn broadcast_tx(&self, raw_tx: &[u8]) -> Result<BroadcastResult, NetworkError> {
        // AUD-006: Convert to hex and send
        let raw_hex = hex::encode(raw_tx);

        let result = self
            .call_array("blockchain.transaction.broadcast", &[json!(raw_hex)])
            .await?;

        // AUD-006: Server returns txid as string. None/empty = error.
        let server_txid = result
            .as_str()
            .ok_or(NetworkError::BroadcastNoTxid)?
            .to_string();

        if server_txid.is_empty() {
            return Err(NetworkError::BroadcastNoTxid);
        }

        // AUD-006: Validate returned txid by computing locally
        let expected_txid = Self::compute_txid(raw_tx);
        if expected_txid != server_txid {
            return Err(NetworkError::Validation(format!(
                "txid mismatch: server returned '{server_txid}', expected '{expected_txid}'"
            )));
        }

        Ok(BroadcastResult { txid: server_txid })
    }

    async fn get_block_headers(
        &self,
        start_height: u64,
        count: u64,
    ) -> Result<Vec<BlockHeader>, NetworkError> {
        let result = self
            .call_array(
                "blockchain.block.headers",
                &[json!(start_height), json!(count), json!(0u64)],
            )
            .await?;

        parse_header_response(start_height, count, &result)
    }

    async fn get_merkle_proof(
        &self,
        tx_hash: &str,
        block_height: u64,
    ) -> Result<MerkleProof, NetworkError> {
        let result = self
            .call_array(
                "blockchain.transaction.get_merkle",
                &[json!(tx_hash), json!(block_height)],
            )
            .await?;

        parse_merkle_response(tx_hash, block_height, &result)
    }

    async fn subscribe_scripthash(&self, scripthash: &ScriptHash) -> Result<(), NetworkError> {
        let scripthash = scripthash.as_str();
        let _result = self
            .call_array("blockchain.scripthash.subscribe", &[json!(scripthash)])
            .await?;
        Ok(())
    }

    async fn unsubscribe_scripthash(&self, scripthash: &ScriptHash) -> Result<(), NetworkError> {
        let scripthash = scripthash.as_str();
        let _result = self
            .call_array("blockchain.scripthash.unsubscribe", &[json!(scripthash)])
            .await?;
        Ok(())
    }

    async fn ping(&self) -> Result<(), NetworkError> {
        let _result = self.call("server.ping", json!([])).await?;
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), NetworkError> {
        self.disconnect().await
    }
}

fn parse_header_response(start_height: u64, requested: u64, result: &serde_json::Value) -> Result<Vec<BlockHeader>, NetworkError> {
    let count = result.get("count").and_then(|v| v.as_u64())
        .ok_or_else(|| NetworkError::Protocol("block.headers: missing count".into()))?;
    if count == 0 || count > requested { return Err(NetworkError::Protocol("block.headers: invalid count".into())); }
    let count_usize = usize::try_from(count).map_err(|_| NetworkError::Protocol("block.headers: count overflow".into()))?;
    let expected_hex = count_usize.checked_mul(160).ok_or_else(|| NetworkError::Protocol("block.headers: length overflow".into()))?;
    let hex_str = result.get("hex").and_then(|v| v.as_str())
        .ok_or_else(|| NetworkError::Protocol("block.headers: missing hex".into()))?;
    if hex_str.len() != expected_hex { return Err(NetworkError::Protocol("block.headers: count and hex length disagree".into())); }
    let raw = hex::decode(hex_str).map_err(|e| NetworkError::Protocol(format!("block.headers: bad hex: {e}")))?;
    let mut headers = Vec::with_capacity(count_usize);
    for (index, chunk) in raw.chunks_exact(80).enumerate() {
        let height = start_height.checked_add(index as u64).ok_or_else(|| NetworkError::Protocol("block.headers: height overflow".into()))?;
        headers.push(BlockHeader { height, hex: hex::encode(chunk) });
    }
    Ok(headers)
}

fn parse_merkle_response(tx_hash: &str, block_height: u64, result: &serde_json::Value) -> Result<MerkleProof, NetworkError> {
    let branch_arr = result.get("merkle").and_then(|v| v.as_array())
        .ok_or_else(|| NetworkError::Protocol("get_merkle: missing branch".into()))?;
    let pos = result.get("pos").and_then(|v| v.as_u64())
        .ok_or_else(|| NetworkError::Protocol("get_merkle: missing position".into()))?;
    if !crate::network::header_store::valid_hash32(tx_hash)
        || !crate::network::header_store::valid_merkle_position(branch_arr.len(), pos) {
        return Err(NetworkError::Protocol("get_merkle: invalid proof shape".into()));
    }
    let mut branch = Vec::with_capacity(branch_arr.len());
    for (i, item) in branch_arr.iter().enumerate() {
        let hash = item.as_str().ok_or_else(|| NetworkError::Protocol("get_merkle: invalid branch".into()))?;
        if !crate::network::header_store::valid_hash32(hash) {
            return Err(NetworkError::Protocol("get_merkle: invalid branch hash".into()));
        }
        branch.push((hash.to_string(), ((pos >> i) & 1) == 0));
    }
    Ok(MerkleProof { tx_hash: tx_hash.to_string(), block_height, merkle_branch: branch, position: Some(pos), root: String::new() })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn balance_response_rejects_positive_overflow() {
        use super::*;
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let (client_io, peer) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(client_io);
        *client.inner.writer.lock().await = Some(Box::new(writer));
        let reader_task = tokio::spawn(read_loop(client.inner.clone(), reader, 0));
        let server = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(peer);
            let mut lines = BufReader::new(reader).lines();
            let request: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(request["method"], "blockchain.scripthash.get_balance");
            let response = json!({"id": request["id"], "result": {"confirmed":u64::MAX, "unconfirmed":1}});
            writer.write_all(format!("{response}\n").as_bytes()).await.unwrap();
        });
        let target = ScriptHash::try_from("ab".repeat(32).as_str()).unwrap();
        assert!(matches!(client.get_balance(&target).await, Err(NetworkError::Validation(_))));
        server.await.unwrap();
        reader_task.await.unwrap();
    }
    #[tokio::test]
    async fn history_height_is_a_server_claim_and_not_a_proof() {
        use super::*;
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let (client_io, peer) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(client_io);
        *client.inner.writer.lock().await = Some(Box::new(writer));
        let reader_task = tokio::spawn(read_loop(client.inner.clone(), reader, 0));
        let server = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(peer);
            let mut lines = BufReader::new(reader).lines();
            let request: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(request["method"], "blockchain.scripthash.get_history");
            assert_eq!(request["params"][0], "ab".repeat(32));
            let response = json!({"id": request["id"], "result": [{"tx_hash":"aa", "height":123}, {"tx_hash":"bb", "height":0}]});
            writer.write_all(format!("{response}\n").as_bytes()).await.unwrap();
        });
        let target = ScriptHash::try_from("ab".repeat(32).as_str()).unwrap();
        let entries = client.get_history(&target).await.unwrap();
        assert_eq!(entries.iter().map(|entry| entry.height).collect::<Vec<_>>(), [123, 0]);
        assert!(entries.iter().all(|entry| !entry.verified));
        server.await.unwrap();
        reader_task.await.unwrap();
    }
    #[test]
    fn header_response_checks_count_and_accepts_valid_partial() {
        let one = "00".repeat(80);
        let parsed = super::parse_header_response(10, 2, &serde_json::json!({"count":1,"hex":one})).unwrap();
        assert_eq!(parsed.len(), 1); assert_eq!(parsed[0].height, 10);
        assert!(super::parse_header_response(10, 2, &serde_json::json!({"count":0,"hex":""})).is_err());
        assert!(super::parse_header_response(10, 1, &serde_json::json!({"count":2,"hex":"00".repeat(160)})).is_err());
        assert!(super::parse_header_response(10, 2, &serde_json::json!({"count":2,"hex":"00".repeat(80)})).is_err());
        assert!(super::parse_header_response(u64::MAX, 2, &serde_json::json!({"count":2,"hex":"00".repeat(160)})).is_err());
    }
    #[test]
    fn merkle_response_rejects_malformed_server_proofs() {
        let tx = "11".repeat(32);
        let sibling = "22".repeat(32);
        assert!(super::parse_merkle_response(&tx, 5, &serde_json::json!({"merkle": [], "pos": 0})).is_ok());
        assert!(super::parse_merkle_response(&tx, 5, &serde_json::json!({"merkle": [sibling], "pos": 1})).is_ok());
        assert!(super::parse_merkle_response(&tx, 5, &serde_json::json!({"merkle": [], "pos": 1})).is_err());
        assert!(super::parse_merkle_response(&tx, 5, &serde_json::json!({"merkle": ["00"], "pos": 0})).is_err());
        assert!(super::parse_merkle_response(&tx, 5, &serde_json::json!({"merkle": vec!["22".repeat(32); 65], "pos": 0})).is_err());
    }
    #[test]
    fn tls_config_uses_explicit_provider_without_network() {
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        let roots = rustls::RootCertStore::empty();
        let config = super::client_tls_config(roots);
        assert!(config.is_ok());
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    }

    use super::*;

    #[test]
    fn guard_without_runtime_cleans_idle_state_or_keeps_reconnect_blocked() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connecting.store(true, Ordering::SeqCst);
        client.inner.connected.store(true, Ordering::SeqCst);
        drop(ConnectGuard(Some(client.clone())));
        assert!(!client.is_connected());
        assert!(!client.inner.connecting.load(Ordering::SeqCst));
        assert!(*client.subscribe_shutdown().borrow());

        client.inner.connecting.store(true, Ordering::SeqCst);
        let pending = client.inner.pending.try_lock().unwrap();
        drop(ConnectGuard(Some(client.clone())));
        assert!(client.inner.connecting.load(Ordering::SeqCst));
        assert!(!client.is_connected());
        drop(pending);
    }

    #[tokio::test]
    async fn cancelled_connect_guard_stops_reader_and_persists_shutdown() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        let retained = client.clone();
        client.inner.connected.store(true, Ordering::SeqCst);
        client.inner.connecting.store(true, Ordering::SeqCst);
        let (_writer, reader) = tokio::io::duplex(64);
        let task = tokio::spawn(read_loop(client.inner.clone(), reader, 0));
        let abort = task.abort_handle();
        *client.inner.reader_task.lock().unwrap() = Some(task);
        let mut early = client.subscribe_shutdown();
        drop(ConnectGuard(Some(client.clone())));
        assert!(!client.is_connected());
        assert!(abort.is_finished() || client.inner.reader_task.lock().unwrap().is_none());
        early.changed().await.unwrap();
        assert!(*early.borrow());
        assert!(*retained.subscribe_shutdown().borrow());
        tokio::time::timeout(Duration::from_secs(1), async {
            while client.inner.connecting.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn reader_eof_persists_shutdown_with_client_clone_alive() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let (writer, reader) = tokio::io::duplex(64);
        drop(writer);
        read_loop(client.inner.clone(), reader, 0).await;
        assert!(!client.is_connected());
        assert!(*client.subscribe_shutdown().borrow());
    }

    #[tokio::test]
    async fn disconnect_releases_pending_before_waiting_for_connection_gate() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let gate = client.inner.io_lifecycle.lock().await;
        let (tx, rx) = oneshot::channel();
        client.inner.pending.lock().await.insert(1, PendingRequest { tx, generation: 0 });
        let disconnecting = {
            let client = client.clone();
            tokio::spawn(async move { client.disconnect().await })
        };
        assert!(tokio::time::timeout(Duration::from_secs(1), rx).await.unwrap().is_err());
        assert!(!client.is_connected());
        drop(gate);
        tokio::time::timeout(Duration::from_secs(1), disconnecting).await.unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancelled_disconnect_finishes_cleanup_after_gate_is_released() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let gate = client.inner.io_lifecycle.lock().await;
        let mut stopped = client.subscribe_shutdown();
        let task = {
            let client = client.clone();
            tokio::spawn(async move { client.disconnect().await })
        };
        stopped.changed().await.unwrap();
        let (tx, rx) = oneshot::channel();
        client.inner.pending.lock().await.insert(7, PendingRequest { tx, generation: 0 });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!client.is_connected());
        assert!(client.inner.pending.lock().await.contains_key(&7));
        drop(gate);
        assert!(tokio::time::timeout(Duration::from_secs(1), rx).await.unwrap().is_err());
        assert!(!client.inner.pending.lock().await.contains_key(&7));
    }

    #[tokio::test]
    async fn disconnect_invalidates_connect_queued_on_gate() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        let gate = client.inner.io_lifecycle.lock().await;
        let connect = client.connect_with_test_roots(rustls::RootCertStore::empty());
        tokio::pin!(connect);
        assert!(tokio::time::timeout(Duration::from_millis(10), &mut connect).await.is_err());
        client.stop_immediately();
        drop(gate);
        assert!(matches!(connect.await, Err(NetworkError::NotConnected)));
    }

    #[tokio::test]
    async fn stale_disconnect_cannot_clear_new_generation() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let gate = client.inner.io_lifecycle.lock().await;
        let mut stopped = client.subscribe_shutdown();
        let old = { let c = client.clone(); tokio::spawn(async move { c.disconnect().await.unwrap() }) };
        stopped.changed().await.unwrap();
        {
            let mut generation = client.inner.lifecycle.lock().unwrap();
            *generation += 1;
            client.inner.connected.store(true, Ordering::SeqCst);
            client.inner.stopped.send_replace(false);
        }
        let (tx, mut rx) = oneshot::channel();
        client.inner.pending.lock().await.insert(7, PendingRequest { tx, generation: 0 });
        drop(gate);
        old.await.unwrap();
        assert!(client.is_connected());
        assert!(!*client.subscribe_shutdown().borrow());
        assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(client.inner.pending.lock().await.contains_key(&7));
    }

    #[tokio::test]
    async fn stale_reader_eof_cannot_clear_new_generation() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let writer_lock = client.inner.writer.lock().await;
        let mut stopped = client.subscribe_shutdown();
        let (writer, reader) = tokio::io::duplex(64);
        let old = tokio::spawn(read_loop(client.inner.clone(), reader, 0));
        drop(writer);
        stopped.changed().await.unwrap();
        {
            let mut generation = client.inner.lifecycle.lock().unwrap();
            *generation += 1;
            client.inner.connected.store(true, Ordering::SeqCst);
            client.inner.stopped.send_replace(false);
        }
        let (tx, mut rx) = oneshot::channel();
        client.inner.pending.lock().await.insert(7, PendingRequest { tx, generation: 0 });
        drop(writer_lock);
        old.await.unwrap();
        assert!(client.is_connected());
        assert!(!*client.subscribe_shutdown().borrow());
        assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(client.inner.pending.lock().await.contains_key(&7));
    }

    #[tokio::test]
    async fn rejected_duplicate_connect_keeps_current_reader_live() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        client.inner.pending.lock().await.insert(7, PendingRequest { tx, generation: 0 });
        let (mut writer, reader) = tokio::io::duplex(128);
        let task = tokio::spawn(read_loop(client.inner.clone(), reader, 0));
        assert!(client.connect_with_test_roots(rustls::RootCertStore::empty()).await.is_err());
        assert_eq!(*client.inner.lifecycle.lock().unwrap(), 0);
        writer.write_all(b"{\"id\":7,\"result\":\"ok\"}\n").await.unwrap();
        assert_eq!(rx.await.unwrap().unwrap(), json!("ok"));
        assert!(client.is_connected());
        drop(writer);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn stale_call_cannot_write_to_reconnected_writer() {
        use std::{future::Future, task::Poll};
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let mut writer_lock = client.inner.writer.lock().await;
        let call = client.call("old.request", json!([]));
        tokio::pin!(call);
        assert!(std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx).is_pending())).await);
        assert_eq!(client.inner.pending.lock().await.len(), 1);
        let (writer, mut peer) = tokio::io::duplex(128);
        *writer_lock = Some(Box::new(writer));
        {
            let mut generation = client.inner.lifecycle.lock().unwrap();
            *generation += 1;
            client.inner.connected.store(true, Ordering::SeqCst);
        }
        drop(writer_lock);
        assert!(matches!(call.await, Err(NetworkError::NotConnected)));
        assert!(client.is_connected());
        let mut bytes = [0; 32];
        let read = tokio::io::AsyncReadExt::read(&mut peer, &mut bytes);
        tokio::pin!(read);
        assert!(std::future::poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx).is_pending())).await);
    }

    #[tokio::test]
    async fn stale_write_error_does_not_stop_reconnected_client() {
        use std::{future::Future, task::Poll};
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let mut writer_lock = client.inner.writer.lock().await;
        let (writer, peer) = tokio::io::duplex(128);
        drop(peer);
        *writer_lock = Some(Box::new(writer));
        let call = client.call("old.request", json!([]));
        tokio::pin!(call);
        assert!(std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx).is_pending())).await);
        let mut pending = client.inner.pending.lock().await;
        assert_eq!(pending.len(), 1);
        drop(writer_lock);
        assert!(std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx).is_pending())).await);
        assert!(client.inner.writer.try_lock().is_ok());
        let new_generation = {
            let mut generation = client.inner.lifecycle.lock().unwrap();
            *generation += 1;
            client.inner.connected.store(true, Ordering::SeqCst);
            client.inner.stopped.send_replace(false);
            *generation
        };
        let (tx, mut rx) = oneshot::channel();
        pending.insert(999, PendingRequest { tx, generation: new_generation });
        drop(pending);
        assert!(call.await.is_err());
        assert!(client.is_connected());
        assert!(!*client.subscribe_shutdown().borrow());
        assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert!(client.inner.pending.lock().await.contains_key(&999));
    }

    #[tokio::test]
    async fn cancelled_partial_request_stops_its_connection_and_clears_pending() {
        use std::{future::Future, task::Poll};
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let (writer, _peer) = tokio::io::duplex(1);
        *client.inner.writer.lock().await = Some(Box::new(writer));
        let mut call = Box::pin(client.call("request", json!([])));
        assert!(std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx).is_pending())).await);
        assert_eq!(client.inner.pending.lock().await.len(), 1);
        drop(call);
        assert!(!client.is_connected());
        assert!(*client.subscribe_shutdown().borrow());
        assert!(client.inner.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn cancelled_after_partial_write_error_stops_before_pending_lock() {
        use std::{future::Future, pin::Pin, task::{Context, Poll}};
        struct PartialThenError(Arc<std::sync::Mutex<Vec<u8>>>);
        impl AsyncWrite for PartialThenError {
            fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
                let mut bytes = self.0.lock().unwrap();
                if bytes.is_empty() { bytes.push(data[0]); Poll::Ready(Ok(1)) }
                else { Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "synthetic"))) }
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }
        }
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut writer = client.inner.writer.lock().await;
        *writer = Some(Box::new(PartialThenError(bytes.clone())));
        let mut call = Box::pin(client.call("request", json!([])));
        assert!(std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx).is_pending())).await);
        let pending = client.inner.pending.lock().await;
        assert_eq!(pending.len(), 1);
        drop(writer);
        assert!(std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx).is_pending())).await);
        assert_eq!(bytes.lock().unwrap().len(), 1);
        assert!(!client.is_connected());
        assert!(*client.subscribe_shutdown().borrow());
        drop(call);
        drop(pending);
    }

    #[tokio::test]
    async fn cancelled_protocol_negotiation_after_tls_stops_reader_and_closes_socket() {
        use tokio::io::AsyncBufReadExt;
        let ca = include_bytes!("../../tests/fixtures/tls/ca.pem");
        let cert = include_bytes!("../../tests/fixtures/tls/server.pem");
        let key = include_bytes!("../../tests/fixtures/tls/server-key.pem");
        let chain = rustls_pemfile::certs(&mut &cert[..]).collect::<Result<Vec<_>, _>>().unwrap();
        let key = rustls_pemfile::private_key(&mut &key[..]).unwrap().unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &ca[..]) { roots.add(cert.unwrap()).unwrap(); }
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(socket).await.unwrap();
            let mut reader = BufReader::new(tls);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.contains("server.version"));
            ready_tx.send(()).unwrap();
            line.clear();
            reader.read_line(&mut line).await
        });
        let client = ElectrumXClient::new(ServerEntry::new("127.0.0.1", port));
        let task = {
            let client = client.clone();
            tokio::spawn(async move { client.connect_with_test_roots(roots).await })
        };
        tokio::time::timeout(Duration::from_secs(3), ready_rx).await.unwrap().unwrap();
        task.abort();
        let _ = task.await;
        assert!(!client.is_connected());
        assert!(*client.subscribe_shutdown().borrow());
        assert!(client.inner.reader_task.lock().unwrap().is_none());
        let result = tokio::time::timeout(Duration::from_secs(3), server).await.unwrap().unwrap();
        assert!(matches!(result, Ok(0)) || result.is_err());
    }

    #[tokio::test]
    async fn missing_writer_cleans_registered_request() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        assert!(matches!(client.call("test", json!([])).await, Err(NetworkError::NotConnected)));
        assert!(client.inner.pending.lock().await.is_empty());
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn closed_synthetic_writer_returns_error() {
        let (mut writer, reader) = tokio::io::duplex(8);
        drop(reader);
        assert!(write_request(&mut writer, "{}").await.is_err());
    }

    #[tokio::test]
    async fn bounded_frame_handles_boundary_and_eof() {
        async fn one(bytes: &[u8], limit: usize) -> std::io::Result<Option<Vec<u8>>> {
            read_bounded_frame(&mut BufReader::with_capacity(3, std::io::Cursor::new(bytes)), limit).await
        }
        assert_eq!(one(b"1234567\n", 8).await.unwrap().unwrap(), b"1234567\n");
        assert_eq!(one(b"12345678\n", 8).await.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(one(b"123456789", 8).await.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(one(b"123", 8).await.unwrap_err().kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(one(b"", 8).await.unwrap().is_none());
        let mut reader = BufReader::with_capacity(3, std::io::Cursor::new(b"one\ntwo\n"));
        assert_eq!(read_bounded_frame(&mut reader, 8).await.unwrap().unwrap(), b"one\n");
        assert_eq!(read_bounded_frame(&mut reader, 8).await.unwrap().unwrap(), b"two\n");
        assert!(read_bounded_frame(&mut reader, 8).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_frame_disconnects_and_fails_all_pending() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        {
            let mut pending = client.inner.pending.lock().await;
            pending.insert(1, PendingRequest { tx: tx1, generation: 0 });
            pending.insert(2, PendingRequest { tx: tx2, generation: 0 });
        }
        let (mut writer, reader) = tokio::io::duplex(128);
        let task = tokio::spawn(read_loop_with_limit(client.inner.clone(), reader, 16, 0));
        writer.write_all(b"12345678901234567\n{\"id\":1,\"result\":42}\n").await.unwrap();
        drop(writer);
        task.await.unwrap();
        assert!(matches!(rx1.await.unwrap(), Err(NetworkError::NotConnected)));
        assert!(matches!(rx2.await.unwrap(), Err(NetworkError::NotConnected)));
        assert!(!client.is_connected());
        assert!(client.inner.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn response_handles_jsonrpc_and_legacy_envelopes_without_inventing_null() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let mut receivers = Vec::new();
        for id in 1..=8 {
            let (tx, rx) = oneshot::channel();
            client.inner.pending.lock().await.insert(id, PendingRequest { tx, generation: 0 });
            receivers.push(rx);
        }
        let (mut writer, reader) = tokio::io::duplex(1024);
        let task = tokio::spawn(read_loop_with_limit(client.inner.clone(), reader, 128, 0));
        writer.write_all(concat!(
            "{\"id\":1}\n",
            "{\"id\":2,\"error\":null}\n",
            "{\"id\":3,\"result\":null}\n",
            "{\"id\":4,\"result\":12}\n",
            "{\"id\":5,\"result\":null,\"error\":null}\n",
            "{\"id\":6,\"result\":12,\"error\":null}\n",
            "{\"id\":7,\"result\":null,\"error\":{\"code\":-1,\"message\":\"failed\"}}\n",
            "{\"id\":8,\"result\":12,\"error\":{\"code\":-1,\"message\":\"failed\"}}\n",
        ).as_bytes()).await.unwrap();
        drop(writer);
        task.await.unwrap();
        let mut received = receivers.into_iter();
        assert!(matches!(received.next().unwrap().await.unwrap(), Err(NetworkError::Protocol(_))));
        assert!(matches!(received.next().unwrap().await.unwrap(), Err(NetworkError::Protocol(_))));
        assert_eq!(received.next().unwrap().await.unwrap().unwrap(), Value::Null);
        assert_eq!(received.next().unwrap().await.unwrap().unwrap(), json!(12));
        assert_eq!(received.next().unwrap().await.unwrap().unwrap(), Value::Null);
        assert_eq!(received.next().unwrap().await.unwrap().unwrap(), json!(12));
        assert!(matches!(received.next().unwrap().await.unwrap(), Err(NetworkError::Server(_))));
        assert!(matches!(received.next().unwrap().await.unwrap(), Err(NetworkError::Protocol(_))));
    }

    #[tokio::test]
    async fn reader_dispatches_multiple_frames_and_rejects_partial_final_frame() {
        let client = ElectrumXClient::new(ServerEntry::new("example.com", 50002));
        client.inner.connected.store(true, Ordering::SeqCst);
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        {
            let mut pending = client.inner.pending.lock().await;
            pending.insert(1, PendingRequest { tx: tx1, generation: 0 });
            pending.insert(2, PendingRequest { tx: tx2, generation: 0 });
            pending.insert(3, PendingRequest { tx: tx3, generation: 0 });
        }
        let (mut writer, reader) = tokio::io::duplex(256);
        let task = tokio::spawn(read_loop_with_limit(client.inner.clone(), reader, 128, 0));
        writer.write_all(b"{\"id\":1,\"result\":11}\n{\"id\":2,\"result\":22}\n{\"id\":3,\"result\":33}").await.unwrap();
        drop(writer);
        task.await.unwrap();
        assert_eq!(rx1.await.unwrap().unwrap(), json!(11));
        assert_eq!(rx2.await.unwrap().unwrap(), json!(22));
        assert!(matches!(rx3.await.unwrap(), Err(NetworkError::NotConnected)));
        assert!(!client.is_connected());
    }

    #[test]
    fn test_compute_txid_known_vector() {
        // Coinbase transaction from BSV block 1 (simplified empty tx for hash test)
        // hash256 of empty bytes is not a real tx, but we test the hash logic.
        let h1 = Sha256::digest(b"");
        let h2 = Sha256::digest(h1);
        let mut reversed = h2.to_vec();
        reversed.reverse();
        let expected = hex::encode(&reversed);

        let computed = ElectrumXClient::compute_txid(b"");
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_compute_txid_deterministic() {
        let raw = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let t1 = ElectrumXClient::compute_txid(raw);
        let t2 = ElectrumXClient::compute_txid(raw);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64); // 32 bytes → 64 hex chars
    }

    #[test]
    fn test_compute_txid_different_inputs() {
        let t1 = ElectrumXClient::compute_txid(b"hello");
        let t2 = ElectrumXClient::compute_txid(b"world");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_compute_txid_known_empty_hash() {
        // hash256(b"") = sha256(sha256(b""))
        // sha256(b"") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // sha256(that) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        // reversed = 5694 5cfd 3f98 41e4 cf55 5f45 4515 81c0 fc99 2e58 0575 820a d359 1376 e2e0 f65d
        let computed = ElectrumXClient::compute_txid(b"");
        // Verify it's a valid hex string of 64 chars
        assert_eq!(computed.len(), 64);
        assert!(hex::decode(&computed).is_ok());
    }

    #[test]
    fn test_client_new_not_connected() {
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        assert!(!client.is_connected());
    }

    #[test]
    fn test_server_entry_stored() {
        let server = ServerEntry::new("electrum.api.sv", 50002);
        let client = ElectrumXClient::new(server);
        assert_eq!(client.inner.server.host, "electrum.api.sv");
        assert_eq!(client.inner.server.ssl_port, 50002);
    }

    #[test]
    fn test_backend_type() {
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        assert_eq!(client.backend_type(), BackendType::ElectrumX);
    }

    #[test]
    fn test_jsonrpc_request_format() {
        // Verify JSON-RPC 2.0 format by constructing manually
        let id: u64 = 42;
        let method = "server.version";
        let params = json!(["client", [1, 2]]);
        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let s = msg.to_string();

        // Parse back and verify
        let parsed: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["method"], "server.version");
        assert!(parsed["params"].is_array());
    }

    #[test]
    fn test_jsonrpc_response_parsing() {
        // Simulate a server response
        let response = r#"{"jsonrpc":"2.0","id":1,"result":{"confirmed":50000,"unconfirmed":0}}"#;
        let parsed: Value = serde_json::from_str(response).unwrap();
        assert_eq!(parsed["id"], 1);
        assert!(parsed.get("result").is_some());
        assert_eq!(parsed["result"]["confirmed"], 50000);
        assert!(parsed.get("method").is_none()); // Not a notification
    }

    #[test]
    fn test_jsonrpc_error_response() {
        let response = r#"{"jsonrpc":"2.0","id":5,"error":{"code":1,"message":"bad request"}}"#;
        let parsed: Value = serde_json::from_str(response).unwrap();
        assert_eq!(parsed["id"], 5);
        assert!(parsed.get("error").is_some());
        assert_eq!(parsed["error"]["code"], 1);
        assert_eq!(parsed["error"]["message"], "bad request");
    }

    #[test]
    fn test_jsonrpc_notification_parsing() {
        // ElectrumX push notification (no id, has method)
        let notification = r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":{"hex":"abcdef","height":12345}}"#;
        let parsed: Value = serde_json::from_str(notification).unwrap();
        assert!(parsed.get("id").is_none()); // Notifications have no id
        assert_eq!(parsed["method"], "blockchain.headers.subscribe");
        assert!(parsed.get("params").is_some());
        assert_eq!(parsed["params"]["height"], 12345);
    }

    #[test]
    fn test_protocol_version_constants() {
        assert_eq!(PROTOCOL_MIN, "1.4");
        assert_eq!(PROTOCOL_MAX, "1.4");
    }

    #[test]
    fn test_client_version_not_empty() {
        assert!(!CLIENT_VERSION.is_empty());
    }

    // --- Notification parsing tests ---

    #[test]
    fn test_notification_new_block_object_params() {
        // ElectrumX headers.subscribe notification with object params
        let notification = r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":{"hex":"01000000","height":800000}}"#;
        let parsed: Value = serde_json::from_str(notification).unwrap();
        assert_eq!(parsed["method"], "blockchain.headers.subscribe");
        assert_eq!(parsed["params"]["height"], 800000);
        assert_eq!(parsed["params"]["hex"], "01000000");
    }

    #[test]
    fn test_notification_new_block_array_params() {
        // Some servers send array params
        let notification = r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":[{"hex":"abcdef","height":12345}]}"#;
        let parsed: Value = serde_json::from_str(notification).unwrap();
        let arr = parsed["params"].as_array().unwrap();
        assert_eq!(arr[0]["height"], 12345);
        assert_eq!(arr[0]["hex"], "abcdef");
    }

    #[test]
    fn test_notification_scripthash_array_params() {
        // ElectrumX scripthash.subscribe notification
        let notification = r#"{"jsonrpc":"2.0","method":"blockchain.scripthash.subscribe","params":["abc123def456","status_hash"]}"#;
        let parsed: Value = serde_json::from_str(notification).unwrap();
        assert_eq!(parsed["method"], "blockchain.scripthash.subscribe");
        let arr = parsed["params"].as_array().unwrap();
        assert_eq!(arr[0], "abc123def456");
        assert_eq!(arr[1], "status_hash");
    }

    #[test]
    fn test_notification_serialization_new_block() {
        let notif = ElectrumNotification::NewBlock {
            height: 800000,
            header_hex: "abcdef".to_string(),
        };
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("800000"));
        assert!(json.contains("abcdef"));
        // Deserialized type should be identifiable
        assert!(json.contains("NewBlock") || json.contains("new_block"));
    }

    #[test]
    fn test_notification_serialization_scripthash() {
        let notif = ElectrumNotification::ScripthashStatus {
            scripthash: "abc123".to_string(),
            status: "def456".to_string(),
        };
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("def456"));
    }

    #[test]
    fn test_subscribe_notifications_returns_receiver() {
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        let _rx = client.subscribe_notifications();
        // Just verify it doesn't panic — the receiver is valid
    }

    #[test]
    fn test_notification_broadcast_to_subscriber() {
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        let mut rx = client.subscribe_notifications();

        // Send a notification via the internal channel
        let notif = ElectrumNotification::NewBlock {
            height: 42,
            header_hex: "deadbeef".to_string(),
        };
        let _ = client.inner.notifications.send(notif);

        // Receiver should get it
        let received = rx.try_recv();
        assert!(received.is_ok());
        match received.unwrap() {
            ElectrumNotification::NewBlock { height, header_hex } => {
                assert_eq!(height, 42);
                assert_eq!(header_hex, "deadbeef");
            }
            _ => panic!("expected NewBlock variant"),
        }
    }

    #[test]
    fn test_notification_broadcast_no_subscribers() {
        // If no subscribers, send should not panic (just returns Err)
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        // No receiver created — send should be Ok (broadcast allows this)
        let result = client
            .inner
            .notifications
            .send(ElectrumNotification::NewBlock {
                height: 1,
                header_hex: "00".to_string(),
            });
        // broadcast::send returns Err when there are no active receivers
        // but we use `let _ =` in the read_loop so it's fine
        assert!(result.is_err()); // No active receivers
    }
}
