//! Lifecycle and shared operations for the active network backend.

use crate::network::{BackendType, ElectrumXClient, NetworkBackend, NetworkError, WhatsOnChainClient};
use crate::state::NetworkState;

/// A snapshot supports broadcast only; provider-specific sync and subscriptions stay separate.
#[derive(Clone)]
pub enum ActiveBackend {
    ElectrumX(ElectrumXClient),
    WhatsOnChain(WhatsOnChainClient),
}

impl ActiveBackend {
    fn is_connected(&self) -> bool {
        match self {
            Self::ElectrumX(client) => client.is_connected(),
            Self::WhatsOnChain(client) => client.is_connected(),
        }
    }

    pub async fn broadcast(&self, bytes: &[u8]) -> Result<String, NetworkError> {
        match self {
            Self::ElectrumX(client) => client.broadcast_tx(bytes).await.map(|result| result.txid),
            Self::WhatsOnChain(client) => client.broadcast_tx(bytes).await.map(|result| result.txid),
        }
    }
}

pub(crate) struct SelectedBackendSnapshot {
    initially_connected: bool,
    backend: Option<ActiveBackend>,
}

impl SelectedBackendSnapshot {
    pub(crate) fn connected_backend(self) -> Option<ActiveBackend> {
        if !self.initially_connected { return None; }
        self.backend.filter(ActiveBackend::is_connected)
    }
}

impl NetworkState {
    pub(crate) fn selected_backend_snapshot(&self) -> SelectedBackendSnapshot {
        let backend = match self.active_backend {
            Some(BackendType::ElectrumX) => self.client.clone().map(ActiveBackend::ElectrumX),
            Some(BackendType::WhatsOnChain) => self.woc_client.clone().map(ActiveBackend::WhatsOnChain),
            None => None,
        };
        SelectedBackendSnapshot { initially_connected: self.connected, backend }
    }

    pub fn active_backend_snapshot(&self) -> Option<ActiveBackend> {
        self.selected_backend_snapshot().connected_backend()
    }

    pub(crate) fn begin_network_operation(&mut self) -> u64 {
        self.lifecycle_generation = self.lifecycle_generation.wrapping_add(1);
        self.lifecycle_generation
    }

    pub(crate) fn is_current_network_operation(&self, generation: u64) -> bool {
        self.lifecycle_generation == generation
    }

    pub(crate) fn take_active_network(&mut self) -> (Option<ElectrumXClient>, Option<WhatsOnChainClient>) {
        if let Some(host) = self.server_list.active().map(|s| s.host.clone()) {
            self.server_list.disconnect(&host);
        }
        self.connected = false;
        self.active_backend = None;
        (self.client.take(), self.woc_client.take())
    }

    pub(crate) fn clear_active_network(&mut self) -> (Option<ElectrumXClient>, Option<WhatsOnChainClient>) {
        self.begin_network_operation();
        self.take_active_network()
    }
}

/// Cleanup is detached so cancellation of a command cannot cancel resource shutdown.
pub(crate) fn cleanup(clients: (Option<ElectrumXClient>, Option<WhatsOnChainClient>)) {
    let generation = clients.0.as_ref().map(|client| client.stop_immediately());
    if clients.0.is_some() || clients.1.is_some() {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let (Some(client), Some(generation)) = (clients.0, generation) { client.finish_disconnect(generation).await; }
                if let Some(client) = clients.1 { let _ = client.disconnect().await; }
            });
        } else {
            if let (Some(client), Some(generation)) = (clients.0, generation) {
                if !client.cleanup_if_idle(generation) { log::warn!("network cleanup requires a running Tokio runtime"); }
            }
            if clients.1.is_some() { log::warn!("WhatsOnChain cleanup requires a running Tokio runtime"); }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::network::{BackendType, ServerStatus};
    use crate::state::NetworkState;

    #[test]
    fn later_operation_invalidates_older_candidate_and_disconnect_is_immediate() {
        let mut net = NetworkState::new();
        let first = net.begin_network_operation();
        let second = net.begin_network_operation();
        assert!(!net.is_current_network_operation(first));
        assert!(net.is_current_network_operation(second));
        net.connected = true;
        net.active_backend = Some(BackendType::ElectrumX);
        net.clear_active_network();
        assert!(!net.connected);
        assert_eq!(net.active_backend, None);
        assert!(!net.is_current_network_operation(second));
    }

    #[tokio::test]
    async fn snapshots_bind_selected_provider_without_fallback_and_dispatch_errors() {
        use super::ActiveBackend;
        use crate::network::{ElectrumXClient, WhatsOnChainClient, ServerEntry};
        let electrum = ElectrumXClient::new(ServerEntry::new("fixture.invalid", 50002));
        electrum.mark_test_connected();
        let woc = WhatsOnChainClient::with_base_url("http://[invalid");
        let mut net = NetworkState::new();
        net.connected = true;
        net.client = Some(electrum);
        net.woc_client = Some(woc.clone());
        net.active_backend = Some(BackendType::ElectrumX);
        let snapshot = net.active_backend_snapshot().expect("selected Electrum client");
        assert!(matches!(&snapshot, ActiveBackend::ElectrumX(_)));
        net.active_backend = Some(BackendType::WhatsOnChain);
        assert!(net.active_backend_snapshot().is_none(), "disconnected selected provider must not fall back");
        assert_eq!(snapshot.broadcast(&[0]).await.unwrap_err().to_string(), "no backend connected");
        let error = ActiveBackend::WhatsOnChain(woc).broadcast(&[0]).await.unwrap_err().to_string();
        assert!(error.contains("WoC broadcast:"), "{error}");
    }

    #[test]
    fn clearing_active_does_not_unban_server() {
        let mut net = NetworkState::new();
        let host = net.server_list.all()[0].host.clone();
        net.server_list.record_success(&host, 0);
        net.server_list.ban(&host);
        net.clear_active_network();
        assert_eq!(net.server_list.status(&host), ServerStatus::Banned);
    }
}
