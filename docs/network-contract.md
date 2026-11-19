# Network boundary and trust contract

This document describes the current implementation; it does not certify a release or chain consensus.

## Provider boundary

`NetworkState` owns selection and lifecycle state. A selected backend snapshot binds a concrete client and its initial connected flag. Payment checks that same client's connectivity after retrieving the plan state; it does not silently select a different provider or retry. A broadcast already recorded as `BROADCASTED` with the expected transaction ID is idempotent even while offline. For a new send, the spend ledger records `BROADCAST_UNKNOWN` before the network await. An unknown outcome requires an explicit retry of the persisted transaction; the reservation remains in place.

| Operation | ElectrumX | WhatsOnChain |
| --- | --- | --- |
| Balance/history/UTXO query target | Validated 64-hex `ScriptHash` | Validated mainnet P2PKH or P2SH Base58Check `MainnetAddress` |
| Scripthash subscriptions | Supported by the client | Explicit `Unsupported`; no implicit polling or successful no-op |
| Wallet sync | Uses the ElectrumX-specific path | Not provided by that sync path |
| Broadcast | Selected client's broadcast | Selected client's broadcast; no provider fallback |

The common Rust `NetworkBackend` trait has an associated `QueryTarget`; it does not make address and scripthash semantics interchangeable. Non-mainnet networks remain disabled. The WhatsOnChain target validator rejects inputs outside the listed address forms; other forms are not claimed to be supported.

## Lifecycle and verification

Network operations use generations to prevent stale connect/disconnect outcomes from replacing a newer selection. ElectrumX request, reader, and cleanup paths are bound to the relevant connection generation. A persistent shutdown signal allows notification forwarders to exit after disconnect or EOF. A GUI event already being emitted cannot be recalled. Cleanup spawned during normal operation is best effort if the runtime is already shutting down; without an available runtime and with contended locks, full asynchronous cleanup is not guaranteed.

Sync distinguishes `SyncKeyRef::Existing(i64)` from `Discovered(usize)` throughout ownership and history processing; it does not encode discovered keys as negative database IDs. Key-row comparison includes flags, description and timestamps as well as derivation fields. Concurrent edits can therefore abort sync; this is not a complete account/master-key snapshot guarantee. `SyncKeySnapshot.key_id` changed from `i64` to `SyncKeyRef`, a public Rust source-compatibility break.

Server-supplied heights, history, and balances are claims. Backend history returns `verified=false` without an independently checked proof, even for a positive reported height. The separate Merkle-proof operation checks against a stored header; that alone does not establish difficulty adjustment, highest chainwork, full consensus, completeness, or a trusted server. No automatic provider fallback is a consensus guarantee.

Server balance totals use checked positive addition in the two provider paths and return an error on overflow. Negative totals retain the existing clamp to zero. `BackendBalance` has public fields and can be constructed or deserialized without this constructor, so that check is not a universal type invariant.

## Rust API compatibility

This stage changes the public Rust API: `NetworkBackend` now requires `QueryTarget`, query and subscription arguments use typed targets, `NetworkError` adds `Unsupported`, and `BackendBalance::new` returns `Result`. External Rust callers and trait implementers may need changes; compatibility with downstream crates has not been verified. The wallet's Tauri and agent JSON contracts were not intentionally changed by this stage.
