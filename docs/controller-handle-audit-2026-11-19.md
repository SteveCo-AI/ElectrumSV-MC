# Controller–Handle Architecture Audit

- **Date:** 2026-11-19
- **Repository:** `/run/media/system/Spiele/Projekte/electrumsv-mc`
- **Purpose:** Identify current wallet domains where a Controller–Handle boundary could reduce concrete implementation wiring and maintenance work.

## Snapshot and coverage

The inspected source was the live, dirty worktree at `bab27657a1465b99f0f027901a13d117136a19dd`, not the commit alone. The 147-file source/configuration selection had this SHA-256 snapshot fingerprint: `4599f0ea8d952deecbe9b20b5b984ec4ef4e04402bd1218df60f33098c067ec2`. It is computed over sorted relative paths and file bytes, each separated by NUL bytes. The selection totaled 1,897,606 bytes; Repomix's `o200k_base` source-tree estimate was 436,904 tokens.

| Included area | Files |
| --- | ---: |
| `src-tauri/src/**/*.rs` | 68 |
| `gui/src/**/*.ts(x)` | 45 |
| Rust integration tests | 7 |
| SQL migrations | 12 |
| Tauri, Rust and GUI build/configuration files | 7 |
| Wry helper and fixture files | 8 |
| **Total** | **147** |

All 147 files were screened for implementation traits, providers, dispatch, construction, and cross-layer call sites. Eight bounded Repomix packs were used for focused review; candidate domains were traced from implementation through service/command wiring and relevant GUI/API callers. This is an architecture-fit audit, not a line-by-line functional or security audit of every unrelated command.

Excluded from the source selection: `src-tauri/target` (52,642 files), `gui/node_modules` (7,419 third-party files), `gui/dist` (6 build files), and `src-tauri/gen` (4 generated files), totaling **60,071** files. `.git` metadata (185 files), Markdown documentation except the findings cited below, `Cargo.lock`, and `gui/src/index.css` were outside the source selection. The historical plans in `../electrumsv-mc-info` were checked as intent/context; current source is treated as behavioral evidence. No tests, builds, live network calls, or transactions were run.

## Findings

### 1. On-chain data detection already fits the pattern

`OnChainDataDetector` defines the stable detection contract (`src-tauri/src/features/mod.rs:40-49`). The current runtime set contains three distinct implementations: Ordinal, OP_RETURN, and STAS (`src-tauri/src/features/mod.rs:241-281`). `DetectorController` owns registration, duplicate-ID rejection, ordered dispatch, and the `Plain` fallback (`src-tauri/src/features/mod.rs:118-174`). Its built-in composition list is in `init_detectors` (`src-tauri/src/features/mod.rs:206-218`). The production path is `src-tauri/src/commands/features.rs:42-73` → `decode_script`/`decode_outputs` (`src-tauri/src/features/mod.rs:290-310`) → `detect_all`; command filters consume the stable `DecodedKind` enum.

This is the clearest qualifying Controller–Handle domain and it is already implemented. Source tests cover unknown lookup, registration collisions, idempotent initialization, order, and fallback (`src-tauri/src/features/mod.rs:353-537`); these tests were read but not executed. Registration has no production caller outside built-in initialization in the reviewed call-site search. `get_handle` currently returns an index and has no production consumer; decoding iterates the registered detectors directly. That is a small API/lifecycle observation, not a reason to replace the controller. Keep registration at the composition point and preserve detector priority, which is observable behavior.

The controller coordinates the detectors; it does not provide timeout, crash, or error isolation. The current detector contract is synchronous and returns `Option<DecodedKind>`.

### 2. Exchange rates already aggregate six implementations

`ExchangeRateProvider` has six production implementations (`src-tauri/src/features/exchange_rate.rs:84-90,138-378`). `ExchangeRateService` owns them in one ordered vector, exposes IDs, and falls back to the first successful provider (`src-tauri/src/features/exchange_rate.rs:384-458`). `src-tauri/src/commands/ecosystem.rs` delegates rate commands to this service. Adding a provider currently requires one implementation and one entry in the service's default list; no repeated command-level provider switch was found.

This domain meets the implementation-count threshold, but the existing service already owns provider composition and fallback. A separate registry/controller would add a second orchestration layer without removing current wiring. Keep the service as the single provider boundary.

### 3. Coin selection is the strongest conditional future candidate; do not add handles yet

The transaction builder supports largest-first plus Branch-and-Bound, RandomSubset, and Privacy modes (`src-tauri/src/core/transaction.rs:153-214,357-435`; `src-tauri/src/core/coinchooser.rs:207-270`). At the algorithm-family level this is largest-first, BnB, and the randomized selector, with Privacy using the randomized implementation with a policy flag. `TxBuilder` owns fee convergence and maps selected coins back to wallet UTXOs, so the strategy boundary must remain limited to candidate selection.

There is a concrete metadata-maintenance seam: `src-tauri/src/services/transaction_service.rs:89-99` parses accepted names while `src-tauri/src/commands/ecosystem.rs:187-197` separately advertises them. The GUI API exposes `getCoinSelectionStrategies` (`gui/src/api.ts:327-328`), but no current view calls it, and `SendView` currently calls `prepareTx` without a strategy (`gui/src/views/SendView.tsx:249-253`). The ordinary UI therefore does not currently select among these modes. A parser in `src-tauri/src/commands/transactions.rs:166-177` is only found at its definition and test sites, not on the production `prepare_tx` path; it should not be counted as a second live dispatch path.

If these choices become a supported UI/plugin extension point, first centralize IDs, labels, parsing, and availability in one typed strategy catalog. A full Controller–Handle split is justified only if algorithms need independent registration or replacement. Until then the enum and match are small and explicit; a new controller would not simplify fee/input safety contracts.

### 4. Network backends have direct wiring, but their common contract is not yet uniform

There are two production `NetworkBackend` implementations (`src-tauri/src/network/electrumx.rs:586`; `src-tauri/src/network/whatsonchain.rs:241`) and a two-case `BackendType` (`src-tauri/src/network/backend.rs:22-35`). State separately stores `connected`, concrete ElectrumX and WhatsOnChain clients, and the active enum (`src-tauri/src/state.rs:136-155`). `set_network_backend` parses a string and switches those fields (`src-tauri/src/commands/network.rs:283-320`); transaction broadcasting repeats concrete backend matches (`src-tauri/src/services/transaction_service.rs:379-399`). Several WOC-only commands also construct that client directly (`src-tauri/src/commands/extra.rs:650-668`).

The trait does not yet give these implementations one safe semantic contract for all callers. Its balance method promises a scripthash (`src-tauri/src/network/backend.rs:260-267`), while WOC treats the argument as an address (`src-tauri/src/network/whatsonchain.rs:256-263`). WOC has no push subscriptions (`src-tauri/src/network/whatsonchain.rs:111-115,490-499`), and wallet sync extracts an `ElectrumXClient` specifically (`src-tauri/src/commands/network.rs:511-524,728-735`). The current UI has a `setNetworkBackend` API wrapper, but no view calls it (`gui/src/api.ts:261-262`; repository-wide GUI search).

This is a direct-wiring hotspot, but **not a current Controller–Handle candidate**: there are only two backends and their capabilities differ. Before adding another backend, consolidate active-client lifecycle behind a typed backend service/state representation and describe capabilities explicitly. Revisit Controller–Handle if a third runtime-selectable backend implements the operations actually needed by the same consumers. A generic handle over the current trait could hide address/scripthash and push/poll differences.

### 5. Signers do not have three usable runtime implementations

`Signer` has Local, Hardware, and Multisig implementations in source (`src-tauri/src/core/signer.rs:37,206,287,357`), but only `LocalSigner` is used by the durable transaction service (`src-tauri/src/services/transaction_service.rs:263-305`). `HardwareSigner` is feature-gated and always reports `can_sign == false` (`src-tauri/src/core/signer.rs:261-302`). The public multisig command returns an unsupported error; its previous body is dead code (`src-tauri/src/commands/transactions.rs:247-267`). Nominal trait-implementation count therefore overstates the runtime alternatives. Do not introduce a signer controller until another signer is operational and its account/key/script capabilities are specified.

### 6. Historical controller plans are not evidence of current Rust extension points

The July migration plan proposed keystore, text-import, account, device, and exchange controllers for the earlier Python architecture (`../electrumsv-mc-info/MASTER-PLAN.md:66-77,280-319`). The current Rust wallet creation path is BIP39/BIP32; `Bip39RestoreMode` selects passphrase normalization conventions, not separate keystore implementations (`src-tauri/src/services/wallet_service.rs:115-149`). The current source contains no corresponding keystore/account handler traits or three usable runtime alternatives. The active project roadmap also says to review service/command dependencies evidentially and avoid a blanket architecture rewrite (`docs/roadmap.md:5-6`). Treat those historical controller proposals as future product direction only if re-accepted, not as current implementation requirements.

## Decision

No new Controller–Handle domain is recommended for the current source snapshot. Preserve the detector controller and the exchange-rate service. The most useful future cleanup is a typed coin-selection catalog if those options become user-facing; for network backends, normalize lifecycle and capability contracts before considering a controller. Static Tauri command registration and heterogeneous command dispatch are composition/transport boundaries, not interchangeable implementation families. A controller changes who owns lookup and orchestration; it does not automatically isolate faults or guarantee safe backend behavior.

## Audit limits

Coverage means every selected source/configuration file was structurally screened and the candidate call paths were source-traced. Unrelated business logic was not reviewed line by line; existing tests were not executed; no live network, wallet, or transaction behavior was exercised. Markdown history and product docs outside the cited roadmap were not treated as source behavior. The aggregate fingerprint identifies the audited 147-file content even though the repository was dirty.
