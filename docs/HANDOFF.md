# ElectrumSV-MC – Work Handoff

Status: 2026-11-20. This document records the state; it does not authorize further work.

## Objective and locations

Develop a functional BSV wallet with an optionally enabled agent interface. Project: `/run/media/system/Spiele/Projekte/electrumsv-mc`. The implementation is based on the original test version, but is not a verified byte-for-byte reconstruction of the lost patch. Follow the workspace and global `AGENTS.md` instructions and the Controller-Handle skill when applicable. Research and historical audits are in `../electrumsv-mc-info/`.

The project worktree is on `main` at `bab27657a1465b99f0f027901a13d117136a19dd` and contains many uncommitted changes and new files. Its `origin` points to the older Minenclown repository. Do not reset or broadly clean this worktree; `.dh/` is excluded from the published wallet snapshot.

The separate publishing snapshot is at `../.electrumsv-publish-snapshot/` on branch `development/wallet-teststand-2026-11-19` in `SteveCo-AI/ElectrumSV-MC`. Verify the actual GitHub branch before another push; local tracking refs may be stale. This checkpoint is not a change to `main` or a 1.0 release.

## Previously accepted stage

[R1–R3 in the roadmap](roadmap.md) were accepted for the review and correction scope defined on 2026-11-19: Controller-Handle error contracts and initialization, isolated backup/recovery and payment scenarios, and bounded header/proof corrections. The 3/3 progress figure applies only to that stage, not to the entire wallet.

The isolated payment test used a real Wry/Tauri send view with synthetic wallet state and a local TLS mock. It covered sync, incorrect and correct TOTP, signing, connection loss with an unknown outcome, and an explicit retry using identical transaction bytes. The mock checked the script VM and actual fee. It did not establish GUI login, GUI connection setup, persistent TOTP policy, live broadcast, or consensus. See the [roadmap](roadmap.md), [KNOWN_ISSUES.md](../KNOWN_ISSUES.md), and [test host](../tools/wry-payment/README.md) for details and boundaries.

The current Linux test artifact is `src-tauri/target/release/electrumsv-mc`, SHA-256 `0e64770557616e19c9ef8762b281ce74efce462b3bba9c1625affe853f08cf5d`. It includes an earlier UTXO view, but predates the accepted U1.1 and U1.2 source changes. A separate isolated agent smoke checked startup, an empty wallet status, and disabled-by-default capabilities; it did not exercise a release-binary payment. The prior artifact is retained as `src-tauri/target/release/electrumsv-mc-18e1b1cd-teststand`, SHA-256 `18e1b1cdf19bc5abc90591f5f33acfd9edca7673240ab29e02139a126ce449d7`. Earlier checks and their source versions are described in [START_HIER_DE.md](../START_HIER_DE.md).

## Current local state: U1

U1 was **accepted** after the UTXO view correction and replacement of ambiguous temporary negative sync IDs with typed references. Focused database, ownership, rollback, two-pass local TLS sync and Wry payment checks passed; the full library suite passed 646 tests with 7 ignored. The changed UTXO view distinguishes wallet path, instance token, and account; separates stale responses, loading errors, and empty results; and validates values and duplicate outpoints. It no longer labels every non-coinbase output as P2PKH without script evidence. This is a GUI guard, not a demonstrated backend instance-CAS guarantee.

Files and SHA-256 hashes at the pause:

- `gui/src/views/UtxoView.tsx`: `f5fa829c2f3a60b2c3d700dd48976dc555423157cfc68996dae525cab7363f4e`
- `gui/src/api.ts`: `c22eea0b367fc2ef94fd90a4d3aabd97a674dc82437a2c2dc6dc5395158d715b`
- `gui/src/__tests__/UtxoView.test.tsx`: `5a8fb90d3cb3ac4c5a7d3dce844a956193987ecf8ced44efec6f0782de1f936a`
- `gui/src/__tests__/WalletViews.test.tsx`: `54b40d5aad248914cf469b2553a8bce49c0ae8f617d84eefd9428bc787ffef90`

U1.1 removed an unnecessarily strict nonnegative check on the read-only backend ID. Two synthetic negative-ID cases failed before the fix; 38/38 focused and 175/175 GUI tests passed afterward, along with a GUI build. No real negative-ID legacy wallet has been identified. U1.2 addresses the separate ambiguity between stored negative IDs and temporary discovery sentinels; the scoped package is accepted after the documented tests and source review. The current release binary predates the latest U1.1 source change.

## Current work: R4

The explicit bounded recovery search and conservative merge are accepted for the synthetic R4 scope. Tauri and agent entry points and a GUI action are implemented. The scan uses the active unlocked account and selected ElectrumX connection, checks both branches for indices 0 through `end_index_exclusive - 1` (1–1000), and preserves the ordinary discovery marker. It rejects unsupported key inventories and inconsistent data. A server can omit activity; the scan does not establish completeness or consensus. The 120-second deadline does not guarantee the outcome if the process or reply is lost around SQLite commit. The accepted matched-response budget is 64 MiB; an additional rejecting frame can already have been read. See [network contract](network-contract.md).

The backend source compiled offline. Focused results: 7 explicit-merge, 25 network-command, 49 ElectrumX, 5 sync regression and 1 ledger test passed. Three local TLS tests passed, including the agent network capability gate, range validation, discovered outputs beyond the gap, reopen/resync, session replacement and out-of-range output rejection. The private Wry test passed the real NetworkView and Tauri command against a local TLS fixture and checked persisted outputs on both branches. The test pre-opens the wallet and pre-connects the server. These are synthetic results; the release binary above predates R4. Preserve the working tree, never publish user data or test secrets, and save reviewed progress on the designated branch.

## Architecture stage

The user approved wallet-specific domain-boundary rules and implementation based on the architecture audit. `AGENTS.md` records the rules. A2 centralizes existing coin-selection identifiers and mappings. A3 adds a bound payment-backend snapshot, lifecycle and request-generation safeguards, typed provider query targets, truthful history verification flags, and explicit balance-overflow errors. The scoped A1–A3 work was accepted after review and risk-based tests; this is not a claim of full consensus or release readiness. Public Rust API changes, address-format restrictions and runtime-cleanup limits are in [network-contract.md](network-contract.md).

On the final source snapshot, the Rust library suite passed 643 tests with 7 ignored; isolated network/command tests passed 175/175, local WoC integration 2/2 and agent TLS/sync 1/1. Rustdoc passed 5 with 1 ignored; the separate Wry/Tauri synthetic payment flow also passed. These are distinct overlapping runs, not an additive unique-test count. The Wry test used a test host and local mock, not the release binary or a real broadcast.

## Remaining limitations

No 1.0 release or approval for real funds has been granted. Normal sync does not prove independent consensus validation or completeness of server responses; difficulty adjustment, chainwork selection, and complete reorg support are missing. The recovery scan uses a gap of 20 addresses. Imported private keys and the old legacy sweep are not approved for safe spending; multisig and further integrations remain open. Windows and macOS are not equivalently verified. See [KNOWN_ISSUES.md](../KNOWN_ISSUES.md) for the authoritative detailed list.
