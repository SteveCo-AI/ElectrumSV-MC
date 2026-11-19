# ElectrumSV-MC – Work Handoff

Status: 2026-11-19. The user requested the architecture stage after the earlier pause. This document records the state; it does not authorize further work.

## Objective and locations

Develop a functional BSV wallet with an optionally enabled agent interface. Project: `/run/media/system/Spiele/Projekte/electrumsv-mc`. The implementation is based on the original test version, but is not a verified byte-for-byte reconstruction of the lost patch. Follow the workspace and global `AGENTS.md` instructions and the Controller-Handle skill when applicable. Research and historical audits are in `../electrumsv-mc-info/`.

The project worktree is on `main` at `bab27657a1465b99f0f027901a13d117136a19dd` and contains many uncommitted changes and new files. Its `origin` points to the older Minenclown repository. Do not reset or broadly clean this worktree; `.dh/` is excluded from the published wallet snapshot.

The separate publishing snapshot is at `../.electrumsv-publish-snapshot/`. The previously confirmed checkpoint is commit `b40fdd3f4cbb3f6674d00bae66676fad08b7f9b1` on branch `development/wallet-teststand-2026-11-19` in `SteveCo-AI/ElectrumSV-MC`; later commits on that branch may contain the unaccepted U1 work in progress. The snapshot's local `origin/*` tracking ref may be stale; verify the actual GitHub branch before another push. This checkpoint is not a change to `main` or a 1.0 release.

## Previously accepted stage

[R1–R3 in the roadmap](roadmap.md) were accepted for the review and correction scope defined on 2026-11-19: Controller-Handle error contracts and initialization, isolated backup/recovery and payment scenarios, and bounded header/proof corrections. The 3/3 progress figure applies only to that stage, not to the entire wallet.

The isolated payment test used a real Wry/Tauri send view with synthetic wallet state and a local TLS mock. It covered sync, incorrect and correct TOTP, signing, connection loss with an unknown outcome, and an explicit retry using identical transaction bytes. The mock checked the script VM and actual fee. It did not establish GUI login, GUI connection setup, persistent TOTP policy, live broadcast, or consensus. See the [roadmap](roadmap.md), [KNOWN_ISSUES.md](../KNOWN_ISSUES.md), and [test host](../tools/wry-payment/README.md) for details and boundaries.

The last built Linux test artifact is `src-tauri/target/release/electrumsv-mc`, SHA-256 `18e1b1cdf19bc5abc90591f5f33acfd9edca7673240ab29e02139a126ce449d7`. It does **not** include the later UTXO-view changes. Earlier checks and their source versions are described in [START_HIER_DE.md](../START_HIER_DE.md).

## Current local state: U1

U1 is **implemented and submitted for review, not accepted**. It is being saved to the development branch as a work-in-progress checkpoint. The changed UTXO view distinguishes wallet path, instance token, and account; separates stale responses, loading errors, and empty results; and validates values and duplicate outpoints. It no longer labels every non-coinbase output as P2PKH without script evidence. This is a GUI guard, not a demonstrated backend instance-CAS guarantee.

Files and SHA-256 hashes at the pause:

- `gui/src/views/UtxoView.tsx`: `66d5320f10278f9dfa0763b8d2178e3462c01fa9f3bcc886bbcf46d4c2d143be`
- `gui/src/api.ts`: `c22eea0b367fc2ef94fd90a4d3aabd97a674dc82437a2c2dc6dc5395158d715b`
- `gui/src/__tests__/UtxoView.test.tsx`: `35b3fdd69bb2eb900b025e4b84ebeebd34c98f1f35403e96e75971562396308f`
- `gui/src/__tests__/WalletViews.test.tsx`: `54b40d5aad248914cf469b2553a8bce49c0ae8f617d84eefd9428bc787ffef90`

The implementer reported three failures reproduced before the fix, followed by 28/28 targeted tests, 165/165 GUI tests, a successful GUI build, and `git diff --check`. These results do not constitute a new release build or acceptance. The initial source review partially confirmed the examined session and DTO contracts; a compatibility point mentioned before the pause had not yet been specified. Do not treat it as resolved.

On resumption, first inspect the current diff and these hashes, complete the independent review including the compatibility point, and address any substantiated findings. Only after successful review should U1 be accepted in the [roadmap](roadmap.md) and a new release artifact considered. Save subsequent changes to the designated GitHub branch; do not publish user data or test secrets.

## Architecture stage in progress

The user approved wallet-specific domain-boundary rules and implementation based on the architecture audit. `AGENTS.md` now records those rules. A2 centralizes the existing coin-selection names and mappings in a typed catalog; focused offline checks and review are complete. A3 network lifecycle and payment-backend boundaries are still in progress, with concurrency, cancellation and cleanup under investigation. See [roadmap](roadmap.md) for acceptance status; do not treat an unfinished A3 as verified.

## Remaining limitations

No 1.0 release or approval for real funds has been granted. Normal sync does not prove independent consensus validation or completeness of server responses; difficulty adjustment, chainwork selection, and complete reorg support are missing. The recovery scan uses a gap of 20 addresses. Imported private keys and the old legacy sweep are not approved for safe spending; multisig and further integrations remain open. Windows and macOS are not equivalently verified. See [KNOWN_ISSUES.md](../KNOWN_ISSUES.md) for the authoritative detailed list.
