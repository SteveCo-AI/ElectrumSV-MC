# BSV ecosystem and Treechat research for ElectrumSV-MC

**Research snapshot:** 2026-11-19 (Europe/Berlin). Web pages and repositories were checked on this date; where an original publication or event date is available, it is stated separately. Dynamic product pages have no reliable publication date and are cited as observed on the research date. This is product and engineering research, not an endorsement of BSV or an investment view.

## Executive summary

The clearest wallet-relevant BSV development is the continuing effort to standardize wallet-to-application interactions through BRC-100 and related BRCs. The BRC repository is active and includes proposals for wallet interoperability, transaction formats, proofs, payment destinations, identities, and overlays. The two older standalone SDK and Wallet Toolbox repositories were archived on 2026-06-12 because development moved into the official [`ts-stack` monorepo](https://github.com/bsv-blockchain/ts-stack). As of this 2026-11-19 snapshot, the monorepo is publicly maintained and npm shows recent package releases, including `@bsv/sdk` 4.1.1 (published two days earlier) and `@bsv/wallet-toolbox` 2.17.0 (published three days earlier). The standards index itself warns that it contains both active interoperability specifications and historical context; each proposal's status and implementations must be checked before adoption.

Treechat is the BSV social application at **treechat.com** (the observed `treechat.ai` URL redirects there), not a generic app with a similar name. Its current official site describes threaded, branching conversations, pay-per-use AI, micropayment “upvalues,” on-chain public posts, and media collectibles. The current onboarding creates a built-in wallet from an email/password account; it does not document a supported external-wallet connection or public wallet API. Treechat's newer CLI and MCP are demonstrably real integrations for reading/posting/generation, but they authenticate to Treechat accounts; the CLI page explicitly says its local BSV wallet settlement is not wired in the current release. Therefore, a direct ElectrumSV-MC ↔ Treechat integration is **not presently evidenced**.

The useful near-term takeaway is to strengthen standard, user-controlled payment interoperability and make verification/trust state obvious, while treating BRC-100 as an active upstream interface to evaluate and Treechat as an unverified integration prospect. Avoid wholesale SDK adoption or a provider-specific bridge before there is a clear custody model and testable end-to-end contract.

## Current wallet constraints that recommendations must preserve

The current wallet's [network contract](network-contract.md) binds each payment to the selected backend, uses typed ElectrumX scripthash and WhatsOnChain address query targets, does not silently fallback or retry, and reports server-supplied history as unverified absent an independently checked proof. Merkle inclusion against a stored header does not prove chainwork, difficulty adjustment, completeness, or consensus. Its [known issues](../KNOWN_ISSUES.md) also identify mainnet-only operation, a 20-address first-restore gap, provider-data omissions, unsupported imported private-key flows, transaction/history size limits, and platform-specific backup caveats.

These are hard boundaries for ecosystem features: an app protocol, payment receipt, BEEF object, Merkle proof, or service response must never be presented as stronger chain verification than the wallet actually performed. Preserve explicit payment confirmation, persisted transaction state and explicit retry for unknown broadcasts. No on-chain writes, external authentication, third-party fees, or new custody relationship should be introduced implicitly.

## Findings and recommendations

### P1 — Make payment requests interoperable before adding a Treechat bridge

**Evidence.** BRC-27 defines invoice-style Direct Payment Protocol (DPP) messages, including terms, expiry, beneficiary, memo, payment and acknowledgement. Crucially, its own status note says it is external/legacy to the current BRC-100 SDK/toolbox surface and must not be inferred as required behavior for BRC-100. BRC-28 documents Paymail payment destination discovery and transaction delivery, but its status note says the listed AtFinder implementation is deprecated and the current SDK/toolbox does not implement Paymail discovery. [BRC-27](https://github.com/bsv-blockchain/BRCs/blob/master/payments/0027.md) and [BRC-28](https://github.com/bsv-blockchain/BRCs/blob/master/payments/0028.md), repository material checked 2026-11-19; the pages do not expose a stable publication date in the retrieved view.

**Wallet benefit.** A standards-reviewed invoice or human-readable destination flow could reduce address transcription errors and improve sender context for ordinary wallet payments, independently of any social app. This is a sensible follow-up to the existing receive/payment-request and contact surfaces.

**Implementation entrypoints.** First map the existing receive and payment-request commands, typed `NetworkBackend` targets, payment planning, and spend ledger. Then select one narrowly scoped interoperability profile only if a maintained, testable implementation exists. Treat BRC-27 and BRC-28 as candidate protocol references, not standards already supported by this wallet. Do not infer that Paymail's server-assisted notification equals verified chain inclusion.

**Required checks and safety.** Add deterministic fixtures for malformed, expired, wrong-network, duplicate-output, unexpected-amount, hostile URL/DNS, TLS, and signature cases; ensure the user sees the verified beneficiary, amount, memo, expiry, and network before signing. Test replay/idempotency and the existing `BROADCAST_UNKNOWN` explicit-retry invariant. Do not add network fetching until privacy exposure and endpoint allowlisting are designed. The wallet's mainnet-only validator must remain authoritative.

### P2 — Track BRC-100 as an interoperability target, not a dependency upgrade

**Evidence.** The BRC repository lists BRC-100 as its unified wallet-to-application interface and maps it to the BSV Association `@bsv/sdk`, `@bsv/wallet-toolbox`, BSV Desktop and BSV Browser reference implementations. The standards repository cautions that its contents mix active and historical material. The former standalone [TypeScript SDK](https://github.com/bsv-blockchain/ts-sdk) and [Wallet Toolbox](https://github.com/bsv-blockchain/wallet-toolbox) repositories were archived on 2026-06-12, and their READMEs explicitly redirect development, issues and releases into [`ts-stack`](https://github.com/bsv-blockchain/ts-stack). The monorepo README maps the SDK and wallet-toolbox packages, describes contribution/security policies and conformance vectors, and names maintainers. Its current package manifests identify `@bsv/sdk` and `@bsv/wallet-toolbox` (the manifest snapshot retrieved during this review reported 4.0.1 and 2.15.3; these source versions lagged the current npm registry pages). On 2026-11-19, npm reported `@bsv/sdk` 4.1.1 published two days earlier and `@bsv/wallet-toolbox` 2.17.0 published three days earlier. The npm package pages reported Apache-2.0; the monorepo README says first-party contributions are Apache 2.0 and incorporated historical materials retain scoped terms in notices. GitHub showed no formal monorepo Releases at the time checked, so npm publication is the stronger release-activity signal. The [BRC standards index](https://github.com/bsv-blockchain/BRCs) and repositories were checked 2026-11-19. The BSV Association's SDK code-along was published 2024-05-20 (historical orientation only), while a BRC-100 explainer from Project Babbage was published 2025-12-12 (secondary/educational source, not used as the normative specification).

**Wallet benefit.** A stable, least-privilege app-to-wallet surface could eventually let users approve app-requested payments or signatures while keeping keys inside the wallet. This can reduce one-off app integrations and make permissions visible and revocable.

**Current blockers.** The standalone repositories are archived, but the successor monorepo and npm packages are active; this is a repository migration, not evidence that the SDK was abandoned. The current monorepo's package manifests and npm-published package versions are not synchronized in the retrieved snapshots, so pin and verify immutable package artifacts, source commit, license bundle and test results before adopting a version. The wallet is a Rust/Tauri desktop product with its own authenticated commands, durable spend ledger, TOTP policy and network capability model; the JavaScript BRC-100 surface is not a drop-in replacement. BRC standards and a maintained toolkit do not prove broad app/provider support. A broad wallet-control API would expand attack surface and could undermine the existing transaction/TOTP invariants.

**Recommended next step.** Record a scoped architecture discovery item: identify the current normative BRC-100 version and mandatory subset, confirm the published npm artifacts against the monorepo commit and package license files, inventory conformance vectors relevant to this wallet, and specify signing/permission lifecycle, revocation and cancellation semantics plus a bridge strategy that keeps key access in Rust. Do not adopt the JavaScript wallet stack wholesale. If an app and maintained integration path are demonstrated, begin with read-only capabilities and an explicit, bounded transaction proposal requiring user review; preserve TOTP and the existing durable payment state machine.

### P2 — Keep proof formats separate from chain-trust claims

**Evidence.** The BRC registry indexes BRC-9 SPV, BRC-10 Merkle proof format, BRC-62 BEEF transactions, BRC-67 SPV, BRC-71 Merkle Path binary format, BRC-74 BUMP and BRC-77 message signatures. The [BRC standards index](https://github.com/bsv-blockchain/BRCs) is the primary directory; individual status notes should be checked before choosing a format. The current wallet already has separate stored-header Merkle proof verification and explicitly documents what it does not establish.

**Wallet benefit.** A carefully scoped proof-import/export or transaction-detail path could help users carry evidence between providers and inspect a transaction without implying that a server-reported confirmation is consensus-verified.

**Implementation entrypoints.** Review the existing header store, proof command and history-detail flow before introducing a new serializer. Prefer parsing into an internal typed representation; keep proof validity, header presence, server claim, and chain-selection status as distinct result fields. BEEF or another transport object is not a substitute for validating the proof against trusted chain state.

**Required checks and safety.** Test malformed and oversized proof encodings, transaction-ID binding, wrong-root and wrong-height cases, missing headers, and maximum allocation behavior. Do not alter header-selection or consensus claims based solely on a format standard. Do not increase current transaction or network frame limits as a side effect.

### P3 — Use Treechat as product research, not an integration commitment

**Identity and evidence.** The official [Treechat homepage](https://treechat.com/) describes the BSV social network; current site material was checked 2026-11-19 and does not provide an original publication date. It claims that each upvalue is a micropayment; public posts are written on-chain; conversations are branching; a built-in wallet is created during account sign-up; and AI/media actions are pay-per-use. These are the provider's descriptions, not independent verification of settlement, custody, permanence, or user counts.

The official [Treechat CLI page](https://treechat.com/cli) says `treecli` can read threads, publish posts and use media generation; it documents macOS/Linux and Windows distribution, Apache-2.0 licensing and checksum verification. It also states that the CLI's local BSV-wallet settlement is not wired in the current release and warns against funding that local wallet for CLI payments. The official [MCP page](https://treechat.com/mcp) documents OAuth 2.1/PKCE, account and thread read/write permissions, paid generation, quote/price caps and user-selected daily limits. These are Treechat account permissions and billing controls, not an external ElectrumSV-MC wallet API. The product pages show ©2026 but no publication date; claims were observed 2026-11-19.

An older official Treechat-channel [video](https://www.youtube.com/watch?v=XbgnNf-8Jhw) describes a 2025-era quick demo of signing up with the Panda Wallet Chrome extension. This historical demonstration conflicts with current homepage onboarding that advertises email/password and an automatically created built-in wallet. No current supported extension protocol, API, SDK, license or wallet-connection guide was found. Treat the older demo as historical evidence only; do not assume external-wallet compatibility persists.

**Useful product ideas.**

- Threaded payment context: a payment request can retain a human-readable reason and return reference, rather than appearing as an opaque address/amount pair.
- User-controlled app spending: Treechat's MCP quote-first flow and explicit per-action/daily spending limits are useful interaction patterns for future wallet-connected app approvals, even though Treechat itself is not currently such an integration.
- Explain permanence before publishing: on-chain public content is difficult to retract; wallet UX should never quietly turn a memo, identity detail or private recovery datum into blockchain data.
- Community features are optional product direction, not wallet protocol work: branching discussions, creator tips, AI and collectibles do not justify exposing wallet secrets or silently enabling token/ordinal handling.

**Concrete recommendation.** Do not add Treechat login, an MCP connector, media spending, ordinal support or a Treechat-specific wallet SDK now. A future proposal should first establish a current official external-wallet API, local-vs-custodial key ownership, recovery/backup behavior, fee schedule, message signing format, payment destination verification, privacy disclosures, and a test environment. Any app-initiated spend must be shown and approved in ElectrumSV-MC with the existing user authentication and transaction state handling.

### P3 — Treat scaling and activity claims as infrastructure context, not wallet guarantees

**Evidence.** The BSV Association's 2026-03-18 AMA describes Teranode architecture, Chronicle, network stability and developer tooling; its description presents topics, not independent uptime or throughput measurements ([official recording](https://www.youtube.com/watch?v=00C-L7E1dxw), event/publication date 2026-03-18). A BSV Association video published 2026-04-01 discusses SV Node 1.2/Chronicle activation around 2026-04-07 at block 943,816 ([official recording](https://www.youtube.com/watch?v=fPwTg4L_0kg)). Verify node release notes and actual network conditions before relying on upgrade details. The SDK and Wallet Toolbox moved to the maintained monorepo; their retrieved source and package-version metadata still need reconciliation. Ecosystem narratives about scale do not by themselves establish stable wallet dependencies, ubiquitous app support, fees, or confirmation quality.

**Wallet implication.** Keep endpoint health, timeouts, payload caps, cancellation, explicit provider selection, and honest verification labels. The current wallet already caps transaction and history resources; BSV's large-block design makes bounded resource policies particularly important. No recommended wallet feature here requires unbounded parsing or trusting a single provider's height claim.

## Ecosystem status, evidence limits, and date handling

- **Standards are not all implemented features.** The BRC repository includes proposal/history material and explicitly directs readers to per-document status notes and implementation maps. The presence of a BRC number is not evidence of deployment or support by Treechat or ElectrumSV-MC.
- **Treechat is a live product surface, but technical details are controlled by its operator.** The public site gives user-visible product behavior; it does not document key custody, recovery internals, full transaction API, offline support, or an external desktop-wallet ABI in the sources reviewed.
- **SDK maintenance is active in the successor monorepo.** The archived standalone repos redirect to `ts-stack`; current npm metadata shows recent SDK and Toolbox releases, and the monorepo documents governance, contribution, security and quality gates. Current source manifests and published versions differed in the views retrieved, and formal GitHub Releases were absent. Treat this as active upstream maintenance with version/source reconciliation still required, not as abandonment or as proof of broad third-party adoption.
- **Current-project evidence takes precedence.** `KNOWN_ISSUES.md`, `docs/network-contract.md`, and the Rust roadmap describe the wallet's actual current constraints; older plans in `electrumsv-mc-info` predate the rebuilt Rust implementation and should not be treated as current implementation facts.
- **No external engagement occurred.** No account was created, app was connected, transaction sent, CLI installed, or third party contacted as part of this research.

## Sources consulted

Primary sources:

- [Treechat homepage](https://treechat.com/) — current product descriptions, observed 2026-11-19.
- [Treechat CLI](https://treechat.com/cli) — capability, license, distribution and explicit local-BSV-payment limitation, observed 2026-11-19.
- [Treechat MCP](https://treechat.com/mcp) — OAuth permissions and spending approval model, observed 2026-11-19.
- [Treechat's older Panda Wallet demo](https://www.youtube.com/watch?v=XbgnNf-8Jhw) — historical wallet onboarding demonstration; published roughly 2025 according to search metadata, exact date not shown in retrieved page.
- [BRC standards repository](https://github.com/bsv-blockchain/BRCs) — standards index and implementation/status guidance, checked 2026-11-19.
- [BRC-27 DPP](https://github.com/bsv-blockchain/BRCs/blob/master/payments/0027.md) and [BRC-28 Paymail](https://github.com/bsv-blockchain/BRCs/blob/master/payments/0028.md) — payment protocol definitions and explicit implementation caveats.
- [Archived TypeScript SDK README](https://raw.githubusercontent.com/bsv-blockchain/ts-sdk/master/README.md) and [archived Wallet Toolbox README](https://raw.githubusercontent.com/bsv-blockchain/wallet-toolbox/master/README.md) — explicit migration notices to `ts-stack`.
- [`ts-stack` monorepo](https://github.com/bsv-blockchain/ts-stack), [SDK package](https://github.com/bsv-blockchain/ts-stack/tree/main/packages/sdk), and [Wallet Toolbox package](https://github.com/bsv-blockchain/ts-stack/tree/main/packages/wallet/wallet-toolbox) — current upstream structure, contribution/security/conformance policies, package map and maintainership, checked 2026-11-19.
- [@bsv/sdk npm package](https://www.npmjs.com/package/%40bsv/sdk) — version 4.1.1 published two days before snapshot; [@bsv/wallet-toolbox npm package](https://www.npmjs.com/package/%40bsv/wallet-toolbox) — version 2.17.0 published three days before snapshot. npm metadata reported Apache-2.0; source/manifests should be reconciled before pinning.
- [BSV Association AMA](https://www.youtube.com/watch?v=00C-L7E1dxw), published 2026-03-18; [Chronicle/SV Node discussion](https://www.youtube.com/watch?v=fPwTg4L_0kg), published 2026-04-01.

Project sources read:

- [Network trust contract](network-contract.md)
- [Known issues](../KNOWN_ISSUES.md)
- Selected historical planning context from `electrumsv-mc-info/RUST-PORT-PLAN.md`, `M5-PREP.md`, and `MASTER-PLAN.md`; used only to recognize older plans, not to infer current implementation.

## Suggested decision

Put a small, non-blocking discovery item on the wallet roadmap to evaluate a bounded, user-approved external payment request flow against maintained BSV interoperability implementations. Treat `ts-stack` as an active upstream candidate and assess a narrow BRC-100 bridge against its published artifacts and conformance contracts; do not treat that upstream maintenance as evidence of broad app adoption. Keep Treechat-specific integration on hold until current external-wallet API, custody, and compatibility-test evidence exists. Continue to treat all backend-supplied transaction/history claims according to the current network trust contract.
