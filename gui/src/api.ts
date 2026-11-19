// API client for ElectrumSV-Mc — Tauri IPC (no REST, no Python backend)
import { invoke } from '@tauri-apps/api/core';

// ─── Types matching Rust backend structs ───

/** NetworkDefinition matches Rust `commands::extra::NetworkDefinition` — static BSV network identity (mainnet / testnet / STN). */
export interface NetworkDefinition {
  id: string;
  name: string;
  default_ports: string[];
  bitcoin_uri_prefix: string;
}

/** NetworkInfo matches Rust `commands::network::NetworkInfo` — live connection status. */
export interface NetworkInfo {
  connected: boolean;
  backend_type: string | null;
  active_server: string | null;
  tip_height: number | null;
  server_count: number;
  connected_count: number;
  banned_count: number;
}

/** BalanceInfo matches Rust `commands::account::BalanceInfo` — wallet balance (i64 fields). */
export interface BalanceInfo {
  confirmed: number;
  unconfirmed: number;
  total: number;
  reserved?: number;
  available?: number;
}

export interface SpendPlanStatus {
  plan_id: string;
  state: 'PREPARED' | 'SIGNED' | 'BROADCAST_UNKNOWN' | 'BROADCASTED' | 'CANCELLED';
  txid: string | null;
}

export interface MigrationPreview {
  from_version: 33;
  to_version: 34;
  policy: {
    legacy_totp_enabled: boolean;
    legacy_wallet_scope: 'unspecified' | 'login' | 'tx';
    legacy_record_scope: 'login' | 'tx' | null;
    target_policy_id: string;
    newly_require_totp: string[];
  };
  confirmation_token: string;
  expires_in_seconds: number;
}
export interface MigrationSuccess { backup_path: string; from_version: 33; to_version: 34; reopen_required: true }

/** UtxoEntry matches Rust `commands::account::UtxoEntry` — wallet UTXO from DB. */
export interface UtxoEntry {
  tx_hash: string;
  tx_index: number;
  value: number;
  keyinstance_id: number;
  is_coinbase: boolean;
  script_pubkey: string;
}

/** HistoryEntry matches Rust `commands::account::HistoryEntry` — wallet transaction history. */
export interface HistoryEntry {
  tx_hash: string;
  value_delta: number | null;
  date_created: number;
  block_height: number | null;
  description: string | null;
}

export interface TransactionDetail {
  txid: string;
  status: string;
  raw_tx: string | null;
  account_id: number | null;
  fee: number | null;
  inputs: { prev_tx_hash: string; prev_vout: number; script_sig: string; sequence: number }[] | null;
  outputs: { value: number; script_pubkey: string }[] | null;
  label: string | null;
  detail_complete: boolean;
}

/** AccountInfo matches Rust `commands::account::AccountInfo` — account summary. */
export interface AccountInfo {
  account_id: number;
  account_name: string;
  default_script_type: number;
}

/** PaymentOutput matches Rust `PaymentOutput { address, satoshis }` */
export interface PaymentOutput {
  address: string;
  satoshis: number;
}

/** DecodedOutput matches Rust `DecodedOutput` — classified on-chain data */
export interface DecodedOutput {
  output_index: number;
  value: number;
  script_pubkey_hex: string;
  kind: {
    type: 'ordinal' | 'op_return_protocol' | 'stas_token' | 'plain';
    // Ordinal fields
    protocol?: string;
    content_type?: string;
    content_hex?: string;
    content_text?: string | null;
    // OP_RETURN protocol fields
    data?: any;
    // STAS token fields
    symbol?: string | null;
    contract_txid?: string | null;
    amount?: number | null;
    script_hex?: string;
  };
}

/** TxPlan is deprecated — the backend no longer sends the full plan to the renderer.
 *  prepare_tx returns only a plan_id handle + metadata; the full plan stays server-side. */
// export interface TxPlan { ... }

/** ServerInfo matches Rust `commands::network::ServerEntry` — ElectrumX server list entry. */
export interface ServerInfo {
  host: string;
  s?: number;  // SSL port
  t?: number;  // TCP port
  note?: string;
}

// These exact backend errors occur before any TOTP policy write. All other
// failures, including transport errors, leave the operation outcome uncertain.
export function isDefiniteTotpAuthFailure(error: unknown): boolean {
  const message = typeof error === 'string' ? error : error instanceof Error ? error.message : '';
  return ['incorrect password', 'wallet authentication failed', 'invalid TOTP code', 'TOTP code required', 'invalid recovery code'].includes(message);
}

export const api = {
  // App
  getAppVersion: () => invoke<string>('get_app_version'),

  // Wallet lifecycle
  createWallet: (password: string, walletName?: string, mnemonic?: string) =>
    invoke<any>('create_wallet', { name: walletName || 'default_wallet', password, mnemonic: mnemonic || null, passphrase: null }),
  restoreBip39Wallet: (name: string, password: string, mnemonic: string, passphrase: string, mode: 'standard_bip39' | 'historical_mc') =>
    invoke<any>('restore_bip39_wallet', { name, password, mnemonic, passphrase, mode }),
  openWallet: (walletPath: string) =>
    invoke<any>('open_wallet', { walletPath }),
  closeWallet: (walletPath: string) =>
    invoke<any>('close_wallet'),

  // Legacy ElectrumSV (1.3.x) seed migration
  restoreLegacyWallet: (seedWords: string, password: string, walletName?: string) =>
    invoke<any>('restore_legacy_wallet', { seedWords, password, walletName: walletName || 'migrated_wallet' }),
  sweepLegacyWallet: (seedWords: string, newWalletPath: string, password: string) =>
    invoke<any>('sweep_legacy_to_new', { seedWords, newWalletPath, password }),
  unlockWallet: (walletPath: string, password: string) =>
    invoke<any>('unlock_wallet', { password }),
  unlockWalletWithTOTP: (walletPath: string, password: string, totpCode?: string) =>
    invoke<any>('unlock_wallet', { password, totpCode: totpCode ?? null }),
  listWallets: () => invoke<any[]>('list_wallets'),

  previewMigration: (password: string, totpCode?: string) =>
    invoke<MigrationPreview>('preview_migration', { password, totpCode: totpCode ?? null }),
  migrateWallet: (password: string, totpCode: string | undefined, backupPath: string, confirmationToken: string) =>
    invoke<MigrationSuccess>('migrate_wallet', { password, totpCode: totpCode ?? null, backupPath, confirmationToken }),

  // Wallet info
  getWalletInfo: () => invoke<any>('get_wallet_status'),
  getAccounts: () => invoke<any[]>('get_accounts'),
  getBalance: (accountId?: number) =>
    invoke<BalanceInfo>('get_balance', { accountId: accountId ?? null }),
  getHistory: (accountId: number) =>
    invoke<HistoryEntry[]>('get_history', { accountId, limit: null, offset: null }),
  listReceiveAddresses: (accountId: number) => invoke<any[]>('list_receive_addresses', { accountId }),
  getUtxos: (accountId: number) =>
    invoke<any[]>('get_utxos', { accountId }),
  getKeys: (accountId: number) =>
    invoke<any[]>('get_keys', { accountId }),
  // Multisig account commands (Task 5)
  createMultisigAccount: (accountName: string, threshold: number, publicKeys: string[]) =>
    invoke<number>('create_multisig_account', { accountName, threshold, publicKeys }),
  getMultisigConfig: (accountId: number) =>
    invoke<{ account_id: number; threshold: number; num_keys: number; public_keys: string[] } | null>(
      'get_multisig_config', { accountId }
    ),
  getReceiveAddress: (accountId: number) =>
    // Backend returns { address, keyinstance_id, derivation_index }
    invoke<any>('get_receive_address', { accountId }).then(r => ({
      ...r,
      key_id: r?.keyinstance_id ?? null,
    })),
  getTransaction: (txid: string) =>
    invoke<TransactionDetail>('get_transaction', { txid }),

  // 3-stage transaction workflow
  // AUD-008: prepare_tx returns a plan_id handle + metadata only — the full
  // TxPlan stays server-side and is never sent to the renderer.
  prepareTx: (body: { outputs: PaymentOutput[]; feeRate: number; opReturn?: string }) =>
    invoke<{
      plan_id: string;
      fee: number;
      total_input: number;
      total_output: number;
      change: number;
      num_inputs: number;
      num_outputs: number;
    }>('prepare_tx', {
      outputs: body.outputs,
      feeRate: body.feeRate,
      opReturn: body.opReturn ?? null,
    }),

  // AUD-008: sign_tx takes a plan_id (server fetches the plan) + TOTP code
  signTx: (planId: string, totpCode: string) =>
    invoke<{ txid: string; signed_tx_hex: string }>('sign_tx', {
      planId,
      totpCode,
    }),

  // broadcast_tx: takes signed hex + expected txid (from sign_tx result)
  broadcastTx: (signedTxHex: string, expectedTxid: string) =>
    invoke<string>('broadcast_tx', { signedTxHex, expectedTxid }),

  getSpendPlanStatus: (planId: string) =>
    invoke<SpendPlanStatus>('get_spend_plan_status', { planId }),
  listSpendPlans: () => invoke<SpendPlanStatus[]>('list_spend_plans'),
  cancelSpendPlan: (planId: string) => invoke<void>('cancel_spend_plan', { planId }),
  broadcastSpendPlan: (planId: string, expectedTxid: string, retryUnknown = false) =>
    invoke<string>('broadcast_spend_plan', { planId, expectedTxid, retryUnknown }),

  // estimate_fee: returns { fee, num_inputs, num_outputs, fee_rate }
  estimateFee: (outputs: PaymentOutput[], feeRate: number, opReturn?: string) =>
    invoke<{ fee: number; num_inputs: number; num_outputs: number; fee_rate: number }>(
      'estimate_fee', { outputs, feeRate, opReturn: opReturn ?? null }
    ),

  // Network
  getNetworkInfo: () => invoke<NetworkInfo>('get_network_info'),
  getServers: () => invoke<ServerInfo[]>('get_servers'),
  connectServer: (host: string, port: number) =>
    invoke<any>('connect_server', { host, port }),
  disconnectServer: () =>
    invoke<any>('disconnect_server'),
  syncWallet: () =>
    invoke<any>('sync_wallet'),
  syncHeaders: () =>
    invoke<any>('sync_headers'),
  banServer: (host: string) =>
    invoke<any>('ban_server', { host }),
  setNetworkBackend: (backend: string) =>
    invoke<any>('set_network_backend', { backend }),
  getHeaderStoreInfo: () =>
    invoke<any>('get_header_store_info'),
  getServersByStatus: () =>
    invoke<any>('get_servers_by_status'),
  verifyTransactionProof: (txid: string, proof: string) =>
    invoke<any>('verify_transaction_proof', { txid, proof }),

  // Network switching
  listNetworks: () => invoke<NetworkDefinition[]>('list_networks'),
  switchNetwork: (networkId: string) =>
    invoke<string>('switch_network', { networkId }),

  // WhatsOnChain extras
  wocGetChainInfo: () =>
    invoke<any>('woc_get_chain_info'),
  wocGetBlockHeader: (height: number) =>
    invoke<any>('woc_get_block_header', { height }),
  wocGetTx: (txid: string) =>
    invoke<any>('woc_get_tx', { txid }),

  // Wallet utilities (extra)
  backupWallet: (backupPath: string, password: string, totpCode: string | undefined, expectedInstanceToken: string) =>
    invoke<string>('backup_wallet', { backupPath, password, totpCode: totpCode ?? null, expectedInstanceToken }),
  importPrivkey: (wif: string, password: string) =>
    invoke<{ address: string; keyinstance_id: number }>('import_privkey', { wif, password }),
  send: (address: string, amount: number, password: string, totpCode: string, opReturn?: string, feeRate?: number) =>
    invoke<{ txid: string; status: string }>('send', {
      address, amount, password, totpCode,
      opReturn: opReturn ?? null, feeRate: feeRate ?? null,
    }),

  // TOTP scope management
  getTotpStatus: () =>
    invoke<{ enabled: boolean | null; scope: string; recovery_codes_remaining: number; scope_editable?: boolean }>('get_totp_status'),
  setTotpScope: (password: string, scope: string, code?: string) =>
    invoke<string>('set_totp_scope', { password, scope, code: code ?? null }),

  // App name
  getAppName: () => invoke<string>('get_app_name'),

  // ─── BSV Ecosystem features ──────────────────────────────────────
  resolvePaymail: (handle: string) =>
    invoke<{ handle: string; address: string }>('resolve_paymail', { handle }),
  getExchangeRates: () =>
    invoke<{ currency: string; rate: number }[]>('get_exchange_rates'),
  getExchangeRate: (currency: string) =>
    invoke<number>('get_exchange_rate', { currency }),
  satoshisToFiat: (satoshis: number, currency: string) =>
    invoke<number>('satoshis_to_fiat', { satoshis, currency }),
  getMapiFeeQuote: (url?: string) =>
    invoke<{ mining_fee_satoshis: number; relay_fee_satoshis: number; raw: any }>('get_mapi_fee_quote', { url: url ?? null }),
  parseBip276Uri: (uri: string) =>
    invoke<{ valid: boolean; prefix: string | null; version: number | null; network: number | null; data_hex: string | null; error: string | null }>('parse_bip276_uri', { uri }),
  getCoinSelectionStrategies: () =>
    invoke<{ strategies: string[] }>('get_coin_selection_strategies'),

  // Config
  getConfig: () => invoke<any>('get_config'),
  updateConfig: (body: Record<string, any>) => {
    const entries = Object.entries(body);
    if (entries.length === 0) return Promise.resolve();
    const [key, value] = entries[0];
    return invoke<any>('update_config', { key, value: String(value) });
  },

  // Contacts — backend returns Vec<ContactInfo> (array, not { contacts: [...] })
  getContacts: () => invoke<any[]>('get_contacts'),
  addContact: (label: string, system: string, systemData: string) =>
    invoke<any>('add_contact', { label, system, systemData }),
  updateContact: (contactId: number, label: string) =>
    invoke<any>('update_contact', { contactId, label }),
  deleteContact: (contactId: number) =>
    invoke<any>('delete_contact', { contactId }),

  // Labels
  setKeyLabel: (keyId: number, label: string, _accountId: number) =>
    invoke<any>('set_key_label', { keyId, label }),
  setTxLabel: (txHash: string, label: string) =>
    invoke<any>('set_tx_label', { txHash, label }),

  // Payment Requests
  createPaymentRequest: (accountId: number, amount: number | null, label?: string) =>
    invoke<{ uri: string; address: string; amount: number | null; label: string | null; paymentrequest_id: number }>(
      'create_payment_request', { accountId, amount, label: label || null }
    ),
  listPaymentRequests: () => invoke<any[]>('list_payment_requests'),

  // Wallet utilities
  exportSeed: (password: string, totpCode?: string) =>
    invoke<any>('export_seed', { password, totpCode: totpCode ?? null }),
  exportPrivkey: (password: string, address?: string, all?: boolean, totpCode?: string) =>
    invoke<any>('export_privkey', { password, address: address || null, all: all || false, totpCode: totpCode ?? null }),
  changePassword: (oldPassword: string, newPassword: string, totpCode?: string) =>
    invoke<any>('change_password', { oldPassword, newPassword, totpCode: totpCode ?? null }),
  signMessage: (address: string, message: string, password: string, totpCode?: string) =>
    invoke<{ signature: string }>('sign_message', { address, message, password, totpCode: totpCode ?? null }),
  verifyMessage: (address: string, message: string, signature: string) =>
    invoke<{ valid: boolean }>('verify_message', { address, message, signature }),
  deleteWallet: (walletPath: string, password: string, totpCode?: string) =>
    invoke<void>('delete_wallet', { walletPath, password, totpCode: totpCode ?? null }),

  // Setup remains pending until confirmation; recovery leaves the wallet locked.
  totpEnable: (password: string) =>
    invoke<{ otpauth_url: string; secret_base32: string }>('begin_totp_setup', { password }),
  confirmTotpSetup: (password: string, code: string) =>
    invoke<void>('confirm_totp_setup', { password, code }),
  cancelTotpSetup: () => invoke<void>('cancel_totp_setup'),
  isTotpEnabled: () => invoke<boolean | null>('is_totp_enabled_cmd'),
  totpDisable: (password: string, code: string) =>
    invoke<any>('disable_totp', { password, code }),
  verifyTotp: (code: string) =>
    invoke<boolean>('verify_totp', { code }),
  generateTotpRecoveryCodes: (password: string, code: string) =>
    invoke<string[]>('generate_totp_recovery_codes', { password, code }),
  totpRecover: (password: string, recoveryCode: string) =>
    invoke<void>('recover_totp', { password, recoveryCode }),

  // Hardware wallet
  setHardwareWalletEnabled: (enabled: boolean) =>
    invoke<any>('set_hardware_wallet_enabled', { enabled }),
  getHardwareWalletStatus: () =>
    invoke<boolean>('get_hardware_wallet_status'),

  // Session logout (no-op in Tauri — no server-side session)
  logout: () => Promise.resolve(),

  // Daemon log (no daemon in Tauri mode — return empty)
  getDaemonLog: (_lines?: number) =>
    Promise.resolve({ lines: [] }),

  // QR code generation — PicQr (Rust backend, replaces qrcode npm package)
  generateQr: (data: string, opts?: {
    ecLevel?: string;     // "L" | "M" | "Q" | "H"
    scale?: number;
    quietZone?: number;
    foreground?: string;  // hex "#000000"
    background?: string;  // hex "#FFFFFF"
    moduleShape?: string; // "square" | "rounded" | "dots"
  }) =>
    invoke<{ svg: string }>('generate_qr', {
      req: {
        data,
        ecLevel: opts?.ecLevel ?? null,
        scale: opts?.scale ?? null,
        quietZone: opts?.quietZone ?? null,
        foreground: opts?.foreground ?? null,
        background: opts?.background ?? null,
        moduleShape: opts?.moduleShape ?? null,
      },
    }),

  // Desktop shortcut (first-launch offer)
  createDesktopShortcut: () =>
    invoke<{ created: boolean; path: string | null; message: string }>('create_desktop_shortcut'),

  // ─── BSV on-chain data protocol decoding ───────────────────────────
  decodeOutput: (value: number, scriptPubkey: string) =>
    invoke<DecodedOutput>('decode_output', {
      req: { value, script_pubkey: scriptPubkey },
    }),

  decodeTxOutputs: (outputs: { value: number; script_pubkey: string }[]) =>
    invoke<DecodedOutput[]>('decode_tx_outputs', { req: { outputs } }),

  getOrdinals: (outputs: { value: number; script_pubkey: string }[]) =>
    invoke<DecodedOutput[]>('get_ordinals', { req: { outputs } }),

  getProtocolData: (outputs: { value: number; script_pubkey: string }[]) =>
    invoke<DecodedOutput[]>('get_protocol_data', { req: { outputs } }),

  getTokenTransfers: (outputs: { value: number; script_pubkey: string }[]) =>
    invoke<DecodedOutput[]>('get_token_transfers', { req: { outputs } }),

  // ─── SPV Channels ──────────────────────────────────────────────────
  /** SPV Channel as returned by the relay. */
  spvCreateChannel: (baseUrl: string, publicKey: string) =>
    invoke<{
      channel_id: string;
      public_key: string;
      description: string | null;
      active: boolean;
    }>('spv_create_channel', { baseUrl, publicKey: publicKey || null }),

  spvListMessages: (baseUrl: string, channelId: string) =>
    invoke<Array<{
      message_id: string;
      channel_id: string;
      encrypted_payload: string;
      received: number;
      read: boolean;
    }>>('spv_list_messages', { baseUrl, channelId }),

  spvPostMessage: (baseUrl: string, channelId: string, encryptedPayload: string) =>
    invoke<{
      message_id: string;
      channel_id: string;
      encrypted_payload: string;
      received: number;
      read: boolean;
    }>('spv_post_message', {
      baseUrl,
      channelId,
      message: { encrypted_payload: encryptedPayload },
    }),

  spvMarkRead: (baseUrl: string, channelId: string, messageId: string) =>
    invoke<void>('spv_mark_read', { baseUrl, channelId, messageId }),

  spvDeleteChannel: (baseUrl: string, channelId: string) =>
    invoke<void>('spv_delete_channel', { baseUrl, channelId }),

  // ─── Cosigner Pool ──────────────────────────────────────────────────
  cosignerSubmitTx: (
    baseUrl: string,
    tx: {
      wallet_id: string;
      txid: string;
      tx_hex: string;
      signers: string[];
      required_sigs: number;
      total_cosigners: number;
    },
  ) => invoke<void>('cosigner_submit_tx', { baseUrl, tx }),

  cosignerGetPending: (baseUrl: string, walletId: string) =>
    invoke<Array<{
      wallet_id: string;
      txid: string;
      tx_hex: string;
      signers: string[];
      required_sigs: number;
      total_cosigners: number;
    }>>('cosigner_get_pending', { baseUrl, walletId }),

  cosignerDeleteTx: (baseUrl: string, walletId: string, txid: string) =>
    invoke<void>('cosigner_delete_tx', { baseUrl, walletId, txid }),

  // ─── Multisig signing (sign_multisig_tx) ──────────────────────────────
  /** Sign a prepared multisig TX plan locally with the key at `localKeyIndex`.
   *  Requires a valid `planId` from prepare_tx; for cosigner-pool TXs without
   *  a server-side plan, pass the txid as a placeholder and note the caveat. */
  signMultisigTx: (planId: string, totpCode: string, localKeyIndex: number) =>
    invoke<{ txid: string; signed_tx_hex: string }>('sign_multisig_tx', {
      planId,
      totpCode,
      localKeyIndex,
    }),

  // ─── Label Sync ─────────────────────────────────────────────────────
  getAllLabels: () =>
    invoke<Array<{
      id: string;
      kind: 'address' | 'transaction';
      label: string;
      updated_at: number;
    }>>('get_all_labels'),

  labelSyncPush: (
    baseUrl: string,
    walletId: string,
    passphrase: string,
    labels: Array<{ id: string; kind: 'address' | 'transaction'; label: string; updated_at: number }>,
  ) => invoke<void>('label_sync_push', { baseUrl, walletId, passphrase, labels }),

  labelSyncPull: (baseUrl: string, walletId: string, passphrase: string) =>
    invoke<Array<{
      id: string;
      kind: 'address' | 'transaction';
      label: string;
      updated_at: number;
    }>>('label_sync_pull', { baseUrl, walletId, passphrase }),
};
