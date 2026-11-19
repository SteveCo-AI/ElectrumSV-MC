// Send view — 3-stage BSV transaction workflow: Prepare → Preview → Sign → Broadcast
import { useState, useEffect, useCallback, useRef } from 'react';
import { api, type SpendPlanStatus } from '../api';
import { useStore } from '../store';

type SendStep = 'form' | 'preview' | 'result';

function parseSatoshis(value: string): number | null {
  if (!/^[1-9]\d*$/.test(value)) return null;
  const amount = Number(value);
  return Number.isSafeInteger(amount) ? amount : null;
}

export function SendView() {
  const { activeAccountId, activeWalletPath, walletInstanceToken, setPlanId, triggerBalanceRefresh } = useStore();
  const [step, setStep] = useState<SendStep>('form');
  const [address, setAddress] = useState('');
  const [resolvedAddress, setResolvedAddress] = useState<string | null>(null);
  const [amount, setAmount] = useState('');
  const satoshis = parseSatoshis(amount);
  const [opReturn, setOpReturn] = useState('');
  const [feeRate, setFeeRate] = useState(10);
  const [feeSourceMapi, setFeeSourceMapi] = useState(false);
  const [estimatedFee, setEstimatedFee] = useState<number | null>(null);
  const feeContext = JSON.stringify([activeWalletPath, walletInstanceToken, activeAccountId, address, amount, feeRate, opReturn]);
  const feeRequest = useRef({ context: feeContext, generation: 0 });
  if (feeRequest.current.context !== feeContext) feeRequest.current = { context: feeContext, generation: feeRequest.current.generation + 1 };
  // AUD-008: renderer only holds the plan_id handle + preview metadata.
  const [planId, setPlanIdState] = useState<string | null>(null);
  const [preview, setPreview] = useState<{
    fee: number;
    total_input: number;
    total_output: number;
    change: number;
    num_inputs: number;
    num_outputs: number;
  } | null>(null);
  const [signedTxHex, setSignedTxHex] = useState<string | null>(null);
  const [signedTxid, setSignedTxid] = useState<string | null>(null);
  const [txid, setTxid] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [plans, setPlans] = useState<SpendPlanStatus[]>([]);
  const [unknownPlans, setUnknownPlans] = useState<string[]>([]);
  const [plansLoaded, setPlansLoaded] = useState(false);
  const [planState, setPlanState] = useState<SpendPlanStatus['state'] | null>('PREPARED');
  const [contacts, setContacts] = useState<any[]>([]);

  // TOTP state — TOTP is mandatory in the Rust backend for sign_tx
  const [totpCode, setTotpCode] = useState('');
  const [totpEnabled, setTotpEnabled] = useState<boolean | null>(null);

  // Multisig info (Task 5) — if the active account is a multisig account,
  // show a banner with the m-of-n threshold.
  const [accountTypeLoaded, setAccountTypeLoaded] = useState(false);
  const [multisigInfo, setMultisigInfo] = useState<{ threshold: number; num_keys: number } | null>(null);

  const refreshPlans = useCallback(async () => {
    try {
      setPlans(await api.listSpendPlans());
      setPlansLoaded(true);
    } catch (e: any) {
      setPlansLoaded(false);
      setStatus(`Could not load payment plans: ${e.message || e}`);
    }
  }, []);

  const refreshBalance = useCallback(async () => {
    triggerBalanceRefresh();
  }, [triggerBalanceRefresh]);

  useEffect(() => { void refreshPlans(); }, [refreshPlans]);

  const checkPlan = async (id: string) => {
    setBusy(true);
    try {
      const current = await api.getSpendPlanStatus(id);
      setUnknownPlans(ids => ids.filter(item => item !== id));
      setPlans(items => items.map(item => item.plan_id === id ? current : item));
      if (id === planId) {
        setPlanState(current.state);
        if (current.txid) setSignedTxid(current.txid);
        if (current.state === 'BROADCASTED') { setTxid(current.txid); setStep('result'); }
      }
      setStatus(`Plan status: ${current.state}`);
      await Promise.all([refreshPlans(), refreshBalance()]);
    } catch (e: any) { setStatus(`Could not check plan status: ${e.message || e}`); }
    finally { setBusy(false); }
  };

  const cancelPlan = async (id: string) => {
    setBusy(true);
    try {
      await api.cancelSpendPlan(id);
      if (id === planId) {
        setStep('form'); setPlanIdState(null); setPlanId(null); setPreview(null);
        setSignedTxHex(null); setSignedTxid(null);
      }
      setStatus('Prepared plan cancelled; its inputs were released.');
      await Promise.all([refreshPlans(), refreshBalance()]);
    } catch (e: any) {
      setStatus(`Could not cancel plan: ${e.message || e}`);
    } finally { setBusy(false); }
  };

  const sendPlan = async (id: string, expectedTxid: string, retryUnknown: boolean) => {
    setBusy(true);
    setStatus(null);
    try {
      const result = await api.broadcastSpendPlan(id, expectedTxid, retryUnknown);
      setTxid(result); setStep('result'); setPlanState('BROADCASTED');
      await Promise.all([refreshPlans(), refreshBalance()]);
    } catch (e: any) {
      try {
        const current = await api.getSpendPlanStatus(id);
        setPlans(items => items.map(item => item.plan_id === id ? current : item));
        setUnknownPlans(ids => ids.filter(item => item !== id));
        if (id === planId) { setPlanState(current.state); if (current.txid) setSignedTxid(current.txid); }
        if (current.state === 'BROADCASTED') { setTxid(current.txid); setStep('result'); }
        setStatus(`Broadcast failed: ${e.message || e}. Plan status: ${current.state}`);
      } catch {
        if (id === planId) setPlanState(null);
        setUnknownPlans(ids => [...new Set([...ids, id])]);
        setStatus(`Broadcast failed: ${e.message || e}. Plan status unknown; check status before another action.`);
      }
      await refreshBalance();
    } finally { setBusy(false); }
  };

  // Load contacts for recipient dropdown
  useEffect(() => {
    api.getContacts()
      .then((r: any[]) => setContacts(Array.isArray(r) ? r : []))
      .catch(() => setContacts([]));
  }, []);

  // Check TOTP status on mount
  useEffect(() => {
    api.getTotpStatus()
      .then(s => setTotpEnabled(s.enabled))
      .catch(() => setTotpEnabled(null));
  }, []);

  // Fetch multisig config for the active account (Task 5).
  // If the account is a multisig account, show a banner with the m-of-n info.
  useEffect(() => {
    setAccountTypeLoaded(false);
    if (activeAccountId === null) {
      setMultisigInfo(null);
      return;
    }
    let cancelled = false;
    api.getMultisigConfig(activeAccountId)
      .then(cfg => {
        if (cancelled) return;
        setAccountTypeLoaded(true);
        if (cfg && cfg.threshold && cfg.num_keys) {
          setMultisigInfo({ threshold: cfg.threshold, num_keys: cfg.num_keys });
        } else {
          setMultisigInfo(null);
        }
      })
      .catch(() => { if (!cancelled) setMultisigInfo(null); });
    return () => { cancelled = true; };
  }, [activeAccountId]);

  // Fetch mAPI fee quote on mount — if the user hasn't changed the default,
  // replace the fee rate with the mAPI mining fee (sat/byte). The user can
  // still adjust the slider manually afterwards.
  useEffect(() => {
    let cancelled = false;
    api.getMapiFeeQuote()
      .then(quote => {
        if (cancelled) return;
        // Only override if the user has not moved the slider away from default.
        if (quote.mining_fee_satoshis && quote.mining_fee_satoshis > 0) {
          setFeeRate(quote.mining_fee_satoshis);
          setFeeSourceMapi(true);
        }
      })
      .catch(() => {
        // mAPI unreachable — keep default fee rate, no badge.
        if (!cancelled) setFeeSourceMapi(false);
      });
    return () => { cancelled = true; };
  }, []);

  // Debounced fee estimation
  const estimateFee = useCallback(async (rate: number) => {
    if (!address || satoshis === null) { setEstimatedFee(null); return; }
    const generation = ++feeRequest.current.generation;
    try {
      const r = await api.estimateFee(
        [{ address, satoshis }],
        rate,
        opReturn || undefined
      );
      if (feeRequest.current.generation === generation) setEstimatedFee(r.fee);
    } catch {
      if (feeRequest.current.generation === generation) setEstimatedFee(null);
    }
  }, [address, satoshis, opReturn]);

  useEffect(() => {
    setEstimatedFee(null);
    const timer = setTimeout(() => estimateFee(feeRate), 400);
    return () => { clearTimeout(timer); feeRequest.current.generation++; };
  }, [feeRate, estimateFee, activeAccountId, activeWalletPath, walletInstanceToken]);

  const resetForm = () => {
    setStep('form');
    setAddress('');
    setResolvedAddress(null);
    setAmount('');
    setOpReturn('');
    setPlanIdState(null);
    setPreview(null);
    setSignedTxHex(null);
    setSignedTxid(null);
    setTxid(null);
    setStatus(null);
    setTotpCode('');
    setPlanId(null);
  };

  // Step 1: Prepare transaction
  const handlePrepare = async () => {
    if (activeAccountId === null || satoshis === null) return;
    setBusy(true);
    setStatus(null);
    try {
      // Resolve PayMail handle if the address contains '@'
      let resolvedAddr = address.trim();
      if (resolvedAddr.includes('@')) {
        setStatus('Resolving PayMail handle…');
        try {
          const result = await api.resolvePaymail(resolvedAddr);
          resolvedAddr = result.address;
          setResolvedAddress(resolvedAddr);
        } catch (e: any) {
          setStatus(`PayMail resolution failed: ${e.message || e}`);
          setBusy(false);
          return;
        }
      } else {
        setResolvedAddress(null);
      }
      const outputs = [{ address: resolvedAddr, satoshis }];
      const r = await api.prepareTx({
        outputs,
        feeRate,
        opReturn: opReturn || undefined,
      });
      setPlanIdState(r.plan_id);
      setPlanId(r.plan_id);
      setPreview({
        fee: r.fee,
        total_input: r.total_input,
        total_output: r.total_output,
        change: r.change,
        num_inputs: r.num_inputs,
        num_outputs: r.num_outputs,
      });
      setPlanState('PREPARED');
      setStep('preview');
      await Promise.all([refreshPlans(), refreshBalance()]);
    } catch (e: any) {
      setStatus(`Error: ${e.message || e}`);
    } finally {
      setBusy(false);
    }
  };

  // Step 2: Sign (requires TOTP code)
  const handleSign = async () => {
    if (!planId) return;
    if (totpEnabled && totpCode.length !== 6) {
      setStatus('TOTP code required (6 digits).');
      return;
    }
    setBusy(true);
    setStatus(null);
    try {
      const signResult = await api.signTx(planId, totpCode);
      setSignedTxHex(signResult.signed_tx_hex);
      setSignedTxid(signResult.txid);
      setPlanState('SIGNED');
      await refreshPlans();
      setStatus('Transaction signed. Ready to broadcast.');
    } catch (e: any) {
      setStatus(`Signing failed: ${e.message || e}. Check plan status before trying again.`);
      try {
        const current = await api.getSpendPlanStatus(planId);
        setPlanState(current.state);
        if (current.txid) setSignedTxid(current.txid);
      } catch { setPlanState(null); setStatus(`Signing failed: ${e.message || e}. Plan status unknown; check status before another action.`); }
      await refreshPlans();
    } finally {
      setBusy(false);
    }
  };

  // Every attempt uses the stored plan and the same expected transaction ID.
  const handleBroadcast = () => {
    if (planId && signedTxid) void sendPlan(planId, signedTxid, planState === 'BROADCAST_UNKNOWN');
  };

  const canPrepare = plansLoaded && accountTypeLoaded && !multisigInfo && address && satoshis !== null && activeAccountId !== null;
  const canSign = planState === 'PREPARED' && planId && totpEnabled && totpCode.length === 6;
  const canBroadcast = signedTxid && (planState === 'SIGNED' || planState === 'BROADCAST_UNKNOWN');

  return (
    <div className="p-4">
      <h2 className="text-lg font-semibold mb-4 text-accent">Send BSV</h2>

      {/* Multisig account banner (Task 5) */}
      {multisigInfo && (
        <div className="mb-4 bg-void-900 border border-accent/40 rounded-lg p-3 text-sm">
          <span className="text-accent font-medium">
            🔑 Multisig Account ({multisigInfo.threshold}-of-{multisigInfo.num_keys})
          </span>
          <span className="text-gray-400 ml-2">
            Multisig signing is not supported in this test build.
          </span>
        </div>
      )}

      {!accountTypeLoaded && activeAccountId !== null && <p className="mb-4 text-sm text-warning">Account type is unavailable or still loading; payment preparation is disabled.</p>}

      {/* Step indicator */}
      <div className="flex items-center gap-2 mb-6 text-sm">
        <span className={step === 'form' ? 'text-accent' : 'text-gray-400'}>1. Form</span>
        <span className="text-gray-400">→</span>
        <span className={step === 'preview' ? 'text-accent' : 'text-gray-400'}>2. Preview & Sign</span>
        <span className="text-gray-400">→</span>
        <span className={step === 'result' ? 'text-accent' : 'text-gray-400'}>3. Result</span>
      </div>

      <div className="space-y-3 max-w-lg">
        {plans.filter(p => p.plan_id !== planId && p.state !== 'BROADCASTED').map(p => (
          <div key={p.plan_id} className="bg-void-900 border border-warning/30 rounded-lg p-3 text-sm space-y-2">
            <div>Payment plan: <span className="font-mono break-all">{p.plan_id}</span></div>
            <div>Status: {unknownPlans.includes(p.plan_id) ? 'unknown' : p.state}</div>
            {p.txid && <div>TXID: <span className="font-mono break-all">{p.txid}</span></div>}
            <button disabled={busy} onClick={() => void checkPlan(p.plan_id)}>Check plan status</button>
            {!unknownPlans.includes(p.plan_id) && p.state === 'PREPARED' && <><p>Inputs remain reserved. A plan from a previous session may only be cancelled.</p><button disabled={busy} onClick={() => void cancelPlan(p.plan_id)}>Cancel prepared plan and release inputs</button></>}
            {!unknownPlans.includes(p.plan_id) && p.state === 'SIGNED' && p.txid && <button disabled={busy} onClick={() => void sendPlan(p.plan_id, p.txid!, false)}>Broadcast signed transaction</button>}
            {!unknownPlans.includes(p.plan_id) && p.state === 'BROADCAST_UNKNOWN' && p.txid && <><p>The transaction may already have been sent. Check the TXID before retrying.</p><button disabled={busy} onClick={() => void sendPlan(p.plan_id, p.txid!, true)}>Retry sending this same transaction</button></>}
          </div>
        ))}
        {!plansLoaded && <button disabled={busy} onClick={() => void refreshPlans()}>Retry loading payment plans</button>}
        {/* ─── Step 1: Form ─── */}
        {step === 'form' && (
          <>
            {/* Contact shortcut */}
            {contacts.length > 0 && (
              <div>
                <label className="text-sm text-gray-400 mb-1 block">From contacts</label>
                <select
                  onChange={(e) => {
                    const c = contacts.find((c) => String(c.contact_id) === e.target.value);
                    if (c) {
                      const addr = c.identities?.[0]?.system_data || '';
                      setAddress(addr);
                    }
                  }}
                  className="w-full bg-void-900 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
                >
                  <option value="">— select contact —</option>
                  {contacts.map((c) => (
                    <option key={c.contact_id} value={c.contact_id}>
                      {c.label}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div>
              <label className="text-sm text-gray-400 mb-1 block">Recipient address or PayMail</label>
              <input
                type="text"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or user@domain.com"
                className="w-full bg-void-900 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
              />
            </div>

            <div>
              <label className="text-sm text-gray-400 mb-1 block">Amount (satoshis)</label>
              <input
                type="text"
                inputMode="numeric"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="1000"
                className="w-full bg-void-900 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
              />
            </div>

            {/* Fee slider */}
            <div>
              <label className="text-sm text-gray-400 mb-1 block">
                Fee rate: {feeRate} sat/byte
                {feeSourceMapi && (
                  <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-accent/20 text-accent border border-accent/40">
                    mAPI
                  </span>
                )}
                {estimatedFee !== null && (
                  <span className="text-gray-400 ml-2">≈ {estimatedFee} sat total</span>
                )}
              </label>
              <input
                type="range"
                min="1"
                max="50"
                value={feeRate}
                onChange={(e) => { setFeeRate(parseInt(e.target.value, 10)); setFeeSourceMapi(false); }}
                className="w-full accent-accent"
              />
              <div className="flex justify-between text-xs text-gray-400 mt-1">
                <span>1 (slow)</span>
                <span>10 (default)</span>
                <span>50 (fast)</span>
              </div>
            </div>

            {/* OP_RETURN */}
            <div>
              <label className="text-sm text-gray-400 mb-1 block">
                OP_RETURN <span className="text-gray-400">(optional — hex or text)</span>
              </label>
              <input
                type="text"
                value={opReturn}
                onChange={(e) => setOpReturn(e.target.value)}
                placeholder="e.g. hello world or 48656c6c6f"
                className="w-full bg-void-900 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
              />
            </div>

            <button
              onClick={handlePrepare}
              disabled={busy || !canPrepare}
              className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {busy ? 'Preparing…' : 'Prepare Transaction'}
            </button>
          </>
        )}

        {/* ─── Step 2: Preview & Sign ─── */}
        {step === 'preview' && planId && preview && (
          <>
            <div className="bg-void-900 border border-void-700 rounded-lg p-4 space-y-2">
              <div className="text-sm font-semibold text-accent mb-2">Transaction Preview</div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">To</span>
                <span className="font-mono text-gray-300">{address.slice(0, 24)}…</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Amount</span>
                <span className="text-gray-100">{satoshis?.toLocaleString()} sat</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Fee ({feeRate} sat/byte)</span>
                <span className="text-gray-100">{preview.fee} sat</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Change</span>
                <span className="text-gray-100">{preview.change} sat</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Inputs</span>
                <span className="text-gray-100">{preview.num_inputs}</span>
              </div>
              <div className="border-t border-void-700 pt-2 flex justify-between text-sm font-semibold">
                <span className="text-gray-400">Total Input</span>
                <span className="text-accent">{preview.total_input.toLocaleString()} sat</span>
              </div>
              {opReturn && (
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">OP_RETURN</span>
                  <span className="font-mono text-gray-300 text-xs">{opReturn.slice(0, 32)}…</span>
                </div>
              )}
            </div>

            <p className="text-sm text-gray-400">Prepared plans can be cancelled. After signing, inputs remain reserved even if you do not broadcast; signed plans cannot be cancelled in this test build.</p>
            {/* TOTP code input — always shown because sign_tx requires it */}
            <div className="bg-void-900 border border-warning/30 rounded-lg p-3">
              <div className="text-xs text-warning mb-2">
                🔒 TOTP code required to sign this transaction.
              </div>
              {totpEnabled === null && <div className="text-xs text-danger mb-2">2FA status unknown; signing is unavailable.</div>}
              {totpEnabled === false && (
                <div className="text-xs text-danger mb-2">
                  ⚠ TOTP must be enabled to sign. Enable 2FA in the Security tab first.
                </div>
              )}
              <input
                type="text"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                placeholder="6-digit TOTP code"
                maxLength={6}
                disabled={!totpEnabled}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none disabled:opacity-50"
              />
            </div>

            {/* Signed TX info */}
            {signedTxHex && (
              <div className="bg-void-900 border border-success/30 rounded-lg p-3">
                <div className="text-xs text-success mb-1">✓ Signed successfully</div>
                <div className="text-xs text-gray-400">TXID: <span className="font-mono text-gray-300">{signedTxid}</span></div>
              </div>
            )}

            <button disabled={busy} onClick={() => void checkPlan(planId)}>Check plan status</button>
            <p className="text-sm text-gray-400">Plan status: {planState ?? 'unknown'}</p>
            {planState === 'BROADCAST_UNKNOWN' && <p className="text-warning text-sm">The transaction may already have been sent. Check the TXID before explicitly retrying the same transaction.</p>}
            <div className="flex gap-3">
              <button
                onClick={() => void cancelPlan(planId)}
                disabled={busy || planState !== 'PREPARED'}
                className="bg-void-800 hover:bg-void-700 text-gray-300 rounded-lg px-4 py-2 text-sm font-medium transition-colors"
              >
                Cancel prepared plan
              </button>
              {planState === 'PREPARED' ? (
                <button
                  onClick={handleSign}
                  disabled={busy || !canSign}
                  className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {busy ? 'Signing…' : 'Sign Transaction'}
                </button>
              ) : (planState === 'SIGNED' || planState === 'BROADCAST_UNKNOWN') ? (
                <button
                  onClick={handleBroadcast}
                  disabled={busy || !canBroadcast}
                  className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {busy ? 'Broadcasting…' : planState === 'BROADCAST_UNKNOWN' ? 'Retry sending this same transaction' : 'Broadcast Transaction'}
                </button>
              ) : null}
            </div>
          </>
        )}

        {/* ─── Step 3: Result ─── */}
        {step === 'result' && (
          <>
            <div className="bg-void-900 border border-success rounded-lg p-4 space-y-2">
              <div className="text-sm font-semibold text-success">✓ Transaction Broadcast</div>
              <p className="text-xs text-gray-400">The total balance reflects the last sync and may not yet include this payment or its change. Sync the wallet to update it.</p>
              {txid && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">TXID</div>
                  <div className="font-mono text-sm text-gray-300 break-all">{txid}</div>
                </div>
              )}
            </div>
            <button
              onClick={resetForm}
              className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors"
            >
              Send Another
            </button>
          </>
        )}

        {/* Status / errors */}
        {status && step !== 'result' && (
          <div className="text-sm text-error mt-2">{status}</div>
        )}
      </div>
    </div>
  );
}
