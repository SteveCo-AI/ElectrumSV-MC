import React from 'react';
import { createRoot } from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import App from '../../gui/src/App';
import { useStore } from '../../gui/src/store';
import '../../gui/src/index.css';

const pause = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
async function until<T>(f: () => T | null | false, label: string): Promise<T> {
  for (let i = 0; i < 600; i++) { const x = f(); if (x) return x; await pause(100); }
  throw new Error(label);
}
function button(label: string) {
  return [...document.querySelectorAll('button')].find(b => b.textContent?.replace(/\s+/g, '') === label.replace(/\s+/g, '') && !b.disabled) || null;
}
function setInput(input: HTMLInputElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, value);
  input.dispatchEvent(new Event('input', { bubbles: true }));
}
async function click(label: string) { (await until(() => button(label), label)).click(); }
async function state(expected: string) {
  await until(() => document.body.textContent?.includes(`Plan status: ${expected}`), expected);
  const observed = await invoke<string>('payment_observe');
  if (observed !== expected) throw new Error(`ledger ${expected}`);
}
async function run() {
  let stage = 'identity';
  try {
    const init = await invoke<{ path: string; token: string }>('payment_identity');
    useStore.setState({ view: 'main', isAuthenticated: true, activeWalletPath: init.path, walletInstanceToken: init.token });
    createRoot(document.getElementById('root')!).render(<App />);
    stage = 'send-tab'; await click('📤Send');
    const recipient = await until(() => document.querySelector<HTMLInputElement>('input[placeholder^="1A1z"]'), 'recipient');
    const amount = document.querySelector<HTMLInputElement>('input[placeholder="1000"]')!;
    setInput(recipient, '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'); setInput(amount, '10000');
    stage = 'prepare'; await click('Prepare Transaction'); await state('PREPARED');
    const totp = await until(() => document.querySelector<HTMLInputElement>('input[placeholder="6-digit TOTP code"]:not(:disabled)'), 'totp');
    stage = 'wrong-totp'; setInput(totp, await invoke<string>('payment_wrong_code')); await click('Sign Transaction');
    await until(() => document.body.textContent?.includes('Signing failed:'), 'wrong code'); await state('PREPARED');
    stage = 'sign'; setInput(totp, await invoke<string>('payment_code')); await click('Sign Transaction'); await state('SIGNED');
    stage = 'broadcast-eof'; await click('Broadcast Transaction'); await state('BROADCAST_UNKNOWN');
    stage = 'reconnect'; await invoke('payment_reconnect');
    stage = 'retry'; await click('Retry sending this same transaction');
    await until(() => document.body.textContent?.includes('Transaction Broadcast'), 'broadcast result');
    if (await invoke<string>('payment_observe') !== 'BROADCASTED') throw new Error('ledger broadcast');
    window.location.assign('https://wallet-payment.invalid/pass');
  } catch { window.location.assign(`https://wallet-payment.invalid/fail-${stage}`); }
}
void run();
