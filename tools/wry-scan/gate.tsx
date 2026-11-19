import React from 'react';
import { createRoot } from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import { NetworkView } from '../../gui/src/views/NetworkView';
import { useStore } from '../../gui/src/store';
import '../../gui/src/index.css';

const pause = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
async function until<T>(f: () => T | null | false, label: string): Promise<T> {
  for (let i = 0; i < 600; i++) { const value = f(); if (value) return value; await pause(100); }
  throw new Error(label);
}
async function run() {
  let stage = 'identity';
  try {
    const init = await invoke<{ path: string; token: string; account: number }>('scan_identity');
    useStore.setState({ activeWalletPath: init.path, walletInstanceToken: init.token, activeAccountId: init.account });
    createRoot(document.getElementById('root')!).render(<NetworkView />);
    stage = 'connection'; await until(() => document.body.textContent?.includes('Connected —'), stage);
    const input = document.querySelector<HTMLInputElement>('#scan-end')!;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, '26');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    stage = 'start'; const button = await until(() => [...document.querySelectorAll('button')].find(b => b.textContent === 'Scan addresses' && !b.disabled), stage);
    button.click();
    stage = 'result'; await until(() => document.body.textContent?.includes('2 new keys found.'), stage);
    stage = 'database'; await invoke('scan_observe', { afterSync: false });
    if (useStore.getState().historyRefreshKey !== 1 || useStore.getState().balanceRefreshKey !== 1) throw new Error('refresh');
    stage = 'sync'; const sync = await until(() => [...document.querySelectorAll('button')].find(b => b.textContent === 'Sync Wallet' && !b.disabled), stage);
    sync.click();
    await until(() => document.body.textContent?.includes('synced wallet '), stage);
    stage = 'sync-database'; await invoke('scan_observe', { afterSync: true });
    if (useStore.getState().historyRefreshKey !== 2 || useStore.getState().balanceRefreshKey !== 2) throw new Error('sync refresh');
    window.location.assign('https://wallet-scan.invalid/pass');
  } catch { window.location.assign(`https://wallet-scan.invalid/fail-${stage}`); }
}
void run();
