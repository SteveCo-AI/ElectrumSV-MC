import { api } from '../../gui/src/api';

const genesisTx = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b';
const otherTx = '11'.repeat(32);
async function run() {
  try {
    const included = await api.verifyTransactionProof(genesisTx, 0);
    if (!included.verified || included.merkle_root !== genesisTx || included.block_height !== 0) throw new Error('inclusion');
    const absent = await api.verifyTransactionProof(otherTx, 0);
    if (absent.verified || absent.merkle_root !== genesisTx || absent.block_height !== 0) throw new Error('noninclusion');
    let invalidRejected = false;
    try { await api.verifyTransactionProof('invalid', 0); } catch { invalidRejected = true; }
    if (!invalidRejected) throw new Error('invalid input');
    let missingRejected = false;
    try { await api.verifyTransactionProof(genesisTx, 1); } catch (error) {
      missingRejected = String(error).includes('no header stored at height 1');
    }
    if (!missingRejected) throw new Error('missing header');
    window.location.assign('https://wallet-gate.invalid/proof-pass');
  } catch {
    window.location.assign('https://wallet-gate.invalid/proof-fail');
  }
}
void run();
