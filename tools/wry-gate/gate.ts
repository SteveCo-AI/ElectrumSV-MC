import { api } from '../../gui/src/api';

async function run() {
  try {
    const version = await api.getAppVersion();
    const target = typeof version === 'string' && version.length > 0 ? `pass?version=${encodeURIComponent(version)}` : 'fail';
    window.location.assign(`https://wallet-gate.invalid/${target}`);
  } catch {
    window.location.assign('https://wallet-gate.invalid/fail');
  }
}
void run();
