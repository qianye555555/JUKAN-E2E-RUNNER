import assert from 'node:assert/strict';
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://usvkntkilndpieybggff.supabase.co';
const SUPABASE_KEY = 'sb_publishable_W07LaXuGxjlR7YkD_Sf15g_CEDBkYhv';
const RECOVERY_REDIRECT = 'https://jukan-preview-git-account-supabase-v1-qianye555555-9461.vercel.app/?account-recovery=1';
const email = String(process.env.JUKAN_E2E_EMAIL || '').trim();
const originalPassword = String(process.env.JUKAN_E2E_PASSWORD || '');

assert.ok(email, 'JUKAN_E2E_EMAIL is required');
assert.ok(originalPassword, 'JUKAN_E2E_PASSWORD is required');

function client(flowType = 'pkce') {
  return createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
      flowType
    }
  });
}

async function ownRecoveryToken(authenticatedClient) {
  for (let attempt = 0; attempt < 10; attempt++) {
    const { data, error } = await authenticatedClient.rpc('e2e_get_own_recovery_token');
    if (error) throw error;
    if (typeof data === 'string' && data.length > 20) return data;
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  throw new Error('Recent recovery token was not available to the authenticated E2E user');
}

function sessionFromImplicitRedirect(location) {
  const callback = new URL(location);
  assert.equal(callback.hostname, new URL(RECOVERY_REDIRECT).hostname, 'unexpected recovery redirect host');
  const fragment = new URLSearchParams(callback.hash.replace(/^#/, ''));
  const accessToken = fragment.get('access_token');
  const refreshToken = fragment.get('refresh_token');
  assert.ok(accessToken, 'implicit recovery redirect missing access token');
  assert.ok(refreshToken, 'implicit recovery redirect missing refresh token');
  assert.equal(fragment.get('type'), 'recovery', 'implicit callback is not a recovery session');
  return { access_token: accessToken, refresh_token: refreshToken };
}

// Authentication used only to read the test account's own recent recovery token
// through the temporary locked-down diagnostic RPC. It is intentionally
// separate from the recovery request and callback clients.
const probeClient = client('pkce');
const login = await probeClient.auth.signInWithPassword({ email, password: originalPassword });
if (login.error) throw login.error;
const userId = login.data.user?.id;
assert.ok(userId, 'initial login user id missing');

// Request recovery with an isolated implicit client. No browser-local verifier
// is created, so the email may be opened on a different device/browser.
const requestClient = client('implicit');
const request = await requestClient.auth.resetPasswordForEmail(email, { redirectTo: RECOVERY_REDIRECT });
if (request.error) throw request.error;

const tokenHash = await ownRecoveryToken(probeClient);
assert.ok(tokenHash.length > 20, 'recovery token hash missing');

const verifyUrl = new URL(`${SUPABASE_URL}/auth/v1/verify`);
verifyUrl.searchParams.set('token', tokenHash);
verifyUrl.searchParams.set('type', 'recovery');
verifyUrl.searchParams.set('redirect_to', RECOVERY_REDIRECT);

const verified = await fetch(verifyUrl, { redirect: 'manual' });
assert.ok([302, 303].includes(verified.status), `recovery verify returned ${verified.status}`);
const location = verified.headers.get('location');
assert.ok(location, 'recovery verify did not return a redirect');
const recoveryTokens = sessionFromImplicitRedirect(location);

// Simulate opening the email on a different browser/device by creating a fresh
// client that has none of the request client's local state.
const recoveryClient = client('pkce');
const recovered = await recoveryClient.auth.setSession(recoveryTokens);
if (recovered.error) throw recovered.error;
assert.equal(recovered.data.user?.id, userId, 'recovery session changed permanent user id');
assert.ok(recovered.data.session, 'recovery session missing');

const temporaryPassword = `${originalPassword}-R${Date.now()}!`;
let passwordChanged = false;
try {
  const changed = await recoveryClient.auth.updateUser({ password: temporaryPassword });
  if (changed.error) throw changed.error;
  passwordChanged = true;
  assert.equal(changed.data.user?.id, userId, 'password update changed user id');

  const tempClient = client('pkce');
  const tempLogin = await tempClient.auth.signInWithPassword({ email, password: temporaryPassword });
  if (tempLogin.error) throw tempLogin.error;
  assert.equal(tempLogin.data.user?.id, userId, 'new-password login changed user id');

  const restore = await tempClient.auth.updateUser({ password: originalPassword });
  if (restore.error) throw restore.error;
  passwordChanged = false;
  await tempClient.auth.signOut({ scope: 'local' });
} finally {
  if (passwordChanged) {
    const restore = await recoveryClient.auth.updateUser({ password: originalPassword });
    if (restore.error) throw restore.error;
  }
}

const finalClient = client('pkce');
const finalLogin = await finalClient.auth.signInWithPassword({ email, password: originalPassword });
if (finalLogin.error) throw finalLogin.error;
assert.equal(finalLogin.data.user?.id, userId, 'restored-password login changed user id');
await finalClient.auth.signOut({ scope: 'local' });
await recoveryClient.auth.signOut({ scope: 'local' });
await probeClient.auth.signOut({ scope: 'local' });

console.log(JSON.stringify({
  mode: 'recovery-implicit-cross-device-e2e',
  recoveryRequested: true,
  tokenResolvedPrivately: true,
  verifyRedirect: true,
  crossDeviceSessionRestore: true,
  passwordUpdated: true,
  newPasswordLogin: true,
  originalPasswordRestored: true,
  permanentUserId: true
}, null, 2));
