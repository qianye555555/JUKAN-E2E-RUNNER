import assert from 'node:assert/strict';
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://usvkntkilndpieybggff.supabase.co';
const SUPABASE_KEY = 'sb_publishable_W07LaXuGxjlR7YkD_Sf15g_CEDBkYhv';
const RECOVERY_REDIRECT = 'https://jukan-preview-5wpbaeil6-qianye555555-9461.vercel.app/?account-recovery=1#/my';
const email = String(process.env.JUKAN_E2E_EMAIL || '').trim();
const originalPassword = String(process.env.JUKAN_E2E_PASSWORD || '');

assert.ok(email, 'JUKAN_E2E_EMAIL is required');
assert.ok(originalPassword, 'JUKAN_E2E_PASSWORD is required');

const memory = new Map();
const storage = {
  getItem(key) { return memory.has(key) ? memory.get(key) : null; },
  setItem(key, value) { memory.set(key, String(value)); },
  removeItem(key) { memory.delete(key); }
};

function pkceClient() {
  return createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: {
      persistSession: true,
      autoRefreshToken: false,
      detectSessionInUrl: false,
      flowType: 'pkce',
      storage
    }
  });
}

function statelessClient() {
  return createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
      flowType: 'pkce'
    }
  });
}

async function ownRecoveryToken(client) {
  for (let attempt = 0; attempt < 10; attempt++) {
    const { data, error } = await client.rpc('e2e_get_own_recovery_token');
    if (error) throw error;
    if (typeof data === 'string' && data.length > 20) return data;
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  throw new Error('Recent recovery token was not available to the authenticated E2E user');
}

const client = pkceClient();
const login = await client.auth.signInWithPassword({ email, password: originalPassword });
if (login.error) throw login.error;
const userId = login.data.user?.id;
assert.ok(userId, 'initial login user id missing');

const request = await client.auth.resetPasswordForEmail(email, { redirectTo: RECOVERY_REDIRECT });
if (request.error) throw request.error;

const tokenHash = await ownRecoveryToken(client);
assert.ok(tokenHash.startsWith('pkce_'), 'expected PKCE recovery token');

const verifyUrl = new URL(`${SUPABASE_URL}/auth/v1/verify`);
verifyUrl.searchParams.set('token', tokenHash);
verifyUrl.searchParams.set('type', 'recovery');
verifyUrl.searchParams.set('redirect_to', RECOVERY_REDIRECT);

const verified = await fetch(verifyUrl, { redirect: 'manual' });
assert.ok([302, 303].includes(verified.status), `recovery verify returned ${verified.status}`);
const location = verified.headers.get('location');
assert.ok(location, 'recovery verify did not return a redirect');
const callback = new URL(location);
const code = callback.searchParams.get('code');
assert.ok(code, 'recovery redirect did not include a PKCE auth code');
assert.equal(callback.hostname, new URL(RECOVERY_REDIRECT).hostname, 'unexpected recovery redirect host');

const exchanged = await client.auth.exchangeCodeForSession(code);
if (exchanged.error) throw exchanged.error;
assert.equal(exchanged.data.user?.id, userId, 'recovery session changed permanent user id');
assert.ok(exchanged.data.session, 'recovery session missing after PKCE exchange');

const temporaryPassword = `${originalPassword}-R${Date.now()}!`;
let passwordChanged = false;
try {
  const changed = await client.auth.updateUser({ password: temporaryPassword });
  if (changed.error) throw changed.error;
  passwordChanged = true;
  assert.equal(changed.data.user?.id, userId, 'password update changed user id');

  const tempClient = statelessClient();
  const tempLogin = await tempClient.auth.signInWithPassword({ email, password: temporaryPassword });
  if (tempLogin.error) throw tempLogin.error;
  assert.equal(tempLogin.data.user?.id, userId, 'new-password login changed user id');

  const restore = await tempClient.auth.updateUser({ password: originalPassword });
  if (restore.error) throw restore.error;
  passwordChanged = false;
  await tempClient.auth.signOut({ scope: 'local' });
} finally {
  if (passwordChanged) {
    const restore = await client.auth.updateUser({ password: originalPassword });
    if (restore.error) throw restore.error;
  }
}

const finalClient = statelessClient();
const finalLogin = await finalClient.auth.signInWithPassword({ email, password: originalPassword });
if (finalLogin.error) throw finalLogin.error;
assert.equal(finalLogin.data.user?.id, userId, 'restored-password login changed user id');
await finalClient.auth.signOut({ scope: 'local' });
await client.auth.signOut({ scope: 'local' });

console.log(JSON.stringify({
  mode: 'recovery-pkce-e2e',
  recoveryRequested: true,
  tokenResolvedPrivately: true,
  verifyRedirect: true,
  pkceExchange: true,
  passwordUpdated: true,
  newPasswordLogin: true,
  originalPasswordRestored: true,
  permanentUserId: true
}, null, 2));
