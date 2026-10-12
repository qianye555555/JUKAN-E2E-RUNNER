import assert from 'node:assert/strict';
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://usvkntkilndpieybggff.supabase.co';
const SUPABASE_KEY = 'sb_publishable_W07LaXuGxjlR7YkD_Sf15g_CEDBkYhv';
const RECOVERY_REDIRECT = 'https://jukan-preview-5wpbaeil6-qianye555555-9461.vercel.app/?account-recovery=1#/my';
const email = String(process.env.JUKAN_E2E_EMAIL || '').trim();

assert.ok(email, 'JUKAN_E2E_EMAIL is required');

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false,
    flowType: 'pkce'
  }
});

const { error } = await supabase.auth.resetPasswordForEmail(email, {
  redirectTo: RECOVERY_REDIRECT
});
if (error) throw error;

console.log(JSON.stringify({
  mode: 'recovery-request',
  requested: true,
  redirectConfigured: true,
  next: 'Open the recovery email and follow the reset link.'
}, null, 2));
