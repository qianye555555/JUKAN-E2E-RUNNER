import assert from 'node:assert/strict';
import {createClient} from '@supabase/supabase-js';

const SUPABASE_URL='https://usvkntkilndpieybggff.supabase.co';
const SUPABASE_KEY='sb_publishable_W07LaXuGxjlR7YkD_Sf15g_CEDBkYhv';
const RECOVERY_REDIRECT='https://jukan-preview-5wpbaeil6-qianye555555-9461.vercel.app/?account-recovery=1';
const PRIVATE_LINK_BRIDGE=`${SUPABASE_URL}/functions/v1/noop-check`;
const email=String(process.env.JUKAN_E2E_EMAIL||'').trim();
const originalPassword=String(process.env.JUKAN_E2E_PASSWORD||'');

assert.ok(email,'JUKAN_E2E_EMAIL is required');
assert.ok(originalPassword,'JUKAN_E2E_PASSWORD is required');

function client(flowType='pkce'){
  return createClient(SUPABASE_URL,SUPABASE_KEY,{
    auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false,flowType}
  });
}

function isEmailSendRateLimit(error){
  const code=String(error?.code||'');
  const message=String(error?.message||'');
  return code==='over_email_send_rate_limit'||/email.*rate.?limit|rate.?limit.*email/i.test(message);
}

function sessionFromImplicitRedirect(location){
  const callback=new URL(location);
  assert.match(callback.hostname,/^jukan-preview(?:-[a-z0-9-]+)?-qianye555555-9461\.vercel\.app$/,'unexpected recovery redirect host');
  assert.equal(callback.searchParams.get('account-recovery'),'1','recovery callback marker missing');
  const fragment=new URLSearchParams(callback.hash.replace(/^#/,''));
  const accessToken=fragment.get('access_token');
  const refreshToken=fragment.get('refresh_token');
  assert.ok(accessToken,'implicit recovery redirect missing access token');
  assert.ok(refreshToken,'implicit recovery redirect missing refresh token');
  assert.equal(fragment.get('type'),'recovery','implicit callback is not a recovery session');
  return {access_token:accessToken,refresh_token:refreshToken};
}

async function privateRecoveryLink(session){
  assert.ok(session?.access_token,'authenticated E2E session missing access token');
  const response=await fetch(PRIVATE_LINK_BRIDGE,{
    method:'POST',
    headers:{
      authorization:`Bearer ${session.access_token}`,
      apikey:SUPABASE_KEY,
      'content-type':'application/json'
    },
    body:'{}'
  });
  assert.equal(response.status,200,`private recovery bridge returned ${response.status}`);
  const payload=await response.json();
  assert.ok(payload?.actionLink,'private recovery bridge did not return an action link');
  return payload.actionLink;
}

async function membership(supabase,userId){
  const {data,error}=await supabase.from('membership_state')
    .select('user_id,entitlement,member,plan_id')
    .eq('user_id',userId)
    .single();
  if(error)throw error;
  return data;
}

const probeClient=client('pkce');
const login=await probeClient.auth.signInWithPassword({email,password:originalPassword});
if(login.error)throw login.error;
const userId=login.data.user?.id;
assert.ok(userId,'initial login user id missing');
assert.ok(login.data.session,'initial login session missing');

// Exercise the real public recovery request exactly once. If Supabase's mail
// rate limit rejects it, stop before generating any private link or changing a
// password. The caller can then report over_email_send_rate_limit precisely.
const requestClient=client('implicit');
const request=await requestClient.auth.resetPasswordForEmail(email,{redirectTo:RECOVERY_REDIRECT});
if(request.error){
  if(isEmailSendRateLimit(request.error)){
    console.log(JSON.stringify({
      mode:'recovery-implicit-cross-device-e2e',
      stage:'recovery-request',
      error:'over_email_send_rate_limit',
      passwordUpdated:false,
      originalPasswordRestored:true
    },null,2));
    process.exit(78);
  }
  throw request.error;
}

// Resolve a second, non-email recovery action link through a temporary
// JWT-locked Supabase Admin bridge. This keeps recovery material out of GitHub
// secrets, repository contents and logs while avoiding the former diagnostic
// RPC that exposed auth.users recovery_token.
const actionLink=await privateRecoveryLink(login.data.session);
const verified=await fetch(actionLink,{redirect:'manual'});
assert.ok([302,303].includes(verified.status),`recovery verify returned ${verified.status}`);
const location=verified.headers.get('location');
assert.ok(location,'recovery verify did not return a redirect');
const recoveryTokens=sessionFromImplicitRedirect(location);

// Fresh client = separate browser/device with none of the request client's
// local state.
const recoveryClient=client('pkce');
const recovered=await recoveryClient.auth.setSession(recoveryTokens);
if(recovered.error)throw recovered.error;
assert.equal(recovered.data.user?.id,userId,'recovery session changed permanent user id');
assert.ok(recovered.data.session,'recovery session missing');

const temporaryPassword=`Jk-${crypto.randomUUID()}!aA9`;
let passwordChanged=false;
let tempClient=null;
try{
  const changed=await recoveryClient.auth.updateUser({password:temporaryPassword});
  if(changed.error)throw changed.error;
  passwordChanged=true;
  assert.equal(changed.data.user?.id,userId,'password update changed user id');

  tempClient=client('pkce');
  const tempLogin=await tempClient.auth.signInWithPassword({email,password:temporaryPassword});
  if(tempLogin.error)throw tempLogin.error;
  assert.equal(tempLogin.data.user?.id,userId,'new-password login changed user id');

  const restore=await tempClient.auth.updateUser({password:originalPassword});
  if(restore.error)throw restore.error;
  passwordChanged=false;
  await tempClient.auth.signOut({scope:'local'});
}catch(error){
  throw error;
}finally{
  if(passwordChanged){
    const restoreClient=tempClient||recoveryClient;
    const restore=await restoreClient.auth.updateUser({password:originalPassword});
    if(restore.error)throw restore.error;
    passwordChanged=false;
  }
}

const finalClient=client('pkce');
const finalLogin=await finalClient.auth.signInWithPassword({email,password:originalPassword});
if(finalLogin.error)throw finalLogin.error;
assert.equal(finalLogin.data.user?.id,userId,'restored-password login changed permanent user id');
const finalMembership=await membership(finalClient,userId);
assert.equal(finalMembership.entitlement,'free','E2E account is no longer Free after recovery');
assert.equal(finalMembership.member,false,'E2E account unexpectedly has member entitlement');

await finalClient.auth.signOut({scope:'local'});
await recoveryClient.auth.signOut({scope:'local'});
await probeClient.auth.signOut({scope:'local'});

console.log(JSON.stringify({
  mode:'recovery-implicit-cross-device-e2e',
  recoveryRequested:true,
  tokenResolvedPrivately:true,
  tokenResolution:'temporary-jwt-locked-admin-bridge',
  verifyRedirect:true,
  crossDeviceSessionRestore:true,
  passwordUpdated:true,
  newPasswordLogin:true,
  originalPasswordRestored:true,
  permanentUserId:true,
  entitlement:'free'
},null,2));
