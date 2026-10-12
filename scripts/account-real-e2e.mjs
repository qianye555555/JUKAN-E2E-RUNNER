import assert from 'node:assert/strict';
import {createClient} from '@supabase/supabase-js';

const JUKAN_SUPABASE_URL='https://usvkntkilndpieybggff.supabase.co';
const JUKAN_SUPABASE_PUBLISHABLE_KEY='sb_publishable_W07LaXuGxjlR7YkD_Sf15g_CEDBkYhv';

function client(){
  return createClient(JUKAN_SUPABASE_URL,JUKAN_SUPABASE_PUBLISHABLE_KEY,{
    auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false,flowType:'pkce'}
  });
}

async function membership(supabase,userId){
  const {data,error}=await supabase.from('membership_state')
    .select('user_id,account_status,subscription_status,plan_id,entitlement,member,entitlement_valid_until,updated_at')
    .eq('user_id',userId)
    .single();
  if(error)throw error;
  return data;
}

async function probeProvider(provider){
  const supabase=client();
  const {data,error}=await supabase.auth.signInWithOAuth({
    provider,
    options:{redirectTo:'https://example.com/',skipBrowserRedirect:true}
  });
  if(error)return {provider,configured:false,stage:'oauth-url',error:error.message};
  if(!data?.url)return {provider,configured:false,stage:'oauth-url',error:'missing authorize URL'};
  try{
    const response=await fetch(data.url,{redirect:'manual'});
    const location=response.headers.get('location')||'';
    let host='';
    try{host=location?new URL(location).hostname:'';}catch{}
    const configured=response.status>=300&&response.status<400&&Boolean(location)&&!location.includes('error=');
    return {provider,configured,status:response.status,redirectHost:host||null};
  }catch(error){
    return {provider,configured:false,stage:'authorize-fetch',error:String(error?.message||error)};
  }
}

async function runProviderProbe(){
  const results=[];
  for(const provider of ['google','apple'])results.push(await probeProvider(provider));
  console.log(JSON.stringify({mode:'provider-probe',results},null,2));
  if(process.env.JUKAN_E2E_REQUIRE_OAUTH==='1'){
    for(const item of results)assert.equal(item.configured,true,`${item.provider} OAuth is not configured`);
  }
}

async function signInOrCreate(supabase,email,password){
  const login=await supabase.auth.signInWithPassword({email,password});
  if(!login.error&&login.data?.session)return login.data;

  const signup=await supabase.auth.signUp({email,password});
  if(signup.error){
    throw new Error(`Email sign-in failed (${login.error?.message||'unknown'}); signup also failed (${signup.error.message})`);
  }
  if(!signup.data?.session){
    console.log(JSON.stringify({
      mode:'account-e2e',
      stage:'email-confirmation-required',
      signupRequested:true,
      next:'Open the Supabase verification email for the E2E address, confirm it, then rerun this workflow.'
    },null,2));
    process.exitCode=2;
    return null;
  }
  return signup.data;
}

async function runAccountFlow(){
  const email=String(process.env.JUKAN_E2E_EMAIL||'').trim();
  const password=String(process.env.JUKAN_E2E_PASSWORD||'');
  assert.ok(email,'JUKAN_E2E_EMAIL is required');
  assert.ok(password,'JUKAN_E2E_PASSWORD is required');

  const deviceA=client();
  const loginA=await signInOrCreate(deviceA,email,password);
  if(!loginA)return;
  assert.ok(loginA.session,'device A session missing');
  const userId=loginA.user?.id;
  assert.ok(userId,'device A user id missing');

  const stateA=await membership(deviceA,userId);
  assert.equal(stateA.user_id,userId);
  assert.equal(stateA.account_status,'active');
  assert.ok(['free','member'].includes(stateA.entitlement));
  assert.equal(stateA.member,stateA.entitlement==='member');

  const expected=String(process.env.JUKAN_E2E_EXPECT_ENTITLEMENT||'').trim().toLowerCase();
  if(expected)assert.equal(stateA.entitlement,expected,'unexpected device A entitlement');

  const deviceB=client();
  const loginB=await deviceB.auth.signInWithPassword({email,password});
  if(loginB.error)throw loginB.error;
  assert.ok(loginB.data.session,'device B session missing');
  assert.equal(loginB.data.user?.id,userId,'cross-device user_id changed');
  const stateB=await membership(deviceB,userId);
  assert.deepEqual(
    {entitlement:stateB.entitlement,member:stateB.member,planId:stateB.plan_id},
    {entitlement:stateA.entitlement,member:stateA.member,planId:stateA.plan_id},
    'cross-device membership restore mismatch'
  );

  const out=await deviceA.auth.signOut({scope:'local'});
  if(out.error)throw out.error;
  const sessionA=await deviceA.auth.getSession();
  if(sessionA.error)throw sessionA.error;
  assert.equal(sessionA.data.session,null,'device A local sign-out did not clear session');

  const sessionB=await deviceB.auth.getSession();
  if(sessionB.error)throw sessionB.error;
  assert.ok(sessionB.data.session,'device B session was incorrectly cleared by device A local sign-out');
  const stateBAfter=await membership(deviceB,userId);
  assert.equal(stateBAfter.entitlement,stateB.entitlement,'device B membership changed after device A local sign-out');

  const deviceAReturn=client();
  const relogin=await deviceAReturn.auth.signInWithPassword({email,password});
  if(relogin.error)throw relogin.error;
  assert.equal(relogin.data.user?.id,userId,'re-login changed permanent user_id');
  const restored=await membership(deviceAReturn,userId);
  assert.equal(restored.entitlement,stateA.entitlement,'membership did not restore after re-login');

  await deviceB.auth.signOut({scope:'local'});
  await deviceAReturn.auth.signOut({scope:'local'});

  console.log(JSON.stringify({
    mode:'account-e2e',
    login:true,
    localSignOut:true,
    permanentUserId:true,
    crossDeviceMembership:true,
    entitlement:stateA.entitlement,
    member:stateA.member,
    planId:stateA.plan_id||null
  },null,2));
}

const args=new Set(process.argv.slice(2));
if(args.has('--providers'))await runProviderProbe();
else await runAccountFlow();
