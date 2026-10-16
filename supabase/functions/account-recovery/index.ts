import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.118.0';
const origins=new Set(['https://5kairosh.github.io','http://127.0.0.1:4187','http://localhost:4187']);
const hash=async(value:string)=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)))).map(x=>x.toString(16).padStart(2,'0')).join('');
const newCode=()=>Array.from(crypto.getRandomValues(new Uint8Array(32))).map(x=>x.toString(16).padStart(2,'0')).join('').match(/.{8}/g)!.join('-');
Deno.serve(async(req:Request)=>{
 const origin=req.headers.get('origin')||'';
 const headers={'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':origins.has(origin)?origin:'https://5kairosh.github.io','Access-Control-Allow-Headers':'authorization, apikey, content-type, x-client-info','Access-Control-Allow-Methods':'POST, OPTIONS','Vary':'Origin'};
 const reply=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers});
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return reply({error:'recoveryFailed'},405);
 if(origin&&!origins.has(origin))return reply({error:'notAllowed'},403);
 if(Number(req.headers.get('content-length'))>2048)return reply({error:'recoveryFailed'},400);
 const url=Deno.env.get('SUPABASE_URL')!,secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
 const admin=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
 let stage='input';
 let claimedUser:string|null=null,claim:string|null=null,newHash:string|null=null,recoveryToken:string|null=null;
 try{
  const raw=await req.text();if(raw.length>2048)return reply({error:'recoveryFailed'},400);
  const input=JSON.parse(raw);
  const password=input.password;
  if(typeof password!=='string'||password.length<10||password.length>128)return reply({error:'invalidPassword'},400);
  const ipHash=await hash((req.headers.get('x-forwarded-for')||'unknown').slice(0,1024));
  for(const [bucket,limit] of [['recover:global',100],['recover:'+ipHash,20]] as const){
   const r=await admin.rpc('sg_claim_signup',{p_bucket:bucket,p_limit:limit});
   if(r.error)return reply({error:'syncError'},503);if(!r.data)return reply({error:'recoveryLimit'},429);
  }
  if(input.action==='generate'){
   const jwt=(req.headers.get('authorization')||'').replace(/^Bearer /i,'');
   const {data,error}=await admin.auth.getUser(jwt);
   if(error||!data.user?.email)return reply({error:'signInRequired'},401);
   const check=createClient(url,Deno.env.get('SUPABASE_ANON_KEY')!,{auth:{persistSession:false,autoRefreshToken:false}});
   const verified=await check.auth.signInWithPassword({email:data.user.email,password});
   if(verified.error||verified.data.user?.id!==data.user.id)return reply({error:'authError'},400);
   await check.auth.signOut({scope:'local'});
   const code=newCode(),stored=await admin.rpc('sg_set_recovery',{p_user:data.user.id,p_hash:await hash(code.replaceAll('-',''))});
   if(stored.error)throw stored.error;
   return reply({recoveryCode:code});
  }
  if(input.action!=='reset')return reply({error:'recoveryFailed'},400);
  const username=typeof input.username==='string'?input.username.trim().toLowerCase():'';
  const code=typeof input.code==='string'?input.code.toLowerCase().replace(/[\s-]/g,''):'';
  if(!/^[a-z0-9][a-z0-9_.-]{2,31}$/.test(username)||!/^[a-f0-9]{64}$/.test(code))return reply({error:'recoveryFailed'},400);
  const email=username+'@accounts.scopeguard.invalid';
  const accountLimit=await admin.rpc('sg_claim_signup',{p_bucket:'recover:user:'+await hash(email),p_limit:10});
  if(accountLimit.error)throw accountLimit.error;
  if(!accountLimit.data)return reply({error:'recoveryLimit'},429);
  claim=crypto.randomUUID();
  const claimed=await admin.rpc('sg_claim_recovery',{p_email:email,p_hash:await hash(code),p_claim:claim});
  if(claimed.error)throw claimed.error;
  claimedUser=claimed.data;if(!claimedUser)return reply({error:'recoveryFailed'},400);
  // Only after the private, single-use recovery secret is verified do we mint a session.
  stage='link';
  const link=await admin.auth.admin.generateLink({type:'recovery',email});
  if(link.error)throw link.error;
  const recovery=createClient(url,Deno.env.get('SUPABASE_ANON_KEY')!,{auth:{persistSession:false,autoRefreshToken:false}});
  stage='verify';
  const verified=await recovery.auth.verifyOtp({type:'recovery',token_hash:link.data.properties.hashed_token});
  if(verified.error||verified.data.user?.id!==claimedUser||!verified.data.session)throw Error('recoveryFailed');
  recoveryToken=verified.data.session.access_token;
  stage='revoke';
  const revoked=await admin.auth.admin.signOut(recoveryToken,'global');if(revoked.error)throw revoked.error;
  recoveryToken=null;
  stage='update';
  const updated=await admin.auth.admin.updateUserById(claimedUser,{password});if(updated.error)throw updated.error;
  const next=newCode();newHash=await hash(next.replaceAll('-',''));
  stage='finish';
  const done=await admin.rpc('sg_finish_recovery',{p_user:claimedUser,p_claim:claim,p_new_hash:newHash});
  if(done.error||!done.data)throw Error('recoveryFailed');
  claimedUser=null;
  return reply({ok:true,recoveryCode:next});
 }catch(error){console.error('recovery backend failure',{stage,code:(error as {code?:string}).code,message:(error as Error).message});return reply({error:'recoveryFailed'},400);}
 finally{
  if(claimedUser&&claim)await admin.rpc('sg_finish_recovery',{p_user:claimedUser,p_claim:claim,p_new_hash:newHash});
  if(recoveryToken)await admin.auth.admin.signOut(recoveryToken,'global');
 }
});
