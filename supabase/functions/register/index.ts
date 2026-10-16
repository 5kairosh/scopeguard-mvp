import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.118.0';

const origins = new Set(['https://5kairosh.github.io','http://127.0.0.1:4187','http://localhost:4187']);
Deno.serve(async (req: Request) => {
 const origin=req.headers.get('origin')||'';
 const headers={'Content-Type':'application/json','Access-Control-Allow-Origin':origins.has(origin)?origin:'https://5kairosh.github.io','Access-Control-Allow-Headers':'authorization, apikey, content-type, x-client-info','Access-Control-Allow-Methods':'POST, OPTIONS','Vary':'Origin'};
 const respond=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers});
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return respond({error:'invalidRequest'},405);
 if(origin&&!origins.has(origin))return respond({error:'notAllowed'},403);
 if(Number(req.headers.get('content-length'))>2048)return respond({error:'invalidRequest'},400);
 try {
  const body=await req.text();if(body.length>2048)return respond({error:'invalidRequest'},400);
  const input=JSON.parse(body),username=typeof input.username==='string'?input.username.trim().toLowerCase():'',password=input.password;
  if(!/^[a-z0-9][a-z0-9_.-]{2,31}$/.test(username))return respond({error:'invalidUsername'},400);
  if(typeof password!=='string'||password.length<10||password.length>128)return respond({error:'invalidPassword'},400);
  // This service key is injected by Supabase; it never reaches browser code.
  const admin=createClient(Deno.env.get('SUPABASE_URL')!,Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,{auth:{persistSession:false,autoRefreshToken:false}});
  const ip=(req.headers.get('x-forwarded-for')||'unknown').slice(0,1024);
  const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(ip)))).map(x=>x.toString(16).padStart(2,'0')).join('');
  const global=await admin.rpc('sg_claim_signup',{p_bucket:'global',p_limit:100});
  const local=await admin.rpc('sg_claim_signup',{p_bucket:hash,p_limit:10});
  if(global.error||local.error)return respond({error:'syncError'},503);
  if(!global.data||!local.data)return respond({error:'signupRateLimit'},429);
  // The internal email is a unique login identifier, never an asserted real email.
  const {error}=await admin.auth.admin.createUser({email:username+'@accounts.scopeguard.invalid',password,email_confirm:true,user_metadata:{username}});
  if(error)return respond({error:'signupFailed'},400);
  return respond({ok:true},201);
 }catch{return respond({error:'signupFailed'},400);}
});
