(function(root){
 'use strict';
 let client=null,user=null,onChange=()=>{};
 const config=root.SCOPE_CONFIG||{};
 const configured=!!(config.supabaseUrl&&config.supabasePublishableKey);
 async function init(callback){
  onChange=callback||onChange;if(!configured)return;
  const url=new URL(config.supabaseUrl);
  if(url.protocol!=='https:'||url.username||url.password||config.supabasePublishableKey.startsWith('sb_secret_'))throw Error('backendNotReady');
  if(config.supabasePublishableKey.startsWith('ey')){const claims=JSON.parse(atob(config.supabasePublishableKey.split('.')[1]));if(claims.role!=='anon')throw Error('backendNotReady');}
  const sdk=await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.118.0/+esm');
  client=sdk.createClient(config.supabaseUrl,config.supabasePublishableKey,{auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true}});
  const {data,error}=await client.auth.getSession();if(error)throw error;user=data.session?.user||null;
  client.auth.onAuthStateChange((event,session)=>{const previous=user?.id;user=session?.user||null;if(event==='SIGNED_OUT'||previous!==user?.id)queueMicrotask(()=>onChange());});
 }
 function requireClient(){if(!client)throw Error('backendNotReady');return client;}
 function accountEmail(username){return username.trim().toLowerCase()+'@accounts.scopeguard.invalid';}
 async function login(username,password){const {error}=await requireClient().auth.signInWithPassword({email:accountEmail(username),password});if(error)throw error;}
 async function signup(username,password){const response=await fetch(config.supabaseUrl+'/functions/v1/register',{method:'POST',headers:{apikey:config.supabasePublishableKey,Authorization:'Bearer '+config.supabasePublishableKey,'Content-Type':'application/json'},body:JSON.stringify({username,password})});const data=await response.json();if(!response.ok)throw Error(data.error||'signupFailed');await login(username,password);return true;}
 async function logout(){const {error}=await requireClient().auth.signOut();if(error)throw error;}
 function record(row){if(Array.isArray(row))row=row[0];return {...row.data,_cloud:{id:row.id,revision:row.revision,managerId:row.manager_id,clientEmail:row.client_email}};}
 async function projects(){const {data,error}=await requireClient().from('sg_projects').select('id,manager_id,client_email,data,revision').order('created_at',{ascending:false});if(error)throw error;return data.map(record);}
 async function createProject(data){if(!/^[a-z0-9][a-z0-9_.-]{2,31}$/i.test(data.clientEmail))throw Error('invalidUsername');const {data:row,error}=await requireClient().rpc('sg_create_project',{p_data:{...data,clientEmail:accountEmail(data.clientEmail)}});if(error)throw error;return record(row);}
 async function mutate(project,action,args){const {data:row,error}=await requireClient().rpc('sg_mutate',{p_project_id:project.id,p_revision:project._cloud.revision,p_action:action,p_args:args});if(error)throw error;return record(row);}
 async function recoveryRequest(body,authenticated=false){
  const session=authenticated?(await requireClient().auth.getSession()).data.session:null;
  if(authenticated&&!session)throw Error('signInRequired');
  const response=await fetch(config.supabaseUrl+'/functions/v1/account-recovery',{method:'POST',headers:{apikey:config.supabasePublishableKey,Authorization:'Bearer '+(session?.access_token||config.supabasePublishableKey),'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data=await response.json();if(!response.ok)throw Error(data.error||'recoveryFailed');return data;
 }
 async function generateRecovery(password){return (await recoveryRequest({action:'generate',password},true)).recoveryCode;}
 async function resetPassword(username,code,password){return (await recoveryRequest({action:'reset',username,code,password})).recoveryCode;}
 async function notifications(){const {data,error}=await requireClient().from('sg_notifications').select('id,project_id,project_name,event,created_at,read_at').order('created_at',{ascending:false}).limit(100);if(error)throw error;return data;}
 async function markRead(ids){if(!ids.length)return;const {error}=await requireClient().from('sg_notifications').update({read_at:new Date().toISOString()}).in('id',ids.slice(0,100));if(error)throw error;}
 function watch(onUpdate,onStatus){
  const uid=user?.id;if(!uid)return ()=>{};
  let disposed=false,debounce,online=false;
  const schedule=()=>{clearTimeout(debounce);debounce=setTimeout(()=>{if(!disposed&&user?.id===uid)onUpdate();},250);};
  const channel=requireClient().channel('scopeguard:'+uid)
   .on('postgres_changes',{event:'INSERT',schema:'public',table:'sg_projects'},schedule)
   .on('postgres_changes',{event:'UPDATE',schema:'public',table:'sg_projects'},schedule)
   .on('postgres_changes',{event:'INSERT',schema:'public',table:'sg_notifications',filter:'recipient_id=eq.'+uid},schedule)
   .on('postgres_changes',{event:'UPDATE',schema:'public',table:'sg_notifications',filter:'recipient_id=eq.'+uid},schedule)
   .subscribe(status=>{if(disposed)return;online=status==='SUBSCRIBED';onStatus(online?'live':'reconnecting');if(online)schedule();});
  const visible=()=>{if(document.visibilityState==='visible')schedule();};
  document.addEventListener('visibilitychange',visible);window.addEventListener('online',schedule);
  // Reconcile missed events even after a reconnect; pause requests in hidden tabs.
  const timer=setInterval(()=>{if(document.visibilityState==='visible')schedule();},15000);
  return ()=>{disposed=true;clearInterval(timer);clearTimeout(debounce);document.removeEventListener('visibilitychange',visible);window.removeEventListener('online',schedule);void client.removeChannel(channel);};
 }
 root.ScopeCloud={configured,init,login,signup,logout,projects,createProject,mutate,notifications,markRead,watch,generateRecovery,resetPassword,getUser:()=>user,active:()=>!!user};
})(typeof globalThis!=='undefined'?globalThis:this);
