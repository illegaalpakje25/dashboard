export function summarizeGallery(items) {
  if (!Array.isArray(items)) throw new Error('Ongeldige galerijgegevens');
  const dated = items.filter(item => item && typeof item.createdAt === 'string' && Number.isFinite(Date.parse(item.createdAt)));
  dated.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  const latest = dated[0];
  return {
    status: 'connected', count: items.length, missingDates: items.length - dated.length,
    latest: latest ? { title: String(latest.title || 'Projectfoto'), at: new Date(latest.createdAt).toISOString() } : null,
    source: 'https://pm-tuning.nl/api/gallery', checkedAt: new Date().toISOString(),
  };
}

export function validateMonitor(data) {
  const login = data?.login;
  const validDate = value => typeof value === 'string' && Number.isFinite(Date.parse(value));
  if (data?.version !== 1 || !login || !validDate(login.since) ||
      !['total', 'successful', 'failed', 'blocked'].every(k => Number.isSafeInteger(login[k]) && login[k] >= 0) ||
      login.total !== login.successful + login.failed + login.blocked ||
      !validDate(data.content?.since) || !(data.content.latest === null || validDate(data.content.latest)) ||
      !(login.lastAttemptAt === null || validDate(login.lastAttemptAt)) ||
      !(data.lastPhotoAdded === null || (validDate(data.lastPhotoAdded?.at) && typeof data.lastPhotoAdded.title === 'string'))) {
    throw new Error('Ongeldige monitorgegevens');
  }
  const attempts = data.attempts ?? [];
  if (!Array.isArray(attempts) || attempts.length > 100 || attempts.some(row => !validDate(row.at) ||
    !['successful','failed','blocked'].includes(row.outcome) || ['username','ip','city','region','country'].some(k => row[k] !== null && typeof row[k] !== 'string'))) throw new Error('Ongeldige inloggeschiedenis');
  const blocks=data.activeBlocks??[],unlocks=data.unlocks??[];
  const validDetails=row=>['username','ip','city','region','country'].every(k=>row[k]===null||typeof row[k]==='string');
  if(!Array.isArray(blocks)||blocks.some(b=>!b||!/^[a-f0-9]{64}$/.test(b.id)||!Number.isSafeInteger(b.startedAt)||b.startedAt<=0||!validDate(b.expiresAt)||!Number.isSafeInteger(b.failures)||b.failures<5||!validDetails(b)))throw Error('Ongeldige blokkades');
  if(!Array.isArray(unlocks)||unlocks.length>100||unlocks.some(r=>!validDate(r.at)||!(r.ip===null||typeof r.ip==='string')||!(r.username===null||typeof r.username==='string')))throw Error('Ongeldige deblokkeergeschiedenis');
  // Whitelist fields: never pass an upstream response or credential through to the browser.
  return {
    login: { status:'connected', since:login.since, total:login.total, successful:login.successful, failed:login.failed, blocked:login.blocked, lastAttemptAt:login.lastAttemptAt },
    content: { status:'connected', since:data.content.since, latest:data.content.latest },
    lastPhotoAdded: data.lastPhotoAdded ? { at:data.lastPhotoAdded.at, title:data.lastPhotoAdded.title.slice(0,200) } : null,
    attempts: attempts.map(row=>({at:row.at,outcome:row.outcome,username:row.username?.slice(0,128)||null,ip:row.ip?.slice(0,64)||null,
      city:row.city?.slice(0,64)||null,region:row.region?.slice(0,64)||null,country:row.country?.slice(0,2)||null})),
    blocksAvailable:Array.isArray(data.activeBlocks),
    canUnblock:data.capabilities?.unlock===true && (process.env.PM_MONITOR_ACTION_TOKEN?.length??0)>=32,
    activeBlocks:blocks.map(b=>({id:b.id,startedAt:b.startedAt,expiresAt:b.expiresAt,failures:b.failures,username:b.username?.slice(0,128)||null,ip:b.ip?.slice(0,64)||null,city:b.city?.slice(0,64)||null,region:b.region?.slice(0,64)||null,country:b.country?.slice(0,2)||null})),
    unlocks:unlocks.map(r=>({at:r.at,ip:r.ip?.slice(0,64)||null,username:r.username?.slice(0,128)||null})),
  };
}

export async function unlockPmBlock(input,{token=process.env.PM_MONITOR_ACTION_TOKEN,fetcher=fetch}={}){
  if(!input||typeof input.id!=='string'||!/^[a-f0-9]{64}$/.test(input.id)||!Number.isSafeInteger(input.startedAt)||input.startedAt<=0)return {status:400,body:{error:'Ongeldige blokkade.'}};
  if(!token||token.length<32)return {status:503,body:{error:'Deblokkeren is nog niet geconfigureerd.'}};
  try{
    const response=await fetcher('https://pm-tuning.nl/api/monitor/unlock',{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({id:input.id,startedAt:input.startedAt}),redirect:'error',signal:AbortSignal.timeout(10000)});
    if(!response.ok)return {status:[400,401,409,503].includes(response.status)?response.status:502,body:{error:response.status===409?'De blokkade is gewijzigd. Vernieuw het overzicht.':response.status===401?'Geen toegang om te deblokkeren. Controleer de actiesleutel.':'Deblokkeren is niet gelukt. Vernieuw het overzicht en probeer opnieuw.'}};
    const data=await response.json();if(data.ok!==true)throw Error('Ongeldig antwoord');
    return {status:200,body:{ok:true,alreadyExpired:data.alreadyExpired===true}};
  }catch{return {status:502,body:{error:'Geen bevestiging ontvangen. Vernieuw het overzicht om de blokkade te controleren.'}};}
}

async function getPrivateActivity(token, fetcher) {
  const empty = status => ({ login:{status,total:null,successful:null,failed:null,blocked:null},content:{status,latest:null} });
  if (!token) return { ...empty('not_connected'), message:'De koppeling staat lokaal klaar. De monitor moet nog op PM Tuning worden geactiveerd.' };
  if (token.length < 32) return { ...empty('error'), message:'De monitorsleutel is niet geldig. Gebruik minimaal 32 tekens.' };
  try {
    const response = await fetcher('https://pm-tuning.nl/api/monitor',{
      headers:{Authorization:`Bearer ${token}`,Accept:'application/json'},redirect:'error',signal:AbortSignal.timeout(10000),
    });
    if (!response.ok) return { ...empty('error'),message:response.status===401?'De monitorsleutel komt niet overeen.':response.status===503||response.status===404?'De monitor op PM Tuning is nog niet geactiveerd.':'De privégegevens van PM Tuning zijn tijdelijk niet beschikbaar.' };
    const reader = response.body.getReader();
    const decoder = new TextDecoder();let text='',bytes=0;
    try { while (true) { const chunk=await reader.read();if(chunk.done)break;bytes+=chunk.value.byteLength;if(bytes>262144)throw new Error('Response te groot');text+=decoder.decode(chunk.value,{stream:true}); }text+=decoder.decode(); }
    finally { await reader.cancel().catch(()=>{}); }
    return { ...validateMonitor(JSON.parse(text)),message:null };
  } catch { return { ...empty('error'), message:'De beveiligde PM Tuning-koppeling kon niet worden uitgelezen. Controleer de configuratie en verbinding.' }; }
}

export async function getPmActivity(request, { token = process.env.PM_MONITOR_TOKEN, fetcher = fetch } = {}) {
  const privateActivity = getPrivateActivity(token,fetcher);
  let gallery;
  try {
    const response = await request('https://pm-tuning.nl/api/gallery');
    if (response.code !== 200) throw new Error(`HTTP ${response.code}`);
    gallery = summarizeGallery(JSON.parse(response.html));
  } catch {
    gallery = { status: 'error', latest: null, count: null, error: 'De galerijgegevens konden niet worden opgehaald.' };
  }
  return { ...await privateActivity, gallery };
}
