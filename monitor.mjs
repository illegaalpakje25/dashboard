import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import {getPmActivity,unlockPmBlock,revokePmSession} from './pm-activity.mjs';
const domains=['jdw-content.nl','jdwtrackside.com','pm-tuning.nl'];
function request(url,redirects=0,deadline=Date.now()+12000){return new Promise((resolve,reject)=>{
 const start=performance.now();const u=new URL(url);
 if(!['https:','http:'].includes(u.protocol)||!domains.some(d=>u.hostname===d||u.hostname===`www.${d}`))return reject(new Error('Redirect buiten toegestane domeinen'));
 const req=(u.protocol==='https:'?https:http).get(u,{signal:AbortSignal.timeout(Math.max(1,deadline-Date.now())),headers:{'User-Agent':'JDW-Monitor/1.0','Accept':'text/html'}},res=>{
 if(res.statusCode>=300&&res.statusCode<400&&res.headers.location){res.resume();if(redirects>=5)return reject(new Error('Te veel redirects'));return request(new URL(res.headers.location,u).href,redirects+1,deadline).then(resolve,reject);}
 let html='';let bytes=0;res.on('data',chunk=>{bytes+=chunk.length;if(bytes<=524288)html+=chunk.toString();else res.destroy(new Error('Pagina groter dan meetlimiet'));});
 res.on('error',reject);res.on('end',()=>resolve({code:res.statusCode,ms:Math.round(performance.now()-start),headers:res.headers,html,url:u.href,redirects}));
 });req.setTimeout(12000,()=>req.destroy(new Error('Timeout na 12 seconden')));req.on('error',reject);
 });}
function certificate(domain){return new Promise(resolve=>{const socket=tls.connect({host:domain,port:443,servername:domain},()=>{const cert=socket.getPeerCertificate();resolve({valid:socket.authorized,issuer:cert.issuer?.O,expires:cert.valid_to,days:Math.floor((new Date(cert.valid_to)-Date.now())/86400000)});socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error('SSL-timeout')));socket.on('error',err=>resolve({valid:false,error:err.message}));});}
const clean=s=>s?.replace(/<[^>]*>/g,'').replace(/&amp;/g,'&').replace(/&#039;/g,"'").replace(/&quot;/g,'"').trim()||null;
function meta(html,name){for(const tag of html.match(/<meta\b[^>]*>/gi)||[]){if(new RegExp(`(?:name|property)\\s*=\\s*["']${name}["']`,'i').test(tag))return clean(tag.match(/content\s*=\s*["']([^"']*)["']/i)?.[1]);}return null;}
const bounded=p=>Promise.race([p,new Promise((_,reject)=>{const timer=setTimeout(()=>reject(new Error('DNS-timeout')),10000);timer.unref();})]);
async function check(domain){const [page,ssl,ip,ns,mx]=await Promise.allSettled([request(`https://${domain}`),certificate(domain),bounded(dns.resolve4(domain)),bounded(dns.resolveNs(domain)),bounded(dns.resolveMx(domain))]);const p=page.status==='fulfilled'?page.value:null;return {domain,checkedAt:new Date().toISOString(),status:p?(p.code>=200&&p.code<400?'up':'error'):'unreachable',code:p?.code??null,ms:p?.ms??null,error:page.status==='rejected'?page.reason.message:null,url:p?.url,title:clean(p?.html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]),description:meta(p?.html||'','description'),generator:meta(p?.html||'','generator'),server:p?.headers.server||null,ssl:ssl.status==='fulfilled'?ssl.value:null,ip:ip.status==='fulfilled'?ip.value:[],ns:ns.status==='fulfilled'?ns.value:[],mx:mx.status==='fulfilled'?mx.value:[],security:{hsts:!!p?.headers['strict-transport-security'],csp:!!p?.headers['content-security-policy'],frame:!!p?.headers['x-frame-options'],nosniff:p?.headers['x-content-type-options']==='nosniff'}};}

let snapshot=null,pending=null;
export async function status(force=false){
 if(pending)return pending;
 if(snapshot&&Date.now()<snapshot.nextCheckAt&&(!force||Date.now()-Date.parse(snapshot.lastChecked)<15000))return snapshot;
 pending=(async()=>{
  const [sites,pmActivity]=await Promise.all([Promise.all(domains.map(check)),getPmActivity(request)]);
  const now=Date.now();
  const history=Object.fromEntries(domains.map(domain=>[domain,[...(snapshot?.history[domain]||[]),{at:sites.find(s=>s.domain===domain).checkedAt,...Object.fromEntries(['status','ms','code'].map(k=>[k,sites.find(s=>s.domain===domain)[k]]))}].filter(s=>now-Date.parse(s.at)<86400000).slice(-1440)]));
  snapshot={sites,history,pmActivity,checking:false,lastChecked:new Date(now).toISOString(),nextCheckAt:now+60000,interval:60000,storageError:null};
  return snapshot;
 })();
 try{return await pending;}finally{pending=null;}
}
export async function unlock(input){const result=await unlockPmBlock(input);if(result.status===200)snapshot=null;return result;}

export async function revoke(input){const result=await revokePmSession(input);if(result.status===200)snapshot=null;return result;}
