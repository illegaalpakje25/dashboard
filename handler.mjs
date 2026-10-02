import {createHash,timingSafeEqual} from 'node:crypto';
import assets from './assets.mjs';
import * as monitor from './monitor.mjs';
export function authorized(header,hash){
 if(!/^[a-f0-9]{64}$/.test(hash||''))return false;
 if(typeof header!=='string'||header.length>1024||!header.startsWith('Basic '))return false;
 const decoded=Buffer.from(header.slice(6),'base64').toString('utf8');
 if(!decoded.startsWith('admin:'))return false;
 return timingSafeEqual(createHash('sha256').update(decoded.slice(6)).digest(),Buffer.from(hash,'hex'));
}
export function createHandler({service=monitor,passwordHash=()=>'46372791018924b8cbc444334300f85a211d2f29a56f2bb4890780b5983fc201'}={}){
 return async(req,res)=>{
  res.setHeader('Cache-Control','private, no-store, max-age=0');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('X-Robots-Tag','noindex, nofollow');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");
  if(process.env.VERCEL)res.setHeader('Strict-Transport-Security','max-age=31536000');
  const json=(code,data)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(data));};
  const hash=passwordHash();
  if(!/^[a-f0-9]{64}$/.test(hash||''))return json(503,{error:'De toegangsconfiguratie is ongeldig.'});
  if(!authorized(req.headers.authorization,hash)){
   res.setHeader('WWW-Authenticate','Basic realm="JDW Dashboard", charset="UTF-8"');
   return json(401,{error:'Inloggen vereist. Gebruikersnaam: admin.'});
  }
  if(req.headers['sec-fetch-site']==='cross-site')return json(403,{error:'Geen toegang.'});
  const path=new URL(req.url,'http://localhost').pathname;
  if(req.method==='POST'){
   const protocol=process.env.VERCEL?'https':'http';
   if(req.headers.origin!==`${protocol}://${req.headers.host}`)return json(403,{error:'Ongeldige herkomst.'});
  }
  try{
   if(path==='/api/status'&&req.method==='GET')return json(200,await service.status());
   if(path==='/api/refresh'&&req.method==='POST'){await service.status(true);return json(200,{ok:true});}
   if(path==='/api/pm/unlock'&&req.method==='POST'){
    if(!req.headers['content-type']?.startsWith('application/json'))return json(415,{error:'JSON vereist.'});
    let body='',size=0;
    if(req.body!==undefined){body=typeof req.body==='string'?req.body:JSON.stringify(req.body);if(Buffer.byteLength(body)>1024)return json(413,{error:'Aanvraag te groot.'});}
    else for await(const chunk of req){size+=Buffer.byteLength(chunk);if(size>1024)return json(413,{error:'Aanvraag te groot.'});body+=chunk;}
    let input;try{input=JSON.parse(body)}catch{return json(400,{error:'Ongeldige aanvraag.'});}
    const result=await service.unlock(input);return json(result.status,result.body);
   }
   const asset=assets[path];
   if(req.method==='GET'&&asset){res.writeHead(200,{'Content-Type':`${asset[0]}; charset=utf-8`});return res.end(asset[1]);}
   return json(404,{error:'Niet gevonden.'});
  }catch{return json(502,{error:'Controle niet gelukt. Probeer opnieuw.'});}
 };
}
export default createHandler();
