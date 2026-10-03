import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {authorized,createHandler} from './handler.mjs';
const password='test-only-long-random-password-123456789';
const hash=createHash('sha256').update(password).digest('hex');
const authorization='Basic '+Buffer.from('admin:'+password).toString('base64');
async function call(handler,url,{method='GET',headers={},body='',parsed}={}){
 const req=Readable.from([body]);Object.assign(req,{url,method,headers:{host:'localhost:3001',...headers}});if(parsed!==undefined)req.body=parsed;
 const result={headers:{}};const res={setHeader(k,v){result.headers[k]=v;},writeHead(status,headers={}){result.status=status;Object.assign(result.headers,headers);},end(body){result.body=body;}};
 await handler(req,res);return result;
}
test('every page and API requires the correct credentials, before any monitoring operation',async()=>{
 let calls=0;const handler=createHandler({passwordHash:()=>hash,service:{status(){calls++;},unlock(){calls++;}}});
 for(const url of ['/','/app.js','/api/status','/api/refresh','/api/pm/unlock','/.env']){
  for(const auth of ['', 'Basic '+Buffer.from('admin:wrong').toString('base64')]){
   const res=await call(handler,url,{headers:{authorization:auth}});assert.equal(res.status,401);assert.match(res.headers['Cache-Control'],/no-store/);
  }
 }
 assert.equal(calls,0);assert.equal(authorized(authorization,hash),true);assert.equal(authorized('Basic '+Buffer.from('other:'+password).toString('base64'),hash),false);
});
test('missing or invalid configuration closes the dashboard',async()=>{
 for(const value of ['',undefined,'abc'])assert.equal((await call(createHandler({passwordHash:()=>value}),'/')).status,503);
});
test('authenticated page and status work, unknown secret and source paths never serve files',async()=>{
 const handler=createHandler({passwordHash:()=>hash,service:{status:async()=>({ok:true})}});
 const headers={authorization};assert.equal((await call(handler,'/',{headers})).status,200);
 assert.deepEqual(JSON.parse((await call(handler,'/api/status',{headers})).body),{ok:true});
 for(const path of ['/.env','/handler.mjs','/assets.mjs','/api/index.mjs','/package.json'])assert.equal((await call(handler,path,{headers})).status,404);
});
test('unlock rejects cross-site requests and handles both Vercel parsed and local streaming bodies',async()=>{
 let count=0;const handler=createHandler({passwordHash:()=>hash,service:{unlock:async input=>{count++;assert.equal(input.id,'test');return {status:200,body:{ok:true}};}}});
 const headers={authorization,'content-type':'application/json'};
 assert.equal((await call(handler,'/api/pm/unlock',{method:'POST',headers,body:'{}'})).status,403);
 assert.equal((await call(handler,'/api/pm/unlock',{method:'POST',headers:{...headers,origin:'https://evil.example'},body:'{}'})).status,403);
 const protocol=process.env.VERCEL?'https':'http';
 headers.origin=`${protocol}://localhost:3001`;
 const wrongProtocol=process.env.VERCEL?'http':'https';
 assert.equal((await call(handler,'/api/pm/unlock',{method:'POST',headers:{...headers,origin:`${wrongProtocol}://localhost:3001`},body:'{}'})).status,403);
 for(const data of [{body:'{"id":"test"}'},{parsed:{id:'test'}}])assert.equal((await call(handler,'/api/pm/unlock',{method:'POST',headers,...data})).status,200);
 assert.equal(count,2);
 assert.equal((await call(handler,'/api/pm/unlock',{method:'POST',headers,body:'x'.repeat(1025)})).status,413);
 assert.equal((await call(handler,'/api/pm/unlock',{method:'POST',headers,body:'invalid'})).status,400);
 assert.equal(count,2);
});

test('owner-selected PIN works without an environment password hash; wrong PIN stays rejected',async()=>{
 const handler=createHandler({service:{status:async()=>({ok:true})}});
 const pinHeader='Basic '+Buffer.from('admin:1025').toString('base64');
 assert.equal((await call(handler,'/api/status',{headers:{authorization:pinHeader}})).status,200);
 const wrongHeader='Basic '+Buffer.from('admin:0000').toString('base64');
 assert.equal((await call(handler,'/api/status',{headers:{authorization:wrongHeader}})).status,401);
 assert.equal((await call(handler,'/api/status')).status,401);
});

test('session revocation requires login and same origin before the action is called',async()=>{
 let calls=0;const handler=createHandler({passwordHash:()=>hash,service:{revoke:async input=>{calls++;assert.equal(input.id,'a'.repeat(64));return {status:200,body:{ok:true}};}}});
 const headers={authorization,'content-type':'application/json',origin:(process.env.VERCEL?'https':'http')+'://localhost:3001'};
 const body=JSON.stringify({id:'a'.repeat(64)});
 assert.equal((await call(handler,'/api/pm/revoke-session',{method:'POST',body})).status,401);
 assert.equal((await call(handler,'/api/pm/revoke-session',{method:'POST',headers:{...headers,origin:'https://example.org'},body})).status,403);
 assert.equal(calls,0);assert.equal((await call(handler,'/api/pm/revoke-session',{method:'POST',headers,body})).status,200);assert.equal(calls,1);
});
