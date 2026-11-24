// Disposable Chromium smoke with a synthetic UBID service port, never real users.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import {resolve,basename} from 'node:path';
import {createRegisteredDeviceSessionBffV1} from '../src/server/registered-device-session-bff-v1.mjs';
import {produceRegisteredDeviceSessionStatementV1} from '../src/server/registered-device-session-statement-v1.mjs';
import {verifyRegisteredDeviceSessionProofV1} from '../src/server/registered-device-session-proof-v1.mjs';
import {canonical} from '../web/social-mobile-protocol-v1.mjs';
const require=createRequire(import.meta.url);
const {chromium}=require(require.resolve('playwright',{paths:[process.env.HXXI_BROWSER_TEST_NODE_MODULES].filter(Boolean)}));
const root=process.cwd(), origin='https://synthetic-social.example';
const config={publicOrigin:origin,authorityOrigin:'https://synthetic-ubid.example',clientId:'synthetic-social'};
const fixture=JSON.parse(await readFile('tests/fixtures/social_preacceptance_ed25519_handoff_v2.json','utf8')).vector;
const content=JSON.parse(JSON.parse(fixture.authorizationWire).content);
const rsa=generateKeyPairSync('rsa',{modulusLength:2048});
let registration,consumes=0,revokes=0;
const sessions=new Map(),challenges=new Set();
const client={async invoke(command,value,credential){
 const now=Date.now();
 if(command==='registered-challenge'){
  assert.equal(value.subject,registration.subjectHint);assert.equal(value.deviceId,registration.deviceId);
  const wire=canonical({associationId:'44'.repeat(32),associationVersion:1,audience:origin,authorityEpoch:1,
   bindingId:registration.x25519BindingId,bindingVersion:1,challengeId:randomBytes(32).toString('hex'),clientId:config.clientId,
   contextCommitment:value.contextCommitment,deviceId:registration.deviceId,domain:'HODLXXI_SOCIAL_REGISTERED_DEVICE_SESSION_CHALLENGE_V1',
   ed25519PublicKey:registration.ed25519PublicKey,expiresAt:now+60000,issuedAt:now,issuer:config.authorityOrigin,
   schema:'hodlxxi.social_registered_device_session_challenge.v1',subject:registration.subjectHint,version:1,
   x25519PublicKeyCommitment:registration.x25519PublicKeyCommitment});
  challenges.add(wire);return {challengeWire:wire};
 }
 if(command==='registered-consume'){
  assert.equal(challenges.delete(value.challengeWire),true);
  assert.equal(verifyRegisteredDeviceSessionProofV1({...value,issuer:config.authorityOrigin,audience:origin,clientId:config.clientId,now}),true);
  const record={sessionId:randomBytes(32).toString('hex'),credential:randomBytes(32).toString('hex'),expiresAt:now+300000,
   subject:registration.subjectHint,deviceId:registration.deviceId};
  sessions.set(record.sessionId,{...record,context:JSON.parse(value.challengeWire).contextCommitment});consumes++;return record;
 }
 const record=sessions.get(value.registeredSession?.sessionId);
 assert.ok(record);assert.equal(credential,record.credential);assert.equal(value.registeredSession.contextCommitment,record.context);
 if(command==='registered-revoke'){record.revoked=true;revokes++;return {sessionId:record.sessionId,status:'revoked'};}
 if(command==='registered-current'){
  assert.notEqual(record.revoked,true);assert.ok(record.expiresAt>now);
  return {sessionId:record.sessionId,subject:record.subject,deviceId:record.deviceId,expiresAt:record.expiresAt,
   authority:{subject:record.subject,status:'full',valid:true}};
 }
 throw new Error('unexpected synthetic command');
}};
const base=async()=>({status:200,headers:{'Content-Type':'application/json'},body:'{"authenticated":false}'});
const bff=createRegisteredDeviceSessionBffV1({config,base,transport:{registeredSessionClient:client,
 registeredStatement:input=>produceRegisteredDeviceSessionStatementV1(input,{kid:'chromium-test',privateKey:rsa.privateKey})}});
const browser=await chromium.launch({headless:true,args:['--disable-dev-shm-usage']});
const failureFrames=[];
try{
 const context=await browser.newContext();
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  assert.equal(url.origin,origin);
  if(url.pathname.startsWith('/auth/')){
   const result=await bff.handle({method:req.method(),url:url.pathname+url.search,headers:await req.allHeaders(),body:req.postData()??undefined})??await base();
   const headers=Object.fromEntries(Object.entries(result.headers).map(([k,v])=>[k,Array.isArray(v)?v.join('\n'):String(v)]));
   return route.fulfill({status:result.status,headers,body:result.body});
  }
  if(url.pathname==='/')return route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Disposable registered-device test</title>'});
  if(url.pathname==='/favicon.ico')return route.fulfill({status:204,body:''});
  assert.equal(url.pathname,'/web/'+basename(url.pathname));
  return route.fulfill({status:200,contentType:'text/javascript',body:await readFile(resolve(root,url.pathname.slice(1)),'utf8')});
 });
 const page=await context.newPage();
 const cdp=await context.newCDPSession(page),scripts=new Map();
 cdp.on('Debugger.scriptParsed',value=>scripts.set(value.scriptId,value.url));
 cdp.on('Debugger.paused',async value=>{
  const frames=value.callFrames.map(f=>({name:f.functionName,url:scripts.get(f.location.scriptId),line:f.location.lineNumber+1})).filter(f=>f.url?.startsWith(origin+'/web/'));
  if(frames.length)failureFrames.push(frames);
  await cdp.send('Debugger.resume');
 });
 await cdp.send('Debugger.enable');await cdp.send('Debugger.setPauseOnExceptions',{state:'all'});
 await page.goto(origin);
 registration=await page.evaluate(async content=>{
  const {createMessagingDeviceStore}=await import('/web/messaging-device-v128c1.mjs');
  const {createMessagingDeviceEd25519KeyV2}=await import('/web/messaging-device-ed25519-key-v2.mjs');
  const {canonicalMessagingDeviceJson:canonical}=await import('/web/messaging-device-authorization-v1.mjs');
  const key=await crypto.subtle.generateKey({name:'X25519'},false,['deriveBits']);
  const publicKey=[...new Uint8Array(await crypto.subtle.exportKey('raw',key.publicKey))].map(v=>v.toString(16).padStart(2,'0')).join('');
  content.authorization.publicKey=publicKey;
  const iso=ms=>new Date(Math.floor(ms/1000)*1000).toISOString().replace('.000Z','');
  const now=Date.now();content.authorization.issuedAt=content.authorization.bindingValidFrom=iso(now-600000);
  content.authorization.expiresAt=iso(now-300000);content.authorization.bindingExpiresAt=iso(now+3600000);
  const a=content.authorization, proposal={deviceId:a.deviceId,expectedBindingId:null,operation:'register',publicKey,requestId:a.requestId};
  const store=createMessagingDeviceStore();
  await store.create({acceptedBinding:null,authorization:null,deviceId:a.deviceId,pendingAuthorization:null,
   pendingProposal:canonical(proposal),privateKey:key.privateKey,publicKey,requestId:a.requestId,rotation:null,
   schema:'hodlxxi.social_messaging_device_local.v1',state:'pending-register',subject:a.subject,version:1});
  const boundary=createMessagingDeviceEd25519KeyV2({getContext:()=>({subjectHint:a.subject,revision:'aa'.repeat(32)}),messageAudience:location.origin});
  return boundary.prepare(canonical(content));
 },content);
 const login=()=>page.evaluate(async()=>{
  const {createRegisteredDeviceSessionClientV1}=await import('/web/registered-device-session-client-v1.mjs');
  globalThis.client=createRegisteredDeviceSessionClientV1();return client.ensure();
 });
 assert.equal(await login(),true);assert.equal(consumes,1);
 const cookies=await context.cookies();assert.ok(cookies.some(c=>c.name==='__Host-hodlxxi-registered-session'&&c.httpOnly&&c.secure));
 await page.reload();assert.equal(await login(),true);assert.equal(consumes,1);
 const retained=await page.evaluate(async()=>{
  const {createMessagingDeviceStore}=await import('/web/messaging-device-v128c1.mjs');
  const x=await createMessagingDeviceStore().read();return {extractable:x.privateKey.extractable,algorithm:x.privateKey.algorithm.name,nostr:typeof window.nostr};
 });assert.deepEqual(retained,{extractable:false,algorithm:'X25519',nostr:'undefined'});
 await page.evaluate(async()=>{client.suspend();const r=await fetch('/auth/logout',{method:'POST'});if(r.status!==200)throw Error('logout failed');});
 assert.equal(revokes,1);await page.reload();assert.equal(await login(),false);assert.equal(consumes,1);
 assert.equal(await page.evaluate(()=>client.ensure({explicit:true})),true);assert.equal(consumes,2);
 assert.equal(await page.evaluate(async()=>{
  const {MESSAGING_DEVICE_DATABASE_NAME,MESSAGING_DEVICE_PROVISIONAL_AUTHENTICATION_STORE_V2}=await import('/web/messaging-device-v128c1.mjs');
  const db=await new Promise((resolve,reject)=>{const r=indexedDB.open(MESSAGING_DEVICE_DATABASE_NAME);r.onsuccess=()=>resolve(r.result);r.onerror=reject;});
  try{return await new Promise((resolve,reject)=>{const tx=db.transaction(MESSAGING_DEVICE_PROVISIONAL_AUTHENTICATION_STORE_V2);const r=tx.objectStore(MESSAGING_DEVICE_PROVISIONAL_AUTHENTICATION_STORE_V2).getAll();r.onsuccess=()=>resolve(r.result.length===1&&r.result[0].privateKey.extractable===false);r.onerror=reject;});}
  finally{db.close();}
 }),true);
 console.log('CHROMIUM_RETAINED_KEY_RESUME=PASS');console.log('CHROMIUM_RELOAD_WITHOUT_REPAIRING=PASS');
 console.log('CHROMIUM_HTTPONLY_LOGOUT_AND_EXPLICIT_RELOGIN=PASS');console.log('CHROMIUM_ED25519_X25519_NONEXTRACTABLE=PASS');
 console.log('AUTHORITY_FIXTURE=SYNTHETIC_NOT_LIVE_ACCEPTANCE');
}catch(error){console.error('BROWSER_THROW_LOCATIONS',JSON.stringify(failureFrames.slice(-12)));throw error;}
finally{await browser.close();}
