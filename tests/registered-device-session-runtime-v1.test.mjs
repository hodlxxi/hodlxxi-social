// Synthetic UBID service port; real retained-key Ed25519 proof and signed
// Social statement. Real native SQL authority is covered by the paired PG16 gate.
import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {generateKeyPairSync,randomBytes,sign,webcrypto} from "node:crypto";
import {createRegisteredDeviceSessionBffV1,REGISTERED_SESSION_COOKIE,REGISTERED_CONTEXT_COOKIE,
  REGISTERED_SIGNED_OUT_COOKIE} from "../src/server/registered-device-session-bff-v1.mjs";
import {produceRegisteredDeviceSessionStatementV1} from "../src/server/registered-device-session-statement-v1.mjs";
import {verifyRegisteredDeviceSessionProofV1} from "../src/server/registered-device-session-proof-v1.mjs";
import {registeredDeviceSessionSigningPreimageV1,createRegisteredDeviceSessionProofWireV1} from "../web/registered-device-session-v1.mjs";
import {createRegisteredDeviceSessionClientV1} from "../web/registered-device-session-client-v1.mjs";
import {canonical} from "../web/social-mobile-protocol-v1.mjs";
import http from "node:http";
import {createHttpHandler} from "../scripts/hodlxxi-social-server.mjs";
import {REGISTERED_SESSION_POST_ROUTES} from "../src/server/registered-device-session-bff-v1.mjs";
import {createSocialEntryActions} from "../web/social-entry-actions-v1.mjs";

const vector=JSON.parse((JSON.parse(await readFile(new URL("./fixtures/social_registered_device_session_v1.json",import.meta.url)))).challengeWire);
const rsa=generateKeyPairSync("rsa",{modulusLength:2048});
const config={publicOrigin:vector.audience,authorityOrigin:vector.issuer,clientId:vector.clientId};
const alias="p_AAAAAAAAAAAAAAAAAAAAAA";
function lab({primarySubject,capacity=4,mobileEntry=false}={}) {
  let at=vector.issuedAt,full=true,proofConsumes=0,challengeCount=0,blockConsume;
  const revoked=new Set();
  const keys=generateKeyPairSync("ed25519"),publicKey=keys.publicKey.export({format:"der",type:"spki"}).subarray(-32).toString("hex");
  const jar=new Map(),issued=new Map(),challenges=new Set(),calls=[];
  const client={async invoke(command,body,credential) {
    calls.push(command);
    if(command==="registered-challenge") {
      assert.equal(credential,undefined);if(!full) throw Error();
      challengeCount++;
      const wire=canonical({...vector,subject:body.subject,deviceId:body.deviceId,contextCommitment:body.contextCommitment,
        ed25519PublicKey:publicKey,challengeId:randomBytes(32).toString("hex"),issuedAt:at,expiresAt:at+60000});
      challenges.add(wire);return {challengeWire:wire};
    }
    if(command==="registered-consume") {
      if(blockConsume) await blockConsume;
      const challenge=JSON.parse(body.challengeWire);
      assert.equal(credential,undefined);
      if(!full || !challenges.delete(body.challengeWire) || !verifyRegisteredDeviceSessionProofV1({...body,
        issuer:config.authorityOrigin,audience:config.publicOrigin,clientId:config.clientId,now:at})) throw Error();
      assert.equal(typeof JSON.parse(body.statementWire).signature,"string");proofConsumes++;
      const record={sessionId:randomBytes(32).toString("hex"),credential:randomBytes(32).toString("hex"),
        expiresAt:at+300000,subject:challenge.subject,deviceId:challenge.deviceId};
      issued.set(record.sessionId,record);return record;
    }
    const record=issued.get(body.registeredSession?.sessionId);
    if(!record || credential!==record.credential) throw Error();
    if(command==="registered-revoke") {revoked.add(record.sessionId);return {sessionId:record.sessionId,status:"revoked"};}
    if(!full || revoked.has(record.sessionId) || at>=record.expiresAt) throw Error();
    if(command==="registered-current") {const {credential:_,...current}=record;return {...current,authority:{subject:record.subject,status:"full",valid:true}};}
    if(command==="registered-directory") return {schema:"hodlxxi.privacy_safe_full_directory.v1",version:1,
      participants:[{alias,identity_class:"full",current_full_relation_satisfied:true}]};
    throw Error("unexpected synthetic command");
  }};
  const inputs=[];
  const transport={registeredSessionClient:client,
    registeredStatement:input=>produceRegisteredDeviceSessionStatementV1(input,{kid:"test-session",privateKey:rsa.privateKey}),
    async currentDeviceForViewer(input) {inputs.push(input);return {deviceId:vector.deviceId,handles:[]};},
    async resolveRecipientForViewer(input) {inputs.push(input);return {alias:input.recipientAlias};},
  };
  const base=async request=>{
    let value={authenticated:false};
    if(request.url==="/auth/session" && primarySubject) value={authenticated:true,subject:primarySubject};
    if(request.url==="/auth/entry-config") value={mobileContextRequired:mobileEntry};
    if(request.url==="/auth/mobile/v1/context") value={csrf:"aa".repeat(32)};
    if(request.url==="/auth/logout" && mobileEntry) {
      assert.equal(request.headers["x-hodlxxi-mobile-csrf"],"aa".repeat(32));value={authenticated:false,logout:"confirmed"};
    }
    return {status:200,body:JSON.stringify(value),headers:{"Content-Type":"application/json"}};
  };
  const bff=createRegisteredDeviceSessionBffV1({config,transport,base,capacity,now:()=>at});
  const request=async (path,value,{origin=config.publicOrigin,cookie,apply=true,headers={}}={})=>{
    const req={url:path,method:value===undefined?"GET":"POST",
      headers:{origin,"content-type":"application/json",cookie:cookie??[...jar].map(([k,v])=>k+"="+v).join(";"),...headers},
      body:value===undefined?undefined:canonical(value)};
    const response=await bff.handle(req)??await base(req);
    if(response && apply) for(const item of [response.headers?.["Set-Cookie"]??[]].flat()) {
      const [pair]=item.split(";"),split=pair.indexOf("="),name=pair.slice(0,split),value=pair.slice(split+1);
      if(/Max-Age=0(?:;|$)/.test(item)) jar.delete(name);else jar.set(name,value);
    }
    return response && {...response,value:JSON.parse(response.body)};
  };
  const challenge=async ()=>{
    assert.equal((await request("/auth/device-session/context",{explicit:false})).status,200);
    return request("/auth/device-session/challenge",{subject:vector.subject,deviceId:vector.deviceId});
  };
  const proofFor=wire=>createRegisteredDeviceSessionProofWireV1(wire,sign(null,registeredDeviceSessionSigningPreimageV1(wire),keys.privateKey).toString("hex"));
  const login=async ()=>{
    const result=await challenge();assert.equal(result.status,200);
    return request("/auth/device-session/proof",{challengeWire:result.value.challengeWire,proofWire:proofFor(result.value.challengeWire)});
  };
  return {request,challenge,proofFor,login,jar,calls,inputs,keys,client,bff,
    set full(value){full=value;},set at(value){at=value;},get at(){return at;},
    set blockConsume(value){blockConsume=value;},get proofConsumes(){return proofConsumes;},get challengeCount(){return challengeCount;}};
}

test("retained-key login returns only an opaque HttpOnly cookie and current authoritative identity",async()=>{
  const l=lab(),response=await l.login();assert.equal(response.status,200);
  assert.deepEqual(Object.keys(response.value).sort(),["authenticated","expiresAt","subject"]);
  assert.ok(l.jar.has(REGISTERED_SESSION_COOKIE));
  for(const cookie of response.headers["Set-Cookie"]) assert.match(cookie,/Secure; HttpOnly; SameSite=Lax/);
  assert.doesNotMatch(response.body,/credential|sessionId|privateKey/);
  assert.deepEqual((await l.request("/auth/session")).value,{authenticated:true,subject:vector.subject});
  assert.equal((await l.request("/auth/authority")).value.status,"full");
  const device=await l.request("/auth/messages/device");assert.equal(device.status,200);
  assert.ok(l.inputs[0].registeredSession);assert.equal(l.inputs[0].viewerAccessToken,undefined);
});
test("current Full loss denies directory and messages and cannot fall back to a subject claim",async()=>{
  const l=lab();await l.login();l.full=false;
  assert.deepEqual((await l.request("/auth/session")).value,{authenticated:false});
  for(const path of ["/auth/authority","/auth/full-directory","/auth/messages/device"]) assert.equal((await l.request(path)).status,403);
  assert.equal(l.inputs.length,0);
});
test("wrong origin, browser context, proof and replay cannot install a scoped session",async()=>{
  const l=lab();assert.equal((await l.request("/auth/device-session/context",{explicit:false},{origin:"https://attacker.example"})).status,403);
  const c=await l.challenge(),wire=c.value.challengeWire,proof=l.proofFor(wire);
  const cookie=REGISTERED_CONTEXT_COOKIE+"="+"ef".repeat(32);
  assert.equal((await l.request("/auth/device-session/proof",{challengeWire:wire,proofWire:proof},{cookie})).status,403);
  assert.equal((await l.request("/auth/device-session/proof",{challengeWire:wire,proofWire:proof})).status,200);
  assert.equal((await l.request("/auth/device-session/proof",{challengeWire:wire,proofWire:proof})).status,403);
  assert.equal(l.proofConsumes,1);
  const bad=lab(),b=await bad.challenge();
  const zero=createRegisteredDeviceSessionProofWireV1(b.value.challengeWire,"00".repeat(64));
  assert.equal((await bad.request("/auth/device-session/proof",{challengeWire:b.value.challengeWire,proofWire:zero})).status,403);
  assert.equal(bad.proofConsumes,0);
});
test("logout revokes even after Full loss and blocks silent automatic sign in until explicit intent",async()=>{
  const l=lab();await l.login();l.full=false;
  assert.equal((await l.request("/auth/logout",{})).status,200);
  assert.ok(l.calls.includes("registered-revoke"));assert.equal(l.jar.has(REGISTERED_SESSION_COOKIE),false);
  assert.ok(l.jar.has(REGISTERED_SIGNED_OUT_COOKIE));
  assert.equal((await l.request("/auth/device-session/config")).value.automaticResumeAllowed,false);
  assert.equal((await l.request("/auth/device-session/context",{explicit:false})).status,403);
  assert.equal((await l.request("/auth/device-session/context",{explicit:true})).status,200);
});
test("pending proof completion cannot install a cookie after same-browser logout",async()=>{
  const l=lab(),c=await l.challenge();let release;
  l.blockConsume=new Promise(resolve=>{release=resolve;});
  const pending=l.request("/auth/device-session/proof",{challengeWire:c.value.challengeWire,proofWire:l.proofFor(c.value.challengeWire)});
  await Promise.resolve();await Promise.resolve();
  await l.request("/auth/logout",{});release();
  assert.equal((await pending).status,403);assert.equal(l.jar.has(REGISTERED_SESSION_COOKIE),false);
});
test("a saved device cannot switch a live primary identity and duplicate security cookies deny",async()=>{
  const l=lab({primarySubject:"99".repeat(32)});assert.equal((await l.challenge()).status,403);
  assert.equal(l.challengeCount,0);
  assert.equal((await l.request("/auth/device-session/status",undefined,
    {cookie:REGISTERED_SESSION_COOKIE+"=one; "+REGISTERED_SESSION_COOKIE+"=two"})).status,400);
});
test("viewer-private capabilities stay tied to the registered cookie generation",async()=>{
  const l=lab();await l.login();
  const capability=await l.request("/auth/recipient-capability",{});
  // The alias is carried only by the dedicated header, not a body override.
  assert.equal(capability.status,403);
  const directory=await l.request("/auth/full-directory");assert.deepEqual(directory.value,{state:"available",participants:[{alias}]});
  const issued=await l.request("/auth/recipient-capability",{},{headers:{"x-hodlxxi-recipient-alias":alias}});
  assert.equal(issued.status,200);
  const headers={"x-hodlxxi-recipient-capability":issued.value.capability};
  assert.equal((await l.request("/auth/messaging-recipient-package",{},{headers})).status,200);
  await l.login();
  assert.equal((await l.request("/auth/messaging-recipient-package",{},{headers})).status,403);
});

async function browserLab() {
  const l=lab(),x=await webcrypto.subtle.generateKey({name:"X25519"},false,["deriveBits"]);
  const local={subject:vector.subject,deviceId:vector.deviceId,privateKey:structuredClone(x.privateKey)};
  const fetchImpl=async(path,options={})=>{
    const response=await l.request(path,options.method==="POST"?JSON.parse(options.body):undefined);
    return {status:response?.status??404,headers:{get:()=>"application/json"},text:async()=>response?.body??"{}"};
  };
  let proofCount=0;
  const factory=options=>({async createRegisteredDeviceSessionProofV1(wire,pins){
    assert.match(options.getContext().revision,/^[0-9a-f]{64}$/);
    assert.equal(options.getContext().subjectHint,local.subject);assert.ok(pins.contextCommitment);
    proofCount++;return l.proofFor(wire);
  }});
  const create=()=>createRegisteredDeviceSessionClientV1({fetchImpl,localStore:{read:async()=>local},
    cryptoImpl:webcrypto,CryptoKeyImpl:webcrypto.CryptoKey,audience:config.publicOrigin,now:()=>l.at,keyFactory:factory});
  return {l,local,create,get proofCount(){return proofCount;}};
}
test("browser resumes once, survives reload without another pairing and renews before expiry",async()=>{
  const b=await browserLab(),client=b.create();
  assert.deepEqual(await Promise.all([client.ensure(),client.ensure()]),[true,true]);assert.equal(b.proofCount,1);
  assert.equal(await b.create().ensure(),true);assert.equal(b.proofCount,1);
  b.l.at+=280000;assert.equal(await client.ensure(),true);assert.equal(b.proofCount,2);
  assert.equal(b.l.challengeCount,2);
  assert.equal((await b.l.request("/auth/session")).value.authenticated,true);
});
test("logout persists through HttpOnly server intent; only a new explicit sign in may resume",async()=>{
  const b=await browserLab(),client=b.create();assert.equal(await client.ensure(),true);
  client.suspend();await b.l.request("/auth/logout",{});
  assert.equal(await client.ensure(),false);const fresh=b.create();assert.equal(await fresh.ensure(),false);
  assert.equal(await fresh.ensure({explicit:true}),true);assert.equal(b.l.jar.has(REGISTERED_SIGNED_OUT_COOKIE),false);
});
test("browser refuses a different subject and never creates or replaces keys on failure",async()=>{
  const b=await browserLab(),client=b.create();
  assert.equal(await client.ensure({expectedSubject:"99".repeat(32)}),false);assert.equal(b.proofCount,0);
  b.l.full=false;assert.equal(await client.ensure(),false);assert.equal(b.proofCount,0);
  assert.equal(b.local.privateKey.extractable,false);assert.equal(b.l.proofConsumes,0);
});
test("ordinary entry logout keeps its existing mobile CSRF and confirmed response contract",async()=>{
  const l=lab({mobileEntry:true});await l.login();
  const actions=createSocialEntryActions({fetchImpl:async(path,options={})=>{
    const result=await l.request(path,options.method==="POST"?JSON.parse(options.body):undefined,{headers:options.headers});
    return new Response(result.body,{status:result.status,headers:result.headers});
  }});
  assert.deepEqual(await actions.logout(),{authenticated:false});
  assert.equal(l.jar.has(REGISTERED_SESSION_COOKIE),false);assert.ok(l.calls.includes("registered-revoke"));
});
test("normal HTTP handler frames registered-session posts and rejects ambiguous security headers",async()=>{
  const l=lab(),server=http.createServer(createHttpHandler({publicOrigin:config.publicOrigin,
    bff:async request=>await l.bff.handle(request)??{status:404,headers:{},body:"{}"},mobilePostRoutes:REGISTERED_SESSION_POST_ROUTES}));
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  const send=headers=>new Promise((resolve,reject)=>{
    const body=canonical({explicit:false});
    const request=http.request({host:"127.0.0.1",port:server.address().port,path:"/auth/device-session/context",method:"POST",
      headers:{origin:config.publicOrigin,"content-type":"application/json","content-length":Buffer.byteLength(body),...headers}},response=>{
      let wire="";response.on("data",chunk=>{wire+=chunk;});response.on("end",()=>resolve({status:response.statusCode,headers:response.headers,wire}));
    });request.on("error",reject);request.end(body);
  });
  try {
    const valid=await send({});assert.equal(valid.status,200);assert.ok(JSON.parse(valid.wire).contextCommitment);
    assert.match(valid.headers["set-cookie"][0],/HttpOnly/);
    for(const headers of [{origin:[config.publicOrigin,config.publicOrigin]},
      {"content-encoding":"gzip"},{authorization:"Bearer arbitrary"},{"x-hodlxxi-viewer-authorization":"Bearer arbitrary"}]) {
      assert.equal((await send(headers)).status,413);
    }
  } finally {await new Promise(resolve=>server.close(resolve));}
});
