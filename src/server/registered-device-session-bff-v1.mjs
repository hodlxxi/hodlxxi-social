// Explicit registered-device messaging scope. Credentials stay behind HttpOnly
// cookies and are never presented as OAuth tokens or general account authority.
import {createHash, randomBytes} from "node:crypto";
import {canonical, exact, parseClosedJson} from "../../web/social-mobile-protocol-v1.mjs";
import {requireCurrentRegisteredDeviceSessionChallengeV1} from "../../web/registered-device-session-v1.mjs";
import {parseCookieHeader, serializeHostCookie, expireHostCookie} from "./social-oauth-cookie.mjs";
import {parseRawRequestTarget, SECURITY_HEADERS} from "./social-oauth-bff.mjs";
import {normalizeUbidFullDirectory} from "./ubid-full-directory-client.mjs";
import {createOpaqueRecipientCapabilityStore} from "./opaque-recipient-capability.mjs";
import {parseCanonicalMessageEnvelopeWireV1} from "./message-envelope-v128f1.mjs";
import {parseDeviceProofV1} from "./messaging-device-proof-profile-v1.mjs";

export const REGISTERED_SESSION_COOKIE = "__Host-hodlxxi-registered-session";
export const REGISTERED_CONTEXT_COOKIE = "__Host-hodlxxi-registered-context";
export const REGISTERED_SIGNED_OUT_COOKIE = "__Host-hodlxxi-device-signed-out";
export const REGISTERED_SESSION_POST_ROUTES = Object.freeze([
  "/auth/device-session/context", "/auth/device-session/challenge", "/auth/device-session/proof"
]);
const hex = value=>typeof value==="string" && /^[0-9a-f]{64}$/.test(value);
const fail = ()=>{throw new Error("registered device session unavailable");};
const json = (status,value,headers={})=>({status,body:JSON.stringify(value),headers:{...SECURITY_HEADERS,
  "Content-Type":"application/json; charset=utf-8",...headers}});
const denied = (status=403)=>json(status,{state:"unavailable"});
const contextCommitment = nonce=>createHash("sha256").update("HODLXXI_REGISTERED_DEVICE_BROWSER_CONTEXT_V1\0"+nonce,"ascii").digest("hex");
// This long-lived cookie carries only a denial preference, never a credential.
const signedOutCookie = ()=>REGISTERED_SIGNED_OUT_COOKIE+"=1; Max-Age=31536000; Path=/; Secure; HttpOnly; SameSite=Lax";

export function createRegisteredDeviceSessionBffV1({config,transport,base,capacity=1024,now=Date.now,random=randomBytes}) {
  const client=transport?.registeredSessionClient;
  if (!client || typeof client.invoke!=="function" || typeof transport.registeredStatement!=="function" ||
      typeof base!=="function" || !Number.isSafeInteger(capacity) || capacity<1 || capacity>10000) fail();
  const contexts=new Map(), sessions=new Map();
  const capabilities=createOpaqueRecipientCapabilityStore();
  const sweep=()=>{
    const at=now();
    for(const [id,context] of contexts) if(context.expiresAt<=at && !context.busy) contexts.delete(id);
    for(const [id,record] of sessions) if(record.expiresAt+300000<=at && !record.revoking) sessions.delete(id);
  };
  const cookies=header=>parseCookieHeader(header,[REGISTERED_SESSION_COOKIE,REGISTERED_CONTEXT_COOKIE,REGISTERED_SIGNED_OUT_COOKIE]);
  const current=async (record)=>{
    if(!record || record.revoking || record.expiresAt<=now()) fail();
    const result=exact(await client.invoke("registered-current",{registeredSession:record.registeredSession},record.credential),
      ["sessionId","subject","deviceId","expiresAt","authority"]);
    exact(result.authority,["subject","status","valid"]);
    if(result.sessionId!==record.registeredSession.sessionId || result.subject!==record.subject ||
        result.deviceId!==record.deviceId || !Number.isSafeInteger(result.expiresAt) || result.expiresAt>record.expiresAt || result.expiresAt<=now() ||
        result.authority.subject!==record.subject || result.authority.status!=="full" || result.authority.valid!==true ||
        record.revoking) fail();
    return result;
  };
  const inputFor=record=>({registeredSession:record.registeredSession,registeredCredential:record.credential,expectedSubject:record.subject});
  const directory=async record=>normalizeUbidFullDirectory(await client.invoke("registered-directory",
    {registeredSession:record.registeredSession},record.credential));
  const body=request=>{
    if(!/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers?.["content-type"]??"") ||
        typeof request.body!=="string" || Buffer.byteLength(request.body)>16384) fail();
    return parseClosedJson(request.body,{canonicalOnly:true,maximum:16384});
  };
  const terminate=async (record)=>{
    record.revoking=true; // Fence all reads and in-flight request completion before awaiting I/O.
    const result=exact(await client.invoke("registered-revoke",{registeredSession:record.registeredSession},record.credential),["sessionId","status"]);
    if(result.sessionId!==record.registeredSession.sessionId || result.status!=="revoked") fail();
  };
  return Object.freeze({postRoutes:REGISTERED_SESSION_POST_ROUTES,handle:async request=>{
    const target=parseRawRequestTarget(request.url,config.publicOrigin);
    if(!target.valid) return denied(400);
    const {path,query}=target;
    let jar;
    try {jar=cookies(request.headers?.cookie);} catch {return denied(400);}
    const sessionAlias=jar.get(REGISTERED_SESSION_COOKIE), record=sessions.get(sessionAlias);
    // Existing entry actions still own their OAuth/mobile CSRF fence. These
    // two infrastructure routes carry no registered-device authority.
    if(path==="/auth/entry-config" || path==="/auth/mobile/v1/context") return null;
    if(path==="/auth/device-session/config") return request.method==="GET" && !query.length
      ? json(200,{enabled:true,issuer:config.authorityOrigin,clientId:config.clientId,
          automaticResumeAllowed:!jar.has(REGISTERED_SIGNED_OUT_COOKIE)}) : denied(405);
    if(path==="/auth/device-session/status") {
      if(request.method!=="GET" || query.length) return denied(405);
      try {
        const live=await current(record);
        return json(200,{authenticated:true,subject:live.subject,expiresAt:live.expiresAt});
      } catch {return json(200,{authenticated:false});}
    }
    if(REGISTERED_SESSION_POST_ROUTES.includes(path)) {
      if(request.method!=="POST" || query.length) return denied(405);
      if(request.headers?.origin!==config.publicOrigin) return denied();
      sweep();
      try {
        const value=body(request);
        if(path.endsWith("/context")) {
          exact(value,["explicit"]);
          if(typeof value.explicit!=="boolean" || jar.has(REGISTERED_SIGNED_OUT_COOKIE) && !value.explicit) fail();
          let nonce=jar.get(REGISTERED_CONTEXT_COOKIE), context=contexts.get(nonce);
          if(!context || context.expiresAt<=now() || context.explicit!==value.explicit) {
            contexts.delete(nonce);
            if(contexts.size>=capacity) fail();
            nonce=random(32).toString("hex");
            if(!hex(nonce) || contexts.has(nonce)) fail();
            context={expiresAt:now()+86400000,busy:false,pending:null,explicit:value.explicit}; contexts.set(nonce,context);
          }
          return json(200,{contextCommitment:contextCommitment(nonce)},{"Set-Cookie":serializeHostCookie(REGISTERED_CONTEXT_COOKIE,nonce,86400)});
        }
        const nonce=jar.get(REGISTERED_CONTEXT_COOKIE), context=contexts.get(nonce);
        if(!hex(nonce) || !context || context.busy || context.expiresAt<=now() ||
            jar.has(REGISTERED_SIGNED_OUT_COOKIE) && !context.explicit) fail();
        context.busy=true;
        const commitment=contextCommitment(nonce), stillCurrent=()=>contexts.get(nonce)===context && context.expiresAt>now();
        try {
          if(path.endsWith("/challenge")) {
            exact(value,["subject","deviceId"]);
            if(!hex(value.subject) || !hex(value.deviceId)) fail();
            // A retained device cannot silently switch a live desktop identity.
            const primary=await base({...request,method:"GET",url:"/auth/session",body:undefined});
            if(primary.status!==200) fail();
            const primarySession=JSON.parse(primary.body);
            if(primarySession.authenticated===true && primarySession.subject!==value.subject || record && record.subject!==value.subject) fail();
            const result=exact(await client.invoke("registered-challenge",{...value,contextCommitment:commitment}),["challengeWire"]);
            const challenge=requireCurrentRegisteredDeviceSessionChallengeV1(result.challengeWire,{issuer:config.authorityOrigin,
              audience:config.publicOrigin,clientId:config.clientId,contextCommitment:commitment,now:now()});
            if(!stillCurrent() || challenge.subject!==value.subject || challenge.deviceId!==value.deviceId) fail();
            context.pending=result.challengeWire;
            return json(200,result);
          }
          exact(value,["challengeWire","proofWire"]);
          if(context.pending!==value.challengeWire) fail();
          context.pending=null; // One attempt per local challenge; UBID also consumes atomically.
          const challenge=requireCurrentRegisteredDeviceSessionChallengeV1(value.challengeWire,{issuer:config.authorityOrigin,
            audience:config.publicOrigin,clientId:config.clientId,contextCommitment:commitment,now:now()});
          const statementWire=transport.registeredStatement({...value,issuer:config.authorityOrigin,audience:config.publicOrigin,
            clientId:config.clientId,contextCommitment:commitment,now:now()});
          const issued=exact(await client.invoke("registered-consume",{...value,statementWire,contextCommitment:commitment}),
            ["sessionId","credential","expiresAt","subject","deviceId"]);
          if(!hex(issued.sessionId) || !hex(issued.credential) || issued.subject!==challenge.subject ||
              issued.deviceId!==challenge.deviceId || !Number.isSafeInteger(issued.expiresAt) ||
              issued.expiresAt<=now() || issued.expiresAt>now()+300000) fail();
          const next={subject:issued.subject,deviceId:issued.deviceId,credential:issued.credential,
            expiresAt:issued.expiresAt,registeredSession:{sessionId:issued.sessionId,contextCommitment:commitment},revoking:false};
          try {
            if(!stillCurrent()) fail();
            await current(next);
            if(record) {await terminate(record);sessions.delete(sessionAlias);}
            await current(next);
            if(!stillCurrent() || sessions.size>=capacity) fail();
            const alias=random(32).toString("base64url");
            const maxAge=Math.floor((issued.expiresAt-now())/1000);
            if(!/^[A-Za-z0-9_-]{43}$/.test(alias) || sessions.has(alias) || maxAge<1) fail();
            sessions.set(alias,next);
            return json(200,{authenticated:true,subject:issued.subject,expiresAt:issued.expiresAt},
              {"Set-Cookie":[serializeHostCookie(REGISTERED_SESSION_COOKIE,alias,maxAge),expireHostCookie(REGISTERED_SIGNED_OUT_COOKIE)]});
          } catch {
            try {await terminate(next);} catch {}
            fail();
          }
        } finally {context.busy=false;}
      } catch {return denied();}
    }
    if(path==="/auth/logout") {
      if(request.method!=="POST" || query.length || request.headers?.origin!==config.publicOrigin) return denied();
      // Cancel a pending login even when no new session has yet been installed.
      contexts.delete(jar.get(REGISTERED_CONTEXT_COOKIE));
      try {
        if(record) await terminate(record);
        const primary=await base(request);
        if(primary.status!==200) fail();
        const primaryResult=parseClosedJson(primary.body,{maximum:1024});
        exact(primaryResult,Object.hasOwn(primaryResult,"logout")?["authenticated","logout"]:["authenticated"]);
        if(primaryResult.authenticated!==false || Object.hasOwn(primaryResult,"logout") &&
            !["confirmed","local-only"].includes(primaryResult.logout)) fail();
        sessions.delete(sessionAlias);
        const inherited=primary.headers?.["Set-Cookie"];
        return json(200,primaryResult,{"Set-Cookie":[...(Array.isArray(inherited)?inherited:inherited?[inherited]:[]),
          expireHostCookie(REGISTERED_SESSION_COOKIE),expireHostCookie(REGISTERED_CONTEXT_COOKIE),
          signedOutCookie()]});
      } catch {return json(503,{state:"unavailable"},{"Set-Cookie":signedOutCookie()});}
    }
    if(!sessionAlias) return null;
    if(!path.startsWith("/auth/")) return null;
    if(query.length) return denied(400);
    const allowedGet=["/auth/session","/auth/authority","/auth/full-directory","/auth/messages/device","/auth/messages/config",
      "/auth/social-read-config","/auth/social-publish-config","/auth/messaging-device-binding-authorization-config"];
    const allowedPost=["/auth/recipient-capability","/auth/messaging-recipient-package","/auth/messages/challenge","/auth/messages","/auth/messages/inbox"];
    if(!(request.method==="GET"?allowedGet:request.method==="POST"?allowedPost:[]).includes(path)) return denied();
    if(request.method==="POST" && request.headers?.origin!==config.publicOrigin) return denied();
    try {
      const live=await current(record);
      const stillCurrent=()=>sessions.get(sessionAlias)===record && !record.revoking;
      let result;
      if(path==="/auth/session") result={authenticated:true,subject:live.subject};
      else if(path==="/auth/authority") result=live.authority;
      else if(path==="/auth/full-directory") result=await directory(record);
      else if(path==="/auth/messages/config") result={enabled:true};
      else if(["/auth/social-read-config","/auth/social-publish-config","/auth/messaging-device-binding-authorization-config"].includes(path)) result={enabled:false};
      else if(path==="/auth/messages/device") result=await transport.currentDeviceForViewer(inputFor(record));
      else {
        const capability=async token=>{
          const aliases=(await directory(record)).participants;
          const resolved=capabilities.resolve({subject:record.subject,sessionId:sessionAlias,capability:token,
            purpose:"direct-message",currentAliases:aliases,now:now()});
          if(resolved.state!=="available") fail(); return resolved.alias;
        };
        if(path==="/auth/recipient-capability") {
          const aliases=(await directory(record)).participants;
          result=capabilities.issue({subject:record.subject,sessionId:sessionAlias,alias:request.headers?.["x-hodlxxi-recipient-alias"],
            purpose:"direct-message",currentAliases:aliases,now:now()});
          if(result.state!=="available") fail();
        } else if(path==="/auth/messaging-recipient-package") {
          result=await transport.resolveRecipientForViewer({...inputFor(record),recipientAlias:await capability(request.headers?.["x-hodlxxi-recipient-capability"])});
        } else {
          if(typeof request.body!=="string" || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers?.["content-type"]??"")) fail();
          if(path==="/auth/messages/challenge") {
            const value=exact(parseClosedJson(request.body,{maximum:65536}),["operation","bodyWire","recipientCapability"]);
            if(!["ciphertext-submit","recipient-self-read"].includes(value.operation) || typeof value.bodyWire!=="string" ||
                value.bodyWire.length>32768 || value.operation==="recipient-self-read" && value.recipientCapability!==null) fail();
            result=await transport.challengeForViewer({...inputFor(record),operation:value.operation,bodyWire:value.bodyWire,
              recipientAlias:value.operation==="ciphertext-submit"?await capability(value.recipientCapability):null});
          } else {
            const deviceProofWire=request.headers?.["x-hodlxxi-message-device-proof"];
            parseDeviceProofV1(deviceProofWire);
            if(path==="/auth/messages") {
              const envelope=parseCanonicalMessageEnvelopeWireV1(request.body);
              const token=request.headers?.["x-hodlxxi-recipient-capability"];
              result=await transport.submitForViewer({...inputFor(record),deviceProofWire,recipientCapability:token,
                recipientAlias:await capability(token),envelopeWire:request.body});
              if(result?.state!=="accepted" || result.messageId!==envelope.messageId) fail();
              result={state:"accepted",messageId:envelope.messageId};
            } else {
              const self=exact(parseClosedJson(request.body,{canonicalOnly:true,maximum:256}),["deviceHandle","schema","version"]);
              if(self.schema!=="hodlxxi.social_messaging_recipient_self_request.v1" || self.version!==1 || !/^d_[A-Za-z0-9_-]{22}$/.test(self.deviceHandle??"")) fail();
              result=await transport.listForViewer({...inputFor(record),deviceProofWire,deviceHandle:self.deviceHandle,requestWire:request.body});
              if(result?.state!=="available" || !Array.isArray(result.messages) || result.messages.length>25 || result.messages.some(wire=>
                typeof wire!=="string" || wire.length>32768 || !parseCanonicalMessageEnvelopeWireV1(wire).recipientDeviceHandles.includes(self.deviceHandle))) fail();
              result={state:"available",messages:result.messages};
            }
          }
        }
      }
      await current(record);
      if(!stillCurrent()) fail();
      return json(200,result);
    } catch {return path==="/auth/session"?json(200,{authenticated:false}):denied();}
  }});
}
