// Resume with the existing device's retained key. No membership ceremony or
// provider access. Private CryptoKeys never leave the approved IndexedDB store.
import {createMessagingDeviceStore} from "./messaging-device-v128c1.mjs";
import {createMessagingDeviceEd25519KeyV2} from "./messaging-device-ed25519-key-v2.mjs";
import {canonical,exact} from "./social-mobile-protocol-v1.mjs";

const fail=()=>{throw new Error("registered device sign in unavailable");};
const hex=value=>typeof value==="string" && /^[0-9a-f]{64}$/.test(value);
export function createRegisteredDeviceSessionClientV1({fetchImpl=globalThis.fetch,indexedDBImpl,
  cryptoImpl=globalThis.crypto,CryptoKeyImpl=globalThis.CryptoKey,
  audience=globalThis.location?.origin,now=Date.now,localStore,keyFactory=createMessagingDeviceEd25519KeyV2}={}) {
  let inFlight,expiresAt=0,subject=null,generation=0,suspended=false;
  const blocked=()=>suspended;
  const call=async (path,value)=>{
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),30000);
    try {
      const response=await fetchImpl(path,{method:value===undefined?"GET":"POST",
        ...(value===undefined?{}:{headers:{"content-type":"application/json"},body:canonical(value)}),
        credentials:"same-origin",redirect:"error",cache:"no-store",signal:controller.signal});
      if(response.status!==200 || !/^application\/json(?:;.*)?$/i.test(response.headers.get("content-type")??"")) fail();
      const wire=await response.text();if(wire.length>16384) fail();return JSON.parse(wire);
    } finally {clearTimeout(timer);}
  };
  const resume=async ({expectedSubject,explicit=false}={})=>{
    if(!explicit && blocked()) return false;
    if(expectedSubject!==undefined && !hex(expectedSubject)) return false;
    if(expiresAt>now()+30000 && (!expectedSubject || expectedSubject===subject)) return true;
    if(inFlight) {const accepted=await inFlight;return accepted && (!expectedSubject || expectedSubject===subject);}
    const revision=++generation;
    const operation=async ()=>{
      try {
        const stored=await (localStore??createMessagingDeviceStore(indexedDBImpl)).read();
        if(!stored || !hex(stored.subject) || !hex(stored.deviceId) || expectedSubject && stored.subject!==expectedSubject ||
            stored.privateKey?.extractable!==false || stored.privateKey?.algorithm?.name!=="X25519") return false;
        subject=stored.subject;
        const check=()=>{if(generation!==revision || !explicit && blocked()) fail();};
        check();
        const config=exact(await call("/auth/device-session/config"),["enabled","issuer","clientId","automaticResumeAllowed"]);
        if(config.enabled!==true || typeof config.issuer!=="string" || new URL(config.issuer).origin!==config.issuer ||
            !config.issuer.startsWith("https://") || typeof config.clientId!=="string" ||
            typeof audience!=="string" || !audience.startsWith("https://") ||
            typeof config.automaticResumeAllowed!=="boolean" || !explicit && !config.automaticResumeAllowed) fail();
        const status=await call("/auth/device-session/status");check();
        if(status.authenticated===true) {
          exact(status,["authenticated","subject","expiresAt"]);
          if(status.subject!==subject || !Number.isSafeInteger(status.expiresAt)) fail();
          if(status.expiresAt>now()+30000) {expiresAt=status.expiresAt;return true;}
        } else {exact(status,["authenticated"]);if(status.authenticated!==false) fail();}
        const context=exact(await call("/auth/device-session/context",{explicit}),["contextCommitment"]);check();
        if(!hex(context.contextCommitment)) fail();
        const challenge=exact(await call("/auth/device-session/challenge",{subject,deviceId:stored.deviceId}),["challengeWire"]);check();
        const localRevision=[...cryptoImpl.getRandomValues(new Uint8Array(32))].map(v=>v.toString(16).padStart(2,"0")).join("");
        const key=keyFactory({indexedDBImpl,cryptoImpl,CryptoKeyImpl,messageAudience:audience,
          getContext:()=>{check();return {subjectHint:subject,revision:localRevision};}});
        const proofWire=await key.createRegisteredDeviceSessionProofV1(challenge.challengeWire,
          {issuer:config.issuer,clientId:config.clientId,contextCommitment:context.contextCommitment});check();
        const result=exact(await call("/auth/device-session/proof",{challengeWire:challenge.challengeWire,proofWire}),
          ["authenticated","subject","expiresAt"]);check();
        if(result.authenticated!==true || result.subject!==subject || !Number.isSafeInteger(result.expiresAt) ||
            result.expiresAt<=now() || result.expiresAt>now()+300000) fail();
        expiresAt=result.expiresAt;
        if(explicit) suspended=false;
        return true;
      } catch {expiresAt=0;return false;}
    };
    inFlight=operation();
    try {return await inFlight;} finally {inFlight=undefined;}
  };
  return Object.freeze({ensure:resume,suspend(){suspended=true;generation++;expiresAt=0;}});
}
