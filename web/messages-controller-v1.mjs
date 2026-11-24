// Plaintext and private CryptoKeys stay in this browser. Transport sees only
// ciphertext and an independent Ed25519 exact-request proof.
import {createMessagingDeviceStore} from "./messaging-device-v128c1.mjs";
import {createMessagingDeviceEd25519KeyV2} from "./messaging-device-ed25519-key-v2.mjs?v=588-message-v1";
import {encryptMessageEnvelope} from "./message-encryption-v128e.mjs";
import {decryptMessageEnvelopeV1} from "./message-decryption-v1.mjs";
const fail=()=>{throw new Error("encrypted messaging unavailable");};
const canonical=value=>JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key=>[key,value[key]])));

export function createMessagesControllerV1({getContext,fetchImpl=globalThis.fetch,indexedDBImpl,
  cryptoImpl=globalThis.crypto,CryptoKeyImpl=globalThis.CryptoKey}={}) {
  const revision=[...cryptoImpl.getRandomValues(new Uint8Array(32))].map(b=>b.toString(16).padStart(2,"0")).join("");
  const local=createMessagingDeviceStore(indexedDBImpl);
  const authentication=createMessagingDeviceEd25519KeyV2({indexedDBImpl,cryptoImpl,CryptoKeyImpl,
    getContext:()=>{const c=getContext(); if(c.access!=="full") fail(); return {revision,subjectHint:c.subject};}});
  let pendingSend, stopped=false;
  const check=()=>{const c=getContext(); if(stopped || c.access!=="full" || !/^[0-9a-f]{64}$/.test(c.subject??"")) fail(); return c.subject;};
  const call=async (path,{method="GET",body,headers={}}={})=>{
    const subject=check();
    const response=await fetchImpl(path,{method,body,headers:{...(body?{"content-type":"application/json"}:{}),...headers},
      credentials:"same-origin",redirect:"error",cache:"no-store"});
    if(check()!==subject || response.status!==200 || !/^application\/json(?:;.*)?$/i.test(response.headers.get("content-type")??"")) fail();
    const wire=await response.text(); if(wire.length>1000000) fail(); return JSON.parse(wire);
  };
  const currentKey=async ()=>{
    const subject=check(), device=await call("/auth/messages/device"), record=await local.read();
    if(check()!==subject || !record || record.subject!==subject || record.deviceId!==device.deviceId ||
        record.privateKey?.algorithm?.name!=="X25519" || record.privateKey.extractable!==false ||
        !Array.isArray(device.handles) || device.handles.length>256 || device.handles.some(h=>!/^d_[A-Za-z0-9_-]{22}$/.test(h))) fail();
    return {record,device};
  };
  const proof=async (operation,bodyWire,recipientCapability=null)=>{
    const result=await call("/auth/messages/challenge",{method:"POST",body:canonical({operation,bodyWire,recipientCapability})});
    return authentication.createDeviceRequestProofV1(result.challengeWire,bodyWire);
  };
  const submit=async ()=>{
    if(!pendingSend) fail();
    const {envelopeWire,capability}=pendingSend;
    const deviceProof=await proof("ciphertext-submit",envelopeWire,capability);
    const result=await call("/auth/messages",{method:"POST",body:envelopeWire,
      headers:{"x-hodlxxi-recipient-capability":capability,"x-hodlxxi-message-device-proof":deviceProof}});
    if(result.state!=="accepted" || result.messageId!==JSON.parse(envelopeWire).messageId) fail();
    pendingSend=undefined; return result;
  };
  return Object.freeze({
    async send(alias,plaintext) {
      check(); if(pendingSend || !/^p_[A-Za-z0-9_-]{22}$/.test(alias??"")) fail();
      await currentKey();
      const capability=await call("/auth/recipient-capability",{method:"POST",headers:{"x-hodlxxi-recipient-alias":alias}});
      const recipientPackage=await call("/auth/messaging-recipient-package",{method:"POST",headers:{"x-hodlxxi-recipient-capability":capability.capability}});
      const envelope=await encryptMessageEnvelope({recipientPackage,plaintext}); check();
      // Retain only ciphertext for an exact retry after an ambiguous response.
      pendingSend={envelopeWire:JSON.stringify(envelope),capability:capability.capability};
      return submit();
    },
    retry:submit,
    async inbox() {
      const {record,device}=await currentKey(), messages=new Map();
      for(const handle of device.handles) {
        const body=canonical({deviceHandle:handle,schema:"hodlxxi.social_messaging_recipient_self_request.v1",version:1});
        const deviceProof=await proof("recipient-self-read",body);
        const result=await call("/auth/messages/inbox",{method:"POST",body,headers:{"x-hodlxxi-message-device-proof":deviceProof}});
        if(result.state!=="available" || !Array.isArray(result.messages) || result.messages.length>25) fail();
        for(const wire of result.messages) {
          const envelope=JSON.parse(wire);
          const plaintext=await decryptMessageEnvelopeV1({envelope,deviceHandle:handle,privateKey:record.privateKey});
          check(); messages.set(envelope.messageId,plaintext);
          if(messages.size>=25) return [...messages.values()];
        }
      }
      return [...messages.values()];
    },
    cancel(){stopped=true;pendingSend=undefined;}
  });
}

export function mountMessagesUIV1({container,controller,selectedAlias}) {
  const doc=container.ownerDocument;
  container.replaceChildren();
  const status=doc.createElement("p"), inbox=doc.createElement("div"), form=doc.createElement("form");
  const input=doc.createElement("textarea"), send=doc.createElement("button"), refresh=doc.createElement("button"), retry=doc.createElement("button");
  input.maxLength=16384; input.setAttribute("aria-label","Message");
  send.textContent="Encrypt and send"; send.type="submit"; send.disabled=!selectedAlias;
  refresh.textContent="Refresh encrypted inbox"; refresh.type="button";
  retry.textContent="Retry pending send"; retry.type="button";
  const run=async work=>{for(const b of [send,refresh,retry]) b.disabled=true; try{await work();}catch{status.textContent="Unavailable. Check device authorization or retry the pending send.";}finally{send.disabled=!selectedAlias;refresh.disabled=retry.disabled=false;}};
  form.append(input,send,retry);
  form.addEventListener("submit",event=>{event.preventDefault();const plaintext=input.value;input.value="";void run(async()=>{await controller.send(selectedAlias,plaintext);status.textContent="Encrypted message stored.";});});
  retry.addEventListener("click",()=>void run(async()=>{await controller.retry();status.textContent="Encrypted message stored.";}));
  refresh.addEventListener("click",()=>void run(async()=>{const values=await controller.inbox();inbox.replaceChildren();for(const value of values){const item=doc.createElement("p");item.textContent=value;inbox.append(item);}status.textContent="Inbox decrypted on this device.";}));
  status.textContent=selectedAlias?"Private keys and message text stay on this device.":"Select a Full Directory recipient to send. You can refresh your inbox.";
  container.append(status,refresh,inbox,form);
}
