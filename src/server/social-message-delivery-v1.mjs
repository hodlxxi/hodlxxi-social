// Explicit normal-startup composition: strict device verification then UBID's
// atomic authorization, followed by a durable ciphertext-only mailbox write.
import {sign} from "node:crypto";
import {readEnrollmentRuntimeManifest} from "./social-enrollment-v2-runtime.mjs";
import {createSessionServiceIntegration} from "./social-mobile-runtime-v1.mjs";
import {createUbidMessageDeliveryClient} from "./ubid-message-delivery-v1.mjs";
import {createCiphertextMailboxV1} from "./message-ciphertext-mailbox-v1.mjs";
import {parseDeviceProofV1} from "./messaging-device-proof-profile-v1.mjs";
import {parseCanonicalMessageEnvelopeWireV1, digestCanonicalMessageEnvelopeV1} from "./message-envelope-v128f1.mjs";
import {createMessagingDeviceVerificationStatementSignerV1, produceMessagingDeviceVerificationStatementV1,
  VERIFICATION_STATEMENT_PURPOSE} from "./messaging-device-verification-statement-v1.mjs";
import {canonical, exact} from "../../web/social-mobile-protocol-v1.mjs";

const fail=()=>{throw new Error("message delivery unavailable");};
export function createMessageDeliveryTransportV1({client,signer,directory,socialOrigin,issuerOrigin,clientId,servicePrincipal}) {
  const identity = input => {
    if(!/^[0-9a-f]{64}$/.test(input.issuanceId??"") || !/^[0-9a-f]{64}$/.test(input.expectedSubject??"")) fail();
    return input.issuanceId;
  };
  const inspect = async (input) => {
    const proof=parseDeviceProofV1(input.deviceProofWire);
    const stored=await client.invoke("inspect",{issuanceId:identity(input),challengeId:proof.challengeId},input.viewerAccessToken);
    const context=JSON.parse(stored.contextWire);
    if(context.subject!==input.expectedSubject || context.audience!==socialOrigin) fail();
    return stored;
  };
  const authorize = async (input,bodyWire,recipientAlias=null) => {
    const stored=await inspect(input);
    const inputWire=canonical({context:stored.contextWire,challenge:stored.challengeWire,
      proof:input.deviceProofWire,approvalEvent:null,actualRequest:stored.requestWire,
      routingRequest:stored.routingWire,schema:"hodlxxi.social_device_verification_input.v1",version:1});
    const now=Date.now(), expires=JSON.parse(stored.challengeWire).expiresAt;
    const statement=await produceMessagingDeviceVerificationStatementV1({contextWire:stored.contextWire,inputWire,signer,now,
      statementLifetimeMs:Math.min(10000,expires-now),expectedAudience:issuerOrigin+"/internal/v1/social/device-admission/consume",
      expectedClientId:clientId,expectedIssuer:socialOrigin,expectedPurpose:VERIFICATION_STATEMENT_PURPOSE,
      expectedServicePrincipal:servicePrincipal},{verificationStatementsEnabled:true});
    return client.invoke("consume",{issuanceId:identity(input),proofWire:input.deviceProofWire,
      statement,bodyWire,recipientAlias},input.viewerAccessToken);
  };
  const mailbox=createCiphertextMailboxV1({directory,
    authorizeSubmission:input=>authorize(input,input.envelopeWire,input.recipientAlias),
    authorizeInbox:input=>authorize(input,input.requestWire)});
  return Object.freeze({...mailbox,
    async currentDeviceForViewer(input) {
      return client.invoke("self",{issuanceId:identity(input)},input.viewerAccessToken);
    },
    async resolveRecipientForViewer(input) {
      return client.invoke("package",{issuanceId:identity(input),recipientAlias:input.recipientAlias},input.viewerAccessToken);
    },
    async challengeForViewer(input) {
      const operation=input.operation;
      let routingWire=null;
      if(operation==="ciphertext-submit") {
        const envelope=parseCanonicalMessageEnvelopeWireV1(input.bodyWire);
        routingWire=canonical({schema:"hodlxxi.social_messaging_recipient_routing_request.v1",version:1,
          messageId:envelope.messageId,envelopeDigest:digestCanonicalMessageEnvelopeV1(envelope),
          recipientPackageSnapshotId:envelope.recipientPackageSnapshotId,recipientDeviceHandles:envelope.recipientDeviceHandles});
      } else if(operation!=="recipient-self-read") fail();
      const result=await client.invoke("challenge",{issuanceId:identity(input),operation,bodyWire:input.bodyWire,routingWire,
        recipientAlias:input.recipientAlias??null},input.viewerAccessToken);
      const context=JSON.parse(result.contextWire);
      if(context.subject!==input.expectedSubject || context.audience!==socialOrigin) fail();
      return {challengeWire:result.challengeWire,publicKey:context.ed25519PublicKey};
    }
  });
}

export async function createMessageDeliveryRuntimeV1(path,config) {
  if(path===undefined) return undefined;
  const m=await readEnrollmentRuntimeManifest(path);
  exact(m,["schema","enabled","issuerOrigin","socialOrigin","socketPath","backendId","clientId","servicePrincipal",
    "clientSigningKeyId","clientSigningKeyPath","statementSigningKeyId","statementSigningKeyPath","mailboxDirectory","timeoutMs"]);
  if(m.schema!=="hodlxxi.social.message_delivery.runtime.v1" || m.enabled!==true || m.issuerOrigin!==config.authorityOrigin ||
      m.socialOrigin!==config.publicOrigin || m.clientId!==config.clientId || config.mobile.enabled!==true) fail();
  const integration={enabled:true,issuerOrigin:m.issuerOrigin,socketPath:m.socketPath,clientId:m.backendId,
    clientSigningKeyId:m.clientSigningKeyId,signingKeyPath:m.clientSigningKeyPath,timeoutMs:m.timeoutMs};
  const client=await createSessionServiceIntegration(integration,{clientFactory:createUbidMessageDeliveryClient});
  const key=await createSessionServiceIntegration({...integration,clientSigningKeyId:m.statementSigningKeyId,
    signingKeyPath:m.statementSigningKeyPath},{clientFactory:value=>value.signingKey});
  const signer=createMessagingDeviceVerificationStatementSignerV1({algorithm:"RS256",audience:m.issuerOrigin+"/internal/v1/social/device-admission/consume",
    clientId:m.clientId,issuer:m.socialOrigin,kid:m.statementSigningKeyId,purpose:VERIFICATION_STATEMENT_PURPOSE,
    servicePrincipal:m.servicePrincipal,signExact:bytes=>sign("RSA-SHA256",bytes,key)});
  return createMessageDeliveryTransportV1({client,signer,directory:m.mailboxDirectory,socialOrigin:m.socialOrigin,
    issuerOrigin:m.issuerOrigin,clientId:m.clientId,servicePrincipal:m.servicePrincipal});
}
