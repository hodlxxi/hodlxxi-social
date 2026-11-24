// Disposable paired test bridge. The only private key here is a synthetic
// server statement key; the participant's Ed25519 proof is already signed.
import {createPrivateKey,sign} from "node:crypto";
import {readFileSync} from "node:fs";
import {canonical,exact} from "../web/social-mobile-protocol-v1.mjs";
import {createMessagingDeviceVerificationStatementSignerV1,produceMessagingDeviceVerificationStatementV1,
  VERIFICATION_STATEMENT_PURPOSE} from "../src/server/messaging-device-verification-statement-v1.mjs";
try {
  const wire=readFileSync(0,"utf8");if(wire.length>65536) throw Error();
  const value=exact(JSON.parse(wire),["serviceSigningKeyPem","kid","issuerOrigin","socialOrigin","clientId",
    "servicePrincipal","stored","proofWire","now"]);
  const key=createPrivateKey(value.serviceSigningKeyPem);
  const signer=createMessagingDeviceVerificationStatementSignerV1({algorithm:"RS256",
    audience:value.issuerOrigin+"/internal/v1/social/device-admission/consume",issuer:value.socialOrigin,
    clientId:value.clientId,servicePrincipal:value.servicePrincipal,kid:value.kid,purpose:VERIFICATION_STATEMENT_PURPOSE,
    signExact:bytes=>sign("RSA-SHA256",bytes,key)});
  const stored=value.stored;
  const inputWire=canonical({context:stored.contextWire,challenge:stored.challengeWire,proof:value.proofWire,
    approvalEvent:null,actualRequest:stored.requestWire,routingRequest:stored.routingWire,
    schema:"hodlxxi.social_device_verification_input.v1",version:1});
  process.stdout.write(await produceMessagingDeviceVerificationStatementV1({contextWire:stored.contextWire,inputWire,
    signer,now:value.now,statementLifetimeMs:10000,expectedAudience:signer.audience,expectedClientId:value.clientId,
    expectedIssuer:value.socialOrigin,expectedPurpose:VERIFICATION_STATEMENT_PURPOSE,
    expectedServicePrincipal:value.servicePrincipal},{verificationStatementsEnabled:true}));
} catch {process.stderr.write("registered message proof denied\n");process.exitCode=1;}
