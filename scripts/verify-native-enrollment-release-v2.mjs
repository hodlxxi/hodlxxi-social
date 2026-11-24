// Isolated release harness: public enrollment proofs plus a test service signer
// arrive on stdin. Never accept or export participant private keys here.
import {createPrivateKey,sign} from "node:crypto";
import {readFileSync} from "node:fs";
import {createMessagingDevicePreacceptedEnrollmentVerificationStatementSignerV2 as signer,
  produceMessagingDevicePreacceptedEnrollmentVerificationStatementV2 as produce}
  from "../src/server/messaging-device-preaccepted-verification-statement-v2.mjs";
try {
  const source=readFileSync(0,"utf8"); if(source.length>65536) throw new Error();
  const input=JSON.parse(source), key=createPrivateKey(input.serviceSigningKeyPem);
  const signing=signer({...input.signer,signExact:bytes=>sign("RSA-SHA256",bytes,key)},
    {freshnessProfile:input.freshnessProfile});
  const result=await produce({...input.request,signer:signing},
    {preacceptedEnrollmentVerificationStatementsV2Enabled:true});
  process.stdout.write(result);
} catch { process.stderr.write("isolated enrollment crypto verification failed\n"); process.exitCode=1; }
