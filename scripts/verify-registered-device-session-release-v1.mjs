// Disposable paired integration-test bridge. Never installed as a runtime route.
import { createPrivateKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { produceRegisteredDeviceSessionStatementV1 } from "../src/server/registered-device-session-statement-v1.mjs";
try {
  const { request, serviceSigningKeyPem, kid } = JSON.parse(readFileSync(0, "utf8"));
  process.stdout.write(produceRegisteredDeviceSessionStatementV1(request, { kid, privateKey:createPrivateKey(serviceSigningKeyPem) }));
} catch { process.stderr.write("registered device proof denied\n"); process.exitCode = 1; }
