import { pathToFileURL } from "node:url";
import { runServer } from "./hodlxxi-social-server.mjs";
import { createNativeV2SessionStore } from "../src/server/social-native-session-v2.mjs";
import { enrollmentRuntimeFactory, readEnrollmentRuntimeManifest } from "../src/server/social-enrollment-v2-runtime.mjs";

export async function runEnrollmentServer({ env = process.env, stderr = console.error, ...dependencies } = {}) {
  try {
    const manifest = await readEnrollmentRuntimeManifest(env.SOCIAL_ENROLLMENT_V2_CONFIG_PATH);
    return await runServer({ ...dependencies, env, stderr, mobileRuntimeFactory: enrollmentRuntimeFactory(manifest),
      sessionStoreFactory: (options) => createNativeV2SessionStore({ ...options, now: Date.now }) });
  } catch { stderr("invalid native enrollment configuration"); return 2; }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runEnrollmentServer().then((code) => { process.exitCode = code; });
}
