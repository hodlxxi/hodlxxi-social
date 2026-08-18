#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  buildSocialProductionReadiness
} from "../src/server/social-production-readiness.mjs";

export async function runProductionReadiness({
  env = process.env,
  cwd = process.cwd(),
  accessImpl,
  stdout = console.log,
  stderr = console.error
} = {}) {
  try {
    const report = await buildSocialProductionReadiness(
      env,
      {
        cwd,
        ...(accessImpl ? { accessImpl } : {})
      }
    );

    stdout(JSON.stringify(report));
    return 0;
  } catch {
    stderr("production readiness failed");
    return 2;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  runProductionReadiness().then((code) => {
    process.exitCode = code;
  });
}
