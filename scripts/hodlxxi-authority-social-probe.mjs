#!/usr/bin/env node
import { parseAuthorityProbeArgs } from "../src/dev/hodlxxi-authority-live-probe.mjs";
import { formatSocialAuthorityFailure, formatSocialAuthorityResult, runSocialAuthorityComposition } from "../src/dev/hodlxxi-authority-live-composition.mjs";
import { pathToFileURL } from "node:url";

export async function runSocialAuthorityCli(argv, { compose = runSocialAuthorityComposition, stdout = console.log, stderr = console.error } = {}) {
  try {
    const options = parseAuthorityProbeArgs(argv);
    const result = formatSocialAuthorityResult(await compose(options));
    stdout(result.output);
    return result.exitCode;
  } catch (error) {
    const result = formatSocialAuthorityFailure(error);
    stderr(result.output);
    return result.exitCode;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await runSocialAuthorityCli(process.argv.slice(2));
