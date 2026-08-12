#!/usr/bin/env node
import { formatAuthorityFailure, formatAuthorityResult, parseAuthorityProbeArgs, runAuthorityProbe } from "../src/dev/hodlxxi-authority-live-probe.mjs";

try {
  const result = formatAuthorityResult(await runAuthorityProbe(parseAuthorityProbeArgs(process.argv.slice(2))));
  console.log(result.output);
  process.exitCode = result.exitCode;
} catch (error) {
  const result = formatAuthorityFailure(error);
  console.error(result.output);
  process.exitCode = result.exitCode;
}
