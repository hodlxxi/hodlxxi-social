#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { formatProbeFailure, formatProbeResult, parseProbeArgs, runProbe } from "../src/dev/nostr-relay-probe.mjs";

export async function main({ argv = process.argv.slice(2), stdout = process.stdout, stderr = process.stderr } = {}) {
  let json = argv.includes("--json");
  try {
    const options = parseProbeArgs(argv);
    json = options.json;
    const result = await runProbe(options);
    stdout.write(`${formatProbeResult(result, { json })}\n`);
    return 0;
  } catch (error) {
    const failure = formatProbeFailure(error, { json });
    stderr.write(`${failure.output}\n`);
    return failure.exitCode;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main();
