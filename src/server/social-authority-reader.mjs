import { AccessStatus } from "../domain.mjs";
import {
  formatSocialAuthorityResult,
  runSocialAuthorityComposition
} from "../dev/hodlxxi-authority-live-composition.mjs";

const SUBJECT = /^[0-9a-f]{64}$/;

const failClosed = (subject) =>
  Object.freeze({
    subject,
    status: AccessStatus.LIMITED,
    valid: false
  });

export function createSocialAuthorityReader(
  config,
  dependencies = Object.freeze({})
) {
  if (
    !config ||
    typeof config !== "object" ||
    typeof config.authorityOrigin !== "string" ||
    !Number.isSafeInteger(config.outboundTimeoutMs) ||
    config.outboundTimeoutMs < 250 ||
    config.outboundTimeoutMs > 30000
  ) {
    throw new TypeError("invalid Social authority reader configuration");
  }

  return async function readSocialAuthority(subject) {
    if (typeof subject !== "string" || !SUBJECT.test(subject)) {
      throw new TypeError("canonical authenticated subject required");
    }

    try {
      const projection = await runSocialAuthorityComposition(
        {
          origin: config.authorityOrigin,
          subject,
          timeoutMs: config.outboundTimeoutMs
        },
        dependencies
      );

      // Reuse the already-audited exact projection validator.
      formatSocialAuthorityResult(projection);

      if (
        projection.subject !== subject ||
        projection.valid !== true ||
        ![
          AccessStatus.LIMITED,
          AccessStatus.FULL
        ].includes(projection.assertedIdentityClass)
      ) {
        return failClosed(subject);
      }

      return Object.freeze({
        subject,
        status: projection.assertedIdentityClass,
        valid: true
      });
    } catch {
      return failClosed(subject);
    }
  };
}
