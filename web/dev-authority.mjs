import { AuthorityProbeError, parseAuthorityProbeArgs } from "../src/dev/hodlxxi-authority-live-probe.mjs";
import { formatSocialAuthorityResult, runSocialAuthorityComposition } from "../src/dev/hodlxxi-authority-live-composition.mjs";

const DIAGNOSTICS = new Set(["argument", "denied", "unavailable", "malformed", "invalid"]);
const NONE = "None";
const SUPPRESSED = "Suppressed";

const fixedDiagnostic = (error) => error instanceof AuthorityProbeError && DIAGNOSTICS.has(error.diagnostic)
  ? error.diagnostic
  : "malformed";

const safeEvidence = (value) => /operator/i.test(value) ? SUPPRESSED : value;

export function bindDevAuthorityPage(document, {
  compose = runSocialAuthorityComposition,
  format = formatSocialAuthorityResult,
  parse = parseAuthorityProbeArgs
} = {}) {
  const form = document.querySelector("#dev-authority-form");
  const originInput = document.querySelector("#authority-origin");
  const subjectInput = document.querySelector("#authority-subject");
  const timeoutInput = document.querySelector("#authority-timeout");
  const button = form.querySelector('button[type="submit"]');
  const fields = {
    subject: document.querySelector("#authority-selected-subject"),
    authorityClass: document.querySelector("#authority-class"),
    validity: document.querySelector("#authority-validity"),
    diagnostic: document.querySelector("#authority-diagnostic"),
    evidence: document.querySelector("#authority-evidence"),
    observedAt: document.querySelector("#authority-observed-at")
  };
  let active = false;

  const failClosed = (diagnostic) => {
    fields.authorityClass.textContent = "Limited";
    fields.validity.textContent = "Fail-closed";
    fields.diagnostic.textContent = diagnostic;
    fields.evidence.textContent = NONE;
    fields.observedAt.textContent = NONE;
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (active) return;

    let options;
    try {
      options = parse([
        "--origin", originInput.value,
        "--subject", subjectInput.value,
        "--timeout-ms", timeoutInput.value
      ]);
    } catch (error) {
      fields.subject.textContent = NONE;
      failClosed(fixedDiagnostic(error));
      return;
    }

    active = true;
    button.disabled = true;
    fields.subject.textContent = options.subject;
    fields.authorityClass.textContent = "Limited";
    fields.validity.textContent = "Loading";
    fields.diagnostic.textContent = "loading";
    fields.evidence.textContent = NONE;
    fields.observedAt.textContent = NONE;
    try {
      const result = await compose(options);
      format(result);
      fields.authorityClass.textContent = result.assertedIdentityClass === "full" ? "Full" : "Limited";
      fields.validity.textContent = "Valid external assertion";
      fields.diagnostic.textContent = "asserted";
      fields.evidence.textContent = safeEvidence(result.evidenceSource);
      fields.observedAt.textContent = result.observedAt ?? NONE;
    } catch (error) {
      failClosed(fixedDiagnostic(error));
    } finally {
      active = false;
      button.disabled = false;
    }
  });

  return Object.freeze({ form });
}

if (typeof document !== "undefined") bindDevAuthorityPage(document);
