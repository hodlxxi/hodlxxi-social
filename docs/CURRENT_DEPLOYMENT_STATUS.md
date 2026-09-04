# Current Deployment Status

Observed production snapshot: 2026-09-04.

This document records a dated operational observation. It is not an authority
source, feature flag, deployment mechanism, or substitute for a fresh
production check.

## Source checkout

At observation time:

- GitHub `main` was
  `a512bab86d3244441fe76ea76a7761d78757c3c5`;
- `/srv/hodlxxi-social` was at the same commit;
- the production checkout was on `main`;
- the production checkout was clean;
- current source therefore included Social through V1.28B.

## Running process versus filesystem

The running `hodlxxi-social.service` process had started while the production
checkout was at:

`937df07d047a2e3ccec45ca17702ef0bbdf207fb`

That revision is the V1.27 opaque-recipient-capability merge.

The production checkout was later fast-forwarded to V1.28B without another
Social service restart.

The V1.28B secure-messaging JavaScript and CSS assets were independently
observed returning HTTP 200 from the live Social origin.

Filesystem revision, statically served browser assets, feature configuration,
and code already loaded into a long-running Node process are therefore separate
deployment facts.

## Observed private feature configuration

The non-secret production configuration reported:

- `SOCIAL_FULL_DIRECTORY_ENABLED=true`;
- `SOCIAL_RECIPIENT_CAPABILITY_ENABLED=true`.

Observed public/fail-closed checks:

- Social health: HTTP 200;
- anonymous Social session read: HTTP 200;
- anonymous Full Directory read: HTTP 401;
- anonymous recipient-capability POST with correct Social Origin: HTTP 401;
- public UBID internal service-token route: HTTP 404;
- public UBID internal Full-directory route: HTTP 404.

The recipient-capability HTTP 401 proves that the route is present and refuses
an unauthenticated caller. It does not prove a successful authenticated
positive issuance path.

## V1.28B messaging state

V1.28B is an authenticated messaging UX shell, not live direct messaging.

It does not currently provide:

- messaging-device key registration;
- recipient crypto-package resolution;
- browser encryption or decryption;
- ciphertext submission;
- message persistence;
- conversation delivery;
- live internal messaging transport.

## Full Directory privacy boundary

The ordinary browser Full Directory remains viewer-private and alias-only.

UBID/CRT remains the canonical source for current Full entitlement. Social does
not grant Full.

A viewer-private alias is not:

- canonical participant identity;
- a Nostr key;
- a Bitcoin key;
- an XPUB or payment address;
- friendship;
- sponsorship;
- covenant relation;
- an encryption key.

## Private labels

V1.26 private labels are browser-device-local presentation state bound to the
authenticated viewer subject and viewer-private alias.

They are not returned by UBID and are not Social or UBID identity or authority.

## Runtime and socket hardening debt

The observed production Node runtime was:

`v18.19.1`

Repository CI currently uses Node 20. A production Node upgrade is a separate
reviewed operations task.

The observed Full Directory private socket state was:

- parent directory: mode `0750`, owner `root`, group `hodlxxi-social`;
- socket: mode `0666`, owner `root`, group `root`.

The restrictive parent directory prevents ordinary world traversal, but the
socket mode itself is broader than a least-privilege final state. Any socket
permission change must be handled as a separate production hardening operation
after verifying nginx worker/group compatibility.

## Separate unmerged V1.28C work

A separate worktree and remote branch were observed for:

`feat/social-v1-28c-device-encryption-key-v1`

with commit:

`b34afa10c20c7db406fd075582a3fef043b323ba`

That branch is not part of current `main` and is not production state. It must
be reviewed independently before reuse, modification, merge, or deployment.
