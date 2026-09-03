# Full Network Member Cards V1.25

V1.25 turns the already-live privacy-safe Full Directory result into an ordinary
authenticated Full Network product surface.

## Authority and data source

The browser does not discover or infer members. The only participant records
rendered by this surface are viewer-private aliases accepted from the existing
same-origin `/auth/full-directory` response.

Full authority remains external to Social. Social does not create, upgrade,
downgrade, infer or persist Full membership.

## Product behavior

For an accepted current Full viewer, each accepted directory alias is rendered
as a Full Network member card with:

- a presentation-only avatar derived from the alias;
- the label `Full Network member`;
- `Current Full`;
- a shortened viewer-private identifier;
- an explanation that the identifier is presentation-only.

The full alias may remain in the DOM only as the same already-authorized
viewer-private presentation value. No participant identity key is introduced.

The surface also displays the count of other aliases already returned to the
viewer by the accepted directory response.

## Privacy boundary

V1.25 adds no participant public key, raw subject, covenant key, address,
transaction, UTXO, descriptor, XPUB, X25519 key, Nostr key, email, phone,
sponsor graph, profile name, presence or payment information.

It adds no browser persistence: no localStorage, sessionStorage or IndexedDB.

It adds no messaging, calls, protected-content transport, encryption,
recipient resolution, membership mutation, UBID write or external relay
publication.

Private human labels such as `sister`, `brother` or `grandson` are deliberately
out of scope for V1.25 because their persistence and privacy boundary require a
separate reviewed design.
