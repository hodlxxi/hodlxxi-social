# Private Local Labels V1.26

V1.26 introduces viewer-private human labels for Full Network cards.

A private label is not participant identity, not a public profile name, not
Canon authority, and not a Full-membership input.

The binding is:

`authenticated viewer subject + viewer-private Full Directory alias -> local label`

Examples include `Brother`, `Grandson`, `Ivan`, or another label meaningful
only to the viewer.

## Privacy boundary

The Full Directory response remains alias-only and unchanged.

Labels:

- are not returned by UBID;
- are not sent to UBID;
- are not added to the Social Full Directory API;
- are not participant public keys;
- are not Nostr profile fields;
- do not affect Limited or Full;
- do not affect sponsorship, covenant state, Checking, payments, or trust.

The browser presentation accepts labels only for aliases already present in
the current accepted viewer-private Full Directory snapshot.

## Persistence boundary

The separate `private-label-store.mjs` module is the sole browser persistence
boundary.

Device-local persistence is intentionally separate from this presentation
layer and is connected only after its storage contract and renderer contract
both pass independently.

A device-local label is not encrypted against compromise of the same browser
profile or execution of hostile JavaScript in the Social origin. V1.26 does
not claim otherwise.

## Active browser behavior

The authenticated Full Network now connects the presentation layer to the
device-local private-label store.

For an accepted current Full viewer:

1. only aliases present in the current accepted Full Directory may be labeled;
2. `Save` writes the label under the current authenticated viewer subject;
3. saving a blank label removes that alias label;
4. the operation performs no Social, UBID, Nostr, Bitcoin, or other network
   request;
5. logout does not delete device-local labels;
6. a later authenticated session for the same viewer on the same browser
   profile can read the label again;
7. another authenticated viewer subject cannot read that label through the
   store binding.

The label remains presentation-only. It never changes the opaque alias,
participant authority, Full status, covenant state, public profile, signer,
payment state, or graph visibility.

Device-local persistence is deliberately not described as encrypted storage.
Someone with access to the same browser profile, or hostile JavaScript running
with the Social origin's authority, may be able to read these labels.
