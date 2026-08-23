import test from "node:test";
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";

import {
  computeNostrEventId,
  verifyBip340Signature,
  verifyNostrEvent
} from "../web/nostr-event-verifier.mjs";

const verificationOptions = Object.freeze({ cryptoImpl: webcrypto });

const vectors = [
  ["F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "00".repeat(32), "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", true],
  ["DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", true],
  ["DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7", true],
  ["25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", "FF".repeat(32), "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3", true],
  ["D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703", "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", true],
  ["EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false],
  ["DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", false],
  ["DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", false],
  ["DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", false],
  ["DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", false],
  ["DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", false],
  ["DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false],
  ["DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false],
  ["DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", false],
  ["FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false],
  ["778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "", "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63", true],
  ["778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "11", "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF", true],
  ["778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0102030405060708090A0B0C0D0E0F1011", "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5", true],
  ["778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "99".repeat(100), "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367", true]
];

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
};
const mod = (value, modulus = P) => (value % modulus + modulus) % modulus;
const pow = (base, exponent, modulus = P) => {
  let result = 1n, factor = mod(base, modulus), power = exponent;
  while (power > 0n) {
    if (power & 1n) result = mod(result * factor, modulus);
    factor = mod(factor * factor, modulus);
    power >>= 1n;
  }
  return result;
};
const add = (left, right) => {
  if (!left) return right;
  if (!right) return left;
  if (left.x === right.x && left.y !== right.y) return null;
  const slope = left.x === right.x
    ? mod(3n * left.x * left.x * pow(2n * left.y, P - 2n))
    : mod((right.y - left.y) * pow(right.x - left.x, P - 2n));
  const x = mod(slope * slope - left.x - right.x);
  return { x, y: mod(slope * (left.x - x) - left.y) };
};
const multiply = (scalar, point = G) => {
  let result = null, addend = point, value = scalar;
  while (value > 0n) {
    if (value & 1n) result = add(result, addend);
    addend = add(addend, addend);
    value >>= 1n;
  }
  return result;
};
const toBytes = (value, size = 32) => Buffer.from(value.toString(16).padStart(size * 2, "0"), "hex");
const taggedHash = (tag, ...parts) => {
  const tagHash = createHash("sha256").update(tag).digest();
  return createHash("sha256").update(tagHash).update(tagHash).update(Buffer.concat(parts)).digest();
};
const signForTest = (message) => {
  const secret = 3n;
  const publicPoint = multiply(secret);
  const privateScalar = publicPoint.y & 1n ? N - secret : secret;
  const auxHash = taggedHash("BIP0340/aux", Buffer.alloc(32));
  const masked = Buffer.from(toBytes(privateScalar).map((byte, index) => byte ^ auxHash[index]));
  const nonceHash = taggedHash("BIP0340/nonce", masked, toBytes(publicPoint.x), message);
  const nonceCandidate = BigInt(`0x${nonceHash.toString("hex")}`) % N;
  assert.notEqual(nonceCandidate, 0n);
  const noncePoint = multiply(nonceCandidate);
  const nonce = noncePoint.y & 1n ? N - nonceCandidate : nonceCandidate;
  const challenge = BigInt(`0x${taggedHash("BIP0340/challenge", toBytes(noncePoint.x), toBytes(publicPoint.x), message).toString("hex")}`) % N;
  return {
    publicKey: toBytes(publicPoint.x).toString("hex"),
    signature: Buffer.concat([toBytes(noncePoint.x), toBytes(mod(nonce + challenge * privateScalar, N))]).toString("hex")
  };
};

const unsignedEvent = () => ({
  id: "0".repeat(64),
  pubkey: "0".repeat(64),
  created_at: 1_707_409_439,
  kind: 1,
  tags: [["t", "hodlxxi"]],
  content: "A signed Social read fixture",
  sig: "0".repeat(128)
});

const signEventForTest = () => {
  const event = unsignedEvent();
  const publicKey = multiply(3n).x.toString(16).padStart(64, "0");
  event.pubkey = publicKey;
  event.id = createHash("sha256").update(JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ])).digest("hex");
  const signed = signForTest(Buffer.from(event.id, "hex"));
  assert.equal(signed.publicKey, publicKey);
  event.sig = signed.signature;
  return event;
};

test("BIP340 verification matches every official Bitcoin test vector", async () => {
  for (const [publicKey, message, signature, expected] of vectors) {
    assert.equal(
      await verifyBip340Signature(publicKey, message, signature, verificationOptions),
      expected
    );
  }
});

test("NIP-01 id computation and BIP340 verification bind the complete event", async () => {
  const event = signEventForTest();
  const expectedId = createHash("sha256").update(JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ])).digest("hex");

  assert.equal(await computeNostrEventId(event, verificationOptions), expectedId);
  const verified = await verifyNostrEvent(event, verificationOptions);
  assert.deepEqual(verified, event);
  assert.ok(Object.isFrozen(verified));
  assert.ok(Object.isFrozen(verified.tags));
  assert.ok(Object.isFrozen(verified.tags[0]));

  await assert.rejects(
    verifyNostrEvent({ ...event, content: "tampered" }, verificationOptions),
    /invalid Nostr event/
  );

  const replacedId = {
    ...event,
    content: "tampered"
  };
  replacedId.id = await computeNostrEventId(replacedId, verificationOptions);
  await assert.rejects(
    verifyNostrEvent(replacedId, verificationOptions),
    /invalid Nostr event/
  );
});

test("wire events reject extensions, uppercase encodings, accessors, sparse tags, and missing crypto", async () => {
  const event = signEventForTest();
  for (const candidate of [
    { ...event, id: event.id.toUpperCase() },
    { ...event, private_key: "secret" },
    { ...event, tags: [["t", , "bad"]] },
    { ...event, kind: 65_536 }
  ]) {
    await assert.rejects(
      verifyNostrEvent(candidate, verificationOptions),
      /invalid Nostr event/
    );
  }

  let getterCalls = 0;
  const accessor = { ...event };
  Object.defineProperty(accessor, "content", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return event.content;
    }
  });
  await assert.rejects(
    verifyNostrEvent(accessor, verificationOptions),
    /invalid Nostr event/
  );
  assert.equal(getterCalls, 0);

  await assert.rejects(
    verifyNostrEvent(event, { cryptoImpl: null }),
    /Nostr verification unavailable/
  );
});
