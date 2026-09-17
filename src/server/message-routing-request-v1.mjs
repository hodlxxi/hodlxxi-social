// Dormant projection into UBID's existing request contract. No authentication,
// transport, persistence, or delivery occurs here; no request is a routing grant.
import { Buffer } from "node:buffer";
import { isProxy } from "node:util/types";
import {
  digestCanonicalMessageEnvelopeV1,
  parseCanonicalMessageEnvelopeWireV1
} from "./message-envelope-v128f1.mjs";

export const MAX_MESSAGE_ROUTING_REQUEST_BYTES = 2048;

export function createMessageRoutingRequestV1(wire, options = {}) {
  try {
    if (options === null || typeof options !== "object" || isProxy(options)) throw new TypeError();
    const flag = Object.getOwnPropertyDescriptor(options, "enabled");
    if (!flag || !Object.hasOwn(flag, "value") || flag.value !== true) throw new TypeError();
    // Parse the original bounded wire, never a JSON-decoded browser object.
    const envelope = parseCanonicalMessageEnvelopeWireV1(wire);
    // UBID's existing handle contract also rejects nonzero base64 pad bits.
    for (const handle of envelope.recipientDeviceHandles) {
      if (Buffer.from(handle.slice(2), "base64url").toString("base64url") !== handle.slice(2)) {
        throw new TypeError();
      }
    }
    const request = JSON.stringify({
      envelopeDigest: digestCanonicalMessageEnvelopeV1(envelope),
      messageId: envelope.messageId,
      recipientDeviceHandles: envelope.recipientDeviceHandles,
      recipientPackageSnapshotId: envelope.recipientPackageSnapshotId,
      schema: "hodlxxi.social_messaging_recipient_routing_request.v1",
      version: 1
    });
    if (request.length > MAX_MESSAGE_ROUTING_REQUEST_BYTES) throw new TypeError();
    return request;
  } catch {
    throw new TypeError("message routing unavailable");
  }
}
