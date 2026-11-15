/**
 * Durable ciphertext-only mailbox storage.
 *
 * Only trusted server composition may inject authorizeSubmission/authorizeInbox.
 * Those callbacks MUST check fresh Current Full, exact authenticated device
 * ownership and recipient-capability/package binding in UBID. There is no
 * bypass or default authorizer. This module stores NO plaintext or keys.
 */
import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, readdir, unlink } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { parseDeviceProofV1 } from "./messaging-device-proof-profile-v1.mjs";
import {
  parseCanonicalMessageEnvelopeWireV1
} from "./message-envelope-v128f1.mjs";

const HANDLE = /^d_[A-Za-z0-9_-]{22}$/;
const SUBJECT = /^[0-9a-f]{64}$/;
const CAPABILITY = /^rc_[A-Za-z0-9_-]{43}$/;
const SNAPSHOT = /^sha256:[0-9a-f]{64}$/;
const FILE_NAME = /^[0-9]{4}\.msg$/;
const MAX_RECORD_BYTES = 36_000;
const MAX_RECORDS = 2048;
const MAX_INBOX_PAGE = 25;
const error = () => new Error("ciphertext message transport unavailable");
const deny = () => { throw error(); };

const validContext = (value) =>
  value && typeof value === "object" && !Array.isArray(value) &&
  typeof value.viewerAccessToken === "string" &&
  value.viewerAccessToken.length > 0 &&
  value.viewerAccessToken.length <= 8192 &&
  !/[\u0000-\u0020\u007f]/.test(value.viewerAccessToken) &&
  typeof value.expectedSubject === "string" &&
  SUBJECT.test(value.expectedSubject);

const privateRoot = async (directory) => {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || (info.mode & 0o077) !== 0 ||
      (typeof process.getuid === "function" && info.uid !== process.getuid())) deny();
};

const slotName = (slot) => String(slot).padStart(4, "0") + ".msg";
const recordNames = async (directory, maximum) => {
  const names = (await readdir(directory)).filter((name) => name.endsWith(".msg"));
  if (names.some((name) => !FILE_NAME.test(name) || Number(name.slice(0, 4)) >= maximum)) deny();
  return names;
};

const readRecord = async (filename) => {
  let handle;
  try {
    handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    // Installation briefly retains the private, fully written temporary link.
    if (!stat.isFile() || stat.nlink < 1 || stat.nlink > 2 ||
        (typeof process.getuid === "function" && stat.uid !== process.getuid()) ||
        (stat.mode & 0o077) !== 0 ||
        stat.size < 1 || stat.size > MAX_RECORD_BYTES) deny();
    const value = JSON.parse(await handle.readFile("utf8"));
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        Object.keys(value).sort().join(",") !== "envelopeWire,receivedAt" ||
        !Number.isSafeInteger(value.receivedAt) || value.receivedAt < 0 ||
        typeof value.envelopeWire !== "string") deny();
    const envelope = parseCanonicalMessageEnvelopeWireV1(value.envelopeWire);
    return {receivedAt: value.receivedAt, envelopeWire: value.envelopeWire, envelope};
  } catch { deny(); }
  finally { await handle?.close(); }
};

const writeExclusive = async (directory, filename, data) => {
  const temp = directory + "/.tmp-" + randomBytes(16).toString("hex");
  let handle;
  try {
    handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(data, { encoding: "utf8" });
    await handle.sync();
    await handle.close();
    handle = undefined;
    // Hard-link installation is atomic, NO replacement on a collision.
    try { await link(temp, filename); }
    catch (caught) {
      if (caught?.code !== "EEXIST") throw caught;
      return false;
    }
    const folder = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await folder.sync(); } finally { await folder.close(); }
    return true;
  } finally {
    await handle?.close();
    await unlink(temp).catch(() => {});
  }
};

export function createCiphertextMailboxV1({
  directory, authorizeSubmission, authorizeInbox, now = Date.now,
  maximumRecords = MAX_RECORDS
} = {}) {
  if (typeof directory !== "string" || directory.length < 2 ||
      directory.length > 2048 || !isAbsolute(directory) ||
      directory === "/" || directory.includes("\0") ||
      typeof authorizeSubmission !== "function" ||
      typeof authorizeInbox !== "function" ||
      typeof now !== "function" ||
      !Number.isInteger(maximumRecords) || maximumRecords < 1 || maximumRecords > MAX_RECORDS ||
      !constants.O_NOFOLLOW || !constants.O_DIRECTORY) deny();

  const submitForViewer = async (input) => {
    try {
      if (!validContext(input) ||
          typeof input.recipientCapability !== "string" ||
          !CAPABILITY.test(input.recipientCapability)) deny();
      const envelope = parseCanonicalMessageEnvelopeWireV1(input.envelopeWire);
      parseDeviceProofV1(input.deviceProofWire);
      const authorized = await authorizeSubmission({
        viewerAccessToken: input.viewerAccessToken,
        expectedSubject: input.expectedSubject,
        recipientCapability: input.recipientCapability,
        envelope,
        deviceProofWire: input.deviceProofWire,
        envelopeWire: input.envelopeWire
      });
      if (authorized?.allowed !== true ||
          authorized.recipientPackageSnapshotId !== envelope.recipientPackageSnapshotId ||
          !SNAPSHOT.test(authorized.recipientPackageSnapshotId) ||
          !Array.isArray(authorized.recipientDeviceHandles) ||
          authorized.recipientDeviceHandles.length !== envelope.recipientDeviceHandles.length ||
          authorized.recipientDeviceHandles.some((h, i) =>
            !HANDLE.test(h) || h !== envelope.recipientDeviceHandles[i]) ||
          !HANDLE.test(authorized.senderDeviceHandle)) deny();
      await privateRoot(directory);
      const receivedAt = now();
      if (!Number.isSafeInteger(receivedAt) || receivedAt < 0) deny();
      const data = JSON.stringify({receivedAt, envelopeWire: input.envelopeWire});
      if (Buffer.byteLength(data, "utf8") > MAX_RECORD_BYTES) deny();
      // The lowest free fixed slot is a cross-process compare-and-install.
      // Slots are never removed/reused. Every loser rescans before retrying,
      // so exact retries converge and concurrent senders cannot exceed quota.
      for (let attempt = 0; attempt <= maximumRecords; attempt += 1) {
        const names = await recordNames(directory, maximumRecords);
        for (const name of names) {
          const old = await readRecord(directory + "/" + name);
          if (old.envelope.messageId === envelope.messageId) {
            if (old.envelopeWire !== input.envelopeWire) deny();
            return {state: "accepted", messageId: envelope.messageId};
          }
        }
        const used = new Set(names);
        let slot = 0;
        while (slot < maximumRecords && used.has(slotName(slot))) slot += 1;
        if (slot === maximumRecords) deny();
        if (await writeExclusive(directory, directory + "/" + slotName(slot), data)) {
          return {state: "accepted", messageId: envelope.messageId};
        }
      }
      deny();
    } catch { deny(); }
  };

  const listForViewer = async (input) => {
    try {
      if (!validContext(input) ||
          typeof input.deviceHandle !== "string" ||
          !HANDLE.test(input.deviceHandle)) deny();
      parseDeviceProofV1(input.deviceProofWire);
      const requestWire = JSON.stringify({deviceHandle: input.deviceHandle,
        schema: "hodlxxi.social_messaging_recipient_self_request.v1", version: 1});
      if (input.requestWire !== requestWire) deny();
      const authorized = await authorizeInbox({
        viewerAccessToken: input.viewerAccessToken,
        expectedSubject: input.expectedSubject,
        deviceHandle: input.deviceHandle,
        deviceProofWire: input.deviceProofWire,
        requestWire
      });
      if (authorized?.allowed !== true ||
          authorized.deviceHandle !== input.deviceHandle) deny();
      await privateRoot(directory);
      const filenames = await recordNames(directory, maximumRecords);
      const found = [];
      const seen = new Set();
      for (const name of filenames) {
        const record = await readRecord(directory + "/" + name);
        if (seen.has(record.envelope.messageId)) deny();
        seen.add(record.envelope.messageId);
        if (record.envelope.recipientDeviceHandles.includes(input.deviceHandle)) found.push(record);
      }
      found.sort((a, b) =>
        b.receivedAt - a.receivedAt ||
        a.envelope.messageId.localeCompare(b.envelope.messageId));
      return {state: "available",
        messages: found.slice(0, MAX_INBOX_PAGE).map((r) => r.envelopeWire)};
    } catch { deny(); }
  };
  return Object.freeze({submitForViewer, listForViewer});
}
