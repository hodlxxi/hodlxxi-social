/**
 * Durable ciphertext-only mailbox storage.
 *
 * Only trusted server composition may inject authorizeSubmission/authorizeInbox.
 * Those callbacks MUST check fresh Current Full, exact authenticated device
 * ownership and recipient-capability/package binding in UBID. There is no
 * bypass or default authorizer. This module stores NO plaintext or keys.
 */
import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, readdir, unlink } from "node:fs/promises";
import { isAbsolute } from "node:path";
import {
  parseCanonicalMessageEnvelopeWireV1
} from "./message-envelope-v128f1.mjs";

const HANDLE = /^d_[A-Za-z0-9_-]{22}$/;
const SUBJECT = /^[0-9a-f]{64}$/;
const CAPABILITY = /^rc_[A-Za-z0-9_-]{43}$/;
const SNAPSHOT = /^sha256:[0-9a-f]{64}$/;
const FILE_NAME = /^[0-9a-f]{64}\.msg$/;
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

const messagePath = (directory, messageId) =>
  directory + "/" + createHash("sha256")
    .update("hodlxxi-social-ciphertext-mailbox-v1\0")
    .update(messageId, "ascii").digest("hex") + ".msg";

const readRecord = async (filename) => {
  let handle;
  try {
    handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 ||
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
  directory, authorizeSubmission, authorizeInbox, now = Date.now
} = {}) {
  if (typeof directory !== "string" || directory.length < 2 ||
      directory.length > 2048 || !isAbsolute(directory) ||
      directory === "/" || directory.includes("\0") ||
      typeof authorizeSubmission !== "function" ||
      typeof authorizeInbox !== "function" ||
      typeof now !== "function" ||
      !constants.O_NOFOLLOW || !constants.O_DIRECTORY) deny();

  const submitForViewer = async (input) => {
    try {
      if (!validContext(input) ||
          typeof input.recipientCapability !== "string" ||
          !CAPABILITY.test(input.recipientCapability)) deny();
      const envelope = parseCanonicalMessageEnvelopeWireV1(input.envelopeWire);
      const authorized = await authorizeSubmission({
        viewerAccessToken: input.viewerAccessToken,
        expectedSubject: input.expectedSubject,
        recipientCapability: input.recipientCapability,
        envelope
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
      const records = (await readdir(directory)).filter((name) => FILE_NAME.test(name));
      const filename = messagePath(directory, envelope.messageId);
      const existing = records.includes(filename.slice(directory.length + 1));
      if (existing) {
        const old = await readRecord(filename);
        if (old.envelopeWire !== input.envelopeWire) deny();
        return {state: "accepted", messageId: envelope.messageId};
      }
      if (records.length >= MAX_RECORDS) deny();
      const receivedAt = now();
      if (!Number.isSafeInteger(receivedAt) || receivedAt < 0) deny();
      const data = JSON.stringify({receivedAt, envelopeWire: input.envelopeWire});
      if (Buffer.byteLength(data, "utf8") > MAX_RECORD_BYTES) deny();
      if (!(await writeExclusive(directory, filename, data))) {
        const old = await readRecord(filename);
        if (old.envelopeWire !== input.envelopeWire) deny();
      }
      return {state: "accepted", messageId: envelope.messageId};
    } catch { deny(); }
  };

  const listForViewer = async (input) => {
    try {
      if (!validContext(input) ||
          typeof input.deviceHandle !== "string" ||
          !HANDLE.test(input.deviceHandle)) deny();
      const authorized = await authorizeInbox({
        viewerAccessToken: input.viewerAccessToken,
        expectedSubject: input.expectedSubject,
        deviceHandle: input.deviceHandle
      });
      if (authorized?.allowed !== true ||
          authorized.deviceHandle !== input.deviceHandle) deny();
      await privateRoot(directory);
      const filenames = (await readdir(directory)).filter((name) => FILE_NAME.test(name));
      if (filenames.length > MAX_RECORDS) deny();
      const found = [];
      for (const name of filenames) {
        const record = await readRecord(directory + "/" + name);
        if (messagePath(directory, record.envelope.messageId) !== directory + "/" + name) deny();
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
