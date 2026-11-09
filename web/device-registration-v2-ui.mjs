import { createEnrollmentBrowserApi, createDesktopEnrollmentController, createPhoneEnrollmentController }
  from "./social-enrollment-v2-browser.mjs";

const panel = document.querySelector("#panel"), status = document.querySelector("#status"), actions = document.querySelector("#actions");
const input = document.querySelector("#input"), locator = document.querySelector("#locator"), timer = document.querySelector("#timer");
let controller, deadline, busy = false, watching = false, nextPoll = 0, onFinished;
const message = (value) => { status.textContent = value; };
const execute = async (work) => {
    if (busy) return; busy = true;
    for (const b of document.querySelectorAll("button")) b.disabled = true;
    try { await work(); }
    catch { message("Unavailable. Keep this page and the pending key. Check status or retry the original operation. A lost signer response must not be signed again."); }
    finally { busy = false; for (const b of document.querySelectorAll("button")) b.disabled = false; }
};
const action = (label, work) => {
  const button = document.createElement("button"); button.type = "button"; button.textContent = label;
  button.addEventListener("click", () => execute(work)); actions.append(button);
};
document.querySelector("#desktop").addEventListener("click", async () => {
  try {
    const response = await fetch("/auth/session", { credentials: "same-origin", cache: "no-store", redirect: "error" });
    const session = await response.json(); if (!session.authenticated) throw new Error();
    controller = createDesktopEnrollmentController({ api: createEnrollmentBrowserApi(), subject: session.subject,
      resolveProvider: () => globalThis.nostr });
    document.querySelector("#roles").hidden = true; panel.hidden = false;
    document.querySelector("#input-label").textContent = "Comparison code shown on your phone";
    action("Create pairing", async () => { const p = await controller.create(); locator.textContent = p.qr; locator.hidden = false;
      deadline = Date.parse(p.offer.expiresAt); message("Share this locator privately with your phone. The approval timer has started."); });
    action("Inspect phone", async () => { const s = await controller.inspect(); message(s.comparisonCode
      ? "Check that the phone shows " + s.comparisonCode + ". Enter that code above before approval." : "Waiting for the phone proposal."); });
    action("Approve matching code", async () => { await controller.approve(input.value.trim()); message("Approved. Finish registration on the phone."); });
    action("Cancel pairing", async () => { await controller.cancel(); message("Pairing cancelled."); });
  } catch { message("Sign in to your Full account on this laptop first."); panel.hidden = false; }
});
document.querySelector("#phone").addEventListener("click", () => {
  controller = createPhoneEnrollmentController({ api: createEnrollmentBrowserApi() });
  document.querySelector("#roles").hidden = true; panel.hidden = false;
  document.querySelector("#input-label").textContent = "Pairing locator from your laptop";
  action("Use locator", async () => { const qr = input.value.trim(); const s = await controller.scan(qr); input.value = "";
    deadline = Date.parse(s.expiresAt); watching = true; nextPoll = 0;
    message("Compare this code with the laptop: " + s.comparisonCode + ". Registration finishes automatically after approval."); });
  action("Check approval", async () => { const s = await controller.status(); message(s.status === "approved"
    ? "Approved. You can finish registration." : "Pairing status: " + s.status); });
  const finished = (s) => { watching = false; message(s.registered ? "Device registration confirmed. Messaging is not ready yet." : "Registration is pending or its outcome is unknown. Keep this page and use Recover original result."); };
  onFinished = finished;
  action("Finish registration", async () => finished(await controller.complete()));
  action("Recover original result", async () => finished(await controller.complete(true)));
  action("Log out", async () => { watching = false; await controller.logout(); message("Signed out."); });
});
setInterval(() => { if (deadline) { const seconds = Math.max(0, Math.floor((deadline - Date.now()) / 1000));
  timer.textContent = seconds ? `Approval window: ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}` : "The original approval window has ended."; } }, 1000);

// Poll only the retained original pairing. A failed completion requires an
// explicit retry/recovery; it never silently recreates a key or approval.
setInterval(() => {
  if (!watching || busy || Date.now() < nextPoll) return;
  nextPoll = Date.now() + 2000;
  execute(async () => {
    const value = await controller.status();
    if (value.status === "approved") {
      watching = false;
      message("Approved. Completing device registration…");
      onFinished(await controller.complete());
    } else if (["expired", "cancelled"].includes(value.status)) {
      watching = false; message("Pairing " + value.status + ". No new approval was created.");
    }
  });
}, 500);


if (new URL(location.href).searchParams.get("browser-check") === "1") {
  document.querySelector("#roles").hidden = true;
  document.querySelector("#panel").hidden = true;
  const view = document.createElement("pre");
  view.style.whiteSpace = "pre-wrap";
  view.textContent = "Checking browser…";
  document.querySelector("main").append(view);
  const output = {
    diagnostic: "V2_PHONE_BROWSER_CHECK_V1",
    keyGeneration: 0, privateKeyReads: 0,
    recordWrites: 0, authorityRequests: 0,
    secureContext: globalThis.isSecureContext === true
  };
  const safeError = (e) => [
    "NotSupportedError", "DataError", "SecurityError",
    "InvalidAccessError", "InvalidStateError", "AbortError",
    "UnknownError", "QuotaExceededError", "VersionError",
    "TypeError", "Error"
  ].includes(e?.name) ? e.name : "OtherError";

  const inspectStorage = async () => {
    const idb = globalThis.indexedDB;
    if (typeof idb?.databases !== "function")
      return { enumeration: "unavailable" };
    const known = (await idb.databases()).find(
      r => r.name === "hodlxxi-social-messaging-device-v1"
    );
    if (!known) return { databasePresent: false };
    return await new Promise(resolve => {
      let finished = false, db;
      const finish = value => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        db?.close();
        resolve(value);
      };
      const timer = setTimeout(
        () => finish({ inspection: "timeout" }), 2500
      );
      const request = idb.open(known.name, known.version);
      request.onupgradeneeded = () => request.transaction.abort();
      request.onerror = () => finish({
        inspection: "error", errorType: safeError(request.error)
      });
      request.onblocked = () => finish({ inspection: "blocked" });
      request.onsuccess = () => {
        db = request.result;
        if (finished) { db.close(); return; }
        const result = { databasePresent: true, version: db.version };
        try {
          const names = [
            "device", "provisional-authentication-key-v2"
          ].filter(name => db.objectStoreNames.contains(name));
          result.deviceStorePresent = names.includes("device");
          result.authenticationStorePresent =
            names.includes("provisional-authentication-key-v2");
          if (!names.length) { finish(result); return; }
          const tx = db.transaction(names, "readonly");
          for (const name of names) {
            const count = tx.objectStore(name).count();
            count.onsuccess = () => {
              result[name === "device"
                ? "deviceRecords" : "authenticationRecords"] = count.result;
            };
          }
          tx.onabort = tx.onerror = () =>
            finish({ ...result, inspection: "error" });
          tx.oncomplete = () => {
            try {
              const check = db.transaction(
                names, "readwrite", { durability: "strict" }
              );
              result.strictDurability = check.durability === "strict";
              check.onabort = check.onerror = () => finish(result);
              check.abort();
            } catch (e) {
              finish({
                ...result, strictDurability: false,
                errorType: safeError(e)
              });
            }
          };
        } catch (e) {
          finish({
            ...result, inspection: "error", errorType: safeError(e)
          });
        }
      };
    });
  };

  (async () => {
    const ua = navigator.userAgent;
    output.platform = /iPhone|iPad|iPod/.test(ua)
      ? "iOS" : /Android/.test(ua) ? "Android" : "other";
    output.osMajor = Number(
      (ua.match(/(?:iPhone OS|CPU OS|Android) (\d+)/) ?? [])[1]
    ) || null;

    for (const [name, hex] of [
      ["X25519", "09" + "00".repeat(31)],
      ["Ed25519",
       "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"]
    ]) {
      try {
        const raw = Uint8Array.from(
          hex.match(/../g), value => parseInt(value, 16)
        );
        await crypto.subtle.importKey(
          "raw", raw, { name }, true,
          name === "Ed25519" ? ["verify"] : []
        );
        output[name] = "PUBLIC_IMPORT_PASS";
      } catch (e) { output[name] = safeError(e); }
    }

    const abort = new AbortController();
    const clockTimer = setTimeout(() => abort.abort(), 3500);
    try {
      const before = Date.now();
      const response = await fetch(
        "/device-registration-v2.css?browser-check=1", {
          credentials: "omit", cache: "no-store",
          redirect: "error", signal: abort.signal
        }
      );
      await response.arrayBuffer();
      const after = Date.now();
      const server = Date.parse(response.headers.get("date"));
      output.clock = response.status === 200 && Number.isFinite(server)
        ? {
            serverAheadBrowserApproxMs:
              Math.round(server - (before + after) / 2),
            roundTripMs: after - before
          }
        : { check: "unavailable" };
    } catch (e) { output.clock = { errorType: safeError(e) }; }
    finally { clearTimeout(clockTimer); }

    try { output.storage = await inspectStorage(); }
    catch (e) {
      output.storage = {
        inspection: "error", errorType: safeError(e)
      };
    }
    view.textContent = JSON.stringify(output, null, 2);
    const copy = document.createElement("button");
    copy.type = "button";
    copy.textContent = "Copy browser check";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(view.textContent);
        copy.textContent = "Copied";
      } catch {
        copy.textContent = "Take a screenshot of this result";
      }
    });
    document.querySelector("main").append(copy);
  })().catch(e => {
    output.errorType = safeError(e);
    view.textContent = JSON.stringify(output, null, 2);
  });
}


// HODLXXI_ISOLATED_PREPARATION_CHECK_V1
if (new URL(location.href).searchParams.get("isolated-check") === "1") {
  document.querySelector("#roles").hidden = true;
  document.querySelector("#panel").hidden = true;
  const output = document.createElement("pre");
  output.style.whiteSpace = "pre-wrap";
  output.textContent = "Isolated preparation check. Test keys use a separate temporary database. Your device database is not opened. No login, approval or enrollment requests are sent.";
  const button = document.createElement("button");
  button.textContent = "Run isolated preparation check";
  document.querySelector("main").append(output, button);
  button.addEventListener("click", async () => {
    button.disabled = true;
    const result = {
      diagnostic: "V2_ISOLATED_PREPARATION_CHECK_V2",
      authorityRequests: 0, realDeviceDatabaseAccesses: 0,
      privateKeyExports: 0, testKeyGenerations: 0, testSignatures: 0
    };
    let step = "imports", firstError;
    const remember = error => {
      firstError ??= {step, type:error?.name ?? "Error"};
    };
    const connections = new Set();
    const nativeIdb = globalThis.indexedDB;
    const name = "hodlxxi-isolated-preparation-" + Date.now() + "-" +
      [...crypto.getRandomValues(new Uint8Array(12))]
        .map(v=>v.toString(16).padStart(2,"0")).join("");
    try {
      const keys = await import("./messaging-device-v128c1.mjs");
      const {createPhoneEnrollmentController} =
        await import("./social-enrollment-v2-browser.mjs");
      const {createPairingQr} =
        await import("./mobile-device-authorization-contract-v1.mjs");
      const {pairingSecretCommitmentV2, verifyPairingPossessionV2} =
        await import("./mobile-device-authorization-contract-v2.mjs");

      const isolated = {open(database, version) {
        if (database !== keys.MESSAGING_DEVICE_DATABASE_NAME)
          throw new Error("unexpected_database");
        step = "test-idb-open-v" + (version ?? "default");
        const request = version === undefined
          ? nativeIdb.open(name) : nativeIdb.open(name, version);
        request.addEventListener("error", ()=>remember(request.error));
        request.addEventListener("blocked", ()=>remember({name:"BlockedError"}));
        request.addEventListener("success", ()=>{
          connections.add(request.result);
          result.testDatabaseVersion = request.result.version;
          request.result.addEventListener("error", e=>{
            try {remember(e.target.error);} catch {}
          });
        });
        return request;
      }};

      const subtle = {};
      for (const method of [
        "generateKey","exportKey","importKey","digest",
        "deriveBits","sign","verify"
      ]) {
        subtle[method] = async (...args)=>{
          step = "crypto-" + method +
            (args[0]?.name ? "-" + args[0].name : "");
          if (method === "generateKey") result.testKeyGenerations++;
          if (method === "sign") result.testSignatures++;
          if (method === "exportKey" && args[1]?.type === "private")
            throw new Error("private_export_forbidden");
          try {return await crypto.subtle[method](...args);}
          catch(error) {remember(error); throw error;}
        };
      }
      const cryptoImpl = {
        subtle,
        getRandomValues:value=>crypto.getRandomValues(value)
      };
      const canonicalCheck = (await import("./messaging-device-authorization-v1.mjs")).canonicalMessagingDeviceJson;
      const originalStore = keys.createMessagingDeviceStore(isolated);
      const store = {};
      let expectedRecord;
      const describeKey = key => {
        try {
          return {
            present: key !== undefined && key !== null,
            cryptoKey: typeof CryptoKey === "function" && key instanceof CryptoKey,
            type: key?.type ?? null,
            extractable: key?.extractable ?? null,
            algorithm: key?.algorithm?.name ?? null,
            usages: key?.usages ? Array.from(key.usages) : null,
            usagesIsArray: Array.isArray(key?.usages),
            usagesPrototypeMatches: key?.usages
              ? Object.getPrototypeOf(key.usages) === Array.prototype : false
          };
        } catch(error) {
          return {metadataErrorType:error.name};
        }
      };
      for (const method of ["read","create","update","discardCancelledPending"]) {
        store[method] = async (...args) => {
          step = "test-store-" + method;
          if (method === "create") {
            expectedRecord = args[0];
            result.generatedKeyMetadata = describeKey(expectedRecord.privateKey);
          }
          try {
            const value = await originalStore[method](...args);
            if (method === "read" && expectedRecord) {
              result.savedKeyMetadata = describeKey(value?.privateKey);
              result.savedRecordPresent = value !== undefined && value !== null;
              result.publicFieldsMatch = Object.fromEntries(
                ["subject","deviceId","publicKey","requestId","pendingProposal"]
                  .map(field => [field,value?.[field] === expectedRecord[field]])
              );
              try {
                result.savedUsagesCanonicalMatch =
                  canonicalCheck(value?.privateKey?.usages) === '["deriveBits"]';
              } catch(error) {
                result.savedUsagesCanonicalErrorType = error.name;
              }
            }
            return value;
          } catch(error) {
            remember(error);
            throw error;
          }
        };
      }

      const subject =
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
      const secret = "22".repeat(32), pairingId = "33".repeat(32);
      const at = Math.floor(Date.now()/1000)*1000;
      const iso = ms=>new Date(ms).toISOString().replace(".000Z","Z");
      const offer = {
        subject, pairingId, revision:"44".repeat(32),
        desktopContext:"55".repeat(32),
        secretCommitment:await pairingSecretCommitmentV2(secret, cryptoImpl),
        createdAt:iso(at), expiresAt:iso(at+300000),
        bindingLifetimeSeconds:3600
      };
      const api = {async call(command, body) {
        step = "synthetic-api-" + command;
        if (command === "context") return {};
        if (command === "offer") return offer;
        if (command === "propose") {
          await verifyPairingPossessionV2(body.authorizationWire, {
            subject, secret, possessionProof:body.possessionProof,
            proposal:undefined, nowMs:Date.now(), cryptoImpl
          });
          result.proposalVerifiedLocally = true;
          return {comparisonCode:"ISOLATED-TEST"};
        }
        throw new Error("authority_request_forbidden");
      }};
      const controller = createPhoneEnrollmentController({
        api, store, indexedDBImpl:isolated, cryptoImpl
      });
      step = "controller-scan";
      await controller.scan(createPairingQr(pairingId, secret));
      result.overall = "PASS_ISOLATED_REAL_BROWSER_PREPARATION";
    } catch(error) {
      result.overall = "PREPARATION_FAILED";
      result.error = firstError ?? {step, type:error?.name ?? "Error"};
      result.frames = String(error?.stack ?? "").split("\n").map(line=>{
        const match =
          line.match(/([A-Za-z0-9_-]+\.mjs)(?:\?[^:\s]*)?:(\d+):(\d+)/);
        return match
          ? {file:match[1],line:Number(match[2]),column:Number(match[3])}
          : null;
      }).filter(Boolean).slice(0,8);
    } finally {
      for (const db of connections) {
        try {db.close();} catch {}
      }
      try {
        await new Promise((resolve,reject)=>{
          const request = nativeIdb.deleteDatabase(name);
          const timer = setTimeout(
            ()=>reject(new Error("cleanup_timeout")),5000
          );
          request.onsuccess = ()=>{clearTimeout(timer);resolve();};
          request.onerror = ()=>{
            clearTimeout(timer);reject(request.error);
          };
          request.onblocked = ()=>{
            clearTimeout(timer);reject(new Error("cleanup_blocked"));
          };
        });
        result.testDatabaseRemoved = true;
      } catch(error) {
        result.testDatabaseRemoved = false;
        result.cleanupErrorType = error?.name ?? "Error";
      }
      output.textContent = JSON.stringify(result,null,2);
    }
  }, {once:true});
}
