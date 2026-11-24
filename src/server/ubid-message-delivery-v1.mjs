// Private Unix-socket client. No participant keys or plaintext cross this port.
import http from "node:http";
import {randomBytes, sign} from "node:crypto";
import {canonicalUnixSocketPath} from "./social-oauth-config.mjs";
import {canonical, exact, parseClosedJson} from "../../web/social-mobile-protocol-v1.mjs";

export const MESSAGE_DELIVERY_PREFIX = "/internal/v1/social/message-delivery";
const fail = () => { throw new Error("message delivery unavailable"); };
export function createUbidMessageDeliveryClient(config) {
  const socketPath = canonicalUnixSocketPath(config.socketPath);
  const origin = new URL(config.issuerOrigin);
  if (origin.protocol !== "https:" || origin.origin !== config.issuerOrigin || config.enabled !== true ||
      config.signingKey?.type !== "private" || config.signingKey.asymmetricKeyType !== "rsa" ||
      config.signingKey.asymmetricKeyDetails.modulusLength < 2048 ||
      !Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 250 || config.timeoutMs > 30000) fail();
  const post = (command, body, service, viewer) => new Promise((resolve, reject) => {
    const wire = canonical(body);
    if (Buffer.byteLength(wire) > 65536) return reject(new Error("message delivery unavailable"));
    const request = http.request({socketPath, path: MESSAGE_DELIVERY_PREFIX + "/" + command, method:"POST",
      agent:false, maxHeaderSize:16384, headers:{host:origin.host,"content-type":"application/json",
        "content-length":Buffer.byteLength(wire), ...(service ? {authorization:"Bearer "+service} : {}),
        ...(viewer ? {"x-hodlxxi-viewer-authorization":"Bearer "+viewer} : {})}}, response => {
      const chunks=[]; let size=0;
      response.on("data", chunk => { size+=chunk.length; if(size>65536) response.destroy(new Error("unavailable")); else chunks.push(chunk); });
      response.on("error",()=>reject(new Error("message delivery unavailable")));
      response.on("end",()=>{ try {
        if(response.statusCode!==200 || !/^application\/json(?:;.*)?$/i.test(response.headers["content-type"]??"")) fail();
        resolve(parseClosedJson(Buffer.concat(chunks).toString("utf8"),{maximum:65536,depth:8}));
      } catch { reject(new Error("message delivery unavailable")); } });
    });
    request.setTimeout(config.timeoutMs,()=>request.destroy());
    request.on("error",()=>reject(new Error("message delivery unavailable"))); request.end(wire);
  });
  const invoke = async (command, body, viewer) => {
    const uncredentialed = ["registered-challenge", "registered-consume"].includes(command);
    if (uncredentialed ? viewer !== undefined :
        typeof viewer!=="string" || viewer.length<1 || viewer.length>8192 || /[\x00-\x20\x7f]/.test(viewer)) fail();
    const now=Math.floor(Date.now()/1000);
    const header=Buffer.from(JSON.stringify({alg:"RS256",typ:"JWT",kid:config.clientSigningKeyId})).toString("base64url");
    const payload=Buffer.from(JSON.stringify({iss:config.clientId,sub:config.clientId,
      aud:config.issuerOrigin+MESSAGE_DELIVERY_PREFIX+"/service-token",iat:now,nbf:now,exp:now+30,jti:randomBytes(32).toString("hex"),
      token_use:"client_assertion",grant_type:"client_credentials",purpose:"service_client_authentication"})).toString("base64url");
    const signing=header+"."+payload;
    const token=await post("service-token",{assertion:signing+"."+sign("RSA-SHA256",Buffer.from(signing),config.signingKey).toString("base64url")});
    exact(token,["access_token","token_type"]); if(token.token_type!=="Bearer") fail();
    return post(command,body,token.access_token,viewer);
  };
  return Object.freeze({invoke});
}
