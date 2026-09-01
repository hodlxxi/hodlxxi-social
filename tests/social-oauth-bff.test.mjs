import test from "node:test"; import assert from "node:assert/strict";
import { createSocialOAuthBff } from "../src/server/social-oauth-bff.mjs"; import { createBoundedStore } from "../src/server/social-oauth-memory.mjs"; import { TRANSACTION_COOKIE_NAME, SESSION_COOKIE_NAME, expireTransactionCookie } from "../src/server/social-oauth-cookie.mjs";
const config={publicOrigin:"https://social.example",authorityOrigin:"https://authority.example",clientId:"social",clientSecret:"secret",callbackUri:"https://social.example/auth/callback",scope:"openid",transactionTtlSeconds:300,sessionTtlSeconds:3600};
const setup=()=>{let byte=0; const pendingTransactions=createBoundedStore({ttlSeconds:300,capacity:10,now:()=>0}); const sessions=createBoundedStore({ttlSeconds:3600,capacity:10,now:()=>0}); let tokenCalls=0,introspectionCalls=0; const codes=[]; const bff=createSocialOAuthBff({config,pendingTransactions,sessions,oauthClient:{async authenticate({code}){tokenCalls++; codes.push(code); introspectionCalls++; return {subject:"a".repeat(64),accessToken:"human-oauth-bearer-private"};}},random:(size)=>Buffer.alloc(size,++byte)}); return {bff,pendingTransactions,sessions,codes,calls:()=>tokenCalls,tokenCalls:()=>tokenCalls,introspectionCalls:()=>introspectionCalls};};
test("login creates exact PKCE redirect and browser-bound transaction",async()=>{const {bff}=setup(); const result=await bff({method:"GET",url:"/auth/login",headers:{}}); assert.equal(result.status,302); const redirect=new URL(result.headers.Location); assert.equal(redirect.origin,"https://authority.example"); assert.equal(redirect.pathname,"/oauth/authorize"); assert.deepEqual([...redirect.searchParams.keys()],["response_type","client_id","redirect_uri","scope","state","code_challenge","code_challenge_method"]); assert.doesNotMatch(redirect.href,/secret|code_verifier/); assert.match(result.headers["Set-Cookie"],/^__Host-hodlxxi-social-oauth=/);});
test("callback binds cookie and state, consumes once, and clears cookie on every terminal result",async()=>{const fixture=setup(); const login=await fixture.bff({method:"GET",url:"/auth/login",headers:{}}); const transaction=login.headers["Set-Cookie"].split(";",1)[0]; const state=new URL(login.headers.Location).searchParams.get("state"); const good=await fixture.bff({method:"GET",url:`/auth/callback?code=code&state=${state}`,headers:{cookie:transaction}}); assert.equal(good.status,303); assert.equal(good.headers.Location,"/"); assert.equal(good.body,""); assert.equal(fixture.calls(),1); assert.ok(Array.isArray(good.headers["Set-Cookie"])); const replay=await fixture.bff({method:"GET",url:`/auth/callback?code=code&state=${state}`,headers:{cookie:transaction}}); assert.equal(replay.status,400); assert.equal(replay.headers["Set-Cookie"],expireTransactionCookie()); assert.equal(fixture.calls(),1);});
test("human OAuth bearer is bound only to the opaque server session and removed on logout",async()=>{const fixture=setup();const login=await fixture.bff({method:"GET",url:"/auth/login",headers:{}});const transaction=login.headers["Set-Cookie"].split(";",1)[0];const state=new URL(login.headers.Location).searchParams.get("state");const callback=await fixture.bff({method:"GET",url:`/auth/callback?code=code&state=${state}`,headers:{cookie:transaction}});const sessionSetCookie=callback.headers["Set-Cookie"].find((value)=>value.startsWith(`${SESSION_COOKIE_NAME}=`)&&!value.startsWith(`${SESSION_COOKIE_NAME}=;`));const sessionCookie=sessionSetCookie.split(";",1)[0];const sessionId=sessionCookie.split("=",2)[1];assert.deepEqual(fixture.sessions.get(sessionId),{subject:"a".repeat(64),viewerAccessToken:"human-oauth-bearer-private",issuedAt:0,expiresAt:3600000});const browserSession=await fixture.bff({method:"GET",url:"/auth/session",headers:{cookie:sessionCookie}});assert.deepEqual(JSON.parse(browserSession.body),{authenticated:true,subject:"a".repeat(64)});assert.doesNotMatch(browserSession.body,/bearer|access.?token/i);const logout=await fixture.bff({method:"POST",url:"/auth/logout",headers:{cookie:sessionCookie,origin:config.publicOrigin}});assert.equal(logout.status,200);assert.equal(fixture.sessions.get(sessionId),null);assert.doesNotMatch(logout.body,/bearer|access.?token/i);});
test("incorrect state does not consume the browser-bound transaction",async()=>{const fixture=setup(); const login=await fixture.bff({method:"GET",url:"/auth/login",headers:{}}); const transaction=login.headers["Set-Cookie"].split(";",1)[0]; const state=new URL(login.headers.Location).searchParams.get("state"); const wrong=await fixture.bff({method:"GET",url:"/auth/callback?code=code&state=wrong",headers:{cookie:transaction}}); assert.equal(wrong.status,400); assert.equal(fixture.calls(),0); const good=await fixture.bff({method:"GET",url:`/auth/callback?code=code&state=${state}`,headers:{cookie:transaction}}); assert.equal(good.status,303); assert.equal(fixture.calls(),1);});
test("malformed transaction cookie and duplicate callback parameters clear transaction cookie",async()=>{const {bff}=setup(); for(const request of [{url:"/auth/callback?code=x&state=y",headers:{cookie:`${TRANSACTION_COOKIE_NAME}=\"quoted\"`}},{url:"/auth/callback?code=x&code=z&state=y",headers:{}}]){const result=await bff({method:"GET",...request}); assert.equal(result.headers["Set-Cookie"],expireTransactionCookie());}});
test("session and logout projections are minimal and origin protected",async()=>{const {bff}=setup(); assert.deepEqual(JSON.parse((await bff({method:"GET",url:"/auth/session",headers:{}})).body),{authenticated:false}); assert.equal((await bff({method:"GET",url:"/auth/logout",headers:{}})).status,405); assert.equal((await bff({method:"POST",url:"/auth/logout",headers:{origin:"https://foreign.example"}})).status,403); const out=await bff({method:"POST",url:"/auth/logout",headers:{origin:config.publicOrigin}}); assert.deepEqual(JSON.parse(out.body),{authenticated:false});});

const beginLogin=async(fixture)=>{const login=await fixture.bff({method:"GET",url:"/auth/login",headers:{}}); return {cookie:login.headers["Set-Cookie"].split(";",1)[0],state:new URL(login.headers.Location).searchParams.get("state")};};
const rejectedBody=JSON.stringify({error:"request_rejected"});

test("malformed raw callback query syntax cannot consume state or reach OAuth",async()=>{
  const hostileTargets=(state)=>[
    `/auth/callback?code=%ZZ&state=${state}`,
    "/auth/callback?code=opaque&state=%ZZ",
    `/auth/callback?code=%&state=${state}`,
    `/auth/callback?code=%A&state=${state}`,
    `/auth/callback?&code=opaque&state=${state}`,
    `/auth/callback?code=opaque&&state=${state}`,
    `/auth/callback?code=opaque&state=${state}&`,
    `/auth/callback?code=opaque&=hostile&state=${state}`,
    `/auth/callback?code=opaque&state=${state}&flag`,
    `/auth/callback?code=%C3%28&state=${state}`,
    `/auth/callback?code=%ED%A0%80&state=${state}`,
    `/auth/callback?code=%0A&state=${state}`,
    `/auth/callback?code=hostile value&state=${state}`,
    `/auth/callback?code=hostile\tvalue&state=${state}`,
    `/auth/callback?code=opaque&state=${state}#hostile-fragment`,
    `/auth/callback?code=opaque+value&state=${state}`,
    `/auth/callback?code=opaque;state=${state}`,
    `/auth/callback?code=opaque?state=${state}`,
    `/auth/callback?code=opaque=value&state=${state}`,
    `/auth/callback?code=opaque&state=${state}&&ignored=x`
  ];
  for(let index=0;index<hostileTargets("placeholder").length;index++){
    const fixture=setup(),transaction=await beginLogin(fixture),url=hostileTargets(transaction.state)[index];
    const rejected=await fixture.bff({method:"GET",url,headers:{cookie:transaction.cookie}});
    assert.equal(rejected.status,400,url);
    assert.equal(rejected.body,rejectedBody,url);
    assert.ok(Buffer.byteLength(rejected.body)<128,url);
    assert.equal(rejected.headers["Set-Cookie"],undefined,url);
    assert.equal(fixture.tokenCalls(),0,url);
    assert.equal(fixture.introspectionCalls(),0,url);
    assert.equal(fixture.sessions.size,0,url);
    assert.equal(fixture.pendingTransactions.size,1,url);
    const valid=await fixture.bff({method:"GET",url:`/auth/callback?code=valid&state=${transaction.state}`,headers:{cookie:transaction.cookie}});
    assert.equal(valid.status,303,url);
    assert.equal(fixture.tokenCalls(),1,url);
    assert.equal(fixture.introspectionCalls(),1,url);
    assert.equal(fixture.pendingTransactions.size,0,url);
    assert.equal(fixture.sessions.size,1,url);
  }
});

test("valid percent encoding is decoded exactly once before one exchange",async()=>{
  const fixture=setup(),transaction=await beginLogin(fixture);
  const result=await fixture.bff({method:"GET",url:`/auth/callback?%63ode=opaque*%252Fvalue%2Btail%F0%9F%92%A9&st%61te=${transaction.state}`,headers:{cookie:transaction.cookie}});
  assert.equal(result.status,303);
  assert.deepEqual(fixture.codes,["opaque*%2Fvalue+tail💩"]);
  assert.equal(fixture.tokenCalls(),1);
  assert.equal(fixture.introspectionCalls(),1);
  assert.equal(fixture.pendingTransactions.size,0);
  assert.equal(fixture.sessions.size,1);
});

test("callback semantic cardinality protections remain ahead of OAuth and consumption",async()=>{
  const queries=(state)=>[
    `code=one&code=two&state=${state}`,
    `code=one&state=${state}&unknown=value`,
    `code=&state=${state}`,
    `code=one&state=`,
    `code=one&state=${state}&error=denied`,
    `code%5B%5D=one&state=${state}`,
    `code=one&st%61te=${state}&state=${state}`
  ];
  for(let index=0;index<queries("placeholder").length;index++){
    const fixture=setup(),transaction=await beginLogin(fixture);
    const result=await fixture.bff({method:"GET",url:`/auth/callback?${queries(transaction.state)[index]}`,headers:{cookie:transaction.cookie}});
    assert.equal(result.status,400);
    assert.equal(result.body,rejectedBody);
    assert.equal(result.headers["Set-Cookie"],expireTransactionCookie());
    assert.equal(fixture.tokenCalls(),0);
    assert.equal(fixture.introspectionCalls(),0);
    assert.equal(fixture.sessions.size,0);
    assert.equal(fixture.pendingTransactions.size,1);
  }
});

test("ambiguous, lookalike, absolute, and overlong callback targets fail before OAuth",async()=>{
  const fixture=setup(),transaction=await beginLogin(fixture),suffix=`?code=hostile&state=${transaction.state}`;
  const targets=[
    [`/x/../auth/callback${suffix}`,400],
    [`/auth/%63allback${suffix}`,400],
    [`/auth/%2563allback${suffix}`,400],
    [`/auth//callback${suffix}`,400],
    [`/auth/callback/${suffix}`,400],
    [`/auth/callback-extra${suffix}`,404],
    [`https://foreign.example/auth/callback${suffix}`,400],
    [`https://social.example:bad/auth/callback${suffix}`,400],
    [`/auth/callback?code=${"a".repeat(4096)}&state=${transaction.state}`,400]
  ];
  for(const [url,status] of targets){const result=await fixture.bff({method:"GET",url,headers:{cookie:transaction.cookie}}); assert.equal(result.status,status,url); assert.equal(result.body,rejectedBody,url);}
  assert.equal(fixture.tokenCalls(),0);
  assert.equal(fixture.introspectionCalls(),0);
  assert.equal(fixture.pendingTransactions.size,1);
  assert.equal(fixture.sessions.size,0);
});


const authoritySetup = (authorityReader, selectedConfig = config) => {
  const pendingTransactions = createBoundedStore({
    ttlSeconds: 300,
    capacity: 10,
    now: () => 0
  });
  const sessions = createBoundedStore({
    ttlSeconds: 3600,
    capacity: 10,
    now: () => 0
  });
  const authenticatedSubject = "b".repeat(64);
  const sessionId = "session123";

  assert.equal(
    sessions.create(sessionId, { subject: authenticatedSubject }),
    true
  );

  const bff = createSocialOAuthBff({
    config: selectedConfig,
    pendingTransactions,
    sessions,
    oauthClient: {
      async authenticate() {
        return {
          subject: authenticatedSubject,
          accessToken: "human-oauth-bearer-private"
        };
      }
    },
    authorityReader,
    random: (size) => Buffer.alloc(size, 7)
  });

  return {
    bff,
    authenticatedSubject,
    cookie: `${SESSION_COOKIE_NAME}=${sessionId}`
  };
};

test("authenticated authority is derived only from the opaque session subject", async () => {
  const seen = [];

  const fixture = authoritySetup(async (candidate) => {
    seen.push(candidate);
    return Object.freeze({
      subject: candidate,
      status: "full",
      valid: true
    });
  });

  const result = await fixture.bff({
    method: "GET",
    url: "/auth/authority",
    headers: { cookie: fixture.cookie }
  });

  assert.equal(result.status, 200);
  assert.deepEqual(JSON.parse(result.body), {
    subject: fixture.authenticatedSubject,
    status: "full",
    valid: true
  });
  assert.deepEqual(seen, [fixture.authenticatedSubject]);
});

test("authority route rejects caller-supplied subjects and unauthenticated reads", async () => {
  let calls = 0;

  const fixture = authoritySetup(async (candidate) => {
    calls += 1;
    return { subject: candidate, status: "full", valid: true };
  });

  const injected = await fixture.bff({
    method: "GET",
    url: `/auth/authority?subject=${"c".repeat(64)}`,
    headers: { cookie: fixture.cookie }
  });

  assert.equal(injected.status, 400);
  assert.equal(calls, 0);

  const unauthenticated = await fixture.bff({
    method: "GET",
    url: "/auth/authority",
    headers: {}
  });

  assert.equal(unauthenticated.status, 401);
  assert.deepEqual(JSON.parse(unauthenticated.body), {
    error: "authentication_required"
  });
  assert.equal(calls, 0);
});

test("authority projection permits only exact Limited or Full and fails closed", async () => {
  const subject = "b".repeat(64);

  const hostile = [
    { subject, status: "operator", valid: true },
    { subject: "c".repeat(64), status: "full", valid: true },
    { subject, status: "full", valid: false },
    { subject, status: "unknown", valid: true },
    { subject, status: "full", valid: true, extra: "elevate" },
    undefined
  ];

  for (const candidate of hostile) {
    const fixture = authoritySetup(async () => candidate);

    const result = await fixture.bff({
      method: "GET",
      url: "/auth/authority",
      headers: { cookie: fixture.cookie }
    });

    assert.equal(result.status, 200);
    assert.deepEqual(JSON.parse(result.body), {
      subject: fixture.authenticatedSubject,
      status: "limited",
      valid: false
    });
  }

  const throwing = authoritySetup(async () => {
    throw new Error("private authority failure");
  });

  const result = await throwing.bff({
    method: "GET",
    url: "/auth/authority",
    headers: { cookie: throwing.cookie }
  });

  assert.deepEqual(JSON.parse(result.body), {
    subject: throwing.authenticatedSubject,
    status: "limited",
    valid: false
  });
  assert.doesNotMatch(result.body, /private authority failure/);
});

test("authority route is GET-only and no-store", async () => {
  let calls = 0;

  const fixture = authoritySetup(async (candidate) => {
    calls += 1;
    return { subject: candidate, status: "limited", valid: true };
  });

  const wrongMethod = await fixture.bff({
    method: "POST",
    url: "/auth/authority",
    headers: { cookie: fixture.cookie }
  });

  assert.equal(wrongMethod.status, 405);
  assert.equal(calls, 0);

  const result = await fixture.bff({
    method: "GET",
    url: "/auth/authority",
    headers: { cookie: fixture.cookie }
  });

  assert.equal(result.status, 200);
  assert.equal(result.headers["Cache-Control"], "no-store");
  assert.deepEqual(JSON.parse(result.body), {
    subject: fixture.authenticatedSubject,
    status: "limited",
    valid: true
  });
});

test("authenticated social read config exposes only one canonical explicit relay", async () => {
  const fixture = authoritySetup(
    undefined,
    {
      ...config,
      nostrRelayUrl: "wss://relay.example/"
    }
  );

  const result = await fixture.bff({
    method: "GET",
    url: "/auth/social-read-config",
    headers: { cookie: fixture.cookie }
  });

  assert.equal(result.status, 200);
  assert.equal(result.headers["Cache-Control"], "no-store");
  assert.deepEqual(JSON.parse(result.body), {
    enabled: true,
    relayUrl: "wss://relay.example/"
  });
  assert.doesNotMatch(result.body, new RegExp(fixture.authenticatedSubject));
});

test("social read config is session-gated, GET-only, query-free, and disabled safely", async () => {
  const fixture = authoritySetup(undefined);

  const disabled = await fixture.bff({
    method: "GET",
    url: "/auth/social-read-config",
    headers: { cookie: fixture.cookie }
  });
  assert.deepEqual(JSON.parse(disabled.body), { enabled: false });

  for (const request of [
    {
      method: "GET",
      url: "/auth/social-read-config",
      headers: {}
    },
    {
      method: "POST",
      url: "/auth/social-read-config",
      headers: { cookie: fixture.cookie }
    },
    {
      method: "GET",
      url: `/auth/social-read-config?subject=${"c".repeat(64)}`,
      headers: { cookie: fixture.cookie }
    }
  ]) {
    const result = await fixture.bff(request);
    assert.equal(result.status, request.headers.cookie ? (request.method === "POST" ? 405 : 400) : 401);
  }

  const noncanonical = authoritySetup(undefined, {
    ...config,
    nostrRelayUrl: "wss://relay.example"
  });
  const rejectedConfig = await noncanonical.bff({
    method: "GET",
    url: "/auth/social-read-config",
    headers: { cookie: noncanonical.cookie }
  });
  assert.deepEqual(JSON.parse(rejectedConfig.body), { enabled: false });
});

test("authenticated publish config exposes only one separate canonical explicit relay", async () => {
  const fixture = authoritySetup(
    undefined,
    {
      ...config,
      nostrRelayUrl: "wss://read.example/",
      nostrPublishRelayUrl: "wss://write.example/"
    }
  );

  const result = await fixture.bff({
    method: "GET",
    url: "/auth/social-publish-config",
    headers: { cookie: fixture.cookie }
  });

  assert.equal(result.status, 200);
  assert.equal(result.headers["Cache-Control"], "no-store");
  assert.deepEqual(JSON.parse(result.body), {
    enabled: true,
    relayUrl: "wss://write.example/"
  });
  assert.doesNotMatch(result.body, new RegExp(fixture.authenticatedSubject));
  assert.doesNotMatch(result.body, /read\.example/);
});

test("publish config is session-gated GET-only query-free and disabled safely", async () => {
  const fixture = authoritySetup(undefined);
  const disabled = await fixture.bff({
    method: "GET",
    url: "/auth/social-publish-config",
    headers: { cookie: fixture.cookie }
  });
  assert.deepEqual(JSON.parse(disabled.body), { enabled: false });

  for (const request of [
    {
      method: "GET",
      url: "/auth/social-publish-config",
      headers: {}
    },
    {
      method: "POST",
      url: "/auth/social-publish-config",
      headers: { cookie: fixture.cookie }
    },
    {
      method: "GET",
      url: `/auth/social-publish-config?subject=${"c".repeat(64)}`,
      headers: { cookie: fixture.cookie }
    }
  ]) {
    const result = await fixture.bff(request);
    assert.equal(
      result.status,
      request.headers.cookie
        ? (request.method === "POST" ? 405 : 400)
        : 401
    );
  }

  const noncanonical = authoritySetup(undefined, {
    ...config,
    nostrPublishRelayUrl: "wss://write.example"
  });
  const rejectedConfig = await noncanonical.bff({
    method: "GET",
    url: "/auth/social-publish-config",
    headers: { cookie: noncanonical.cookie }
  });
  assert.deepEqual(JSON.parse(rejectedConfig.body), { enabled: false });
});

const directorySetup = ({
  authority = "full",
  valid = true,
  viewerAccessToken = "canonical-human-oauth-bearer",
  enabled = true,
  fullDirectoryClient
} = {}) => {
  const pendingTransactions = createBoundedStore({
    ttlSeconds: 300,
    capacity: 4,
    now: () => 0
  });
  const sessions = createBoundedStore({
    ttlSeconds: 3600,
    capacity: 4,
    now: () => 0
  });
  const subject = "e".repeat(64);
  const sessionId = "full-directory-session";
  sessions.create(sessionId, {
    subject,
    ...(viewerAccessToken === undefined ? {} : { viewerAccessToken })
  });
  const bff = createSocialOAuthBff({
    config: {
      ...config,
      fullDirectory: Object.freeze({ enabled })
    },
    pendingTransactions,
    sessions,
    oauthClient: {
      async authenticate() {
        throw new Error("not used");
      }
    },
    authorityReader: async (candidate) => ({
      subject: candidate,
      status: authority,
      valid
    }),
    fullDirectoryClient,
    random: (size) => Buffer.alloc(size, 8)
  });
  return {
    bff,
    subject,
    cookie: `${SESSION_COOKIE_NAME}=${sessionId}`
  };
};

test("Full directory BFF passes only the retained viewer bearer and returns aliases", async () => {
  const seen = [];
  const fixture = directorySetup({
    fullDirectoryClient: {
      async readForViewer(input) {
        seen.push(input);
        return {
          state: "available",
          participants: [
            { alias: "pairwise.alias-1" },
            { alias: "pairwise.alias-2" }
          ]
        };
      }
    }
  });
  const result = await fixture.bff({
    method: "GET",
    url: "/auth/full-directory",
    headers: { cookie: fixture.cookie }
  });
  assert.equal(result.status, 200);
  assert.equal(result.headers["Cache-Control"], "no-store");
  assert.deepEqual(seen, [{
    viewerAccessToken: "canonical-human-oauth-bearer"
  }]);
  assert.deepEqual(JSON.parse(result.body), {
    state: "available",
    participants: [
      { alias: "pairwise.alias-1" },
      { alias: "pairwise.alias-2" }
    ]
  });
  assert.doesNotMatch(
    result.body,
    /canonical-human|service|subject|public.?key|identity_class/i
  );
});

test("Full directory BFF denies unauthenticated missing-bearer and non-Full requests without population data", async () => {
  let clientCalls = 0;
  const client = {
    async readForViewer() {
      clientCalls += 1;
      return {
        state: "available",
        participants: [{ alias: "must-not-render" }]
      };
    }
  };
  const full = directorySetup({ fullDirectoryClient: client });
  const missingBearer = directorySetup({
    viewerAccessToken: null,
    fullDirectoryClient: client
  });
  const limited = directorySetup({
    authority: "limited",
    fullDirectoryClient: client
  });
  const invalid = directorySetup({
    authority: "limited",
    valid: false,
    fullDirectoryClient: client
  });
  const cases = [
    [full, {}, 401],
    [missingBearer, { cookie: missingBearer.cookie }, 403],
    [limited, { cookie: limited.cookie }, 403],
    [invalid, { cookie: invalid.cookie }, 403]
  ];
  for (const [fixture, headers, status] of cases) {
    const result = await fixture.bff({
      method: "GET",
      url: "/auth/full-directory",
      headers
    });
    assert.equal(result.status, status);
    assert.equal(result.headers["Cache-Control"], "no-store");
    assert.deepEqual(JSON.parse(result.body), { state: "unavailable" });
    assert.doesNotMatch(result.body, /participant|count|must-not-render/i);
  }
  assert.equal(clientCalls, 0);
});

test("disabled missing failing and malformed directory clients fail closed identically", async () => {
  const rawSubject = "f".repeat(64);
  const fixtures = [
    directorySetup({ enabled: false }),
    directorySetup({ enabled: true }),
    directorySetup({
      fullDirectoryClient: {
        async readForViewer() {
          throw new Error("private UBID 503 with 42 participants");
        }
      }
    }),
    directorySetup({
      fullDirectoryClient: {
        async readForViewer() {
          return {
            state: "available",
            participants: [{ alias: "safe", subject: rawSubject }]
          };
        }
      }
    }),
    directorySetup({
      fullDirectoryClient: {
        async readForViewer() {
          return {
            state: "available",
            participants: [{ alias: "xpub-synthetic-private-value" }]
          };
        }
      }
    })
  ];
  for (const fixture of fixtures) {
    const result = await fixture.bff({
      method: "GET",
      url: "/auth/full-directory",
      headers: { cookie: fixture.cookie }
    });
    assert.equal(result.status, 503);
    assert.deepEqual(JSON.parse(result.body), { state: "unavailable" });
    assert.equal(result.headers["Cache-Control"], "no-store");
    assert.doesNotMatch(result.body, /42|participant|UBID|safe/i);
    assert.doesNotMatch(result.body, new RegExp(rawSubject));
  }
});

test("Full directory route is GET-only and rejects query-based identity selection", async () => {
  let calls = 0;
  const fixture = directorySetup({
    fullDirectoryClient: {
      async readForViewer() {
        calls += 1;
        return { state: "available", participants: [] };
      }
    }
  });
  for (const request of [
    { method: "POST", url: "/auth/full-directory", status: 405 },
    {
      method: "GET",
      url: `/auth/full-directory?subject=${"f".repeat(64)}`,
      status: 400
    }
  ]) {
    const result = await fixture.bff({
      method: request.method,
      url: request.url,
      headers: { cookie: fixture.cookie }
    });
    assert.equal(result.status, request.status);
    assert.deepEqual(JSON.parse(result.body), { state: "unavailable" });
  }
  assert.equal(calls, 0);
});
