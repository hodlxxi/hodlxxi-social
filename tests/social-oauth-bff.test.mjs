import test from "node:test"; import assert from "node:assert/strict";
import { createSocialOAuthBff } from "../src/server/social-oauth-bff.mjs"; import { createBoundedStore } from "../src/server/social-oauth-memory.mjs"; import { TRANSACTION_COOKIE_NAME, SESSION_COOKIE_NAME, expireTransactionCookie } from "../src/server/social-oauth-cookie.mjs";
const config={publicOrigin:"https://social.example",authorityOrigin:"https://authority.example",clientId:"social",clientSecret:"secret",callbackUri:"https://social.example/auth/callback",scope:"openid",transactionTtlSeconds:300,sessionTtlSeconds:3600};
const setup=()=>{let byte=0; const pendingTransactions=createBoundedStore({ttlSeconds:300,capacity:10,now:()=>0}); const sessions=createBoundedStore({ttlSeconds:3600,capacity:10,now:()=>0}); let tokenCalls=0,introspectionCalls=0; const codes=[]; const bff=createSocialOAuthBff({config,pendingTransactions,sessions,oauthClient:{async authenticate({code}){tokenCalls++; codes.push(code); introspectionCalls++; return "a".repeat(64);}},random:(size)=>Buffer.alloc(size,++byte)}); return {bff,pendingTransactions,sessions,codes,calls:()=>tokenCalls,tokenCalls:()=>tokenCalls,introspectionCalls:()=>introspectionCalls};};
test("login creates exact PKCE redirect and browser-bound transaction",async()=>{const {bff}=setup(); const result=await bff({method:"GET",url:"/auth/login",headers:{}}); assert.equal(result.status,302); const redirect=new URL(result.headers.Location); assert.equal(redirect.origin,"https://authority.example"); assert.equal(redirect.pathname,"/oauth/authorize"); assert.deepEqual([...redirect.searchParams.keys()],["response_type","client_id","redirect_uri","scope","state","code_challenge","code_challenge_method"]); assert.doesNotMatch(redirect.href,/secret|code_verifier/); assert.match(result.headers["Set-Cookie"],/^__Host-hodlxxi-social-oauth=/);});
test("callback binds cookie and state, consumes once, and clears cookie on every terminal result",async()=>{const fixture=setup(); const login=await fixture.bff({method:"GET",url:"/auth/login",headers:{}}); const transaction=login.headers["Set-Cookie"].split(";",1)[0]; const state=new URL(login.headers.Location).searchParams.get("state"); const good=await fixture.bff({method:"GET",url:`/auth/callback?code=code&state=${state}`,headers:{cookie:transaction}}); assert.equal(good.status,303); assert.equal(good.headers.Location,"/"); assert.equal(good.body,""); assert.equal(fixture.calls(),1); assert.ok(Array.isArray(good.headers["Set-Cookie"])); const replay=await fixture.bff({method:"GET",url:`/auth/callback?code=code&state=${state}`,headers:{cookie:transaction}}); assert.equal(replay.status,400); assert.equal(replay.headers["Set-Cookie"],expireTransactionCookie()); assert.equal(fixture.calls(),1);});
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


const authoritySetup = (authorityReader) => {
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
    config,
    pendingTransactions,
    sessions,
    oauthClient: {
      async authenticate() {
        return authenticatedSubject;
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
