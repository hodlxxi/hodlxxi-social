import test from "node:test"; import assert from "node:assert/strict"; import { classifyRequestTarget, createHttpHandler } from "../scripts/hodlxxi-social-server.mjs"; import { expireTransactionCookie } from "../src/server/social-oauth-cookie.mjs";
const invoke=async({url,method="GET",headers={},rawHeaders=[]},bff=async()=>{throw new Error("must not route");})=>{const incoming={url,method,headers,rawHeaders}; const result={headers:{},setHeader(k,v){this.headers[k]=v;},end(body){this.body=body;}}; await createHttpHandler({publicOrigin:"https://social.example",bff})(incoming,result); return result;};
test("request-target recognition is bounded and exact",()=>{assert.deepEqual(classifyRequestTarget("/auth/callback?code=x&state=y","https://social.example"),{valid:true,callback:true}); for(const target of ["/auth/callback-extra","/auth/callback/","/auth/callback%2fextra","/x/%2e%2e/auth/callback","/auth/callback#x","//auth/callback","https://foreign.example/auth/callback","/bad target","/"+"a".repeat(4097)]) assert.equal(classifyRequestTarget(target,"https://social.example").callback,false);});
test("framed exact callback rejects, clears transaction cookie, sanitizes, and performs zero routing",async()=>{let calls=0; for(const url of ["/auth/callback","/auth/callback?code=secret&state=hidden"]){const result=await invoke({url,headers:{"content-length":"1"},rawHeaders:["Content-Length","1"]},async()=>{calls++;}); assert.equal(result.statusCode,413); assert.equal(result.headers["Set-Cookie"],expireTransactionCookie()); assert.equal(result.headers["Cache-Control"],"no-store"); assert.doesNotMatch(result.body,/secret|hidden|Content-Length/);} assert.equal(calls,0);});
test("framed non-callback and near matches never clear OAuth cookie",async()=>{for(const url of ["/auth/session","/auth/callback-extra","/auth/callback/","/auth/callback%2fextra","//auth/callback"]){const result=await invoke({url,headers:{"content-length":"1"},rawHeaders:["Content-Length","1"]}); assert.equal(result.headers["Set-Cookie"],undefined);}});
test("fragment-bearing callback targets are malformed with no callback behavior",async()=>{let calls=0; for(const framed of [false,true]){const result=await invoke({url:"/auth/callback#secret",headers:framed?{"content-length":"1"}:{},rawHeaders:framed?["Content-Length","1"]:[]},async()=>{calls++;}); assert.equal(result.statusCode,framed?413:400); assert.equal(result.headers["Set-Cookie"],undefined); assert.doesNotMatch(result.body,/secret/);} assert.equal(calls,0);});
test("encoded dot-segment callback targets are malformed with no callback behavior",async()=>{let calls=0; for(const framed of [false,true]){const result=await invoke({url:"/x/%2e%2e/auth/callback",headers:framed?{"content-length":"1"}:{},rawHeaders:framed?["Content-Length","1"]:[]},async()=>{calls++;}); assert.equal(result.statusCode,framed?413:400); assert.equal(result.headers["Set-Cookie"],undefined);} assert.equal(calls,0);});
test("duplicate and conflicting framing fails closed without reflection",async()=>{for(const input of [{headers:{"content-length":"1"},rawHeaders:["Content-Length","1","Content-Length","2"]},{headers:{"transfer-encoding":"chunked"},rawHeaders:["Transfer-Encoding","hostile-secret"]}]){const result=await invoke({url:"/auth/callback",...input}); assert.equal(result.statusCode,413); assert.doesNotMatch(result.body,/hostile|secret|chunked/);}});

const framed={headers:{"content-length":"1"},rawHeaders:["Content-Length","1"]};
const rejectedBody=JSON.stringify({error:"request_rejected"});

test("malformed framed callback-like targets remain generic and never route",async()=>{
  const targets=[
    "/auth/callback?code=%ZZ&state=valid",
    "/auth/callback?code=valid&state=%ZZ",
    "/auth/callback?code=%&state=valid",
    "/auth/callback?code=%A&state=valid",
    "/auth/callback?&code=valid&state=valid",
    "/auth/callback?code=valid&&state=valid",
    "/auth/callback?code=valid&state=valid&",
    "/auth/callback?code=valid&=empty&state=valid",
    "/auth/callback?code=valid&state=valid&flag",
    "/auth/callback?code=%C3%28&state=valid",
    "/auth/callback?code=%0A&state=valid",
    "/auth/callback?code=bad value&state=valid",
    "/auth/callback?code=valid&state=valid#hostile",
    "/auth/%63allback?code=valid&state=valid",
    "/auth/%2563allback?code=valid&state=valid",
    "/x/../auth/callback?code=valid&state=valid",
    "https://foreign.example/auth/callback?code=valid&state=valid",
    "https://social.example:bad/auth/callback?code=valid&state=valid"
  ];
  let calls=0;
  for(const url of targets){
    assert.deepEqual(classifyRequestTarget(url,"https://social.example"),{valid:false,callback:false},url);
    const result=await invoke({url,...framed},async()=>{calls++;});
    assert.equal(result.statusCode,413,url);
    assert.equal(result.headers["Set-Cookie"],undefined,url);
    assert.equal(result.body,rejectedBody,url);
    assert.ok(Buffer.byteLength(result.body)<128,url);
  }
  assert.equal(calls,0);
});

test("valid framed exact callbacks, including encoded values, retain cookie clearing",async()=>{
  for(const url of ["/auth/callback","/auth/callback?code=opaque%252Fvalue&state=valid","https://social.example/auth/callback?code=opaque%2Bvalue&state=valid"]){
    assert.deepEqual(classifyRequestTarget(url,"https://social.example"),{valid:true,callback:true});
    const result=await invoke({url,...framed});
    assert.equal(result.statusCode,413);
    assert.equal(result.headers["Set-Cookie"],expireTransactionCookie());
    assert.equal(result.body,rejectedBody);
  }
});

test("callback path lookalikes stay non-callback and valid non-callback routing is unchanged",async()=>{
  for(const url of ["/auth/callback-extra","/auth/callback.old","/auth/callbackish?code=x&state=y","/AUTH/callback"]){
    assert.equal(classifyRequestTarget(url,"https://social.example").callback,false,url);
    const result=await invoke({url,...framed});
    assert.equal(result.headers["Set-Cookie"],undefined,url);
  }
  let calls=0;
  const routed=await invoke({url:"/auth/session"},async()=>{calls++;return {status:200,headers:{"Content-Type":"application/json"},body:"{}"};});
  assert.equal(calls,1);
  assert.equal(routed.statusCode,200);
  assert.equal(routed.body,"{}");
});


test("exact zero-length framing permits a bodyless POST while duplicate or nonzero framing remains closed", async()=>{
  let calls=0;

  const accepted=await invoke({
    url:"/auth/logout",
    method:"POST",
    headers:{"content-length":"0"},
    rawHeaders:["Content-Length","0"]
  },async(request)=>{
    calls++;
    assert.equal(request.method,"POST");
    return {
      status:200,
      headers:{"Content-Type":"application/json"},
      body:"{}"
    };
  });

  assert.equal(calls,1);
  assert.equal(accepted.statusCode,200);

  for(const rawHeaders of [
    ["Content-Length","1"],
    ["Content-Length","0","Content-Length","0"],
    ["Content-Length","0","Transfer-Encoding","chunked"]
  ]){
    const rejected=await invoke({
      url:"/auth/logout",
      method:"POST",
      headers:{},
      rawHeaders
    },async()=>{
      calls++;
      throw new Error("must not route");
    });

    assert.equal(rejected.statusCode,413);
  }

  assert.equal(calls,1);
});
