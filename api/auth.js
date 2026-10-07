/**
 * Vercel Node.js Function: /api/auth
 * Experimental LALIGA Fantasy login using the public client used by the official flow.
 * Never returns or logs access/refresh tokens.
 */
const TOKEN_URL="https://login.laliga.es/laligadspprob2c.onmicrosoft.com/oauth2/v2.0/token?p=B2C_1A_ResourceOwnerv2";
const CLIENT_ID="af88bcff-1157-40a0-b579-030728aacf0b";
const COOKIE="lf_session";
const ISSUER="https://login.laliga.es/335316eb-f606-4361-bb86-35a7edcdcec1/v2.0/";
const attempts=new Map();

function json(res,status,body){res.status(status).setHeader("Content-Type","application/json; charset=utf-8").setHeader("Cache-Control","no-store").end(JSON.stringify(body))}
function parseCookies(v){const out={};for(const part of String(v||"").split(";")){const i=part.indexOf("=");if(i>0)out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim());}return out}
function cookie(name,value,maxAge,extra=""){return name+"="+encodeURIComponent(value)+"; Max-Age="+maxAge+"; Path=/; HttpOnly; Secure; SameSite=Lax"+extra}
function origin(req){
  const proto=String(req.headers["x-forwarded-proto"]||"https").split(",")[0];
  const host=String(req.headers["x-forwarded-host"]||req.headers.host||"");
  return proto+"://"+host;
}
function base64url(buf){return Buffer.from(buf).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
function randomUrlSafe(bytes=32){return base64url(require("crypto").randomBytes(bytes))}
function pkceChallenge(verifier){return base64url(require("crypto").createHash("sha256").update(verifier).digest())}
function tokenPayload(token){try{const p=token.split(".")[1];return JSON.parse(Buffer.from(p,"base64url").toString("utf8"))}catch{return null}}
function sameOrigin(req){
  const origin=req.headers.origin;
  if(!origin)return true;
  const host=req.headers["x-forwarded-host"]||req.headers.host;
  try{return new URL(origin).host===host}catch{return false}
}
function allowedAttempt(req){
  const ip=String(req.headers["x-forwarded-for"]||req.socket?.remoteAddress||"unknown").split(",")[0].trim();
  const now=Date.now(), five=5*60*1000, prev=attempts.get(ip)||[];
  const fresh=prev.filter(x=>now-x<five);
  if(fresh.length>=10)return false;
  fresh.push(now);attempts.set(ip,fresh);return true;
}

export default async function handler(req,res){
  if(req.method==="GET" && req.query?.provider==="google"){
    const state=randomUrlSafe(24), verifier=randomUrlSafe(48), nonce=randomUrlSafe(24);
    const redirectUri=origin(req)+"/api/auth?callback=google";
    const authorize="https://login.laliga.es/laligadspprob2c.onmicrosoft.com/oauth2/v2.0/authorize";
    const params=new URLSearchParams({
      p:"B2C_1A_5ULAIP_PARAMETRIZED_SIGNIN",
      client_id:CLIENT_ID,
      response_type:"code",
      redirect_uri:redirectUri,
      scope:"openid offline_access",
      code_challenge:pkceChallenge(verifier),
      code_challenge_method:"S256",
      state,
      nonce
    });
    res.setHeader("Set-Cookie",[
      cookie("lf_oauth_state",state,600),
      cookie("lf_oauth_verifier",verifier,600),
      cookie("lf_oauth_nonce",nonce,600)
    ]);
    return res.redirect(302,authorize+"?"+params.toString());
  }

  if(req.method==="GET" && req.query?.callback==="google"){
    const code=typeof req.query?.code==="string"?req.query.code:"";
    const state=typeof req.query?.state==="string"?req.query.state:"";
    const cookies=parseCookies(req.headers.cookie);
    const verifier=cookies.lf_oauth_verifier||"";
    const expected=cookies.lf_oauth_state||"";
    if(!code || !state || !verifier || state!==expected)return res.redirect(302,"/?login=error&reason=oauth_state");
    try{
      const redirectUri=origin(req)+"/api/auth?callback=google";
      const upstream=await fetch(TOKEN_URL+"?p=B2C_1A_5ULAIP_PARAMETRIZED_SIGNIN",{
        method:"POST",
        headers:{"Content-Type":"application/x-www-form-urlencoded","Accept":"application/json"},
        body:new URLSearchParams({
          grant_type:"authorization_code",
          client_id:CLIENT_ID,
          code,
          redirect_uri:redirectUri,
          code_verifier:verifier,
          scope:"openid offline_access"
        }),
        cache:"no-store"
      });
      const data=await upstream.json().catch(()=>({}));
      if(!upstream.ok)return res.redirect(302,"/?login=error&reason=oauth_exchange");
      const token=typeof data.access_token==="string"?data.access_token:(typeof data.id_token==="string"?data.id_token:"");
      if(!token)return res.redirect(302,"/?login=error&reason=oauth_token");
      const p=tokenPayload(token);
      if(!p?.exp || p.exp*1000<=Date.now())return res.redirect(302,"/?login=error&reason=oauth_expired");
      const maxAge=Math.max(60,Math.floor((p.exp*1000-Date.now())/1000));
      res.setHeader("Set-Cookie",[
        cookie(COOKIE,token,maxAge,"; SameSite=Strict"),
        cookie("lf_oauth_state","",0),
        cookie("lf_oauth_verifier","",0),
        cookie("lf_oauth_nonce","",0)
      ]);
      return res.redirect(302,"/?login=success");
    }catch(e){
      console.error("LALIGA OAuth error",e instanceof Error?e.message:String(e));
      return res.redirect(302,"/?login=error&reason=oauth_unavailable");
    }
  }

  if(req.method==="GET"){
    const token=parseCookies(req.headers.cookie)[COOKIE];
    if(!token)return json(res,200,{authenticated:false});
    const p=tokenPayload(token);
    if(!p?.exp || p.exp*1000<=Date.now()){res.setHeader("Set-Cookie",COOKIE+"=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict");return json(res,200,{authenticated:false})}
    return json(res,200,{authenticated:true,expiresAt:p.exp*1000,subject:typeof p.sub==="string"?p.sub:null});
  }
  if(req.method==="DELETE"){
    res.setHeader("Set-Cookie",COOKIE+"=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict");
    return json(res,200,{authenticated:false});
  }
  if(req.method!=="POST"){res.setHeader("Allow","GET, POST, DELETE");return json(res,405,{error:"Only GET, POST or DELETE is allowed"})}
  if(!sameOrigin(req))return json(res,403,{error:"Origen no permitido"});
  if(!allowedAttempt(req))return json(res,429,{error:"Demasiados intentos. Prueba de nuevo en unos minutos."});
  try{
    const raw=typeof req.body==="string"?req.body:JSON.stringify(req.body||{});
    if(Buffer.byteLength(raw,"utf8")>8192)return json(res,413,{error:"Solicitud demasiado grande"});
    const body=typeof req.body==="object"&&req.body!==null?req.body:JSON.parse(raw);
    const email=typeof body.email==="string"?body.email.trim():"";
    const password=typeof body.password==="string"?body.password:"";
    if(!email || !password)return json(res,400,{error:"Correo y contraseña son obligatorios"});
    if(email.length>320 || password.length>1024)return json(res,400,{error:"Credenciales no válidas"});
    const upstream=await fetch(TOKEN_URL,{
      method:"POST",
      headers:{"Content-Type":"application/x-www-form-urlencoded","Accept":"application/json"},
      body:new URLSearchParams({
        grant_type:"password",
        client_id:CLIENT_ID,
        scope:"openid "+CLIENT_ID+" offline_access",
        redirect_uri:"authredirect://com.lfp.laligafantasy",
        username:email,
        password,
        response_type:"id_token"
      }),
      cache:"no-store"
    });
    if(!upstream.ok)return json(res,401,{error:"LALIGA no ha aceptado las credenciales. Comprueba el correo y la contraseña."});
    const data=await upstream.json();
    const token=typeof data.access_token==="string"?data.access_token:"";
    if(!token)return json(res,502,{error:"LALIGA no devolvió un access token"});
    const p=tokenPayload(token);
    if(!p?.exp || p.exp*1000<=Date.now())return json(res,502,{error:"Token de LALIGA no válido o caducado"});
    if(p.iss && p.iss!==ISSUER)return json(res,502,{error:"Token emitido por un proveedor inesperado"});
    if(p.aud && String(p.aud)!==CLIENT_ID)return json(res,502,{error:"Token emitido para una aplicación distinta"});
    const maxAge=Math.max(60,Math.floor((p.exp*1000-Date.now())/1000));
    res.setHeader("Set-Cookie",COOKIE+"="+encodeURIComponent(token)+"; Max-Age="+maxAge+"; Path=/; HttpOnly; Secure; SameSite=Strict");
    return json(res,200,{authenticated:true,expiresAt:p.exp*1000});
  }catch(e){
    console.error("LALIGA auth error",e instanceof Error?e.message:String(e));
    return json(res,502,{error:"No se pudo contactar con el servicio de autenticación de LALIGA"});
  }
}
