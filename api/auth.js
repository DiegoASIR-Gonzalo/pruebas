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
