/**
 * Vercel serverless function: browser -> this function -> LALIGA Fantasy API.
 * It is intentionally NOT a generic proxy.
 */
const UPSTREAM="https://fantasy-api.llt-services.com";
const ALLOWED=[
  /^\/v3\/teams-master$/,
  /^\/v1\/competition\/1\/players$/,
  /^\/v1\/competition\/1\/player\/[^/]+\/market-value$/,
  /^\/v1\/competition\/1\/week\/current$/,
  /^\/v1\/competition\/1\/calendar$/,
  /^\/stats\/v1\/competition\/1\/stats\/week\/[^/]+$/
];
function allowed(p){return ALLOWED.some(r=>r.test(p))}
export default async function handler(req,res){
  if(req.method!=="GET"){res.setHeader("Allow","GET");return res.status(405).json({error:"Only GET is allowed"})}
  let parts=req.query?.path;if(typeof parts==="string")parts=[parts];if(!Array.isArray(parts))parts=[];
  const p="/"+parts.map(x=>encodeURIComponent(String(x))).join("/");
  if(!allowed(p))return res.status(403).json({error:"Endpoint is not on the public allowlist",path:p});
  const u=new URL("/api"+p,UPSTREAM);
  for(const key of ["week","weekNumber","x-lang"]){
    const v=req.query?.[key];
    if(typeof v==="string" && (key==="x-lang"?/^[a-z]{2}(?:-[A-Z]{2})?$/.test(v):/^[0-9]+$/.test(v)))u.searchParams.set(key,v);
  }
  try{
    const r=await fetch(u,{method:"GET",headers:{Accept:"application/json", "User-Agent":"LALIGA-Fantasy-Public-Viewer/1.0"},cache:"no-store"});
    const body=await r.text();
    res.setHeader("Content-Type",r.headers.get("content-type")||"application/json; charset=utf-8");
    res.setHeader("Cache-Control","no-store");
    return res.status(r.status).send(body);
  }catch(e){
    console.error(e);
    return res.status(502).json({error:"Could not reach the LALIGA Fantasy API",details:e instanceof Error?e.message:String(e)});
  }
}