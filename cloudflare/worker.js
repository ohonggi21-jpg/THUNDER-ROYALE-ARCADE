const cors = {
  "Access-Control-Allow-Origin": "https://ohonggi21-jpg.github.io",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Vary": "Origin"
};

function json(data, status=200) {
  return new Response(JSON.stringify(data), { status, headers: { ...cors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}
function cleanReason(v) { return String(v || "").trim().slice(0, 240); }
function validId(v) { return typeof v === "string" && /^[a-z0-9_]{1,180}$/.test(v); }

let firebaseJwksCache = null;
let firebaseJwksCacheUntil = 0;

function base64UrlBytes(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("토큰 조각에 허용되지 않은 문자가 있습니다.");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, ch => ch.charCodeAt(0));
}

function decodeJwtJson(segment, label) {
  try {
    const bytes = base64UrlBytes(segment);
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch (_) {
    throw new Error("Firebase 로그인 토큰의 " + label + " 부분을 해석할 수 없습니다.");
  }
}

async function getFirebaseJwks() {
  const now = Date.now();
  if (firebaseJwksCache && now < firebaseJwksCacheUntil) return firebaseJwksCache;
  const response = await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
  if (!response.ok) throw new Error("Firebase 공개키를 가져오지 못했습니다. HTTP " + response.status);
  const data = await response.json();
  if (!data.keys || !Array.isArray(data.keys)) throw new Error("Firebase 공개키 응답이 올바르지 않습니다.");
  const cacheControl = response.headers.get("Cache-Control") || "";
  const maxAge = Number((cacheControl.match(/max-age=(\d+)/i) || [])[1]) || 3600;
  firebaseJwksCache = data.keys;
  firebaseJwksCacheUntil = now + Math.min(maxAge, 86400) * 1000;
  return firebaseJwksCache;
}

async function verifyFirebase(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!bearerMatch) throw new Error("Firebase 로그인 토큰이 Authorization Bearer 헤더에 없습니다.");
  const token = bearerMatch[1].trim();
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some(part => !part)) throw new Error("Firebase 로그인 토큰 형식이 올바르지 않습니다.");
  const header = decodeJwtJson(parts[0], "헤더");
  const payload = decodeJwtJson(parts[1], "본문");
  if (header.alg !== "RS256" || typeof header.kid !== "string" || !header.kid) throw new Error("Firebase 로그인 토큰 서명 정보가 올바르지 않습니다.");
  const now = Math.floor(Date.now() / 1000);
  const projectId = String(env.FIREBASE_PROJECT_ID || "").trim();
  if (!projectId || payload.aud !== projectId || payload.iss !== "https://securetoken.google.com/" + projectId ||
      typeof payload.sub !== "string" || !payload.sub || payload.sub.length > 128 ||
      typeof payload.exp !== "number" || payload.exp <= now ||
      typeof payload.iat !== "number" || payload.iat > now + 300) {
    throw new Error("Firebase 로그인 토큰이 만료되었거나 프로젝트 정보가 일치하지 않습니다.");
  }
  const keys = await getFirebaseJwks();
  const jwk = keys.find(key => key.kid === header.kid && key.kty === "RSA");
  if (!jwk) { firebaseJwksCache = null; firebaseJwksCacheUntil = 0; throw new Error("Firebase 로그인 서명 키를 찾을 수 없습니다. 다시 인증해 주세요."); }
  let valid = false;
  try {
    const publicKey = await crypto.subtle.importKey("jwk", jwk, { name:"RSASSA-PKCS1-v1_5", hash:"SHA-256" }, false, ["verify"]);
    valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, base64UrlBytes(parts[2]), new TextEncoder().encode(parts[0]+"."+parts[1]));
  } catch (_) { throw new Error("Firebase 로그인 토큰 서명을 확인하지 못했습니다."); }
  if (!valid) throw new Error("Firebase 로그인 토큰 서명이 유효하지 않습니다.");
  return { uid: payload.sub, token, projectId };
}
async function requireAdmin(request, env) {
  const identity = await verifyFirebase(request, env);
  const allowed = String(env.ADMIN_UIDS || "").split(",").map(x => x.trim()).filter(Boolean);
  if (!allowed.includes(identity.uid)) throw new Error("관리자 권한이 없습니다.");
  return identity;
}
function firestoreValue(v) {
  if (v === null) return { nullValue:"NULL_VALUE" };
  if (typeof v === "boolean") return { booleanValue:v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue:String(v) } : { doubleValue:v };
  if (typeof v === "string") return { stringValue:v };
  if (Array.isArray(v)) return { arrayValue:{ values:v.map(firestoreValue) } };
  if (typeof v === "object") {
    const fields={}; for (const [k,x] of Object.entries(v)) fields[k]=firestoreValue(x);
    return { mapValue:{ fields } };
  }
  return { nullValue:"NULL_VALUE" };
}
function fromFirestoreValue(v) {
  if ("nullValue" in v) return null;
  if ("booleanValue" in v) return v.booleanValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return Number(v.doubleValue);
  if ("stringValue" in v) return v.stringValue;
  if ("timestampValue" in v) return v.timestampValue;
  if ("arrayValue" in v) return (v.arrayValue.values||[]).map(fromFirestoreValue);
  if ("mapValue" in v) return Object.fromEntries(Object.entries(v.mapValue.fields||{}).map(([k,x])=>[k,fromFirestoreValue(x)]));
  return null;
}
function decodeFirestoreDoc(doc) {
  return Object.fromEntries(Object.entries(doc.fields||{}).map(([k,v])=>[k,fromFirestoreValue(v)]));
}
function firestoreBase(env) {
  const project=String(env.FIREBASE_PROJECT_ID||"").trim();
  if (!project) throw new Error("FIREBASE_PROJECT_ID 설정이 없습니다.");
  return "https://firestore.googleapis.com/v1/projects/"+encodeURIComponent(project)+"/databases/(default)/documents/";
}
async function firestoreRequest(env, token, path, options={}) {
  const response=await fetch(firestoreBase(env)+path,{...options,headers:{Authorization:"Bearer "+token,"Content-Type":"application/json",...(options.headers||{})}});
  const raw=await response.text(); let body={}; try{body=raw?JSON.parse(raw):{}}catch(_){}
  if(!response.ok) {
    const msg=body.error&&body.error.message?body.error.message:("Firestore 요청 실패 · HTTP "+response.status);
    throw new Error(msg.slice(0,500));
  }
  return body;
}
async function firestoreGet(env,token,path) {
  const response=await fetch(firestoreBase(env)+path,{headers:{Authorization:"Bearer "+token}});
  if(response.status===404)return null;
  const raw=await response.text();let body={};try{body=raw?JSON.parse(raw):{}}catch(_){}
  if(!response.ok)throw new Error((body.error&&body.error.message)||("Firestore 조회 실패 · HTTP "+response.status));
  return body;
}
async function firestoreSet(env,token,path,value,previous={}) {
  const fields={};for(const [k,v] of Object.entries(value))fields[k]=firestoreValue(v);
  const oldKeys=Object.keys(previous||{}),newKeys=Object.keys(value||{});
  const masks=[...new Set([...oldKeys,...newKeys])];
  const qs=masks.map(k=>"updateMask.fieldPaths="+encodeURIComponent(k)).join("&");
  const suffix=qs?"?"+qs:"";
  return firestoreRequest(env,token,path+suffix,{method:"PATCH",body:JSON.stringify({fields})});
}
async function firestoreDelete(env,token,path) {
  const response=await fetch(firestoreBase(env)+path,{method:"DELETE",headers:{Authorization:"Bearer "+token}});
  if(response.status===404)return;
  if(!response.ok){const raw=await response.text();throw new Error("Firestore 삭제 실패 · HTTP "+response.status+" "+raw.slice(0,300));}
}

async function firestoreListAll(env,token,collectionName,limit=5000) {
  const documents=[];let pageToken="";
  do {
    const params=new URLSearchParams({pageSize:"1000"});
    if(pageToken)params.set("pageToken",pageToken);
    const page=await firestoreRequest(env,token,collectionName+"?"+params.toString());
    documents.push(...(page.documents||[]));
    pageToken=page.nextPageToken||"";
    if(documents.length>limit&&pageToken)throw new Error("Firestore 목록이 안전 조회 한도 "+limit+"개를 초과했습니다.");
  } while(pageToken);
  return documents;
}
async function isPlayerDeleted(env,token,id) {
  return !!(await firestoreGet(env,token,"meta/deletedPlayer_"+id));
}
async function setPlayerDeleted(env,token,id,uid) {
  const path="meta/deletedPlayer_"+id;
  const beforeDoc=await firestoreGet(env,token,path);
  const before=beforeDoc?decodeFirestoreDoc(beforeDoc):{};
  const after={kind:"deletedPlayer",id,deletedAt:Date.now(),deletedBy:uid||"admin"};
  await firestoreSet(env,token,path,after,before);
}
async function clearPlayerDeleted(env,token,id) {
  await firestoreDelete(env,token,"meta/deletedPlayer_"+id);
}
async function listDeletedPlayerIds(env,token) {
  const docs=await firestoreListAll(env,token,"meta");
  return new Set(docs.filter(d=>d.fields?.kind?.stringValue==="deletedPlayer").map(d=>d.fields?.id?.stringValue||d.name.split("/").pop().replace(/^deletedPlayer_/,"")));
}
function withAdminChange(before,after,fields) {
  const protectedFields=new Set([...(Array.isArray(before.adminFields)?before.adminFields:[]),...fields]);
  return {...after,adminRevision:(Number(before.adminRevision)||0)+1,adminFields:[...protectedFields]};
}

async function audit(db, actor, action, playerId, before, after, note="", details={}) {
  await db.prepare("INSERT INTO admin_audit(actor_uid, action, player_id, note, before_json, after_json, details_json, created_at) VALUES(?,?,?,?,?,?,?,?)")
    .bind(actor, action, playerId || null, cleanReason(note), before == null ? null : JSON.stringify(before), after == null ? null : JSON.stringify(after), JSON.stringify(details || {}), Date.now()).run();
}

async function adminAction(request, env, action, data) {
  const identity=await requireAdmin(request,env), uid=identity.uid, token=identity.token, db=env.DB;
  if (action==="check") {
    const doc=await firestoreGet(env,token,"meta/season");
    const meta=doc?decodeFirestoreDoc(doc):{n:1,hof:[],history:[]};
    return {ok:true,uid,season:Number(meta.n)||1};
  }
  if (action==="importBackup") {
    if (!["THUNDER ROYALE ARCADE","THUNDER ROYALE CASINO"].includes(data.app)) throw new Error("지원하지 않는 백업 게임입니다.");
    const players=data.players;
    if (!players||typeof players!=="object"||Array.isArray(players)||Object.keys(players).length<1||Object.keys(players).length>5000) throw new Error("백업의 플레이어 데이터 형식이 올바르지 않습니다.");
    if (!data.meta||typeof data.meta!=="object"||Array.isArray(data.meta)) throw new Error("백업의 시즌 데이터가 올바르지 않습니다.");
    for(const [id,p] of Object.entries(players))if(!validId(id)||!p||typeof p!=="object"||Array.isArray(p))throw new Error("백업에 올바르지 않은 플레이어 항목이 있습니다: "+id);
    const existing=await db.prepare("SELECT COUNT(*) AS count FROM players").first();
    const existingMeta=await db.prepare("SELECT key FROM meta WHERE key='season'").first();
    if((Number(existing&&existing.count)||0)>0||existingMeta)throw new Error("D1에 이미 데이터가 있어 가져오기를 중단했습니다. 기존 데이터를 덮어쓰지 않았습니다.");
    const now=Date.now(),statements=Object.entries(players).map(([id,p])=>db.prepare("INSERT INTO players(id,data_json,updated_at) VALUES(?,?,?)").bind(id,JSON.stringify(p),now));
    statements.push(db.prepare("INSERT INTO meta(key,value_json,updated_at) VALUES('season',?,?)").bind(JSON.stringify(data.meta),now));
    statements.push(db.prepare("INSERT INTO admin_audit(actor_uid,action,player_id,note,before_json,after_json,details_json,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(uid,"importBackup",null,"사용자 백업 JSON D1 보관",null,null,JSON.stringify({imported:Object.keys(players).length,version:data.version||null}),now));
    await db.batch(statements);return {ok:true,imported:Object.keys(players).length,season:Number(data.meta.n)||1};
  }
  if(action==="listAudit"){
    const rows=await db.prepare("SELECT id,actor_uid,action,player_id,note,created_at FROM admin_audit ORDER BY id DESC LIMIT 40").all();
    return {items:rows.results||[]};
  }
  if(action==="listPlayers"){
    const [documents,deleted]=await Promise.all([firestoreListAll(env,token,"players"),listDeletedPlayerIds(env,token)]);
    const items=[];
    for(const doc of documents){
      const id=doc.name.split("/").pop();
      if(deleted.has(id)){await firestoreDelete(env,token,"players/"+id);continue;}
      items.push({id,player:decodeFirestoreDoc(doc)});
    }
    return {items};
  }
  if(action==="setSeason"){
    const season=Number(data.season);
    if(!Number.isInteger(season)||season<1||season>9999)throw new Error("시즌 번호는 1~9999 사이의 정수여야 합니다.");
    const path="meta/season",doc=await firestoreGet(env,token,path);
    /** @type {Record<string, any>} */
    const before = doc ? decodeFirestoreDoc(doc) : {n:1,hof:[],history:[]};
    /** @type {Record<string, any>} */
    const after = {...before,n:season,seasonAdjustedAt:Date.now()};
    if(data.resetChampionship===true){
      const [allDocs,deleted]=await Promise.all([firestoreListAll(env,token,"players"),listDeletedPlayerIds(env,token)]);
      const docs=allDocs.filter(d=>!deleted.has(d.name.split("/").pop()));
      const ranked=docs.map(d=>({id:d.name.split("/").pop(),...decodeFirestoreDoc(d)})).filter(p=>(Number(p.cm)||0)>0).sort((a,b)=>(Number(b.cp)||0)-(Number(a.cp)||0));
      const champ=ranked[0];
      if(season!==(Number(before.n)||1)&&champ)after.hof=[...(Array.isArray(before.hof)?before.hof:[]),{s:Number(before.n)||1,name:champ.name||"Unknown",points:Number(champ.cp)||0,wins:Number(champ.cw)||0,matches:Number(champ.cm)||0}];
      for(const d of docs){
        const p=decodeFirestoreDoc(d),reset=withAdminChange(p,{...p,cp:0,cw:0,cd:0,cl:0,cm:0},["cp","cw","cd","cl","cm"]);
        await firestoreSet(env,token,"players/"+d.name.split("/").pop(),reset,p);
      }
    }
    await firestoreSet(env,token,path,after,before);
    await audit(db,uid,action,null,before,after,"Firebase 시즌 번호 변경");
    return {ok:true,season,meta:after};
  }
  const id=String(data.playerId||"");
  if(!validId(id))throw new Error("잘못된 계정 ID입니다.");
  const path="players/"+id,doc=await firestoreGet(env,token,path);
  if(action==="deletePlayer"){
    if(!doc){
      if(await isPlayerDeleted(env,token,id))return {ok:true,deleted:id,alreadyDeleted:true};
      throw new Error("Firebase에서 계정을 찾을 수 없습니다.");
    }
    const before=decodeFirestoreDoc(doc);
    await audit(db,uid,action,id,before,null,data.reason||"관리자 계정 삭제");
    // Write a durable tombstone before deleting so old/offline clients cannot resurrect it.
    await setPlayerDeleted(env,token,id,uid);
    await firestoreDelete(env,token,path);
    if(await firestoreGet(env,token,path))throw new Error("계정 삭제 후에도 Firestore 문서가 남아 있습니다. 다시 시도해 주세요.");
    return {ok:true,deleted:id};
  }
  if(!doc)throw new Error("Firebase에서 계정을 찾을 수 없습니다.");
  const before=decodeFirestoreDoc(doc);
  if(action==="setBan"){
    const after=withAdminChange(before,{...before,moderation:data.banned?{status:"banned",reason:cleanReason(data.reason)||"관리자 제재",detectedAt:Date.now(),source:"admin"}:{status:"clear",reason:"",clearedAt:Date.now(),source:"admin"}},["moderation"]);
    await firestoreSet(env,token,path,after,before);
    await audit(db,uid,action,id,before,after,data.reason||"");
    return {ok:true,player:after};
  }
  if(action==="adjustScore"){
    const field=String(data.field||""),delta=Number(data.delta);
    if(!Number.isInteger(delta)||Math.abs(delta)>1000000)throw new Error("점수 변경값은 -1,000,000~1,000,000 정수여야 합니다.");
    const after={...before};
    if(field.startsWith("s.")){const game=field.slice(2);if(!/^[a-z0-9_-]{1,40}$/.test(game))throw new Error("잘못된 게임 항목입니다.");after.s={...(before.s||{})};after.s[game]=Math.max(0,(Number(after.s[game])||0)+delta);}
    else if(["pts","cp","xp","dw"].includes(field))after[field]=Math.max(0,(Number(before[field])||0)+delta);
    else throw new Error("허용되지 않은 점수 항목입니다.");
    const versioned=withAdminChange(before,after,[field]);
    await firestoreSet(env,token,path,versioned,before);
    await audit(db,uid,action,id,before,versioned,cleanReason(data.reason)||field+" "+delta,{field,delta});
    return {ok:true,player:after};
  }
  if(action==="rollback"){
    const auditId=Number(data.auditId);
    if(!Number.isInteger(auditId)||auditId<1)throw new Error("잘못된 감사 기록 ID입니다.");
    const log=await db.prepare("SELECT action,player_id,before_json,after_json,details_json FROM admin_audit WHERE id=?").bind(auditId).first();
    if(!log||!log.before_json)throw new Error("복원 가능한 변경 기록이 아닙니다.");
    const restore=JSON.parse(log.before_json);
    if(log.action==="setSeason"){
      const seasonPath="meta/season",currentDoc=await firestoreGet(env,token,seasonPath),current=currentDoc?decodeFirestoreDoc(currentDoc):{};
      await firestoreSet(env,token,seasonPath,restore,current);
      await audit(db,uid,"rollback",null,current,restore,"시즌 변경 롤백",{sourceAuditId:auditId});
      return {ok:true,meta:restore};
    }
    if(!log.player_id)throw new Error("복원 가능한 플레이어 변경 기록이 아닙니다.");
    const playerId=log.player_id,playerPath="players/"+playerId;
    const currentDoc=await firestoreGet(env,token,playerPath),current=currentDoc?decodeFirestoreDoc(currentDoc):{};
    let next;
    if(log.action==="deletePlayer"){
      await clearPlayerDeleted(env,token,playerId);
      next=restore;
    } else if(log.action==="setBan"){
      next={...current};
      if(Object.prototype.hasOwnProperty.call(restore,"moderation"))next.moderation=restore.moderation;else delete next.moderation;
      next=withAdminChange(current,next,["moderation"]);
    } else if(log.action==="adjustScore"){
      const details=JSON.parse(log.details_json||"{}"),field=String(details.field||"");
      next={...current};
      if(field.startsWith("s.")){
        const game=field.slice(2);next.s={...(current.s||{})};
        if(Object.prototype.hasOwnProperty.call(restore.s||{},game))next.s[game]=restore.s[game];else delete next.s[game];
      } else if(["pts","cp","xp","dw"].includes(field)){
        if(Object.prototype.hasOwnProperty.call(restore,field))next[field]=restore[field];else delete next[field];
      } else throw new Error("점수 롤백 항목을 확인할 수 없습니다.");
      next=withAdminChange(current,next,[field]);
    } else {
      next=restore;
      if(current&&Object.keys(current).length)next=withAdminChange(current,next,Object.keys(restore));
    }
    await firestoreSet(env,token,playerPath,next,current);
    await audit(db,uid,"rollback",playerId,current,next,"관리자 롤백",{sourceAuditId:auditId});
    return {ok:true,player:next,playerId};
  }
  throw new Error("지원하지 않는 관리자 작업입니다.");
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null,{status:204,headers:cors});
    const url=new URL(request.url);
    try {
      if (request.method==="GET" && url.pathname==="/health") {
        const row=await env.DB.prepare("SELECT 1 AS ok").first();
        return json({ok:!!row,service:"thunder-royale-api",database:"connected"});
      }
      if (request.method!=="POST" || !url.pathname.startsWith("/admin/")) return json({error:"Not found"},404);
      const data=await request.json();
      const action=url.pathname.slice("/admin/".length);
      const result=await adminAction(request,env,action,data);
      return json(result);
    } catch (error) {
      const message=error && error.message ? error.message : "요청 처리에 실패했습니다.";
      const status=/로그인|토큰/.test(message)?401:/권한/.test(message)?403:400;
      return json({error:message},status);
    }
  }
};
