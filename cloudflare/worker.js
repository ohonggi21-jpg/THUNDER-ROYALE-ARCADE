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
  const allowed = [env.ADMIN_UIDS, env.ADMIN_UIDS_EXTRA]
    .flatMap(value => String(value || "").split(","))
    .map(x => x.trim())
    .filter(Boolean);
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
/**
 * @param {{fields?: Record<string, any>}} doc
 * @returns {Record<string, any>}
 */
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
async function firestoreSet(env,token,path,value,previous={},updateTime=null) {
  const fields={};for(const [k,v] of Object.entries(value))fields[k]=firestoreValue(v);
  const oldKeys=Object.keys(previous||{}),newKeys=Object.keys(value||{});
  const params=new URLSearchParams();
  for(const key of [...new Set([...oldKeys,...newKeys])])params.append("updateMask.fieldPaths",key);
  if(updateTime)params.set("currentDocument.updateTime",updateTime);
  const suffix=params.toString()?"?"+params.toString():"";
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


const DUEL_GAMES = new Set(["dice","slot","card","roulette","poker","bj"]);
const DUEL_TICKET_MAX = 3;
const DUEL_REFILL_MS = 5 * 60 * 1000;

async function ensureDuelTables(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS duel_wallets (uid TEXT PRIMARY KEY, player_id TEXT NOT NULL, tickets INTEGER NOT NULL DEFAULT 3, refill_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS duel_rooms (code TEXT PRIMARY KEY, game TEXT NOT NULL, host_uid TEXT NOT NULL, host_player_id TEXT NOT NULL, host_name TEXT NOT NULL, guest_uid TEXT, guest_player_id TEXT, guest_name TEXT, created_at INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS duel_bets (code TEXT NOT NULL, mid INTEGER NOT NULL, uid TEXT NOT NULL, player_id TEXT NOT NULL, role TEXT NOT NULL, stake INTEGER NOT NULL, game TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY(code,mid,uid), UNIQUE(code,mid,role))").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS duel_settlements (code TEXT NOT NULL, mid INTEGER NOT NULL, host_result TEXT NOT NULL, host_points INTEGER NOT NULL, guest_points INTEGER NOT NULL, host_stake INTEGER NOT NULL, guest_stake INTEGER NOT NULL, settled_at INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY(code,mid))").run();
}
async function duelIdentity(request,env,data) {
  const identity=await verifyFirebase(request,env);
  const playerId=String(data.playerId||"");
  if(!validId(playerId))throw new Error("플레이어 계정 ID가 올바르지 않습니다.");
  const doc=await firestoreGet(env,identity.token,"players/"+playerId);
  if(!doc)throw new Error("플레이어 계정을 찾을 수 없습니다. 게임에 다시 입장해 주세요.");
  const player=decodeFirestoreDoc(doc);
  if(player.ownerUid!==identity.uid)throw new Error("이 닉네임은 현재 로그인 계정에 연결되어 있지 않습니다.");
  if(player.moderation&&player.moderation.status==="banned")throw new Error("이 계정은 온라인 대결 이용이 제한되어 있습니다.");
  return {...identity,playerId,player};
}
function duelWalletView(row,now) {
  const tickets=Math.max(0,Math.min(DUEL_TICKET_MAX,Number(row.tickets)||0));
  const refillAt=Number(row.refill_at)||now;
  return {tickets,maxTickets:DUEL_TICKET_MAX,refillInMs:tickets>=DUEL_TICKET_MAX?0:Math.max(0,refillAt+DUEL_REFILL_MS-now),nextRefillAt:tickets>=DUEL_TICKET_MAX?null:refillAt+DUEL_REFILL_MS};
}
async function duelWalletStatus(env,uid,playerId) {
  const now=Date.now();
  await env.DB.prepare("INSERT OR IGNORE INTO duel_wallets(uid,player_id,tickets,refill_at,updated_at) VALUES(?,?,3,?,?)").bind(uid,playerId,now,now).run();
  for(let tries=0;tries<6;tries++){
    const row=await env.DB.prepare("SELECT uid,player_id,tickets,refill_at FROM duel_wallets WHERE uid=?").bind(uid).first();
    if(!row)throw new Error("티켓 지갑을 불러오지 못했습니다.");
    const oldTickets=Number(row.tickets)||0,oldAnchor=Number(row.refill_at)||now;
    const elapsed=Math.max(0,Math.floor((now-oldAnchor)/DUEL_REFILL_MS));
    const tickets=Math.min(DUEL_TICKET_MAX,oldTickets+elapsed);
    let anchor=oldAnchor+elapsed*DUEL_REFILL_MS;
    if(tickets>=DUEL_TICKET_MAX)anchor=now;
    if(tickets===oldTickets&&anchor===oldAnchor)return duelWalletView(row,now);
    const updated=await env.DB.prepare("UPDATE duel_wallets SET tickets=?,refill_at=?,updated_at=?,player_id=? WHERE uid=? AND tickets=? AND refill_at=?")
      .bind(tickets,anchor,now,playerId,uid,oldTickets,oldAnchor).run();
    if(Number(updated.meta&&updated.meta.changes)>0)return duelWalletView({tickets,refill_at:anchor},now);
  }
  throw new Error("티켓 정보를 동시에 변경 중입니다. 다시 눌러 주세요.");
}
async function debitDuelTickets(env,uid,playerId,stake) {
  if(!Number.isInteger(stake)||stake<1||stake>3)throw new Error("베팅은 티켓 1~3개 중에서 선택해 주세요.");
  const now=Date.now();
  await env.DB.prepare("INSERT OR IGNORE INTO duel_wallets(uid,player_id,tickets,refill_at,updated_at) VALUES(?,?,3,?,?)").bind(uid,playerId,now,now).run();
  for(let tries=0;tries<8;tries++){
    const row=await env.DB.prepare("SELECT tickets,refill_at FROM duel_wallets WHERE uid=?").bind(uid).first();
    if(!row)throw new Error("티켓 지갑을 찾을 수 없습니다.");
    const oldTickets=Number(row.tickets)||0,oldAnchor=Number(row.refill_at)||now;
    const elapsed=Math.max(0,Math.floor((now-oldAnchor)/DUEL_REFILL_MS));
    const available=Math.min(DUEL_TICKET_MAX,oldTickets+elapsed);
    let anchor=oldAnchor+elapsed*DUEL_REFILL_MS;
    if(available>=DUEL_TICKET_MAX)anchor=now;
    if(available<stake)throw new Error("티켓이 부족합니다. 현재 "+available+"개이며, 5분마다 1개 충전됩니다.");
    const updated=await env.DB.prepare("UPDATE duel_wallets SET tickets=?,refill_at=?,updated_at=?,player_id=? WHERE uid=? AND tickets=? AND refill_at=?")
      .bind(available-stake,anchor,now,playerId,uid,oldTickets,oldAnchor).run();
    if(Number(updated.meta&&updated.meta.changes)>0)return {tickets:available-stake,refill_at:anchor};
  }
  throw new Error("티켓을 차감하는 중 충돌이 발생했습니다. 다시 시도해 주세요.");
}
async function creditDuelTickets(env,uid,playerId,amount) {
  const now=Date.now();
  await duelWalletStatus(env,uid,playerId);
  for(let tries=0;tries<8;tries++){
    const row=await env.DB.prepare("SELECT tickets,refill_at FROM duel_wallets WHERE uid=?").bind(uid).first();
    if(!row)throw new Error("티켓 지갑을 찾을 수 없습니다.");
    const oldTickets=Number(row.tickets)||0,oldAnchor=Number(row.refill_at)||now;
    const elapsed=Math.max(0,Math.floor((now-oldAnchor)/DUEL_REFILL_MS));
    const current=Math.min(DUEL_TICKET_MAX,oldTickets+elapsed);
    let anchor=oldAnchor+elapsed*DUEL_REFILL_MS;
    const next=Math.min(DUEL_TICKET_MAX,current+amount);
    if(next>=DUEL_TICKET_MAX)anchor=now;
    const updated=await env.DB.prepare("UPDATE duel_wallets SET tickets=?,refill_at=?,updated_at=?,player_id=? WHERE uid=? AND tickets=? AND refill_at=?")
      .bind(next,anchor,now,playerId,uid,oldTickets,oldAnchor).run();
    if(Number(updated.meta&&updated.meta.changes)>0)return {tickets:next,refill_at:anchor};
  }
  throw new Error("티켓 반환 처리 중 충돌이 발생했습니다.");
}
function duelCode(v){const code=String(v||"");if(!/^\d{4}$/.test(code))throw new Error("방 코드는 숫자 4자리여야 합니다.");return code;}
function duelStake(v){const n=Number(v);if(!Number.isInteger(n)||n<1||n>3)throw new Error("베팅 티켓은 1~3개여야 합니다.");return n;}
async function createDuelRoom(request,env,data) {
  await ensureDuelTables(env);
  const id=await duelIdentity(request,env,data),code=duelCode(data.code),game=String(data.game||"");
  if(!DUEL_GAMES.has(game))throw new Error("지원하지 않는 온라인 게임입니다.");
  const stake=duelStake(data.stake),name=String(id.player.name||data.name||"Player").slice(0,40),createdAt=Date.now();
  const exists=await env.DB.prepare("SELECT code FROM duel_rooms WHERE code=?").bind(code).first();
  if(exists)throw new Error("방 코드가 중복되었습니다. 새 방을 다시 만들어 주세요.");
  try{
    await env.DB.prepare("INSERT INTO duel_rooms(code,game,host_uid,host_player_id,host_name,created_at) VALUES(?,?,?,?,?,?)")
      .bind(code,game,id.uid,id.playerId,name,createdAt).run();
  }catch(e){
    throw new Error("방 코드가 중복되었거나 생성 중 충돌이 발생했습니다. 새 방을 다시 만들어 주세요.");
  }
  let debited=false;
  try{
    await debitDuelTickets(env,id.uid,id.playerId,stake);
    debited=true;
    await env.DB.prepare("INSERT INTO duel_bets(code,mid,uid,player_id,role,stake,game,state) VALUES(?,0,?,?, 'h',?,?, 'pending')")
      .bind(code,id.uid,id.playerId,stake,game).run();
  }catch(e){
    await env.DB.prepare("DELETE FROM duel_bets WHERE code=? AND mid=0 AND uid=? AND role='h'").bind(code,id.uid).run().catch(()=>{});
    await env.DB.prepare("DELETE FROM duel_rooms WHERE code=? AND host_uid=? AND created_at=?").bind(code,id.uid,createdAt).run().catch(()=>{});
    if(debited)await creditDuelTickets(env,id.uid,id.playerId,stake).catch(()=>{});
    throw e;
  }
  return {ok:true,code,game,stake,wallet:await duelWalletStatus(env,id.uid,id.playerId)};
}
async function joinDuelRoom(request,env,data) {
  await ensureDuelTables(env);
  const id=await duelIdentity(request,env,data),code=duelCode(data.code),stake=duelStake(data.stake);
  const room=await env.DB.prepare("SELECT * FROM duel_rooms WHERE code=?").bind(code).first();
  if(!room)throw new Error("방을 찾을 수 없습니다.");
  if(room.host_uid===id.uid)throw new Error("자기 방에는 참가할 수 없습니다.");
  const hostBet=await env.DB.prepare("SELECT uid FROM duel_bets WHERE code=? AND mid=0 AND role='h'").bind(code).first();
  if(!hostBet)throw new Error("방이 아직 준비 중입니다. 잠시 후 다시 시도해 주세요.");
  if(room.guest_uid){
    if(room.guest_uid===id.uid&&room.guest_player_id===id.playerId){
      const existing=await env.DB.prepare("SELECT stake FROM duel_bets WHERE code=? AND mid=0 AND uid=? AND role='g'").bind(code,id.uid).first();
      if(!existing)throw new Error("참가 정보가 불완전합니다. 방장에게 새 방을 만들어 달라고 요청해 주세요.");
      if(Number(existing.stake)!==stake)throw new Error("이미 참가 확정된 베팅은 바꿀 수 없습니다.");
      return {ok:true,code,game:room.game,stake,wallet:await duelWalletStatus(env,id.uid,id.playerId),alreadyJoined:true};
    }
    throw new Error("이미 다른 플레이어가 참가한 방입니다.");
  }
  await debitDuelTickets(env,id.uid,id.playerId,stake);
  const name=String(id.player.name||data.name||"Player").slice(0,40);
  let claimed=false;
  try{
    const updated=await env.DB.prepare("UPDATE duel_rooms SET guest_uid=?,guest_player_id=?,guest_name=? WHERE code=? AND guest_uid IS NULL")
      .bind(id.uid,id.playerId,name,code).run();
    if(Number(updated.meta&&updated.meta.changes)!==1)throw new Error("다른 플레이어가 먼저 참가했습니다. 다른 방을 이용해 주세요.");
    claimed=true;
    await env.DB.prepare("INSERT INTO duel_bets(code,mid,uid,player_id,role,stake,game,state) VALUES(?,0,?,?, 'g',?,?, 'pending')")
      .bind(code,id.uid,id.playerId,stake,room.game).run();
  }catch(e){
    if(claimed)await env.DB.prepare("UPDATE duel_rooms SET guest_uid=NULL,guest_player_id=NULL,guest_name=NULL WHERE code=? AND guest_uid=? AND guest_player_id=?").bind(code,id.uid,id.playerId).run().catch(()=>{});
    await creditDuelTickets(env,id.uid,id.playerId,stake).catch(()=>{});
    throw e;
  }
  return {ok:true,code,game:room.game,stake,wallet:await duelWalletStatus(env,id.uid,id.playerId)};
}
async function reserveDuelBet(request,env,data) {
  await ensureDuelTables(env);
  const id=await duelIdentity(request,env,data),code=duelCode(data.code),mid=Number(data.mid),game=String(data.game||"");
  if(!Number.isSafeInteger(mid)||mid<1)throw new Error("다음 경기 번호가 올바르지 않습니다.");
  if(!DUEL_GAMES.has(game))throw new Error("지원하지 않는 온라인 게임입니다.");
  const stake=duelStake(data.stake),room=await env.DB.prepare("SELECT * FROM duel_rooms WHERE code=?").bind(code).first();
  if(!room)throw new Error("온라인 대결 방을 찾을 수 없습니다.");
  const role=room.host_uid===id.uid?"h":room.guest_uid===id.uid?"g":null;
  if(!role)throw new Error("이 대결 방의 참가자가 아닙니다.");
  if(!room.guest_uid)throw new Error("상대가 참가할 때까지 기다려 주세요.");
  const existing=await env.DB.prepare("SELECT * FROM duel_bets WHERE code=? AND mid=? AND uid=?").bind(code,mid,id.uid).first();
  if(existing){
    if(Number(existing.stake)!==stake)throw new Error("이미 확정한 다음 경기 베팅은 바꿀 수 없습니다.");
    await env.DB.prepare("UPDATE duel_bets SET game=? WHERE code=? AND mid=? AND uid=? AND state='pending'").bind(game,code,mid,id.uid).run();
    return {ok:true,code,mid,stake,game,wallet:await duelWalletStatus(env,id.uid,id.playerId),alreadyReserved:true};
  }
  const settled=await env.DB.prepare("SELECT state FROM duel_settlements WHERE code=? AND mid=?").bind(code,mid).first();
  if(settled)throw new Error("이미 종료된 경기입니다.");
  await debitDuelTickets(env,id.uid,id.playerId,stake);
  try{
    await env.DB.prepare("INSERT INTO duel_bets(code,mid,uid,player_id,role,stake,game,state) VALUES(?,?,?,?,?,?,?,'pending')")
      .bind(code,mid,id.uid,id.playerId,role,stake,game).run();
  }catch(e){
    await creditDuelTickets(env,id.uid,id.playerId,stake).catch(()=>{});
    throw e;
  }
  const otherRole=role==="h"?"g":"h";
  const other=await env.DB.prepare("SELECT stake,game FROM duel_bets WHERE code=? AND mid=? AND role=?").bind(code,mid,otherRole).first();
  return {ok:true,code,mid,stake,game,ready:!!other,wallet:await duelWalletStatus(env,id.uid,id.playerId)};
}
async function cancelDuelBet(request,env,data) {
  await ensureDuelTables(env);
  const id=await duelIdentity(request,env,data),code=duelCode(data.code),mid=Number(data.mid)||0;
  const room=await env.DB.prepare("SELECT * FROM duel_rooms WHERE code=?").bind(code).first();
  if(!room) return {ok:true,cancelled:false};
  const role=room.host_uid===id.uid?"h":room.guest_uid===id.uid?"g":null;
  if(!role)throw new Error("이 대결 방의 참가자가 아닙니다.");
  const otherRole=role==="h"?"g":"h";
  const other=await env.DB.prepare("SELECT uid FROM duel_bets WHERE code=? AND mid=? AND role=?").bind(code,mid,otherRole).first();
  if(other)throw new Error("상대 베팅까지 확정되어 티켓을 환불할 수 없습니다.");
  const own=await env.DB.prepare("SELECT stake FROM duel_bets WHERE code=? AND mid=? AND uid=? AND state='pending'").bind(code,mid,id.uid).first();
  let cancelled=false;
  if(own){
    await duelWalletStatus(env,id.uid,id.playerId);
    const t=Date.now(),stake=Number(own.stake)||0;
    const batch=await env.DB.batch([
      env.DB.prepare("UPDATE duel_wallets SET tickets=MIN(3,tickets+?),refill_at=CASE WHEN MIN(3,tickets+?)>=3 THEN ? ELSE refill_at END,updated_at=? WHERE uid=? AND EXISTS(SELECT 1 FROM duel_bets WHERE code=? AND mid=? AND uid=? AND state='pending')").bind(stake,stake,t,t,id.uid,code,mid,id.uid),
      env.DB.prepare("DELETE FROM duel_bets WHERE code=? AND mid=? AND uid=? AND state='pending'").bind(code,mid,id.uid)
    ]);
    cancelled=Number(batch[0]&&batch[0].meta&&batch[0].meta.changes)>0;
  }
  if(mid===0&&role==="h"){
    await env.DB.prepare("DELETE FROM duel_rooms WHERE code=? AND host_uid=?").bind(code,id.uid).run();
  }else if(mid===0&&role==="g"){
    await env.DB.prepare("UPDATE duel_rooms SET guest_uid=NULL,guest_player_id=NULL,guest_name=NULL WHERE code=? AND guest_uid=?").bind(code,id.uid).run();
  }
  return {ok:true,cancelled,wallet:await duelWalletStatus(env,id.uid,id.playerId)};
}
async function syncDuelPlayer(env,token,playerId,uid,opponent,stake,result,delta,settlementId,now) {
  const path="players/"+playerId;
  for(let tries=0;tries<4;tries++){
    const doc=await firestoreGet(env,token,path);
    if(!doc)throw new Error("정산할 플레이어 문서가 없습니다: "+playerId);
    const before=decodeFirestoreDoc(doc);
    if(before.ownerUid!==uid)throw new Error("정산 대상 계정의 소유자가 일치하지 않습니다.");
    const done=Array.isArray(before.duelSettlementIds)?before.duelSettlementIds:[];
    if(done.includes(settlementId))return;
    const p={...before};
    const deltaPoints=Number(delta)||0;
    p.cp=(Number(p.cp)||0)+deltaPoints;
    p.cpt=(Number(p.cpt)||0)+deltaPoints;
    p.cm=(Number(p.cm)||0)+1;
    p.cmt=(Number(p.cmt)||0)+1;
    p.xp=(Number(p.xp)||0)+20;
    const day=new Date(now+9*60*60*1000).toISOString().slice(0,10);
    if(!p.daily||p.daily.day!==day)p.daily={day,solo:0,games:[],duels:0,claims:{}};
    p.daily.onlineDuels=(Number(p.daily.onlineDuels)||0)+1;
    p.matchLog=[...(Array.isArray(p.matchLog)?p.matchLog:[]),{at:now,opponent,result,points:deltaPoints,stake}].slice(-50);
    if(result==="draw"){p.cd=(Number(p.cd)||0)+1;p.cdt=(Number(p.cdt)||0)+1;}
    else if(result==="win"){p.cw=(Number(p.cw)||0)+1;p.cwt=(Number(p.cwt)||0)+1;p.dw=(Number(p.dw)||0)+1;}
    else{p.cl=(Number(p.cl)||0)+1;p.clt=(Number(p.clt)||0)+1;}
    p.duelSettlementIds=[...done,settlementId].slice(-120);
    p.t=now;
    try{
      await firestoreSet(env,token,path,p,before,doc.updateTime);
      return;
    }catch(e){
      const msg=String(e&&e.message||e);
      if(tries===3||!/(409|ABORTED|FAILED_PRECONDITION|conflict|update time)/i.test(msg))throw e;
    }
  }
}
async function appendDuelSeasonHistory(env,token,entry) {
  for(let tries=0;tries<4;tries++){
    const doc=await firestoreGet(env,token,"meta/season");
    const before=doc?decodeFirestoreDoc(doc):{n:1,hof:[],history:[]};
    const history=Array.isArray(before.history)?before.history:[];
    if(history.some(x=>x&&x.id===entry.id))return;
    const next={...before,history:[...history,entry].slice(-200)};
    try{await firestoreSet(env,token,"meta/season",next,before,doc&&doc.updateTime);return;}
    catch(e){const msg=String(e&&e.message||e);if(tries===3||!/(409|ABORTED|FAILED_PRECONDITION|conflict|update time)/i.test(msg))throw e;}
  }
}
async function updateDuelHostDocument(env,token,code,settlement) {
  for(let tries=0;tries<4;tries++){
    const path="duels/"+code+"h",doc=await firestoreGet(env,token,path);
    if(!doc)return;
    const before=decodeFirestoreDoc(doc),next={...before,settlement};
    try{await firestoreSet(env,token,path,next,before,doc.updateTime);return;}
    catch(e){const msg=String(e&&e.message||e);if(tries===3||!/(409|ABORTED|FAILED_PRECONDITION|conflict|update time)/i.test(msg))throw e;}
  }
}
async function settleDuelMatch(request,env,data) {
  await ensureDuelTables(env);
  const id=await duelIdentity(request,env,data),code=duelCode(data.code),mid=Number(data.mid);
  if(!Number.isSafeInteger(mid)||mid<0)throw new Error("경기 번호가 올바르지 않습니다.");
  const room=await env.DB.prepare("SELECT * FROM duel_rooms WHERE code=?").bind(code).first();
  if(!room||room.host_uid!==id.uid)throw new Error("경기 결과는 방장만 정산할 수 있습니다.");
  if(!room.guest_uid)throw new Error("상대가 아직 참가하지 않았습니다.");
  const hostBet=await env.DB.prepare("SELECT * FROM duel_bets WHERE code=? AND mid=? AND role='h'").bind(code,mid).first();
  const guestBet=await env.DB.prepare("SELECT * FROM duel_bets WHERE code=? AND mid=? AND role='g'").bind(code,mid).first();
  if(!hostBet||!guestBet)throw new Error("양쪽 플레이어의 베팅이 확정되지 않았습니다.");
  const result=String(data.result||"");
  if(!["h","g","draw"].includes(result))throw new Error("경기 결과 값이 올바르지 않습니다.");
  const now=Date.now(),hostStake=Number(hostBet.stake),guestStake=Number(guestBet.stake);
  const hostPoints=result==="h"?3*hostStake:result==="g"?-3*hostStake:0;
  const guestPoints=result==="g"?3*guestStake:result==="h"?-3*guestStake:0;
  await env.DB.prepare("INSERT OR IGNORE INTO duel_settlements(code,mid,host_result,host_points,guest_points,host_stake,guest_stake,settled_at,state) VALUES(?,?,?,?,?,?,?,?,'pending')")
    .bind(code,mid,result,hostPoints,guestPoints,hostStake,guestStake,now).run();
  const settled=await env.DB.prepare("SELECT * FROM duel_settlements WHERE code=? AND mid=?").bind(code,mid).first();
  if(!settled)throw new Error("정산 기록을 만들지 못했습니다.");
  if(settled.host_result!==result)throw new Error("이미 다른 결과로 정산된 경기입니다.");
  if(settled.state==="pending"){
    if(result==="draw"){
      await Promise.all([
        duelWalletStatus(env,room.host_uid,room.host_player_id),
        duelWalletStatus(env,room.guest_uid,room.guest_player_id)
      ]);
      const t=Date.now();
      await env.DB.batch([
        env.DB.prepare("UPDATE duel_wallets SET tickets=MIN(3,tickets+?),refill_at=CASE WHEN MIN(3,tickets+?)>=3 THEN ? ELSE refill_at END,updated_at=? WHERE uid=? AND EXISTS(SELECT 1 FROM duel_settlements WHERE code=? AND mid=? AND state='pending')").bind(hostStake,hostStake,t,t,room.host_uid,code,mid),
        env.DB.prepare("UPDATE duel_wallets SET tickets=MIN(3,tickets+?),refill_at=CASE WHEN MIN(3,tickets+?)>=3 THEN ? ELSE refill_at END,updated_at=? WHERE uid=? AND EXISTS(SELECT 1 FROM duel_settlements WHERE code=? AND mid=? AND state='pending')").bind(guestStake,guestStake,t,t,room.guest_uid,code,mid),
        env.DB.prepare("UPDATE duel_bets SET state='settled' WHERE code=? AND mid=?").bind(code,mid),
        env.DB.prepare("UPDATE duel_settlements SET state='settled' WHERE code=? AND mid=? AND state='pending'").bind(code,mid)
      ]);
    }else{
      await env.DB.batch([
        env.DB.prepare("UPDATE duel_bets SET state='settled' WHERE code=? AND mid=?").bind(code,mid),
        env.DB.prepare("UPDATE duel_settlements SET state='settled' WHERE code=? AND mid=? AND state='pending'").bind(code,mid)
      ]);
    }
  }
  const settlementId=code+":"+mid;
  const hostResult=result==="draw"?"draw":result==="h"?"win":"loss";
  const guestResult=result==="draw"?"draw":result==="g"?"win":"loss";
  await syncDuelPlayer(env,id.token,room.host_player_id,room.host_uid,room.guest_name,hostStake,hostResult,Number(settled.host_points),settlementId,Number(settled.settled_at)||now);
  await syncDuelPlayer(env,id.token,room.guest_player_id,room.guest_uid,room.host_name,guestStake,guestResult,Number(settled.guest_points),settlementId,Number(settled.settled_at)||now);
  const entry={id:settlementId,time:Number(settled.settled_at)||now,p1:room.host_name,p2:room.guest_name,result:result==="draw"?-1:result==="h"?0:1,winner:result==="draw"?"":result==="h"?room.host_name:room.guest_name,hostStake,guestStake,hostPoints:Number(settled.host_points),guestPoints:Number(settled.guest_points)};
  await appendDuelSeasonHistory(env,id.token,entry);
  const clientSettlement={id:settlementId,mid,hostResult:result,hostPoints:Number(settled.host_points),guestPoints:Number(settled.guest_points),hostStake:Number(settled.host_stake),guestStake:Number(settled.guest_stake),settledAt:Number(settled.settled_at)};
  await updateDuelHostDocument(env,id.token,code,clientSettlement);
  return {ok:true,settlement:clientSettlement,wallet:await duelWalletStatus(env,id.uid,id.playerId)};
}
async function duelAction(request,env,action,data) {
  if(action==="wallet"){
    await ensureDuelTables(env);
    const id=await duelIdentity(request,env,data);
    return {ok:true,wallet:await duelWalletStatus(env,id.uid,id.playerId)};
  }
  if(action==="create")return createDuelRoom(request,env,data);
  if(action==="join")return joinDuelRoom(request,env,data);
  if(action==="reserve")return reserveDuelBet(request,env,data);
  if(action==="cancel")return cancelDuelBet(request,env,data);
  if(action==="settle")return settleDuelMatch(request,env,data);
  throw new Error("지원하지 않는 온라인 대결 작업입니다.");
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
      const ranked=/** @type {Array<Record<string, any> & {id: string}>} */ (docs.map(d=>({id:String(d.name.split("/").pop()||""),...decodeFirestoreDoc(d)}))).filter(p=>(Number(p.cm)||0)>0).sort((a,b)=>(Number(b.cp)||0)-(Number(a.cp)||0));
      const champ=ranked[0];
      if(season!==(Number(before.n)||1)&&champ)after.hof=[...(Array.isArray(before.hof)?before.hof:[]),{s:Number(before.n)||1,name:champ.name||"Unknown",points:Number(champ.cp)||0,wins:Number(champ.cw)||0,matches:Number(champ.cm)||0}];
      for(const d of docs){
        const p=decodeFirestoreDoc(d),reset=withAdminChange(p,{...p,cp:0,cw:0,cd:0,cl:0,cm:0},["cp","cw","cd","cl","cm"]);
        await firestoreSet(env,token,"players/"+d.name.split("/").pop(),reset,p,d.updateTime);
        await audit(db,uid,"resetChampionship",d.name.split("/").pop(),p,reset,"시즌 변경에 따른 챔피언십 점수 초기화",{fields:["cp","cw","cd","cl","cm"]});
      }
    }
    await firestoreSet(env,token,path,after,before,doc&&doc.updateTime);
    await audit(db,uid,action,null,before,after,"Firebase 시즌 번호 변경");
    return {ok:true,season,meta:after};
  }
  // Rollback identifies the target from the audit row, not request.playerId.
  const id=String(data.playerId||"");
  if(action!=="rollback"&&!validId(id))throw new Error("잘못된 계정 ID입니다.");
  const path=id ? "players/"+id : "";
  const doc=id ? await firestoreGet(env,token,path) : null;
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
    await firestoreSet(env,token,path,after,before,doc&&doc.updateTime);
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
    await firestoreSet(env,token,path,versioned,before,doc&&doc.updateTime);
    await audit(db,uid,action,id,before,versioned,cleanReason(data.reason)||field+" "+delta,{field,delta});
    return {ok:true,player:versioned};
  }
  if(action==="rollback"){
    const auditId=Number(data.auditId);
    if(!Number.isInteger(auditId)||auditId<1)throw new Error("잘못된 감사 기록 ID입니다.");
    const log=await db.prepare("SELECT action,player_id,before_json,after_json,details_json FROM admin_audit WHERE id=?").bind(auditId).first();
    if(!log||!log.before_json)throw new Error("복원 가능한 변경 기록이 아닙니다.");
    const restore=JSON.parse(log.before_json);
    if(log.action==="setSeason"){
      const seasonPath="meta/season",currentDoc=await firestoreGet(env,token,seasonPath),current=currentDoc?decodeFirestoreDoc(currentDoc):{};
      await firestoreSet(env,token,seasonPath,restore,current,currentDoc&&currentDoc.updateTime);
      await audit(db,uid,"rollback",null,current,restore,"시즌 변경 롤백",{sourceAuditId:auditId});
      return {ok:true,meta:restore};
    }
    const playerId=String(log.player_id||"");
    if(!validId(playerId))throw new Error("복원 기록의 계정 ID가 올바르지 않습니다.");
    const playerPath="players/"+playerId;
    const currentDoc=await firestoreGet(env,token,playerPath),current=currentDoc?decodeFirestoreDoc(currentDoc):{};
    if(!currentDoc&&log.action!=="deletePlayer")throw new Error("현재 플레이어 문서가 없어 이 변경은 안전하게 롤백할 수 없습니다.");
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
    } else if(log.action==="resetChampionship"){
      next={...current};
      for(const field of ["cp","cw","cd","cl","cm"]){
        if(Object.prototype.hasOwnProperty.call(restore,field))next[field]=restore[field];else delete next[field];
      }
      next=withAdminChange(current,next,["cp","cw","cd","cl","cm"]);
    } else {
      next=restore;
      if(current&&Object.keys(current).length)next=withAdminChange(current,next,Object.keys(restore));
    }
    await firestoreSet(env,token,playerPath,next,current,currentDoc&&currentDoc.updateTime);
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
        return json({ok:!!row,service:"thunder-royale-api",database:"connected",version:"duel-room-race-fix-2026-11-07-v5"});
      }
      if (request.method!=="POST") return json({error:"Not found"},404);
      const data=await request.json();
      if(url.pathname.startsWith("/duel/")){
        const action=url.pathname.slice("/duel/".length);
        const result=await duelAction(request,env,action,data);
        return json(result);
      }
      if(!url.pathname.startsWith("/admin/")) return json({error:"Not found"},404);
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
