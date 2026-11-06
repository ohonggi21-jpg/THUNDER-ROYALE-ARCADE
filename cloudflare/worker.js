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

async function verifyFirebase(request, env) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) throw new Error("로그인이 필요합니다.");
  // Google validates the Firebase ID token signature and expiry.
  const response = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(token));
  if (!response.ok) throw new Error("로그인 토큰을 확인할 수 없습니다.");
  const info = await response.json();
  if (info.aud !== env.FIREBASE_PROJECT_ID || info.iss !== "https://securetoken.google.com/" + env.FIREBASE_PROJECT_ID || !info.sub) {
    throw new Error("다른 프로젝트의 로그인 토큰입니다.");
  }
  return info.sub;
}

async function requireAdmin(request, env) {
  const uid = await verifyFirebase(request, env);
  const allowed = String(env.ADMIN_UIDS || "").split(",").map(x => x.trim()).filter(Boolean);
  if (!allowed.includes(uid)) throw new Error("관리자 권한이 없습니다.");
  return uid;
}

async function audit(db, actor, action, playerId, before, after, note="", details={}) {
  await db.prepare("INSERT INTO admin_audit(actor_uid, action, player_id, note, before_json, after_json, details_json, created_at) VALUES(?,?,?,?,?,?,?,?)")
    .bind(actor, action, playerId || null, cleanReason(note), before == null ? null : JSON.stringify(before), after == null ? null : JSON.stringify(after), JSON.stringify(details || {}), Date.now()).run();
}

async function adminAction(request, env, action, data) {
  const uid = await requireAdmin(request, env), db = env.DB;
  if (action === "check") {
    const row = await db.prepare("SELECT value_json FROM meta WHERE key='season'").first();
    const meta = row ? JSON.parse(row.value_json) : { n: 1, hof: [], history: [] };
    return { ok: true, uid, season: Number(meta.n) || 1 };
  }
  if (action === "importBackup") {
    if (!["THUNDER ROYALE ARCADE", "THUNDER ROYALE CASINO"].includes(data.app)) throw new Error("지원하지 않는 백업 게임입니다.");
    const players = data.players;
    if (!players || typeof players !== "object" || Array.isArray(players) || Object.keys(players).length < 1 || Object.keys(players).length > 5000) throw new Error("백업의 플레이어 데이터 형식이 올바르지 않습니다.");
    if (!data.meta || typeof data.meta !== "object" || Array.isArray(data.meta)) throw new Error("백업의 시즌 데이터가 올바르지 않습니다.");
    for (const [id, player] of Object.entries(players)) {
      if (!validId(id) || !player || typeof player !== "object" || Array.isArray(player)) throw new Error("백업에 올바르지 않은 플레이어 항목이 있습니다: " + id);
    }
    const existing = await db.prepare("SELECT COUNT(*) AS count FROM players").first();
    const existingMeta = await db.prepare("SELECT key FROM meta WHERE key='season'").first();
    if ((Number(existing && existing.count) || 0) > 0 || existingMeta) throw new Error("D1에 이미 데이터가 있어 가져오기를 중단했습니다. 기존 데이터를 덮어쓰지 않았습니다.");
    const now = Date.now();
    const statements = Object.entries(players).map(([id, player]) =>
      db.prepare("INSERT INTO players(id,data_json,updated_at) VALUES(?,?,?)").bind(id, JSON.stringify(player), now)
    );
    statements.push(
      db.prepare("INSERT INTO meta(key,value_json,updated_at) VALUES('season',?,?)").bind(JSON.stringify(data.meta), now),
      db.prepare("INSERT INTO admin_audit(actor_uid,action,player_id,note,before_json,after_json,details_json,created_at) VALUES(?,?,?,?,?,?,?,?)")
        .bind(uid, "importBackup", null, "사용자 백업 JSON D1 보관", null, null, JSON.stringify({ imported: Object.keys(players).length, version: data.version || null }), now)
    );
    await db.batch(statements);
    return { ok: true, imported: Object.keys(players).length, season: Number(data.meta.n) || 1 };
  }
  if (action === "listPlayers") {
    const rows = await db.prepare("SELECT id,data_json FROM players ORDER BY updated_at DESC LIMIT 500").all();
    return { items: (rows.results || []).map(r => ({ id:r.id, player:JSON.parse(r.data_json) })) };
  }
  if (action === "listAudit") {
    const rows = await db.prepare("SELECT id,actor_uid,action,player_id,note,created_at FROM admin_audit ORDER BY id DESC LIMIT 40").all();
    return { items: rows.results || [] };
  }
  if (action === "setSeason") {
    const season = Number(data.season);
    if (!Number.isInteger(season) || season < 1 || season > 9999) throw new Error("시즌 번호는 1~9999 사이의 정수여야 합니다.");
    const row = await db.prepare("SELECT value_json FROM meta WHERE key='season'").first();
    const before = row ? JSON.parse(row.value_json) : { n:1, hof:[], history:[] };
    const after = { ...before, n:season, seasonAdjustedAt:Date.now() };
    if (data.resetChampionship === true) {
      const rows = await db.prepare("SELECT id,data_json FROM players").all();
      const ranked = (rows.results || []).map(r=>({id:r.id,...JSON.parse(r.data_json)})).filter(p=>(Number(p.cm)||0)>0).sort((a,b)=>(Number(b.cp)||0)-(Number(a.cp)||0));
      const champion = ranked[0];
      if (season !== (Number(before.n)||1) && champion) after.hof=[...(Array.isArray(before.hof)?before.hof:[]),{s:Number(before.n)||1,name:champion.name||"Unknown",points:Number(champion.cp)||0,wins:Number(champion.cw)||0,matches:Number(champion.cm)||0}];
      for (const r of rows.results || []) {
        const p=JSON.parse(r.data_json); Object.assign(p,{cp:0,cw:0,cd:0,cl:0,cm:0});
        await db.prepare("UPDATE players SET data_json=?,updated_at=? WHERE id=?").bind(JSON.stringify(p),Date.now(),r.id).run();
      }
    }
    await db.prepare("INSERT INTO meta(key,value_json,updated_at) VALUES('season',?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at").bind(JSON.stringify(after),Date.now()).run();
    await audit(db,uid,action,null,before,after,"시즌 번호 변경");
    return { ok:true, season };
  }
  const id=String(data.playerId||"");
  if (!validId(id)) throw new Error("잘못된 계정 ID입니다.");
  const row=await db.prepare("SELECT data_json FROM players WHERE id=?").bind(id).first();
  if (!row) throw new Error("계정을 찾을 수 없습니다.");
  const before=JSON.parse(row.data_json);
  if (action==="deletePlayer") {
    await audit(db,uid,action,id,before,null,data.reason);
    await db.prepare("DELETE FROM players WHERE id=?").bind(id).run();
    return {ok:true};
  }
  if (action==="setBan") {
    const after={...before,moderation:data.banned?{status:"banned",reason:cleanReason(data.reason)||"관리자 제재",detectedAt:Date.now(),source:"admin"}:{status:"clear",reason:"",clearedAt:Date.now(),source:"admin"}};
    await db.prepare("UPDATE players SET data_json=?,updated_at=? WHERE id=?").bind(JSON.stringify(after),Date.now(),id).run();
    await audit(db,uid,action,id,before,after,data.reason);
    return {ok:true};
  }
  if (action==="adjustScore") {
    const field=String(data.field||""), delta=Number(data.delta);
    if (!Number.isInteger(delta)||Math.abs(delta)>1000000) throw new Error("점수 변경값은 -1,000,000~1,000,000 정수여야 합니다.");
    const after={...before};
    if(field.startsWith("s.")){const game=field.slice(2);if(!/^[a-z0-9_-]{1,40}$/.test(game))throw new Error("잘못된 게임 항목입니다.");after.s={...(before.s||{})};after.s[game]=Math.max(0,(Number(after.s[game])||0)+delta);}
    else if(["pts","cp","xp","dw"].includes(field))after[field]=Math.max(0,(Number(before[field])||0)+delta);
    else throw new Error("허용되지 않은 점수 항목입니다.");
    await db.prepare("UPDATE players SET data_json=?,updated_at=? WHERE id=?").bind(JSON.stringify(after),Date.now(),id).run();
    await audit(db,uid,action,id,before,after,field+" "+delta,{field,delta});
    return {ok:true};
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
